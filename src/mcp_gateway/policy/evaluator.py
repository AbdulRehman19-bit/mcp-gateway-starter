"""Pure policy evaluation: what may a role call and see. No I/O; unknown means denied.

Why a catalog: policy says `columns: ["*"]`, which only has meaning against the columns that
really exist, so the evaluator takes the (role-visible) catalog as input instead of guessing.
"""

from dataclasses import dataclass

from mcp_gateway.policy.models import Policy, RolePolicy


@dataclass(frozen=True)
class ColumnInfo:
    type: str
    masked: bool = False


# (schema, table) -> column name -> SQL type, as read from the DB by the read-only role.
Catalog = dict[tuple[str, str], dict[str, str]]
# (schema, table) -> column name -> info. Only what the role may reference.
AllowedTables = dict[tuple[str, str], dict[str, ColumnInfo]]


def get_role(policy: Policy, role: str) -> RolePolicy | None:
    return policy.roles.get(role)


def tool_allowed(policy: Policy, role: str, tool: str) -> bool:
    rp = get_role(policy, role)
    return rp is not None and tool in rp.tools


def effective_read_only(policy: Policy, role: str, global_read_only: bool) -> bool:
    """Read-only if the global switch OR the role says so. Unknown role: read-only."""
    rp = get_role(policy, role)
    return global_read_only or rp is None or rp.read_only


def writable_columns(policy: Policy, role: str, schema: str, table: str) -> frozenset[str]:
    """Columns update_record may touch: only what the policy lists, never a denied column."""
    rp = get_role(policy, role)
    rule = rp.schemas[schema].tables.get(table) if rp and schema in rp.schemas else None
    if rule is None:
        return frozenset()
    return frozenset(rule.writable_columns) - frozenset(rule.deny_columns)


def is_deletable(policy: Policy, role: str, schema: str, table: str) -> bool:
    rp = get_role(policy, role)
    rule = rp.schemas[schema].tables.get(table) if rp and schema in rp.schemas else None
    return rule is not None and rule.deletable


def allowed_tables(policy: Policy, role: str, catalog: Catalog) -> AllowedTables:
    """Resolve the role's table/column rules against the catalog.

    Denied columns are removed entirely so the SQL analyzer cannot even resolve them.
    Tables or columns the policy names but the DB does not show are ignored (fail closed).
    """
    rp = get_role(policy, role)
    if rp is None:
        return {}
    out: AllowedTables = {}
    for schema, schema_rule in rp.schemas.items():
        for table, rule in schema_rule.tables.items():
            existing = catalog.get((schema, table))
            if not existing:
                continue
            wanted = list(existing) if "*" in rule.columns else rule.columns
            denied = set(rule.deny_columns)
            masked = set(rule.mask_columns)
            cols = {
                c: ColumnInfo(type=existing[c], masked=c in masked)
                for c in wanted
                if c in existing and c not in denied
            }
            if cols:
                out[(schema, table)] = cols
    return out
