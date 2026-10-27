"""Startup probe: what can the CURRENT database role actually do to the gateway tables?

A wrong URL (the audit URL pointing at the schema owner, say) would silently defeat the
append-only guarantee, so the server checks effective privileges instead of trusting names.
"""

from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

_PROBE = text(
    "SELECT current_user AS who, "
    "(SELECT rolsuper OR rolcreaterole OR rolbypassrls FROM pg_roles "
    " WHERE rolname = current_user) AS admin, "
    "(SELECT count(*) FROM pg_tables WHERE tableowner = current_user) AS owns_tables, "
    "has_table_privilege('audit_log', 'INSERT') AS audit_insert, "
    "has_table_privilege('audit_log', 'SELECT') AS audit_select, "
    "has_table_privilege('audit_log', 'UPDATE') AS audit_update, "
    "has_table_privilege('audit_log', 'DELETE') AS audit_delete, "
    "has_table_privilege('audit_log', 'TRUNCATE') AS audit_truncate, "
    "has_table_privilege('approvals', 'INSERT') AS appr_insert, "
    "has_table_privilege('approvals', 'DELETE') AS appr_delete, "
    "has_table_privilege('approvals', 'TRUNCATE') AS appr_truncate"
)


async def probe_privileges(engine: AsyncEngine) -> dict[str, Any]:
    async with engine.connect() as conn:
        return dict((await conn.execute(_PROBE)).mappings().one())


def audit_role_problems(p: dict[str, Any]) -> list[str]:
    """The audit writer may INSERT into audit_log and do nothing else."""
    problems = _common_problems(p)
    if not p["audit_insert"]:
        problems.append("cannot INSERT into audit_log")
    for k in ("audit_select", "audit_update", "audit_delete", "audit_truncate", "appr_insert"):
        if p[k]:
            problems.append(f"has excess privilege: {k}")
    return problems


def approvals_role_problems(p: dict[str, Any]) -> list[str]:
    """The approvals role works on approvals only and never touches the audit trail."""
    problems = _common_problems(p)
    if not p["appr_insert"]:
        problems.append("cannot INSERT into approvals")
    for k in ("audit_insert", "audit_select", "audit_update", "audit_delete", "audit_truncate",
              "appr_delete", "appr_truncate"):  # fmt: skip
        if p[k]:
            problems.append(f"has excess privilege: {k}")
    return problems


def _common_problems(p: dict[str, Any]) -> list[str]:
    problems = []
    if p["admin"]:
        problems.append("is a superuser/createrole/bypassrls role")
    if p["owns_tables"]:
        problems.append("owns tables (ownership makes grants meaningless)")
    return problems
