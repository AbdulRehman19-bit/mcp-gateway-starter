"""Policy-aware SQL analysis and rewriting (pure).

Pipeline: single-SELECT guard -> sqlglot `qualify` against the role's allowed columns ->
post-checks on the qualified AST -> mask projections -> clamp LIMIT -> re-validate.
The SQL we execute is regenerated from the validated AST, never the caller's text.

Default deny: if anything cannot be resolved to an allowed table column, the query is rejected.
"""

from typing import Any

from sqlglot import exp, parse_one
from sqlglot.errors import SqlglotError
from sqlglot.optimizer.qualify import qualify

from mcp_gateway.policy.evaluator import AllowedTables
from mcp_gateway.sqlguard.guard import GuardError, ensure_single_select

MASK = "***"
_DIALECT = "postgres"

_Aliases = dict[str, set[tuple[str, str]]]
_Masked = dict[tuple[str, str], set[str]]

# Constructs that introduce row sources we cannot attribute to an allowed table, plus
# TableColumn: sqlglot's node for a whole-row reference (`SELECT users FROM users`), which
# would expose columns the policy denies.
_FORBIDDEN_SOURCES = (exp.Lateral, exp.Values, exp.Unnest, exp.TableColumn)


def _outer_selects(node: exp.Expr) -> list[exp.Select]:
    if isinstance(node, exp.Select):
        return [node]
    if isinstance(node, exp.SetOperation):
        return _outer_selects(node.left) + _outer_selects(node.right)
    raise GuardError(f"unexpected root: {type(node).__name__}")


def _clamp_limit(tree: exp.Expr, max_rows: int) -> None:
    current = tree.args.get("limit")
    value = max_rows
    if isinstance(current, exp.Limit):
        lit = current.expression
        if isinstance(lit, exp.Literal) and not lit.is_string and lit.name.isdigit():
            value = min(int(lit.name), max_rows)
    # LIMIT ALL, FETCH FIRST, negatives, expressions: all replaced by a plain bounded LIMIT.
    tree.set("limit", exp.Limit(expression=exp.Literal.number(value)))


def _schema_for_sqlglot(allowed: AllowedTables) -> dict[str, Any]:
    schema: dict[str, Any] = {}
    for (s, t), cols in allowed.items():
        schema.setdefault(s, {})[t] = {c: info.type for c, info in cols.items()}
    return schema


def rewrite_for_policy(sql: str, allowed: AllowedTables, *, max_rows: int) -> str:
    """Return SQL that is safe to run for this role, or raise GuardError."""
    ensure_single_select(sql)
    if not allowed:
        raise GuardError("role has no readable tables")
    try:
        tree = parse_one(sql, read=_DIALECT)
        if any(w.args.get("recursive") for w in tree.find_all(exp.With)):
            raise GuardError("recursive CTE not allowed")
        tree = qualify(
            tree,
            schema=_schema_for_sqlglot(allowed),
            db="public",
            dialect=_DIALECT,
            validate_qualify_columns=True,
        )
    except GuardError:
        raise
    except (SqlglotError, RecursionError, ValueError, KeyError) as exc:
        raise GuardError(f"unresolvable: {type(exc).__name__}: {str(exc)[:80]}") from exc

    _check_tables(tree, allowed)
    _check_stars(tree)
    _resolve_bare_columns(tree)
    aliases = _alias_map(tree)
    _check_columns(tree, aliases, allowed)
    masked = _masked_lookup(allowed)
    _mask_outer_projections(tree, aliases, masked)
    for col in tree.find_all(exp.Column):  # anything masked left over is a predicate/join use
        if _is_masked(col, aliases, masked):
            raise GuardError(f"masked column used outside projection: {col.name}")

    _clamp_limit(tree, max_rows)
    out = tree.sql(dialect=_DIALECT)
    ensure_single_select(out)  # re-validate exactly what we will execute
    return out


def _check_tables(tree: exp.Expr, allowed: AllowedTables) -> None:
    if tree.find(*_FORBIDDEN_SOURCES) is not None:
        raise GuardError("LATERAL, VALUES, UNNEST and whole-row references are not allowed")
    cte_names = {c.alias for c in tree.find_all(exp.CTE)}
    for t in tree.find_all(exp.Table):
        if not isinstance(t.this, exp.Identifier) or t.args.get("catalog"):
            raise GuardError("table function or catalog reference not allowed")
        # A table is a row source. Anywhere else it is a whole-row value (`SELECT users ...`).
        if not isinstance(t.parent, exp.From | exp.Join):
            raise GuardError("table used as a value")
        if t.db:  # qualify() puts `public` on every real table; CTE refs stay unqualified
            if (t.db, t.name) not in allowed:
                raise GuardError(f"table not allowed: {t.db}.{t.name}")
        elif t.name not in cte_names:
            raise GuardError(f"unknown relation: {t.name}")


def _check_stars(tree: exp.Expr) -> None:
    for star in tree.find_all(exp.Star):
        if not isinstance(star.parent, exp.Count):
            raise GuardError("unexpanded star")


def _nearest_select_child(col: exp.Expr, sel: exp.Select) -> exp.Expr:
    node: exp.Expr = col
    while node.parent is not None and node.parent is not sel:
        node = node.parent
    return node


def _resolve_bare_columns(tree: exp.Expr) -> None:
    """Handle columns `qualify` left without a table (almost always a projection alias).

    Allowed only where Postgres itself resolves a bare name to an output column (ORDER BY), or
    where it is the identity alias of a qualified column (GROUP BY/HAVING on `status` after
    `SELECT status`). Anything else, notably a bare name inside a projection, is a whole-row
    reference like `SELECT users FROM users` and is denied.
    """
    for col in list(tree.find_all(exp.Column)):
        if col.table:
            continue
        if not isinstance(col.this, exp.Identifier):
            raise GuardError("unsupported column reference")
        name = col.name
        order = col.find_ancestor(exp.Order)
        sel = col.find_ancestor(exp.Select)
        if order is not None and isinstance(order.parent, exp.SetOperation):
            projections = _outer_selects(order.parent)[0].expressions
            if any(isinstance(p, exp.Alias) and p.alias == name for p in projections):
                continue
            raise GuardError(f"unresolved name in ORDER BY: {name}")
        if sel is None:
            raise GuardError(f"unresolved name: {name}")
        child = _nearest_select_child(col, sel)
        if any(child is p for p in sel.expressions):
            raise GuardError(f"whole-row or unresolved name in projection: {name}")
        aliased = [p for p in sel.expressions if isinstance(p, exp.Alias) and p.alias == name]
        if order is not None and order.parent is sel and aliased:
            continue  # ORDER BY resolves output names first; the output column is vetted
        if len(aliased) == 1:
            target = aliased[0].this
            if isinstance(target, exp.Column) and target.table and target.name == name:
                col.replace(target.copy())  # identity alias: same column, now qualified
                continue
        raise GuardError(f"unresolved name: {name}")


def _alias_map(tree: exp.Expr) -> _Aliases:
    out: _Aliases = {}
    for t in tree.find_all(exp.Table):
        if t.db:
            out.setdefault(t.alias_or_name, set()).add((t.db, t.name))
    return out


def _check_columns(tree: exp.Expr, aliases: _Aliases, allowed: AllowedTables) -> None:
    """Every column on a real table must be one the policy allows on that table."""
    for col in tree.find_all(exp.Column):
        if not isinstance(col.this, exp.Identifier):
            raise GuardError("unsupported column reference")
        tables = aliases.get(col.table)
        if tables and not all(col.name in allowed[t] for t in tables):
            raise GuardError(f"column not allowed: {col.table}.{col.name}")


def _masked_lookup(allowed: AllowedTables) -> _Masked:
    return {k: {c for c, i in cols.items() if i.masked} for k, cols in allowed.items()}


def _is_masked(col: exp.Column, aliases: _Aliases, masked: _Masked) -> bool:
    # An alias can map to several tables across scopes; if ANY masks the column, treat it
    # as masked. That can only over-deny, never leak.
    return any(col.name in masked.get(tbl, ()) for tbl in aliases.get(col.table, ()))


def _mask_outer_projections(tree: exp.Expr, aliases: _Aliases, masked: _Masked) -> None:
    """Replace a masked column that is directly projected by the outermost SELECT(s)."""
    for sel in _outer_selects(tree):
        for proj in list(sel.expressions):
            col = proj.this if isinstance(proj, exp.Alias) else proj
            if isinstance(col, exp.Column) and _is_masked(col, aliases, masked):
                col.replace(exp.Literal.string(MASK))
