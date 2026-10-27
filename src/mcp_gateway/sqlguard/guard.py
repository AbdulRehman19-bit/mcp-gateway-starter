"""Minimal default-deny SQL guard (Phase 1). Phase 2 extends this with policy-aware checks.

Why: the DB role is the real boundary, but rule 2 requires the app to also reject anything
that does not positively parse as a single read-only SELECT.
"""

import sqlglot
from sqlglot import exp
from sqlglot.errors import SqlglotError

_FORBIDDEN: tuple[type[exp.Expression], ...] = (
    exp.Insert,
    exp.Update,
    exp.Delete,
    exp.Merge,
    exp.Create,
    exp.Drop,
    exp.Alter,
    exp.Command,
    exp.Copy,
    exp.Into,
    exp.Lock,
    exp.Set,
    exp.Transaction,
    exp.Commit,
    exp.Rollback,
)


# Default-deny for functions: pg_sleep, set_config, pg_advisory_lock, dblink, lo_*, version(),
# current_user, repeat(), generate_series() can override the statement timeout, hold locks,
# disclose server details or burn CPU/memory. Only the names/types below pass.
_ALLOWED_FUNCTIONS = frozenset(
    {"now", "length", "round", "abs", "date_trunc", "nullif", "greatest", "least", "concat"}
)
# Looked up by name so an sqlglot rename can only shrink the allow-list (fail closed).
_ALLOWED_FUNC_TYPES: frozenset[type] = frozenset(
    getattr(exp, n)
    for n in (
        "Count",
        "Sum",
        "Avg",
        "Min",
        "Max",
        "Lower",
        "Upper",
        "Length",
        "Round",
        "Abs",
        "Coalesce",
        "Nullif",
        "Greatest",
        "Least",
        "Concat",
        "Cast",
        "TryCast",
        "Extract",
        "DateTrunc",
        "Substring",
        "Trim",
        "Case",
        "If",
        "CurrentDate",
        "CurrentTimestamp",
        "Exists",
    )
    if hasattr(exp, n)
)
_SAFE_CAST_TYPES = frozenset(
    getattr(exp.DataType.Type, n)
    for n in (
        "INT",
        "BIGINT",
        "SMALLINT",
        "TEXT",
        "VARCHAR",
        "CHAR",
        "DECIMAL",
        "DOUBLE",
        "FLOAT",
        "BOOLEAN",
        "DATE",
        "TIMESTAMP",
        "TIMESTAMPTZ",
        "TIME",
    )
    if hasattr(exp.DataType.Type, n)
)
_MAX_JOINS = 4
_MAX_SELECTS = 8  # bounds subquery nesting; statement_timeout is always the backstop


class GuardError(Exception):
    """SQL rejected. `reason` is for the audit log; clients get a generic message."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def ensure_single_select(sql: str) -> None:
    """Raise GuardError unless `sql` is exactly one plain SELECT."""
    try:
        statements = sqlglot.parse(sql, read="postgres")
    except (SqlglotError, RecursionError, ValueError) as exc:
        raise GuardError(f"unparseable: {type(exc).__name__}") from exc
    statements = [s for s in statements if s is not None]
    if len(statements) != 1:
        raise GuardError(f"expected exactly one statement, got {len(statements)}")
    tree = statements[0]
    if not isinstance(tree, exp.Select | exp.SetOperation):
        raise GuardError(f"root is {type(tree).__name__}, not Select")
    bad = tree.find(*_FORBIDDEN)
    if bad is not None:
        raise GuardError(f"forbidden construct: {type(bad).__name__}")
    for fn in tree.find_all(exp.Func):
        _check_function(fn)
    _check_structure(tree)


def _check_function(fn: exp.Func) -> None:
    if isinstance(fn, exp.Anonymous):
        name = str(fn.name).lower()
        if name not in _ALLOWED_FUNCTIONS:
            raise GuardError(f"function not allowed: {name}")
        return
    if type(fn) not in _ALLOWED_FUNC_TYPES:
        # Typed functions are default-deny too: version(), current_user, repeat(),
        # generate_series() ... are all typed in sqlglot and all unwanted.
        raise GuardError(f"function not allowed: {type(fn).__name__}")
    if isinstance(fn, exp.Cast | exp.TryCast) and fn.to.this not in _SAFE_CAST_TYPES:
        raise GuardError(f"cast target not allowed: {fn.to.sql()[:30]}")  # e.g. ::regclass


def _check_structure(tree: exp.Expr) -> None:
    for t in tree.find_all(exp.Table):
        alias = t.args.get("alias")
        # `FROM users AS u(a, b, c)` renames columns by position onto the real table, which
        # would let a denied column hide behind an allowed name.
        if alias is not None and alias.args.get("columns"):
            raise GuardError("column alias list on a table is not allowed")
    joins = list(tree.find_all(exp.Join))
    if len(joins) > _MAX_JOINS:
        raise GuardError(f"too many joins: {len(joins)}")
    if any(j.method == "NATURAL" for j in joins):
        raise GuardError("NATURAL JOIN not allowed")  # joins on columns the caller never named
    if len(list(tree.find_all(exp.Select))) > _MAX_SELECTS:
        raise GuardError("query nesting too deep")
    if tree.find(exp.TableSample) is not None:
        raise GuardError("TABLESAMPLE not allowed")
