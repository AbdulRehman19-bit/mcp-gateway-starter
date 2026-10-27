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


# Unknown functions are denied: pg_sleep, set_config, pg_advisory_lock, dblink, lo_* etc. can
# override the statement timeout or hold locks. Typed sqlglot functions (count, sum, ...) pass.
_ALLOWED_FUNCTIONS = frozenset(
    {"now", "length", "round", "abs", "date_trunc", "nullif", "greatest", "least", "concat"}
)


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
    if not isinstance(tree, exp.Select):
        raise GuardError(f"root is {type(tree).__name__}, not Select")
    bad = tree.find(*_FORBIDDEN)
    if bad is not None:
        raise GuardError(f"forbidden construct: {type(bad).__name__}")
    for fn in tree.find_all(exp.Anonymous):
        name = str(fn.name).lower()
        if name not in _ALLOWED_FUNCTIONS:
            raise GuardError(f"function not allowed: {name}")
