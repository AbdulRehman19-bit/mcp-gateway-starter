"""Startup guards: wrong database roles must stop the server before it serves anything."""

from typing import Any

import pytest

from mcp_gateway.db_probe import approvals_role_problems, audit_role_problems
from mcp_gateway.server import EXPECTED_SCHEMA_VERSION, _require_distinct_roles, _require_schema

CLEAN_AUDIT: dict[str, Any] = {
    "who": "gateway_audit", "admin": False, "owns_tables": 0,
    "audit_insert": True, "audit_select": False, "audit_update": False, "audit_delete": False,
    "audit_truncate": False, "appr_insert": False, "appr_delete": False, "appr_truncate": False,
}  # fmt: skip
CLEAN_APP: dict[str, Any] = {
    **CLEAN_AUDIT, "who": "gateway_app", "audit_insert": False, "appr_insert": True,
}  # fmt: skip


def test_the_real_roles_pass() -> None:
    assert audit_role_problems(CLEAN_AUDIT) == []
    assert approvals_role_problems(CLEAN_APP) == []


@pytest.mark.parametrize(
    "excess", ["audit_select", "audit_update", "audit_delete", "audit_truncate", "appr_insert"]
)
def test_audit_role_with_any_extra_privilege_is_refused(excess: str) -> None:
    problems = audit_role_problems({**CLEAN_AUDIT, excess: True})
    assert problems and excess in problems[0]


def test_audit_role_that_cannot_insert_is_refused() -> None:
    assert audit_role_problems({**CLEAN_AUDIT, "audit_insert": False})


@pytest.mark.parametrize(
    "excess",
    [
        "audit_insert",
        "audit_select",
        "audit_update",
        "audit_delete",
        "appr_delete",
        "appr_truncate",
    ],
)
def test_approvals_role_with_excess_privilege_is_refused(excess: str) -> None:
    assert approvals_role_problems({**CLEAN_APP, excess: True})


def test_admin_or_owner_roles_are_refused_for_both_jobs() -> None:
    for probe, check in ((CLEAN_AUDIT, audit_role_problems), (CLEAN_APP, approvals_role_problems)):
        assert any("superuser" in p for p in check({**probe, "admin": True}))
        assert any("owns tables" in p for p in check({**probe, "owns_tables": 3}))


def test_four_database_users_must_be_distinct() -> None:
    ok = {"ro": "u1", "rw": "u2", "app": "u3", "audit": "u4"}
    _require_distinct_roles({k: f"postgresql+asyncpg://{u}:pw@h/db" for k, u in ok.items()})
    for clash in (("ro", "rw"), ("app", "audit"), ("ro", "audit")):
        urls = {k: f"postgresql+asyncpg://{u}:pw@h/db" for k, u in ok.items()}
        urls[clash[1]] = urls[clash[0]]
        with pytest.raises(SystemExit, match="same DB user"):
            _require_distinct_roles(urls)


def test_missing_urls_are_skipped_not_treated_as_clashes() -> None:
    _require_distinct_roles({"ro": "postgresql+asyncpg://u1:pw@h/db", "rw": None, "app": None})


def test_schema_must_be_at_head() -> None:
    _require_schema(EXPECTED_SCHEMA_VERSION)
    for bad in (None, "0001", "0003", ""):
        with pytest.raises(SystemExit, match="alembic upgrade head"):
            _require_schema(bad)
