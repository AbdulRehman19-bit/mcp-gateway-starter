from pathlib import Path

import pytest

from mcp_gateway.auth.roles import resolve_role
from mcp_gateway.policy import load_policy

POLICY = load_policy(Path(__file__).parents[2] / "policies" / "policy.example.yaml")


def test_single_scope_maps_to_role() -> None:
    ident = resolve_role(POLICY, "u1", frozenset({"openid", "db:read"}))
    assert ident is not None
    assert (ident.subject, ident.role) == ("u1", "analyst")


@pytest.mark.parametrize(
    ("scope", "role"),
    [("db:read", "analyst"), ("db:write", "operator"), ("approvals:decide", "approver")],
)
def test_each_scope(scope: str, role: str) -> None:
    ident = resolve_role(POLICY, "u", frozenset({scope}))
    assert ident is not None
    assert ident.role == role


@pytest.mark.parametrize(
    "scopes",
    [
        frozenset(),
        frozenset({"openid", "profile"}),
        frozenset({"admin"}),
        frozenset({"DB:READ"}),  # scopes are case-sensitive
        frozenset({"db:read ", "db:readx"}),
        frozenset({"role:operator"}),  # a role name is not a scope
    ],
)
def test_unmapped_scopes_denied(scopes: frozenset[str]) -> None:
    assert resolve_role(POLICY, "u", scopes) is None


def test_ambiguous_scopes_denied_not_guessed() -> None:
    assert resolve_role(POLICY, "u", frozenset({"db:read", "db:write"})) is None
    assert resolve_role(POLICY, "u", frozenset({"db:read", "approvals:decide"})) is None


def test_two_scopes_same_role_is_fine() -> None:
    policy = POLICY.model_copy(update={"scope_to_role": {"a": "analyst", "b": "analyst"}})
    ident = resolve_role(policy, "u", frozenset({"a", "b"}))
    assert ident is not None
    assert ident.role == "analyst"
