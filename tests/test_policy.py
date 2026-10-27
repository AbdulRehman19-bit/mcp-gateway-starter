from pathlib import Path

import pytest
from pydantic import ValidationError

from mcp_gateway.policy import Policy, load_policy

EXAMPLE = Path(__file__).parent.parent / "policies" / "policy.example.yaml"


def test_example_policy_loads() -> None:
    policy = load_policy(EXAMPLE)
    assert policy.defaults.read_only is True
    assert policy.risk.tier_of("run_query") == "low"
    assert policy.risk.tier_of("delete_record") == "high"
    assert policy.risk.tier_of("nonexistent") is None


def test_unknown_key_is_rejected() -> None:
    with pytest.raises(ValidationError):
        Policy.model_validate({"version": 1, "typo_key": True})


def test_scope_mapped_to_unknown_role_is_rejected() -> None:
    with pytest.raises(ValidationError):
        Policy.model_validate({"version": 1, "scope_to_role": {"db:read": "ghost"}})


def test_role_tool_without_risk_tier_is_rejected() -> None:
    with pytest.raises(ValidationError):
        Policy.model_validate({"version": 1, "roles": {"r": {"tools": ["mystery_tool"]}}})
