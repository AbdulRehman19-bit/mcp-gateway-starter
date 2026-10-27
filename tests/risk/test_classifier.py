from pathlib import Path

import pytest
from pydantic import ValidationError

from mcp_gateway.policy import Policy, load_policy
from mcp_gateway.risk import classify, needs_approval

POLICY = load_policy(Path(__file__).parents[2] / "policies" / "policy.example.yaml")


@pytest.mark.parametrize(
    ("tool", "tier"),
    [
        ("list_tables", "low"),
        ("run_query", "low"),
        ("update_record", "medium"),
        ("delete_record", "high"),
        ("bulk_update", "high"),
    ],
)
def test_tiers_come_from_policy(tool: str, tier: str) -> None:
    assert classify(POLICY, tool) == tier


@pytest.mark.parametrize("tool", ["drop_everything", "", "DELETE_RECORD", "update_record "])
def test_unknown_tool_is_high(tool: str) -> None:
    assert classify(POLICY, tool) == "high"
    assert needs_approval(POLICY, "operator", tool)


def test_high_always_needs_approval_medium_does_not_by_default() -> None:
    assert needs_approval(POLICY, "operator", "delete_record")
    assert not needs_approval(POLICY, "operator", "update_record")
    assert not needs_approval(POLICY, "analyst", "run_query")


def test_role_can_require_approval_for_lower_tiers() -> None:
    raw = POLICY.model_dump()
    raw["roles"]["operator"]["approval_required"] = ["update_record"]
    policy = Policy.model_validate(raw)
    assert needs_approval(policy, "operator", "update_record")


def test_unknown_role_needs_approval() -> None:
    assert needs_approval(POLICY, "nobody", "run_query")


def test_policy_refuses_to_disable_different_approver() -> None:
    raw = POLICY.model_dump()
    raw["approvals"]["require_different_approver"] = False
    with pytest.raises(ValidationError):
        Policy.model_validate(raw)


def test_approval_required_must_name_role_tools() -> None:
    raw = POLICY.model_dump()
    raw["roles"]["analyst"]["approval_required"] = ["delete_record"]
    with pytest.raises(ValidationError):
        Policy.model_validate(raw)


def _with_risk(**tiers: list[str]) -> dict:  # type: ignore[type-arg]
    raw = POLICY.model_dump()
    raw["risk"] = {"low": [], "medium": [], "high": [], **tiers}
    return raw


def test_tool_in_two_tiers_is_a_policy_error() -> None:
    raw = _with_risk(low=["list_tables", "run_query", "describe_table"], high=["run_query"])
    raw["roles"]["operator"]["tools"] = ["run_query"]
    with pytest.raises(ValidationError, match="more than one risk tier"):
        Policy.model_validate(raw)


@pytest.mark.parametrize("tier", ["low", "medium"])
def test_destructive_tools_cannot_be_lowered_by_policy(tier: str) -> None:
    raw = _with_risk(**{tier: ["delete_record"], "high": []})
    raw["roles"] = {}
    with pytest.raises(ValidationError, match="must be in the high tier"):
        Policy.model_validate(raw)


def test_classify_has_a_code_level_floor_for_destructive_tools() -> None:
    policy = POLICY.model_copy(deep=True)
    policy.risk.high.remove("delete_record")  # bypassing validation on purpose
    policy.risk.low.append("delete_record")
    assert classify(policy, "delete_record") == "high"
    assert needs_approval(policy, "operator", "delete_record")


def test_highest_tier_wins_if_validation_were_bypassed() -> None:
    policy = POLICY.model_copy(deep=True)
    policy.risk.low.append("update_record")
    assert classify(policy, "update_record") == "medium"
