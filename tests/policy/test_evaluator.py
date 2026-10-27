from pathlib import Path

from mcp_gateway.policy import load_policy
from mcp_gateway.policy.evaluator import allowed_tables, effective_read_only, tool_allowed

POLICY = load_policy(Path(__file__).parents[2] / "policies" / "policy.example.yaml")

CATALOG = {
    ("public", "orders"): {"id": "integer", "status": "text"},
    ("public", "customers"): {"id": "integer", "name": "text", "country": "text", "extra": "text"},
    ("public", "users"): {
        "id": "integer",
        "email": "text",
        "phone": "text",
        "password_hash": "text",
    },
    ("public", "secrets"): {"id": "integer"},
}


def test_tool_allowed_by_role() -> None:
    assert tool_allowed(POLICY, "analyst", "run_query")
    assert not tool_allowed(POLICY, "analyst", "update_record")
    assert not tool_allowed(POLICY, "approver", "run_query")


def test_unknown_role_is_denied_everything() -> None:
    assert not tool_allowed(POLICY, "nobody", "run_query")
    assert allowed_tables(POLICY, "nobody", CATALOG) == {}
    assert effective_read_only(POLICY, "nobody", False)


def test_read_only_global_or_role() -> None:
    assert effective_read_only(POLICY, "analyst", False)  # role is read-only
    assert effective_read_only(POLICY, "operator", True)  # global switch wins
    assert not effective_read_only(POLICY, "operator", False)


def test_wildcard_keeps_denied_out_and_marks_masked() -> None:
    users = allowed_tables(POLICY, "analyst", CATALOG)[("public", "users")]
    assert set(users) == {"id", "phone"}
    assert users["phone"].masked
    assert not users["id"].masked


def test_listed_columns_only_and_unlisted_tables_hidden() -> None:
    allowed = allowed_tables(POLICY, "analyst", CATALOG)
    assert set(allowed[("public", "customers")]) == {"id", "name", "country"}
    assert ("public", "secrets") not in allowed


def test_policy_table_missing_from_catalog_is_ignored() -> None:
    assert ("public", "orders") not in allowed_tables(POLICY, "analyst", {})
