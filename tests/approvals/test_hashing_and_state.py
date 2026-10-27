from datetime import UTC, datetime, timedelta

from mcp_gateway.approvals.hashing import args_hash, canonical_json
from mcp_gateway.approvals.state import ApprovalRow, why_not_consumable, why_not_decidable

NOW = datetime(2026, 1, 1, tzinfo=UTC)
ARGS = {"schema_name": "public", "table": "orders", "pk": 3}
H = args_hash("delete_record", ARGS)


def row(**over: object) -> ApprovalRow:
    base: dict[str, object] = {
        "id": "a1", "requester": "bob", "requester_role": "operator", "tool": "delete_record",
        "args_hash": H, "args": ARGS, "status": "approved", "created_at": NOW,
        "expires_at": NOW + timedelta(minutes=30),
    }  # fmt: skip
    base.update(over)
    return ApprovalRow(**base)  # type: ignore[arg-type]


def test_hash_is_stable_across_key_order_and_whitespace() -> None:
    reordered = {"pk": 3, "table": "orders", "schema_name": "public"}
    assert args_hash("delete_record", reordered) == H
    assert canonical_json(reordered) == canonical_json(ARGS)


def test_hash_binds_tool_and_every_argument() -> None:
    assert args_hash("update_record", ARGS) != H
    assert args_hash("delete_record", {**ARGS, "pk": 4}) != H
    assert args_hash("delete_record", {**ARGS, "table": "customers"}) != H
    assert args_hash("delete_record", {**ARGS, "schema_name": "other"}) != H
    assert args_hash("delete_record", {**ARGS, "pk": "3"}) != H  # type matters: 3 is not "3"
    assert args_hash("delete_record", {**ARGS, "extra": 1}) != H


def test_hash_binds_changes_values() -> None:
    a = args_hash("update_record", {**ARGS, "changes": {"status": "paid"}})
    assert a != args_hash("update_record", {**ARGS, "changes": {"status": "shipped"}})
    assert a != args_hash("update_record", {**ARGS, "changes": {"status": "paid", "notes": "x"}})


def test_hash_is_hex_sha256() -> None:
    assert len(H) == 64
    assert set(H) <= set("0123456789abcdef")


def test_decide_refusal_reasons() -> None:
    pending = row(status="pending")
    assert why_not_decidable(None, "carol", NOW) == "approval not found"
    assert why_not_decidable(pending, "bob", NOW) == "requester cannot decide own request"
    assert why_not_decidable(row(status="approved"), "carol", NOW) == "already approved"
    assert why_not_decidable(row(status="used"), "carol", NOW) == "already used"
    late = row(status="pending", expires_at=NOW - timedelta(seconds=1))
    assert why_not_decidable(late, "carol", NOW) == "expired"


def test_consume_refusal_reasons() -> None:
    ok = row()
    assert why_not_consumable(None, "bob", "delete_record", H, NOW) == "approval not found"
    assert "another requester" in why_not_consumable(ok, "mallory", "delete_record", H, NOW)
    assert "does not match" in why_not_consumable(ok, "bob", "update_record", H, NOW)
    assert "does not match" in why_not_consumable(ok, "bob", "delete_record", "0" * 64, NOW)
    assert why_not_consumable(row(status="used"), "bob", "delete_record", H, NOW) == "already used"
    assert why_not_consumable(row(status="denied"), "bob", "delete_record", H, NOW) == "denied"
    assert (
        why_not_consumable(row(status="pending"), "bob", "delete_record", H, NOW) == "still pending"
    )
    gone = row(expires_at=NOW - timedelta(minutes=1))
    assert why_not_consumable(gone, "bob", "delete_record", H, NOW) == "expired"
