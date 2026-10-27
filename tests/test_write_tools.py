"""update_record / delete_record / approvals through the handler pipeline (fakes, no Docker)."""

import dataclasses
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from mcp_gateway.approvals.state import ApprovalRow
from mcp_gateway.approvals.store import MAX_LIVE_PER_REQUESTER, ApprovalLimitError
from mcp_gateway.audit.sink import Auditor, MemorySink
from mcp_gateway.auth.roles import Identity
from mcp_gateway.connectors.postgres import ConnectorError, QueryResult
from mcp_gateway.policy import Policy, load_policy
from mcp_gateway.policy.evaluator import Catalog, allowed_tables
from mcp_gateway.tools.handlers import ToolFailure, ToolService

POLICY = load_policy(Path(__file__).parents[1] / "policies" / "policy.example.yaml")
CATALOG: Catalog = {
    ("public", "orders"): {
        "id": "integer",
        "customer_id": "integer",
        "total_cents": "integer",
        "status": "text",
        "notes": "text",
    },
    ("public", "customers"): {"id": "integer", "name": "text", "country": "text"},
    ("public", "users"): {"id": "integer", "phone": "text"},
}
PKS = {("public", "orders"): "id", ("public", "customers"): "id"}
BOB = Identity("bob", "operator", frozenset())
CAROL = Identity("carol", "approver", frozenset())
ALICE = Identity("alice", "analyst", frozenset())


class FakeReader:
    async def run_query(self, sql: str, *, limit: int | None = None) -> QueryResult:
        return QueryResult(columns=[], rows=[], truncated=False)


class FakeWriter:
    def __init__(self, error: Exception | None = None) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.error = error

    async def update_row(self, **kw: Any) -> int:
        self.calls.append(("update", kw))
        if self.error:
            raise self.error
        return 1

    async def delete_row(self, **kw: Any) -> int:
        self.calls.append(("delete", kw))
        if self.error:
            raise self.error
        return 1

    def real(self) -> list[tuple[str, dict[str, Any]]]:
        return [c for c in self.calls if not c[1]["dry_run"]]


class FakeApprovals:
    """In-memory twin of ApprovalStore with the same guard semantics (DB atomicity is covered
    by the integration tests against real Postgres)."""

    def __init__(self) -> None:
        self.rows: dict[str, ApprovalRow] = {}

    def _put(self, row: ApprovalRow, **over: Any) -> ApprovalRow:
        new = dataclasses.replace(row, **over)
        self.rows[new.id] = new
        return new

    async def create(self, *, requester: str, requester_role: str, tool: str, args_hash: str,
                     args: dict[str, Any], ttl_minutes: int) -> ApprovalRow:  # fmt: skip
        now = datetime.now(UTC)
        for r in self.rows.values():
            live = r.status in ("pending", "approved") and r.expires_at > now
            if live and r.requester == requester and r.args_hash == args_hash:
                return r
        mine = [r for r in self.rows.values() if r.requester == requester
                and r.status in ("pending", "approved") and r.expires_at > now]  # fmt: skip
        if len(mine) >= MAX_LIVE_PER_REQUESTER:
            raise ApprovalLimitError("too many live approvals")
        row = ApprovalRow(str(uuid.uuid4()), requester, requester_role, tool, args_hash, args,
                          "pending", now, now + timedelta(minutes=ttl_minutes))  # fmt: skip
        self.rows[row.id] = row
        return row

    async def list_pending(self, limit: int = 50) -> list[ApprovalRow]:
        now = datetime.now(UTC)
        return [r for r in self.rows.values() if r.status == "pending" and r.expires_at > now]

    async def get(self, approval_id: str) -> ApprovalRow | None:
        return self.rows.get(approval_id)

    async def decide(self, approval_id: str, *, approver: str, approve: bool,
                     reason: str | None) -> ApprovalRow | None:  # fmt: skip
        r = self.rows.get(approval_id)
        if not r or r.status != "pending" or r.expires_at <= datetime.now(UTC):
            return None
        if r.requester == approver:
            return None
        return self._put(r, status="approved" if approve else "denied", decided_by=approver)

    async def consume(self, approval_id: str, *, requester: str, tool: str,
                      args_hash: str) -> bool:  # fmt: skip
        r = self.rows.get(approval_id)
        ok = bool(
            r
            and r.status == "approved"
            and r.expires_at > datetime.now(UTC)
            and r.requester == requester
            and r.tool == tool
            and r.args_hash == args_hash
        )
        if ok and r:
            self._put(r, status="used")
        return ok

    async def cancel(self, approval_id: str, *, requester: str) -> None:
        r = self.rows.get(approval_id)
        if r and r.requester == requester and r.status == "pending":
            self._put(r, status="denied", args={})

    def expire(self, approval_id: str) -> None:
        self._put(self.rows[approval_id], expires_at=datetime.now(UTC) - timedelta(seconds=1))


class World:
    def __init__(self, *, global_ro: bool = False, policy: Policy = POLICY,
                 sink: MemorySink | None = None, approvals: bool = True,
                 pks: dict[tuple[str, str], str] | None = None,
                 writer: FakeWriter | None = None) -> None:  # fmt: skip
        self.who: Identity | None = BOB
        self.sink = sink or MemorySink()
        self.writer = writer or FakeWriter()
        self.approvals = FakeApprovals()
        allowed = {r: allowed_tables(policy, r, CATALOG) for r in policy.roles}
        self.svc = ToolService(
            FakeReader(),  # type: ignore[arg-type]
            policy, allowed, lambda: self.who,
            auditor=Auditor(self.sink), global_read_only=global_ro,
            writer=self.writer,  # type: ignore[arg-type]
            approvals=self.approvals if approvals else None,  # type: ignore[arg-type]
            primary_keys=PKS if pks is None else pks,
        )  # fmt: skip

    def as_(self, who: Identity | None) -> "World":
        self.who = who
        return self

    def decisions(self, tool: str | None = None) -> list[str]:
        return [r["decision"] for r in self.sink.records if tool in (None, r["tool"])]


async def pending_for(w: World, pk: int = 3) -> str:
    out = await w.as_(BOB).svc.delete_record("orders", pk)
    assert out["status"] == "pending_approval"
    return str(out["approval_id"])


# ---- update_record -------------------------------------------------------------------------


async def test_update_allowed_audits_before_and_after_and_hides_values() -> None:
    w = World()
    out = await w.svc.update_record("orders", 3, {"status": "SECRET-VALUE-123"})
    assert out == {"status": "ok", "rows_affected": 1}
    kind, kw = w.writer.calls[0]
    assert kind == "update"
    assert kw["changes"] == {"status": "SECRET-VALUE-123"}
    assert kw["pk_col"] == "id"
    assert kw["column_types"] == {"status": "text"}
    assert w.decisions("update_record") == ["allow", "success"]
    assert "SECRET-VALUE-123" not in str(w.sink.records)  # column names only, never values
    first = w.sink.records[0]
    assert (first["subject"], first["role"], first["risk"]) == ("bob", "operator", "medium")


async def test_update_denied_when_global_read_only() -> None:
    w = World(global_ro=True)
    with pytest.raises(ToolFailure, match="disabled"):
        await w.svc.update_record("orders", 3, {"status": "x"})
    assert w.writer.calls == []
    assert w.decisions() == ["deny"]


async def test_update_denied_for_read_only_role_and_unknown_role() -> None:
    w = World()
    for who in (ALICE, CAROL, Identity("x", "nobody", frozenset()), None):
        with pytest.raises(ToolFailure):
            await w.as_(who).svc.update_record("orders", 3, {"status": "x"})
    assert w.writer.calls == []
    assert set(w.decisions()) == {"deny"}


async def test_role_read_only_flag_blocks_writes_even_with_tool_listed() -> None:
    raw = POLICY.model_dump()
    raw["roles"]["operator"]["read_only"] = True
    w = World(policy=Policy.model_validate(raw))
    with pytest.raises(ToolFailure, match="disabled"):
        await w.svc.update_record("orders", 3, {"status": "x"})
    assert w.writer.calls == []


@pytest.mark.parametrize(
    "changes",
    [
        {"total_cents": 1},  # readable but not writable
        {"id": 9},  # primary key is never writable
        {"customer_id": 2, "status": "x"},  # one bad column poisons the call
        {"password_hash": "x"},  # not a column at all
    ],
)
async def test_update_denies_non_writable_columns(changes: dict[str, Any]) -> None:
    w = World()
    with pytest.raises(ToolFailure, match="Not permitted"):
        await w.svc.update_record("orders", 3, changes)
    assert w.writer.calls == []


@pytest.mark.parametrize(
    ("table", "msg"),
    [("customers", "Not permitted"), ("users", "Unknown table"), ("nope", "Unknown table")],
)
async def test_update_denies_tables_without_writable_columns(table: str, msg: str) -> None:
    w = World()
    with pytest.raises(ToolFailure, match=msg):
        await w.svc.update_record(table, 1, {"name": "x"})
    assert w.writer.calls == []


@pytest.mark.parametrize(
    "kwargs",
    [
        {"table": "orders; DROP TABLE orders", "pk": 1, "changes": {"status": "x"}},
        {"table": "orders", "pk": 1, "changes": {"status; DROP": "x"}},
        {"table": 'orders"', "pk": 1, "changes": {"status": "x"}},
        {"table": "orders", "pk": True, "changes": {"status": "x"}},  # bool is not an int pk
        {"table": "orders", "pk": 1.5, "changes": {"status": "x"}},
        {"table": "orders", "pk": [1], "changes": {"status": "x"}},
        {"table": "orders", "pk": 1, "changes": {}},
        {"table": "orders", "pk": 1, "changes": {"status": {"nested": 1}}},
        {"table": "orders", "pk": 1, "changes": {"status": ["a"]}},
        {"table": "orders", "pk": 1, "changes": {"status": "x" * 10_001}},
        {"table": "orders", "pk": 1, "changes": {f"c{i}": 1 for i in range(11)}},
        {"table": "orders", "pk": 1, "changes": {"status": "x"}, "approval_id": "not-a-uuid"},
        {"table": "orders", "pk": 1, "changes": {"status": "x"}, "schema": "pg_catalog"},
    ],
)
async def test_update_rejects_invalid_input(kwargs: dict[str, Any]) -> None:
    w = World()
    with pytest.raises(ToolFailure):
        await w.svc.update_record(**kwargs)
    assert w.writer.calls == []


async def test_update_pk_type_must_match_column() -> None:
    w = World()
    with pytest.raises(ToolFailure, match="Invalid input"):
        await w.svc.update_record("orders", "3", {"status": "x"})  # integer pk, string given
    assert w.writer.calls == []


async def test_update_needs_a_usable_primary_key() -> None:
    w = World(pks={})
    with pytest.raises(ToolFailure, match="Unsupported table"):
        await w.svc.update_record("orders", 3, {"status": "x"})
    assert w.writer.calls == []


async def test_update_dry_run_is_flagged_and_still_policy_checked() -> None:
    w = World()
    out = await w.svc.update_record("orders", 3, {"status": "x"}, dry_run=True)
    assert out == {"status": "dry_run", "rows_affected": 1}
    assert w.writer.calls[0][1]["dry_run"] is True
    with pytest.raises(ToolFailure):
        await w.svc.update_record("orders", 3, {"total_cents": 1}, dry_run=True)
    assert len(w.writer.calls) == 1


async def test_connector_error_is_safe_and_audited() -> None:
    w = World(writer=FakeWriter(ConnectorError("No single matching row.", "rowcount=0")))
    with pytest.raises(ToolFailure, match="No single matching row"):
        await w.svc.update_record("orders", 999, {"status": "x"})
    assert w.decisions("update_record") == ["allow", "error"]
    w = World(writer=FakeWriter(RuntimeError("password=hunter2")))
    with pytest.raises(ToolFailure, match="Internal error") as ei:
        await w.svc.update_record("orders", 1, {"status": "x"})
    assert "hunter2" not in str(ei.value) + str(w.sink.records)


async def test_writes_not_configured_fail_closed() -> None:
    w = World()
    w.svc._writer = None
    with pytest.raises(ToolFailure, match="not configured"):
        await w.svc.update_record("orders", 3, {"status": "x"})


# ---- audit is fail-closed for writes -----------------------------------------------------------


async def test_write_refused_when_audit_cannot_be_persisted() -> None:
    w = World(sink=MemorySink(fail=True))
    with pytest.raises(ToolFailure, match="Audit unavailable"):
        await w.svc.update_record("orders", 3, {"status": "x"})
    assert w.writer.calls == []


async def test_write_refused_with_no_audit_sink_at_all() -> None:
    w = World()
    w.svc._auditor = Auditor(None)
    with pytest.raises(ToolFailure, match="Audit unavailable"):
        await w.svc.update_record("orders", 3, {"status": "x"})
    assert w.writer.calls == []


async def test_reads_survive_an_audit_outage() -> None:
    w = World(sink=MemorySink(fail=True))
    assert (await w.svc.list_tables())["tables"]
    assert (await w.svc.run_query("SELECT id FROM orders"))["row_count"] == 0


# ---- delete_record + approval gate ----------------------------------------------------------


async def test_delete_without_approval_returns_pending_and_writes_nothing() -> None:
    w = World()
    out = await w.svc.delete_record("orders", 3)
    assert out["status"] == "pending_approval"
    assert uuid.UUID(out["approval_id"])
    assert w.writer.calls == []
    assert w.decisions("delete_record") == ["pending_approval"]
    assert w.sink.records[0]["risk"] == "high"


async def test_repeating_the_request_reuses_the_pending_approval() -> None:
    w = World()
    a = await w.svc.delete_record("orders", 3)
    b = await w.svc.delete_record("orders", 3)
    assert a["approval_id"] == b["approval_id"]
    assert len(w.approvals.rows) == 1


async def test_full_flow_executes_exactly_once() -> None:
    w = World()
    aid = await pending_for(w)
    listed = (await w.as_(CAROL).svc.list_approvals())["approvals"]
    assert [(a["approval_id"], a["requester"], a["tool"]) for a in listed] == [
        (aid, "bob", "delete_record")
    ]
    assert listed[0]["args"] == {"schema_name": "public", "table": "orders", "pk": 3}
    assert listed[0]["own_request"] is False
    assert await w.svc.decide_approval(aid, "approve") == {"approval_id": aid, "status": "approved"}

    assert w.writer.real() == []  # approving alone executes nothing
    out = await w.as_(BOB).svc.delete_record("orders", 3, approval_id=aid)
    assert out == {"status": "ok", "rows_affected": 1}
    assert [c[0] for c in w.writer.real()] == ["delete"]

    with pytest.raises(ToolFailure, match="Approval not valid"):  # replay
        await w.svc.delete_record("orders", 3, approval_id=aid)
    assert len(w.writer.real()) == 1
    deny_reasons = [r["reason"] for r in w.sink.records if r["decision"] == "deny"]
    assert any("already used" in r for r in deny_reasons)


async def test_requester_cannot_approve_own_request() -> None:
    raw = POLICY.model_dump()
    raw["roles"]["operator"]["tools"] += ["list_approvals", "decide_approval"]
    w = World(policy=Policy.model_validate(raw))
    aid = await pending_for(w)
    with pytest.raises(ToolFailure, match="Cannot decide"):
        await w.as_(BOB).svc.decide_approval(aid, "approve")
    assert w.approvals.rows[aid].status == "pending"
    with pytest.raises(ToolFailure, match="Approval not valid"):
        await w.svc.delete_record("orders", 3, approval_id=aid)
    assert w.writer.real() == []
    assert any("own request" in r["reason"] for r in w.sink.records if r["decision"] == "deny")


async def test_pending_or_denied_approval_cannot_be_used() -> None:
    w = World()
    aid = await pending_for(w)
    with pytest.raises(ToolFailure, match="Approval not valid"):
        await w.as_(BOB).svc.delete_record("orders", 3, approval_id=aid)  # still pending
    await w.as_(CAROL).svc.decide_approval(aid, "deny", "no")
    with pytest.raises(ToolFailure, match="Approval not valid"):
        await w.as_(BOB).svc.delete_record("orders", 3, approval_id=aid)
    with pytest.raises(ToolFailure, match="Cannot decide"):  # a denied one cannot be flipped
        await w.as_(CAROL).svc.decide_approval(aid, "approve")
    assert w.writer.real() == []


async def test_approval_is_bound_to_exact_arguments() -> None:
    w = World()
    aid = await pending_for(w, pk=3)
    await w.as_(CAROL).svc.decide_approval(aid, "approve")
    with pytest.raises(ToolFailure, match="Approval not valid"):
        await w.as_(BOB).svc.delete_record("orders", 4, approval_id=aid)  # different row
    with pytest.raises(ToolFailure, match="Not permitted"):  # different table: refused earlier
        await w.as_(BOB).svc.delete_record("customers", 3, approval_id=aid)
    assert w.writer.real() == []
    assert w.approvals.rows[aid].status == "approved"  # mismatches did not burn it
    # A delete approval is not an update approval: update_record (medium, no approval needed
    # for this role) runs on its own merits, and the delete approval is NOT consumed by it.
    await w.svc.update_record("orders", 3, {"status": "x"}, approval_id=aid)
    assert [c[0] for c in w.writer.real()] == ["update"]
    assert w.approvals.rows[aid].status == "approved"
    await w.svc.delete_record("orders", 3, approval_id=aid)
    assert [c[0] for c in w.writer.real()] == ["update", "delete"]


async def test_approval_is_bound_to_the_requester() -> None:
    raw = POLICY.model_dump()
    raw["roles"]["analyst"]["tools"] += ["delete_record"]  # let another user try to use it
    w = World()
    aid = await pending_for(w)
    await w.as_(CAROL).svc.decide_approval(aid, "approve")
    other = Identity("mallory", "operator", frozenset())
    with pytest.raises(ToolFailure, match="Approval not valid"):
        await w.as_(other).svc.delete_record("orders", 3, approval_id=aid)
    assert w.writer.real() == []


async def test_expired_approval_cannot_be_decided_or_used() -> None:
    w = World()
    aid = await pending_for(w)
    w.approvals.expire(aid)
    with pytest.raises(ToolFailure, match="Cannot decide"):
        await w.as_(CAROL).svc.decide_approval(aid, "approve")
    aid2 = await pending_for(w, pk=5)
    await w.as_(CAROL).svc.decide_approval(aid2, "approve")
    w.approvals.expire(aid2)
    with pytest.raises(ToolFailure, match="Approval not valid"):
        await w.as_(BOB).svc.delete_record("orders", 5, approval_id=aid2)
    assert w.writer.real() == []
    assert any("expired" in r["reason"] for r in w.sink.records if r["decision"] == "deny")


async def test_delete_refuses_tables_that_are_not_deletable() -> None:
    w = World()
    with pytest.raises(ToolFailure, match="Not permitted"):
        await w.svc.delete_record("customers", 1)
    assert w.approvals.rows == {}  # not even an approval request is created
    assert w.writer.calls == []


async def test_delete_dry_run_needs_no_approval_and_persists_nothing() -> None:
    w = World()
    out = await w.svc.delete_record("orders", 3, dry_run=True)
    assert out == {"status": "dry_run", "rows_affected": 1}
    assert w.writer.calls[0][1]["dry_run"] is True
    assert w.approvals.rows == {}
    assert w.writer.real() == []


async def test_delete_denied_when_approvals_not_configured() -> None:
    w = World(approvals=False)
    with pytest.raises(ToolFailure, match="not configured"):
        await w.svc.delete_record("orders", 3)
    assert w.writer.calls == []


async def test_pending_creation_is_refused_if_it_cannot_be_audited() -> None:
    w = World(sink=MemorySink(fail=True))
    with pytest.raises(ToolFailure, match="Audit unavailable"):
        await w.svc.delete_record("orders", 3)
    assert w.writer.calls == []


async def test_role_can_force_approval_for_a_medium_tool() -> None:
    raw = POLICY.model_dump()
    raw["roles"]["operator"]["approval_required"] = ["update_record"]
    w = World(policy=Policy.model_validate(raw))
    out = await w.svc.update_record("orders", 3, {"status": "x"})
    assert out["status"] == "pending_approval"
    assert w.writer.calls == []
    await w.as_(CAROL).svc.decide_approval(out["approval_id"], "approve")
    done = await w.as_(BOB).svc.update_record(
        "orders", 3, {"status": "x"}, approval_id=out["approval_id"]
    )
    assert done["status"] == "ok"
    with pytest.raises(ToolFailure):  # changed value => different hash => not valid
        await w.svc.update_record("orders", 3, {"status": "y"}, approval_id=out["approval_id"])


# ---- approver tools -----------------------------------------------------------------------


async def test_approver_tools_are_role_gated() -> None:
    w = World()
    for who in (BOB, ALICE, None):
        with pytest.raises(ToolFailure, match="Not permitted"):
            await w.as_(who).svc.list_approvals()
        with pytest.raises(ToolFailure, match="Not permitted"):
            await w.svc.decide_approval(str(uuid.uuid4()), "approve")
    assert w.approvals.rows == {}


@pytest.mark.parametrize(
    ("approval_id", "decision"),
    [("nope", "approve"), ("1" * 36, "approve"), (str(uuid.uuid4()), "maybe"),
     (str(uuid.uuid4()), "APPROVE"), (str(uuid.uuid4()), "")],
)  # fmt: skip
async def test_decide_rejects_bad_input(approval_id: str, decision: str) -> None:
    w = World()
    with pytest.raises(ToolFailure, match="Invalid input"):
        await w.as_(CAROL).svc.decide_approval(approval_id, decision)


async def test_decide_unknown_approval_is_denied_and_audited() -> None:
    w = World()
    with pytest.raises(ToolFailure, match="Cannot decide"):
        await w.as_(CAROL).svc.decide_approval(str(uuid.uuid4()), "approve")
    assert "approval not found" in w.sink.records[-1]["reason"]


async def test_decision_is_audited_with_who_and_what() -> None:
    w = World()
    aid = await pending_for(w)
    await w.as_(CAROL).svc.decide_approval(aid, "approve", "looks fine")
    recs = [r for r in w.sink.records if r["tool"] == "decide_approval"]
    assert [r["decision"] for r in recs] == ["allow", "approved"]
    assert all(r["subject"] == "carol" and r["role"] == "approver" for r in recs)
    assert "bob" in recs[-1]["reason"]


async def test_list_approvals_hides_expired_and_decided() -> None:
    w = World()
    a, b = await pending_for(w, 1), await pending_for(w, 2)
    await w.as_(CAROL).svc.decide_approval(a, "deny")
    w.approvals.expire(b)
    assert (await w.svc.list_approvals())["approvals"] == []


# ---- review fixes --------------------------------------------------------------------------------


async def test_unaudited_pending_approval_is_cancelled_not_left_approvable() -> None:
    w = World(sink=MemorySink(fail=True))
    with pytest.raises(ToolFailure, match="Audit unavailable"):
        await w.svc.delete_record("orders", 3)
    (row,) = w.approvals.rows.values()
    assert row.status == "denied"  # nobody can approve a request that is not in the audit trail
    assert w.approvals.rows[row.id].args == {}


async def test_audit_outage_does_not_burn_an_approved_approval() -> None:
    w = World()
    aid = await pending_for(w)
    await w.as_(CAROL).svc.decide_approval(aid, "approve")
    w.svc._auditor = Auditor(MemorySink(fail=True))
    with pytest.raises(ToolFailure, match="Audit unavailable"):
        await w.as_(BOB).svc.delete_record("orders", 3, approval_id=aid)
    assert w.approvals.rows[aid].status == "approved"  # still usable once audit is back
    assert w.writer.real() == []
    w.svc._auditor = Auditor(w.sink)
    await w.as_(BOB).svc.delete_record("orders", 3, approval_id=aid)
    assert len(w.writer.real()) == 1


async def test_queue_flooding_is_capped_per_requester() -> None:
    w = World()
    for pk in range(1, MAX_LIVE_PER_REQUESTER + 1):
        assert (await w.svc.delete_record("orders", pk))["status"] == "pending_approval"
    with pytest.raises(ToolFailure, match="Too many pending approvals"):
        await w.svc.delete_record("orders", 999)
    # an identical re-ask is not a new request, and other users are unaffected
    assert (await w.svc.delete_record("orders", 1))["status"] == "pending_approval"
    other = Identity("dave", "operator", frozenset())
    assert (await w.as_(other).svc.delete_record("orders", 999))["status"] == "pending_approval"
    assert any("too many live" in r["reason"] for r in w.sink.records if r["decision"] == "deny")


async def test_primary_key_is_never_writable_even_if_policy_lists_it() -> None:
    raw = POLICY.model_dump()
    raw["roles"]["operator"]["schemas"]["public"]["tables"]["orders"]["writable_columns"] = [
        "status", "id",
    ]  # fmt: skip
    w = World(policy=Policy.model_validate(raw))
    with pytest.raises(ToolFailure, match="Not permitted"):
        await w.svc.update_record("orders", 3, {"id": 99})
    assert w.writer.calls == []
    assert (await w.svc.update_record("orders", 3, {"status": "x"}))["status"] == "ok"
