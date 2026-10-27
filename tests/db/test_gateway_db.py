"""Real Postgres: roles, constraints, atomic approval transitions (docker compose up -d db).

Needs the gateway schema: GATEWAY_DB_ADMIN_URL=... uv run alembic upgrade head
"""

import asyncio
import os
import uuid
from collections.abc import AsyncIterator
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, ProgrammingError
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from mcp_gateway.approvals.hashing import args_hash
from mcp_gateway.approvals.store import ApprovalStore
from mcp_gateway.audit.sink import Auditor, DbAuditSink

pytestmark = pytest.mark.integration

ADMIN = os.environ.get(
    "GATEWAY_DB_ADMIN_URL", "postgresql+asyncpg://postgres:postgres-dev-only@localhost:5432/gateway"
)
APP = os.environ.get(
    "GATEWAY_DB_URL", "postgresql+asyncpg://gateway_app:change-me-app@localhost:5432/gateway"
)
AUDIT = os.environ.get(
    "GATEWAY_AUDIT_DB_URL",
    "postgresql+asyncpg://gateway_audit:change-me-audit@localhost:5432/gateway",
)
ARGS: dict[str, Any] = {"schema_name": "public", "table": "orders", "pk": 3}
H = args_hash("delete_record", ARGS)


@pytest.fixture
async def admin() -> AsyncIterator[AsyncEngine]:
    engine = create_async_engine(ADMIN)
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1 FROM approvals LIMIT 1"))
    except Exception:
        pytest.skip("gateway DB not migrated: run `alembic upgrade head`")
    yield engine
    await engine.dispose()


@pytest.fixture
async def store(admin: AsyncEngine) -> AsyncIterator[ApprovalStore]:
    s = ApprovalStore.from_url(APP)
    yield s
    await s.close()


async def make(
    store: ApprovalStore, requester: str | None = None, args: dict[str, Any] | None = None
):  # type: ignore[no-untyped-def]
    requester = requester or f"bob-{uuid.uuid4().hex[:8]}"  # unique: the per-requester cap persists
    a = args or {**ARGS, "pk": uuid.uuid4().int % 10**9}  # unique per test: no dedup collisions
    return await store.create(
        requester=requester, requester_role="operator", tool="delete_record",
        args_hash=args_hash("delete_record", a), args=a, ttl_minutes=30,
    )  # fmt: skip


async def age(admin: AsyncEngine, approval_id: str) -> None:
    """Make an approval expired. expires_at is immutable, so this uses the superuser-only
    replica role to skip the guard trigger, as a DBA would for maintenance."""
    async with admin.begin() as conn:
        await conn.execute(text("SET LOCAL session_replication_role = replica"))
        await conn.execute(
            text("UPDATE approvals SET expires_at = now() - interval '1 second' "
                 "WHERE id = CAST(:i AS uuid)"), {"i": approval_id},
        )  # fmt: skip


async def force(admin: AsyncEngine, sql: str, **params: Any) -> None:
    async with admin.begin() as conn:
        await conn.execute(text(sql), params)


# ---- roles and constraints ----------------------------------------------------------------


async def test_audit_role_is_insert_only(admin: AsyncEngine) -> None:
    sink = DbAuditSink.from_url(AUDIT)
    rid = uuid.uuid4().hex
    await sink.write(
        {"request_id": rid, "subject": "bob", "role": "operator", "tool": "t", "risk": "high",
         "decision": "allow", "args": {"x": 1}, "reason": "", "duration_ms": 1.5}
    )  # fmt: skip
    async with admin.connect() as conn:
        row = (
            await conn.execute(
                text("SELECT subject, args_redacted FROM audit_log WHERE request_id = :r"),
                {"r": rid},
            )
        ).first()
    assert row is not None
    assert row[0] == "bob"
    engine = create_async_engine(AUDIT)
    try:
        for sql in (
            "SELECT * FROM audit_log",
            "UPDATE audit_log SET decision = 'allow'",
            "DELETE FROM audit_log",
            "TRUNCATE audit_log",
            "DROP TABLE audit_log",
            "ALTER TABLE audit_log ADD COLUMN x int",
            "SELECT * FROM approvals",
            "INSERT INTO approvals (expires_at, requester, requester_role, tool, args_hash, args) "
            "VALUES (now(), 'a', 'b', 'c', 'd', '{}'::jsonb)",
        ):
            async with engine.connect() as conn:
                with pytest.raises((ProgrammingError, DBAPIError)):
                    await conn.execute(text(sql))
    finally:
        await engine.dispose()
        await sink.close()


async def test_app_role_cannot_touch_audit_or_destroy_approvals(admin: AsyncEngine) -> None:
    engine = create_async_engine(APP)
    try:
        for sql in (
            "SELECT * FROM audit_log",
            "INSERT INTO audit_log (request_id, tool, decision) VALUES ('x', 'y', 'z')",
            "UPDATE audit_log SET decision = 'allow'",
            "DELETE FROM approvals",
            "TRUNCATE approvals",
            "DROP TABLE approvals",
            "ALTER TABLE approvals DROP COLUMN requester",
        ):
            async with engine.connect() as conn:
                with pytest.raises((ProgrammingError, DBAPIError)):
                    await conn.execute(text(sql))
    finally:
        await engine.dispose()


async def test_self_approval_is_blocked_by_the_table_itself(
    admin: AsyncEngine, store: ApprovalStore
) -> None:
    row = await make(store)
    with pytest.raises((DBAPIError, ProgrammingError)):  # even a buggy app / admin is refused
        await force(
            admin, "UPDATE approvals SET status = 'approved', decided_by = requester "
            "WHERE id = CAST(:id AS uuid)", id=row.id,
        )  # fmt: skip


async def test_status_values_are_constrained(admin: AsyncEngine, store: ApprovalStore) -> None:
    row = await make(store)
    with pytest.raises((DBAPIError, ProgrammingError)):
        await force(
            admin, "UPDATE approvals SET status = 'expired' WHERE id = CAST(:id AS uuid)", id=row.id
        )


# ---- approval store: atomic transitions ------------------------------------------------------


async def test_create_is_idempotent_for_identical_live_requests(store: ApprovalStore) -> None:
    args = {**ARGS, "pk": uuid.uuid4().int % 10**9}
    who = f"bob-{uuid.uuid4().hex[:8]}"
    a, b = await make(store, who, args), await make(store, who, args)
    assert a.id == b.id
    assert (await make(store, f"dave-{uuid.uuid4().hex[:8]}", args)).id != a.id  # per requester
    assert a.status == "pending"
    assert a.args == args


async def test_decide_refuses_self_and_allows_a_different_user(store: ApprovalStore) -> None:
    row = await make(store)
    assert await store.decide(row.id, approver=row.requester, approve=True, reason=None) is None
    assert (await store.get(row.id)).status == "pending"  # type: ignore[union-attr]
    done = await store.decide(row.id, approver="carol", approve=True, reason="ok")
    assert done is not None
    assert (done.status, done.decided_by) == ("approved", "carol")
    assert await store.decide(row.id, approver="erin", approve=False, reason=None) is None  # once


async def test_consume_exactly_once_sequentially(store: ApprovalStore) -> None:
    row = await make(store)
    kw = {"requester": row.requester, "tool": "delete_record", "args_hash": row.args_hash}
    assert not await store.consume(row.id, **kw)  # still pending
    await store.decide(row.id, approver="carol", approve=True, reason=None)
    assert await store.consume(row.id, **kw)
    assert not await store.consume(row.id, **kw)  # replay
    assert (await store.get(row.id)).status == "used"  # type: ignore[union-attr]


async def test_concurrent_consumers_get_exactly_one_win(store: ApprovalStore) -> None:
    row = await make(store)
    await store.decide(row.id, approver="carol", approve=True, reason=None)
    kw = {"requester": row.requester, "tool": "delete_record", "args_hash": row.args_hash}
    results = await asyncio.gather(*[store.consume(row.id, **kw) for _ in range(25)])
    assert sum(results) == 1


async def test_concurrent_decisions_get_exactly_one_win(store: ApprovalStore) -> None:
    row = await make(store)
    results = await asyncio.gather(
        *[
            store.decide(row.id, approver=f"approver{i}", approve=i % 2 == 0, reason=None)
            for i in range(20)
        ]
    )
    assert sum(r is not None for r in results) == 1


async def test_consume_is_bound_to_requester_tool_and_hash(store: ApprovalStore) -> None:
    row = await make(store)
    await store.decide(row.id, approver="carol", approve=True, reason=None)
    good = {"requester": row.requester, "tool": "delete_record", "args_hash": row.args_hash}
    assert not await store.consume(row.id, **{**good, "requester": "mallory"})
    assert not await store.consume(row.id, **{**good, "tool": "update_record"})
    assert not await store.consume(row.id, **{**good, "args_hash": "0" * 64})
    assert (await store.get(row.id)).status == "approved"  # type: ignore[union-attr]
    assert await store.consume(row.id, **good)


async def test_expiry_uses_the_database_clock(admin: AsyncEngine, store: ApprovalStore) -> None:
    row = await make(store)
    await age(admin, row.id)
    assert await store.decide(row.id, approver="carol", approve=True, reason=None) is None
    assert row.id not in [r.id for r in await store.list_pending(500)]

    row2 = await make(store)
    await store.decide(row2.id, approver="carol", approve=True, reason=None)
    await age(admin, row2.id)
    kw = {"requester": row2.requester, "tool": "delete_record", "args_hash": row2.args_hash}
    assert not await store.consume(row2.id, **kw)


async def test_ttl_is_applied(store: ApprovalStore) -> None:
    row = await make(store)
    minutes = (row.expires_at - row.created_at).total_seconds() / 60
    assert 29.9 < minutes < 30.1


async def test_malformed_ids_do_not_crash_into_sql(store: ApprovalStore) -> None:
    from mcp_gateway.approvals.store import ApprovalStoreError

    with pytest.raises(ApprovalStoreError):  # tool schema rejects these first; DB is backstop
        await store.get("1'; DROP TABLE approvals; --")


# ---- audit writer ------------------------------------------------------------------------------


async def test_auditor_persists_critical_records(admin: AsyncEngine) -> None:
    sink = DbAuditSink.from_url(AUDIT)
    rid = uuid.uuid4().hex
    await Auditor(sink).record(
        request_id=rid, tool="update_record", decision="allow", started=0.0, role="operator",
        subject="bob", risk="medium", args={"table": "orders", "changes": {"status": "SECRET"}},
        critical=True,
    )  # fmt: skip
    async with admin.connect() as conn:
        row = (
            await conn.execute(
                text(
                    "SELECT args_redacted::text, risk, subject FROM audit_log WHERE request_id=:r"
                ),
                {"r": rid},
            )
        ).first()
    assert row is not None
    assert "SECRET" not in row[0]
    assert (row[1], row[2]) == ("medium", "bob")
    await sink.close()


# ---- review fixes: hardening, cap, race, privilege probes ----------------------------------


async def test_app_role_cannot_rewrite_identity_columns(
    admin: AsyncEngine, store: ApprovalStore
) -> None:
    row = await make(store)
    engine = create_async_engine(APP)
    try:
        for col, val in (
            ("args_hash", "'x'"), ("requester", "'mallory'"), ("tool", "'run_query'"),
            ("expires_at", "now() + interval '9 days'"), ("requester_role", "'admin'"),
        ):  # fmt: skip
            async with engine.begin() as conn:
                with pytest.raises((ProgrammingError, DBAPIError)):
                    await conn.execute(
                        text(f"UPDATE approvals SET {col} = {val} WHERE id = CAST(:i AS uuid)"),  # noqa: S608
                        {"i": row.id},
                    )
    finally:
        await engine.dispose()


async def test_trigger_allows_only_legal_transitions_even_for_the_owner(
    admin: AsyncEngine, store: ApprovalStore
) -> None:
    row = await make(store)
    for sql in (
        "UPDATE approvals SET status = 'used' WHERE id = CAST(:i AS uuid)",  # pending -> used
        "UPDATE approvals SET args_hash = 'x' WHERE id = CAST(:i AS uuid)",  # identity edit
        "UPDATE approvals SET status = 'approved' WHERE id = CAST(:i AS uuid)",  # no decider
    ):
        with pytest.raises((DBAPIError, ProgrammingError)):
            await force(admin, sql, i=row.id)
    await store.decide(row.id, approver="carol", approve=True, reason=None)
    kw = {"requester": row.requester, "tool": "delete_record", "args_hash": row.args_hash}
    assert await store.consume(row.id, **kw)
    for sql in (  # a spent approval can never be revived
        "UPDATE approvals SET status = 'approved' WHERE id = CAST(:i AS uuid)",
        "UPDATE approvals SET status = 'pending' WHERE id = CAST(:i AS uuid)",
        "UPDATE approvals SET status = 'denied' WHERE id = CAST(:i AS uuid)",
    ):
        with pytest.raises((DBAPIError, ProgrammingError)):
            await force(admin, sql, i=row.id)
    with pytest.raises((DBAPIError, ProgrammingError)):  # and rows cannot be inserted decided
        await force(
            admin,
            "INSERT INTO approvals (expires_at, requester, requester_role, tool, args_hash, args, "
            "status, decided_by) VALUES (now(), 'a', 'b', 'c', 'd', '{}'::jsonb, 'approved', 'z')",
        )


async def test_concurrent_identical_requests_create_one_row(
    admin: AsyncEngine, store: ApprovalStore
) -> None:
    args = {**ARGS, "pk": uuid.uuid4().int % 10**9}
    h = args_hash("delete_record", args)
    rows = await asyncio.gather(*[make(store, "racer", args) for _ in range(15)])
    assert len({r.id for r in rows}) == 1
    async with admin.connect() as conn:
        n = (
            await conn.execute(
                text("SELECT count(*) FROM approvals WHERE args_hash = :h"), {"h": h}
            )
        ).scalar()
    assert n == 1


async def test_requester_cap_and_expired_rows_free_the_slot(
    admin: AsyncEngine, store: ApprovalStore
) -> None:
    from mcp_gateway.approvals.store import MAX_LIVE_PER_REQUESTER, ApprovalLimitError

    who = f"flooder-{uuid.uuid4().hex[:8]}"
    made = [await make(store, who, {**ARGS, "pk": i}) for i in range(MAX_LIVE_PER_REQUESTER)]
    with pytest.raises(ApprovalLimitError):
        await make(store, who, {**ARGS, "pk": 10_000})
    assert (await make(store, who, {**ARGS, "pk": 0})).id == made[0].id  # re-ask is not new
    await age(admin, made[0].id)
    fresh = await make(store, who, {**ARGS, "pk": 0})  # stale row is retired, slot is reusable
    assert fresh.id != made[0].id
    assert (await store.get(made[0].id)).status == "denied"  # type: ignore[union-attr]


async def test_arguments_are_dropped_once_an_approval_is_spent_or_denied(
    admin: AsyncEngine, store: ApprovalStore
) -> None:
    a = await make(store)
    assert a.args
    await store.decide(a.id, approver="carol", approve=False, reason="no")
    assert (await store.get(a.id)).args == {}  # type: ignore[union-attr]

    b = await make(store)
    await store.decide(b.id, approver="carol", approve=True, reason=None)
    assert (await store.get(b.id)).args  # type: ignore[union-attr]  # kept while approvable
    await store.consume(b.id, requester=b.requester, tool="delete_record", args_hash=b.args_hash)
    assert (await store.get(b.id)).args == {}  # type: ignore[union-attr]


async def test_cancel_withdraws_only_own_pending_approvals(store: ApprovalStore) -> None:
    row = await make(store)
    await store.cancel(row.id, requester="mallory")
    assert (await store.get(row.id)).status == "pending"  # type: ignore[union-attr]
    await store.cancel(row.id, requester=row.requester)
    assert (await store.get(row.id)).status == "denied"  # type: ignore[union-attr]
    assert await store.decide(row.id, approver="carol", approve=True, reason=None) is None


async def test_privilege_probes_accept_the_real_roles_and_reject_wrong_ones(
    admin: AsyncEngine, store: ApprovalStore
) -> None:
    from mcp_gateway.db_probe import approvals_role_problems, audit_role_problems, probe_privileges

    sink = DbAuditSink.from_url(AUDIT)
    try:
        assert audit_role_problems(await sink.verify_privileges()) == []
        assert approvals_role_problems(await store.verify_privileges()) == []
        # swapped URLs: each role is wrong for the other's job
        assert audit_role_problems(await store.verify_privileges())
        assert approvals_role_problems(await sink.verify_privileges())
        # the schema owner / superuser must be refused for either job
        owner = await probe_privileges(admin)
        assert any("superuser" in p for p in audit_role_problems(owner))
        assert any("superuser" in p for p in approvals_role_problems(owner))
    finally:
        await sink.close()
