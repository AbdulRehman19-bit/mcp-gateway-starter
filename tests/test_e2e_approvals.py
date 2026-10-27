"""Phase 4 demo, end to end: bob (operator) asks to delete a row, carol (approver) approves,
bob runs it, it executes exactly once. Real Keycloak tokens, real HTTP server, real Postgres.
"""

import asyncio
import json
import os
import socket
import subprocess
import sys
import time
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

pytestmark = pytest.mark.integration

KC = "http://localhost:8080/realms/mcp-gateway"
PORT = 8766
URL = f"http://127.0.0.1:{PORT}/mcp"
ROW = 9100
HOST = "localhost:5432"
ENV = {
    "TARGET_DB_RO_URL": f"postgresql+asyncpg://gateway_ro:change-me-ro@{HOST}/demo",
    "TARGET_DB_RW_URL": f"postgresql+asyncpg://gateway_rw:change-me-rw@{HOST}/demo",
    "GATEWAY_DB_URL": f"postgresql+asyncpg://gateway_app:change-me-app@{HOST}/gateway",
    "GATEWAY_AUDIT_DB_URL": f"postgresql+asyncpg://gateway_audit:change-me-audit@{HOST}/gateway",
    "GATEWAY_READ_ONLY": "false",
    "OAUTH_ISSUER": KC,
    "OAUTH_JWKS_URL": f"{KC}/protocol/openid-connect/certs",
    "GATEWAY_PORT": str(PORT),
}
DEMO_ADMIN = f"postgresql+asyncpg://postgres:postgres-dev-only@{HOST}/demo"
GW_ADMIN = f"postgresql+asyncpg://postgres:postgres-dev-only@{HOST}/gateway"
SECRET = "E2E-SECRET-VALUE"


def token(user: str, scope: str) -> str:
    try:
        resp = httpx.post(
            f"{KC}/protocol/openid-connect/token",
            data={"grant_type": "password", "client_id": "mcp-gateway-dev", "username": user,
                  "password": f"{user}-dev-only", "scope": scope},
            timeout=10,
        )  # fmt: skip
    except httpx.TransportError:
        pytest.skip("Keycloak not running (docker compose --profile auth up -d keycloak)")
    assert resp.status_code == 200, resp.text
    return str(resp.json()["access_token"])


@pytest.fixture(scope="module")
def server(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Path]:
    token("bob", "db:write")  # skip early if Keycloak is down
    log = tmp_path_factory.mktemp("srv") / "server.log"
    with log.open("wb") as fh:
        proc = subprocess.Popen(
            [sys.executable, "-m", "mcp_gateway.server", "--transport", "http"],
            env={**os.environ, **ENV}, stdout=fh, stderr=subprocess.STDOUT,
        )  # fmt: skip
        try:
            deadline = time.monotonic() + 40
            while time.monotonic() < deadline:
                with socket.socket() as s:
                    if s.connect_ex(("127.0.0.1", PORT)) == 0:
                        break
                assert proc.poll() is None, log.read_text()
                time.sleep(0.3)
            else:
                pytest.fail("server did not start")
            yield log
        finally:
            proc.terminate()
            proc.wait(timeout=10)


@pytest.fixture
async def db() -> AsyncIterator[AsyncEngine]:
    engine = create_async_engine(DEMO_ADMIN)
    async with engine.begin() as conn:
        await conn.execute(text("DELETE FROM orders WHERE id = :i"), {"i": ROW})
        await conn.execute(
            text(
                "INSERT INTO orders (id, customer_id, total_cents, status) VALUES (:i, 1, 5, 'new')"
            ),
            {"i": ROW},
        )
    yield engine
    async with engine.begin() as conn:
        await conn.execute(text("DELETE FROM orders WHERE id = :i"), {"i": ROW})
    await engine.dispose()


async def call(tok: str, tool: str, args: dict[str, Any]) -> Any:
    client = httpx.AsyncClient(headers={"Authorization": f"Bearer {tok}"}, timeout=30)
    async with (
        client,
        streamable_http_client(URL, http_client=client) as (r, w, _),
        ClientSession(r, w) as s,
    ):
        await s.initialize()
        return await s.call_tool(tool, args)


def body(result: Any) -> Any:
    return json.loads(result.content[0].text)


async def row_status(db: AsyncEngine) -> str | None:
    async with db.connect() as conn:
        r = (
            await conn.execute(text("SELECT status FROM orders WHERE id = :i"), {"i": ROW})
        ).first()
    return None if r is None else str(r[0])


async def test_full_approval_flow_executes_exactly_once(server: Path, db: AsyncEngine) -> None:
    bob, carol, alice = (
        token("bob", "db:write"),
        token("carol", "approvals:decide"),
        token("alice", "db:read"),
    )

    # dry run: measured, never persisted, no approval needed even for a high-risk tool
    out = body(await call(bob, "delete_record", {"table": "orders", "pk": ROW, "dry_run": True}))
    assert out == {"status": "dry_run", "rows_affected": 1}
    assert await row_status(db) == "new"

    # medium risk: runs directly, only the policy-writable columns
    out = body(
        await call(
            bob, "update_record", {"table": "orders", "pk": ROW, "changes": {"status": SECRET}}
        )
    )
    assert out["status"] == "ok"
    assert await row_status(db) == SECRET
    bad = await call(
        bob, "update_record", {"table": "orders", "pk": ROW, "changes": {"total_cents": 1}}
    )
    assert bad.isError

    # high risk: pending, nothing deleted
    pending = body(await call(bob, "delete_record", {"table": "orders", "pk": ROW}))
    assert pending["status"] == "pending_approval"
    aid = pending["approval_id"]
    assert await row_status(db) == SECRET

    # not yet approved: cannot be used
    assert (
        await call(bob, "delete_record", {"table": "orders", "pk": ROW, "approval_id": aid})
    ).isError
    # role gates: requester cannot approve, approver cannot delete, analyst sees nothing
    assert (await call(bob, "decide_approval", {"approval_id": aid, "decision": "approve"})).isError
    assert (await call(carol, "delete_record", {"table": "orders", "pk": ROW})).isError
    assert (await call(alice, "list_approvals", {})).isError

    # a different user reviews the real arguments and approves
    mine = None
    offset: int | None = 0
    while mine is None and offset is not None:  # the queue is paged; walk it like an approver
        page = body(await call(carol, "list_approvals", {"offset": offset}))
        mine = next((a for a in page["approvals"] if a["approval_id"] == aid), None)
        offset = page["next_offset"]
    assert mine is not None
    assert mine["requester"] != "carol"
    assert mine["tool"] == "delete_record"
    assert mine["args"]["pk"] == ROW
    decided = body(
        await call(carol, "decide_approval", {"approval_id": aid, "decision": "approve"})
    )
    assert decided["status"] == "approved"
    assert await row_status(db) == SECRET  # approving does not execute anything

    # approval is bound to the exact arguments
    wrong = await call(bob, "delete_record", {"table": "orders", "pk": ROW + 1, "approval_id": aid})
    assert wrong.isError
    assert await row_status(db) == SECRET

    # executes once...
    done = body(
        await call(bob, "delete_record", {"table": "orders", "pk": ROW, "approval_id": aid})
    )
    assert done == {"status": "ok", "rows_affected": 1}
    assert await row_status(db) is None
    # ...and never again
    again = await call(bob, "delete_record", {"table": "orders", "pk": ROW, "approval_id": aid})
    assert again.isError


async def test_audit_trail_has_who_what_and_no_values(server: Path, db: AsyncEngine) -> None:
    engine = create_async_engine(GW_ADMIN)
    async with engine.connect() as conn:
        rows = (
            await conn.execute(
                text(
                    "SELECT tool, decision, subject, role, risk, args_redacted::text, reason "
                    "FROM audit_log WHERE ts > now() - interval '10 minutes' ORDER BY ts"
                )
            )
        ).all()
    await engine.dispose()
    seen = {(r[0], r[1]) for r in rows}
    for expected in [
        ("authenticate", "allow"), ("update_record", "allow"), ("update_record", "success"),
        ("update_record", "deny"), ("delete_record", "pending_approval"),
        ("delete_record", "allow"), ("delete_record", "success"), ("delete_record", "deny"),
        ("decide_approval", "approved"), ("decide_approval", "deny"),
    ]:  # fmt: skip
        assert expected in seen, expected
    writes = [r for r in rows if r[0] in ("update_record", "delete_record") and r[1] == "success"]
    assert all(r[2] and r[3] == "operator" for r in writes)
    deletes = [r for r in rows if r[0] == "delete_record"]
    assert all(r[4] == "high" for r in deletes)
    approver_rows = [r for r in rows if r[0] == "decide_approval" and r[1] == "approved"]
    assert approver_rows
    assert all(r[3] == "approver" for r in approver_rows)
    assert not any(SECRET in str(r) for r in rows)  # written values never reach the audit table
    assert SECRET not in await asyncio.to_thread(server.read_text)  # nor the JSON logs
