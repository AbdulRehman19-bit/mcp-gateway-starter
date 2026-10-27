"""End-to-end demo of mcp-gateway against the `docker compose up` stack.

    docker compose up --build -d        # db + keycloak + migrate + gateway
    uv run python scripts/demo.py

It logs in as three Keycloak users (alice = analyst, bob = operator, carol = approver), calls
the gateway over Streamable HTTP with real bearer tokens, and shows: column masking and
denial, a high-risk delete that waits for a different human, single-use approval, and the
audit trail. It exits non-zero if anything behaves differently from what is documented, so it
doubles as a smoke test of a fresh clone.

Dev only: the credentials below are the placeholders from docker-compose.yml.
"""

import argparse
import asyncio
import json
import sys
from typing import Any

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

KEYCLOAK = "http://localhost:8080/realms/mcp-gateway"
GATEWAY = "http://127.0.0.1:8000/mcp"  # override with --gateway
DEMO_DB = "postgresql+asyncpg://postgres:postgres-dev-only@localhost:5432/demo"
GATEWAY_DB = "postgresql+asyncpg://postgres:postgres-dev-only@localhost:5432/gateway"
ROW = 9900  # a throwaway order created (and removed) by this script

BOLD, DIM, GREEN, RED, YELLOW, RESET = (
    "\033[1m",
    "\033[2m",
    "\033[32m",
    "\033[31m",
    "\033[33m",
    "\033[0m",
)
failures: list[str] = []


def say(msg: str = "") -> None:
    print(msg, flush=True)


def step(title: str) -> None:
    say(f"\n{BOLD}== {title}{RESET}")


def show(who: str, what: str, result: str, ok: bool) -> None:
    colour = GREEN if ok else RED
    say(f"  {DIM}{who:<6}{RESET} {what:<58} {colour}{result}{RESET}")


def check(condition: bool, description: str) -> None:
    if not condition:
        failures.append(description)
        say(f"  {RED}UNEXPECTED: {description}{RESET}")


def login(user: str, scope: str) -> str:
    resp = httpx.post(
        f"{KEYCLOAK}/protocol/openid-connect/token",
        data={
            "grant_type": "password",
            "client_id": "mcp-gateway-dev",
            "username": user,
            "password": f"{user}-dev-only",
            "scope": scope,
        },
        timeout=10,
    )
    resp.raise_for_status()
    return str(resp.json()["access_token"])


async def call(token: str, tool: str, args: dict[str, Any] | None = None) -> tuple[bool, Any]:
    """Returns (ok, payload). Errors come back as (False, message)."""
    client = httpx.AsyncClient(headers={"Authorization": f"Bearer {token}"}, timeout=30)
    async with (
        client,
        streamable_http_client(GATEWAY, http_client=client) as (r, w, _),
        ClientSession(r, w) as session,
    ):
        await session.initialize()
        res = await session.call_tool(tool, args or {})
    body = res.content[0].text if res.content else ""  # type: ignore[union-attr]
    if res.isError:
        return False, body
    try:
        return True, json.loads(body)
    except ValueError:
        return True, body


async def row_status(engine: Any) -> str | None:
    async with engine.connect() as conn:
        r = (
            await conn.execute(text("SELECT status FROM orders WHERE id = :i"), {"i": ROW})
        ).first()
    return None if r is None else str(r[0])


async def main(keep: bool) -> int:
    try:
        alice = login("alice", "db:read")
        bob = login("bob", "db:write")
        carol = login("carol", "approvals:decide")
    except httpx.HTTPError as exc:
        say(f"{RED}Cannot reach Keycloak at {KEYCLOAK}: {exc}{RESET}")
        say("Is the stack up?  docker compose up --build -d   (give Keycloak ~40 s)")
        return 2

    db = create_async_engine(DEMO_DB)
    async with db.begin() as conn:
        await conn.execute(text("DELETE FROM orders WHERE id = :i"), {"i": ROW})
        await conn.execute(
            text(
                "INSERT INTO orders (id, customer_id, total_cents, status) "
                "VALUES (:i, 1, 100, 'new')"
            ),
            {"i": ROW},
        )
    try:
        step("1. Read access follows the policy (alice, analyst)")
        ok, out = await call(alice, "list_tables")
        show(
            "alice", "list_tables", ", ".join(t["table"] for t in out["tables"]) if ok else out, ok
        )
        ok, out = await call(alice, "run_query", {"sql": "SELECT id, phone FROM users ORDER BY id"})
        show(
            "alice",
            "SELECT id, phone FROM users",
            f"phone -> {out['rows'][0][1]!r} (masked)" if ok else out,
            ok,
        )
        check(ok and out["rows"][0][1] == "***", "phone is masked in the rewritten SQL")
        for sql in ("SELECT email FROM users", "SELECT users FROM users", "SELECT * FROM pg_roles"):
            ok, out = await call(alice, "run_query", {"sql": sql})
            show("alice", sql, f"denied: {out}" if not ok else "ALLOWED?!", not ok)
            check(not ok, f"query must be denied: {sql}")

        step("2. A high-risk delete waits for a different human (bob asks, carol approves)")
        ok, out = await call(bob, "delete_record", {"table": "orders", "pk": ROW, "dry_run": True})
        show("bob", f"delete_record orders/{ROW} dry_run", f"{out}" if ok else out, ok)
        check(
            ok and out["status"] == "dry_run" and await row_status(db) == "new",
            "dry run persists nothing",
        )

        ok, out = await call(bob, "delete_record", {"table": "orders", "pk": ROW})
        show("bob", f"delete_record orders/{ROW}", out["status"] if ok else out, ok)
        check(
            ok and out["status"] == "pending_approval",
            "high-risk call must return pending_approval",
        )
        check(await row_status(db) == "new", "nothing is deleted while pending")
        aid = out["approval_id"]

        ok, out = await call(bob, "decide_approval", {"approval_id": aid, "decision": "approve"})
        show(
            "bob",
            "decide_approval (his own request)",
            f"refused: {out}" if not ok else "ALLOWED?!",
            not ok,
        )
        check(not ok, "requester cannot approve their own request")

        ok, out = await call(carol, "list_approvals")
        mine = [a for a in (out["approvals"] if ok else []) if a["approval_id"] == aid]
        show(
            "carol",
            "list_approvals",
            f"sees {mine[0]['tool']} on {mine[0]['args']['table']}/{mine[0]['args']['pk']}"
            if mine
            else str(out),
            bool(mine),
        )
        check(bool(mine), "approver sees the pending request with its real arguments")
        ok, out = await call(carol, "decide_approval", {"approval_id": aid, "decision": "approve"})
        show("carol", "decide_approval approve", out["status"] if ok else out, ok)
        check(await row_status(db) == "new", "approving alone executes nothing")

        step("3. The approval is bound to the exact call and works exactly once")
        ok, out = await call(
            bob, "delete_record", {"table": "orders", "pk": ROW + 1, "approval_id": aid}
        )
        show(
            "bob",
            f"delete orders/{ROW + 1} with that approval",
            f"refused: {out}" if not ok else "ALLOWED?!",
            not ok,
        )
        check(not ok, "an approval cannot be used for different arguments")
        ok, out = await call(
            bob, "delete_record", {"table": "orders", "pk": ROW, "approval_id": aid}
        )
        show("bob", f"delete orders/{ROW} with approval", f"{out}" if ok else out, ok)
        check(ok and await row_status(db) is None, "the approved delete executes")
        ok, out = await call(
            bob, "delete_record", {"table": "orders", "pk": ROW, "approval_id": aid}
        )
        show(
            "bob", "replay the same approval", f"refused: {out}" if not ok else "ALLOWED?!", not ok
        )
        check(not ok, "an approval is single-use")

        step("4. Every step is in the audit trail (who, what, decision), without the data")
        engine = create_async_engine(GATEWAY_DB)
        async with engine.connect() as conn:
            rows = (
                await conn.execute(
                    text(
                        "SELECT role, tool, decision, reason FROM audit_log "
                        "WHERE tool IN ('delete_record', 'decide_approval') "
                        "AND ts > now() - interval '5 minutes' ORDER BY ts"
                    )
                )
            ).all()
        await engine.dispose()
        for role, tool, decision, reason in rows:
            say(f"  {DIM}{role:<9}{RESET} {tool:<16} {decision:<17} {DIM}{reason[:46]}{RESET}")
        check(any(r[2] == "pending_approval" for r in rows), "pending_approval is audited")
        check(
            any(r[1] == "delete_record" and r[2] == "success" for r in rows),
            "the delete is audited",
        )
        check(
            any(r[1] == "decide_approval" and r[2] == "deny" for r in rows),
            "the refused self-approval is audited",
        )
    finally:
        if not keep:
            async with db.begin() as conn:
                await conn.execute(text("DELETE FROM orders WHERE id = :i"), {"i": ROW})
        await db.dispose()

    say()
    if failures:
        say(f"{RED}{BOLD}{len(failures)} unexpected result(s):{RESET}")
        for f in failures:
            say(f"  - {f}")
        return 1
    say(f"{GREEN}{BOLD}Demo complete: everything behaved as documented.{RESET}")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--keep", action="store_true", help="leave the demo order row in the DB")
    parser.add_argument("--gateway", default=GATEWAY, help="gateway MCP URL")
    args = parser.parse_args()
    GATEWAY = args.gateway
    sys.exit(asyncio.run(main(args.keep)))
