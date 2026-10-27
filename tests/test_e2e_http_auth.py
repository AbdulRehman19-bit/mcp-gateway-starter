"""End to end: real Keycloak tokens against the real HTTP server (docker compose --profile auth).

Run order matters for the last test, which inspects the server's audit log.
"""

import json
import os
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

pytestmark = pytest.mark.integration

KC = "http://localhost:8080/realms/mcp-gateway"
PORT = 8765
URL = f"http://127.0.0.1:{PORT}/mcp"
RO_URL = os.environ.get(
    "TARGET_DB_RO_URL", "postgresql+asyncpg://gateway_ro:change-me-ro@localhost:5432/demo"
)
INIT = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-03-26",
        "capabilities": {},
        "clientInfo": {"name": "t", "version": "0"},
    },
}
HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
ISSUED: list[str] = []  # every token we mint, to prove none reaches the logs


def token(user: str, scope: str | None) -> str:
    data = {
        "grant_type": "password",
        "client_id": "mcp-gateway-dev",
        "username": user,
        "password": f"{user}-dev-only",
    }
    if scope:
        data["scope"] = scope
    try:
        resp = httpx.post(f"{KC}/protocol/openid-connect/token", data=data, timeout=10)
    except httpx.TransportError:
        pytest.skip("Keycloak not running (docker compose --profile auth up -d keycloak)")
    assert resp.status_code == 200, resp.text
    tok: str = resp.json()["access_token"]
    ISSUED.append(tok)
    return tok


@pytest.fixture(scope="module")
def server(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Path]:
    token("alice", "db:read")  # skips the module early if Keycloak is down
    log = tmp_path_factory.mktemp("srv") / "server.log"
    env = {
        **os.environ,
        "TARGET_DB_RO_URL": RO_URL,
        "OAUTH_ISSUER": KC,
        "OAUTH_JWKS_URL": f"{KC}/protocol/openid-connect/certs",
        "GATEWAY_PORT": str(PORT),
    }
    with log.open("wb") as fh:
        proc = subprocess.Popen(
            [sys.executable, "-m", "mcp_gateway.server", "--transport", "http"],
            env=env,
            stdout=fh,
            stderr=subprocess.STDOUT,
        )
        try:
            deadline = time.monotonic() + 30
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


def raw_init(bearer: str | None) -> httpx.Response:
    headers = dict(HEADERS)
    if bearer is not None:
        headers["Authorization"] = f"Bearer {bearer}"
    return httpx.post(URL, json=INIT, headers=headers, timeout=10)


async def call(tok: str, tool: str, args: dict[str, Any]) -> Any:
    client = httpx.AsyncClient(headers={"Authorization": f"Bearer {tok}"}, timeout=30)
    async with (
        client,
        streamable_http_client(URL, http_client=client) as (r, w, _),
        ClientSession(r, w) as s,
    ):
        await s.initialize()
        return await s.call_tool(tool, args)


def text(result: Any) -> str:
    return str(result.content[0].text)


def test_no_token_is_401(server: Path) -> None:
    resp = raw_init(None)
    assert resp.status_code == 401
    assert "www-authenticate" in resp.headers


@pytest.mark.parametrize("bad", ["", "garbage", "a.b.c", "x" * 9000])
def test_garbage_tokens_are_401(server: Path, bad: str) -> None:
    assert raw_init(bad).status_code == 401


def test_token_with_no_mapped_scope_is_401(server: Path) -> None:
    assert raw_init(token("alice", None)).status_code == 401


def test_ambiguous_scopes_are_401(server: Path) -> None:
    assert raw_init(token("alice", "db:read db:write")).status_code == 401


def test_tampered_token_is_401(server: Path) -> None:
    head, body, sig = token("alice", "db:read").split(".")
    forged = token("bob", "db:write").split(".")[1]  # operator claims, analyst signature
    assert raw_init(f"{head}.{forged}.{sig}").status_code == 401
    assert raw_init(f"{head}.{body}.{sig[:-4]}AAAA").status_code == 401


def test_valid_token_is_accepted(server: Path) -> None:
    assert raw_init(token("alice", "db:read")).status_code == 200


async def test_analyst_sees_masked_users_and_cannot_read_email(server: Path) -> None:
    tok = token("alice", "db:read")
    out = await call(tok, "run_query", {"sql": "SELECT id, phone FROM users ORDER BY id"})
    assert json.loads(text(out))["rows"] == [[1, "***"], [2, "***"]]
    out = await call(tok, "run_query", {"sql": "SELECT email FROM users"})
    assert out.isError


async def test_operator_role_comes_from_its_own_token(server: Path) -> None:
    out = await call(token("bob", "db:write"), "list_tables", {})
    names = {t["table"] for t in json.loads(text(out))["tables"]}
    assert names == {"orders", "customers"}  # operator policy has no `users`
    out = await call(token("bob", "db:write"), "run_query", {"sql": "SELECT id FROM users"})
    assert out.isError


async def test_approver_cannot_query(server: Path) -> None:
    out = await call(token("carol", "approvals:decide"), "run_query", {"sql": "SELECT 1"})
    assert out.isError


async def test_role_in_tool_arguments_is_ignored(server: Path) -> None:
    out = await call(token("alice", "db:read"), "list_tables", {"role": "operator"})
    if not out.isError:  # extra args may be dropped; either way the role must not change
        names = {t["table"] for t in json.loads(text(out))["tables"]}
        assert "users" in names  # still the analyst's view


async def test_concurrent_users_keep_their_own_identity(server: Path) -> None:
    import asyncio

    alice, bob = token("alice", "db:read"), token("bob", "db:write")
    results = await asyncio.gather(
        *[call(alice if i % 2 == 0 else bob, "list_tables", {}) for i in range(8)]
    )
    for i, out in enumerate(results):
        names = {t["table"] for t in json.loads(text(out))["tables"]}
        assert ("users" in names) == (i % 2 == 0)


def test_audit_log_has_denials_and_subjects_but_no_tokens(server: Path) -> None:
    log = server.read_text()
    records = [json.loads(line) for line in log.splitlines() if line.startswith("{")]
    auth = [r for r in records if r.get("tool") == "authenticate"]
    assert any(r["decision"] == "deny" for r in auth)
    assert any(r["decision"] == "allow" and r["role"] == "analyst" for r in auth)
    calls = [r for r in records if r.get("tool") == "run_query" and r["decision"] == "allow"]
    assert calls
    assert all(r["subject"] and r["role"] for r in calls)
    for tok in ISSUED:
        assert tok not in log
        assert tok.split(".")[1] not in log
