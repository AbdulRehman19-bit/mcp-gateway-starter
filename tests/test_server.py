import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any, ClassVar

import httpx
import pytest
import structlog
from mcp.server.auth.provider import AccessToken

from mcp_gateway import __version__, server
from mcp_gateway.auth.roles import Identity
from mcp_gateway.connectors.postgres import QueryResult
from mcp_gateway.policy import load_policy
from mcp_gateway.policy.evaluator import allowed_tables
from mcp_gateway.tools.handlers import ToolFailure, ToolService

POLICY = load_policy(Path(__file__).parents[1] / "policies" / "policy.example.yaml")
CATALOG = {
    ("public", "orders"): {"id": "integer"},
    ("public", "customers"): {"id": "integer", "name": "text", "country": "text"},
    ("public", "users"): {"id": "integer", "phone": "text"},
}
ALLOWED = {r: allowed_tables(POLICY, r, CATALOG) for r in POLICY.roles}


class NullConnector:
    async def run_query(self, sql: str, *, limit: int | None = None) -> QueryResult:
        return QueryResult(columns=[], rows=[], truncated=False)


def use_service(identity: Any) -> None:
    server._service = ToolService(NullConnector(), POLICY, ALLOWED, identity)  # type: ignore[arg-type]


@pytest.fixture(autouse=True)
def _reset_service() -> Iterator[None]:
    yield
    server._service = None


async def test_ping_with_identity_is_audited() -> None:
    use_service(lambda: Identity("u1", "analyst", frozenset()))
    with structlog.testing.capture_logs() as logs:
        assert __version__ in await server.ping()
    assert (logs[0]["tool"], logs[0]["decision"], logs[0]["subject"]) == ("ping", "allow", "u1")


async def test_ping_without_identity_or_service_is_denied() -> None:
    with pytest.raises(ToolFailure):  # not configured: fail closed
        await server.ping()
    use_service(lambda: None)
    with structlog.testing.capture_logs() as logs, pytest.raises(ToolFailure):
        await server.ping()
    assert logs[0]["decision"] == "deny"


class StubVerifier:
    """Two bearer tokens for the SAME user (same sub/azp) with different scopes."""

    TOKENS: ClassVar[dict[str, list[str]]] = {
        "A": ["db:read"],
        "B": ["db:write"],
        "X": ["db:read"],
    }

    async def verify_token(self, token: str) -> AccessToken | None:
        if token not in self.TOKENS:
            return None
        exp = 1 if token == "X" else 4_000_000_000  # X is already expired at call time
        return AccessToken(
            token=token, client_id="c", scopes=self.TOKENS[token], subject="alice", expires_at=exp
        )


async def _post(client: httpx.AsyncClient, token: str | None, body: dict[str, Any]) -> Any:
    headers = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return await client.post("/mcp", json=body, headers=headers)


def _tables(resp: httpx.Response) -> set[str]:
    data = resp.text
    if data.startswith("event:"):
        data = next(line[5:] for line in data.splitlines() if line.startswith("data:"))
    result = json.loads(data)["result"]
    assert not result.get("isError"), result
    return {t["table"] for t in json.loads(result["content"][0]["text"])["tables"]}


async def test_each_request_uses_its_own_token_not_the_first_one() -> None:
    """Regression: identity must not stick to the request that opened the session."""
    use_service(server.token_identity(POLICY))
    app = server.create_server(
        host="127.0.0.1",
        port=8000,
        verifier=StubVerifier(),
        issuer="http://localhost:8080/realms/gw",
        public_url="http://127.0.0.1:8000/mcp",
    )
    call = {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "list_tables", "arguments": {}}}  # fmt: skip
    init = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-03-26", "capabilities": {},
                       "clientInfo": {"name": "t", "version": "0"}}}  # fmt: skip
    asgi = app.streamable_http_app()  # must exist before session_manager is available
    async with (
        app.session_manager.run(),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=asgi),
            base_url="http://127.0.0.1:8000",
        ) as client,
    ):
        first = await _post(client, "A", init)
        assert first.status_code == 200
        session = first.headers.get("mcp-session-id")
        extra = {"mcp-session-id": session} if session else {}
        client.headers.update(extra)
        analyst = await _post(client, "A", call)
        operator = await _post(client, "B", call)  # same user, same client, new token
        assert "users" in _tables(analyst)
        assert "users" not in _tables(operator)  # operator's view, not the opener's
        expired = await _post(client, "X", call)
        assert expired.status_code in (200, 401)
        if expired.status_code == 200:  # authenticated at the edge, but denied at call time
            assert json.loads(expired.text.split("data:")[-1] if "data:" in expired.text
                              else expired.text)["result"]["isError"]  # fmt: skip
        assert (await _post(client, None, call)).status_code == 401
        assert (await _post(client, "nope", call)).status_code == 401
