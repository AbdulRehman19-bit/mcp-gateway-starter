from pathlib import Path
from typing import Any

import pytest
import structlog

from mcp_gateway.connectors.postgres import ConnectorError, QueryResult
from mcp_gateway.policy import load_policy
from mcp_gateway.policy.evaluator import Catalog, allowed_tables
from mcp_gateway.tools.handlers import ToolFailure, ToolService

POLICY = load_policy(Path(__file__).parents[1] / "policies" / "policy.example.yaml")
CATALOG: Catalog = {
    ("public", "orders"): {"id": "integer", "status": "text"},
    ("public", "customers"): {"id": "integer", "name": "text", "country": "text"},
    ("public", "users"): {"id": "integer", "email": "text", "phone": "text"},
}


class FakeConnector:
    def __init__(self, error: Exception | None = None) -> None:
        self.error = error
        self.calls: list[str] = []

    async def run_query(self, sql: str, *, limit: int | None = None) -> QueryResult:
        self.calls.append(sql)
        if self.error:
            raise self.error
        return QueryResult(columns=["a"], rows=[[1]], truncated=False)


def svc(c: FakeConnector, role: str = "analyst") -> ToolService:
    allowed = allowed_tables(POLICY, role, CATALOG)
    return ToolService(c, POLICY, role, allowed)  # type: ignore[arg-type]


async def test_run_query_allow_executes_rewritten_sql() -> None:
    c = FakeConnector()
    with structlog.testing.capture_logs() as logs:
        out = await svc(c).run_query("SELECT * FROM users")
    assert out["row_count"] == 1
    assert logs[0]["decision"] == "allow"
    assert logs[0]["role"] == "analyst"
    assert "SELECT" not in str(logs[0]["args"])
    sent = c.calls[0].lower()
    assert "email" not in sent
    assert "'***'" in sent
    assert sent.rstrip().endswith("limit 500")


async def test_denied_query_never_reaches_connector() -> None:
    c = FakeConnector()
    for sql in ["SELECT email FROM users", "SELECT 1; DROP TABLE orders", "SELECT * FROM pg_roles"]:
        with structlog.testing.capture_logs() as logs, pytest.raises(ToolFailure) as ei:
            await svc(c).run_query(sql)
        assert logs[0]["decision"] == "deny"
        assert logs[0]["role"] == "analyst"
        assert "email" not in str(ei.value)
    assert c.calls == []


async def test_user_limit_is_clamped_to_policy() -> None:
    c = FakeConnector()
    await svc(c).run_query("SELECT id FROM orders LIMIT 99999", limit=10_000)
    assert c.calls[0].rstrip().endswith("LIMIT 500")


async def test_invalid_input_audited() -> None:
    with structlog.testing.capture_logs() as logs, pytest.raises(ToolFailure):
        await svc(FakeConnector()).run_query("")
    assert logs[0]["decision"] == "deny"


async def test_role_without_tool_is_denied_and_audited() -> None:
    c = FakeConnector()
    with structlog.testing.capture_logs() as logs, pytest.raises(ToolFailure):
        await svc(c, role="approver").run_query("SELECT 1")
    assert logs[0]["decision"] == "deny"
    assert logs[0]["role"] == "approver"
    assert c.calls == []


async def test_unknown_role_is_denied_everything() -> None:
    s = svc(FakeConnector(), role="nobody")
    for call in (s.list_tables(), s.describe_table("orders"), s.run_query("SELECT 1")):
        with pytest.raises(ToolFailure):
            await call


async def test_connector_error_is_safe_for_client_detailed_in_audit() -> None:
    err = ConnectorError("Database error.", "secret-host:5432 refused")
    with structlog.testing.capture_logs() as logs, pytest.raises(ToolFailure) as ei:
        await svc(FakeConnector(err)).run_query("SELECT id FROM orders")
    assert "secret-host" not in str(ei.value)
    assert logs[0]["decision"] == "error"
    assert "secret-host" in logs[0]["reason"]


async def test_unexpected_exception_is_audited_and_not_leaked() -> None:
    boom = RuntimeError("password=hunter2")
    with structlog.testing.capture_logs() as logs, pytest.raises(ToolFailure) as ei:
        await svc(FakeConnector(boom)).run_query("SELECT id FROM orders")
    assert "hunter2" not in str(ei.value)
    assert logs[0]["decision"] == "error"
    assert "hunter2" not in str(logs[0])


async def test_list_tables_shows_only_allowed() -> None:
    names = {t["table"] for t in (await svc(FakeConnector()).list_tables())["tables"]}
    assert names == {"orders", "customers", "users"}
    # operator has no `users` rule in the example policy
    names = {t["table"] for t in (await svc(FakeConnector(), "operator").list_tables())["tables"]}
    assert names == {"orders", "customers"}


async def test_describe_hides_denied_and_flags_masked() -> None:
    out: dict[str, Any] = await svc(FakeConnector()).describe_table("users")
    cols = {c["column"]: c["masked"] for c in out["columns"]}
    assert cols == {"id": False, "phone": True}


async def test_describe_unknown_and_unpermitted_look_the_same() -> None:
    s = svc(FakeConnector(), "operator")
    for table in ("nope", "users"):
        with structlog.testing.capture_logs() as logs, pytest.raises(ToolFailure) as ei:
            await s.describe_table(table)
        assert str(ei.value) == "Unknown table."
        assert logs[0]["decision"] == "deny"
    with pytest.raises(ToolFailure):
        await s.describe_table("orders; drop table x")
