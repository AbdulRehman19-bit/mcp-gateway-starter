from typing import Any

import pytest
import structlog

from mcp_gateway.connectors.postgres import ConnectorError, QueryResult
from mcp_gateway.tools.handlers import ToolFailure, ToolService


class FakeConnector:
    def __init__(self, error: ConnectorError | None = None) -> None:
        self.error = error
        self.calls: list[str] = []

    async def run_query(self, sql: str, *, limit: int | None = None) -> QueryResult:
        self.calls.append(sql)
        if self.error:
            raise self.error
        return QueryResult(columns=["a"], rows=[[1]], truncated=False)

    async def list_tables(self) -> list[dict[str, str]]:
        if self.error:
            raise self.error
        return [{"schema": "public", "table": "orders", "type": "BASE TABLE"}]

    async def describe_table(self, schema: str, table: str) -> list[dict[str, Any]]:
        if self.error:
            raise self.error
        return [{"column": "id", "type": "integer", "nullable": False}]


def svc(c: FakeConnector) -> ToolService:
    return ToolService(c)  # type: ignore[arg-type]


async def test_run_query_allow() -> None:
    with structlog.testing.capture_logs() as logs:
        out = await svc(FakeConnector()).run_query("SELECT 1")
    assert out["row_count"] == 1
    assert logs[0]["decision"] == "allow"
    assert "SELECT" not in str(logs[0]["args"])


async def test_run_query_denied_never_reaches_connector() -> None:
    c = FakeConnector()
    with structlog.testing.capture_logs() as logs, pytest.raises(ToolFailure):
        await svc(c).run_query("SELECT 1; DROP TABLE orders")
    assert c.calls == []
    assert logs[0]["decision"] == "deny"


async def test_run_query_invalid_input_audited() -> None:
    with structlog.testing.capture_logs() as logs, pytest.raises(ToolFailure):
        await svc(FakeConnector()).run_query("")
    assert logs[0]["decision"] == "deny"


async def test_connector_error_is_safe_for_client_detailed_in_audit() -> None:
    err = ConnectorError("Database error.", "secret-host:5432 refused")
    with structlog.testing.capture_logs() as logs, pytest.raises(ToolFailure) as ei:
        await svc(FakeConnector(err)).run_query("SELECT 1")
    assert "secret-host" not in str(ei.value)
    assert logs[0]["decision"] == "error"
    assert "secret-host" in logs[0]["reason"]


async def test_list_tables_allow_and_error() -> None:
    assert (await svc(FakeConnector()).list_tables())["tables"]
    with structlog.testing.capture_logs() as logs, pytest.raises(ToolFailure):
        await svc(FakeConnector(ConnectorError("Database error."))).list_tables()
    assert logs[0]["decision"] == "error"


async def test_describe_table_allow_deny_error() -> None:
    assert (await svc(FakeConnector()).describe_table("orders"))["columns"]
    with structlog.testing.capture_logs() as logs, pytest.raises(ToolFailure):
        await svc(FakeConnector()).describe_table("orders; drop table x")
    assert logs[0]["decision"] == "deny"
    with pytest.raises(ToolFailure):
        await svc(FakeConnector(ConnectorError("Unknown table."))).describe_table("nope")


async def test_unexpected_exception_is_audited_and_not_leaked() -> None:
    c = FakeConnector()

    async def boom(sql: str, *, limit: int | None = None) -> QueryResult:
        raise RuntimeError("password=hunter2")

    c.run_query = boom  # type: ignore[method-assign]
    with structlog.testing.capture_logs() as logs, pytest.raises(ToolFailure) as ei:
        await svc(c).run_query("SELECT 1")
    assert "hunter2" not in str(ei.value)
    assert logs[0]["decision"] == "error"
    assert "hunter2" not in str(logs[0])
