import json
import os
import sys

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

pytestmark = pytest.mark.integration

RO_URL = os.environ.get(
    "TARGET_DB_RO_URL", "postgresql+asyncpg://gateway_ro:change-me-ro@localhost:5432/demo"
)


async def test_three_tools_over_stdio() -> None:
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "mcp_gateway.server", "--transport", "stdio"],
        env={**os.environ, "TARGET_DB_RO_URL": RO_URL},
    )
    async with stdio_client(params) as (r, w), ClientSession(r, w) as s:
        await s.initialize()
        names = {t.name for t in (await s.list_tools()).tools}
        assert {"list_tables", "describe_table", "run_query"} <= names

        out = await s.call_tool("list_tables", {})
        assert not out.isError
        assert "orders" in out.content[0].text  # type: ignore[union-attr]

        out = await s.call_tool("describe_table", {"table": "users"})
        body = json.loads(out.content[0].text)  # type: ignore[union-attr]
        assert {c["column"] for c in body["columns"]} == {"id", "created_at"}

        out = await s.call_tool("run_query", {"sql": "SELECT count(*) AS n FROM orders"})
        assert json.loads(out.content[0].text)["rows"] == [[3]]  # type: ignore[union-attr]

        out = await s.call_tool("run_query", {"sql": "SELECT 1; DROP TABLE orders"})
        assert out.isError
