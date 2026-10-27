"""Tool handlers. Phase 1 pipeline: validate -> guard -> connector -> audit.

Auth, policy and approval stages arrive in later phases; they slot in before the connector.
Every outcome (allow, deny, error) writes an audit record. Errors returned to the client are
short and safe; details go to the audit log only.
"""

import time
from typing import Any

from pydantic import BaseModel, ValidationError

from mcp_gateway.audit.logging import audit, new_request_id
from mcp_gateway.connectors.postgres import ConnectorError, PostgresReadConnector
from mcp_gateway.sqlguard import GuardError, ensure_single_select
from mcp_gateway.tools.schemas import DescribeTableInput, ListTablesInput, RunQueryInput


class ToolFailure(Exception):
    """Safe, client-visible failure."""


class ToolService:
    def __init__(self, connector: PostgresReadConnector) -> None:
        self._connector = connector

    def _parse[M: BaseModel](
        self, model: type[M], tool: str, raw: dict[str, Any], rid: str, started: float
    ) -> M:
        try:
            return model.model_validate(raw)
        except ValidationError as exc:
            audit(
                request_id=rid, tool=tool, decision="deny", args=raw, started=started,
                reason=f"invalid_input: {exc.error_count()} error(s)",
            )  # fmt: skip
            raise ToolFailure("Invalid input.") from exc

    async def list_tables(self) -> dict[str, Any]:
        rid, started = new_request_id(), time.monotonic()
        self._parse(ListTablesInput, "list_tables", {}, rid, started)
        try:
            tables = await self._connector.list_tables()
        except ConnectorError as exc:
            audit(request_id=rid, tool="list_tables", decision="error", args={},
                  started=started, reason=exc.detail)  # fmt: skip
            raise ToolFailure(exc.safe_message) from exc
        except Exception as exc:
            audit(request_id=rid, tool="list_tables", decision="error", args={},
                  started=started, reason=type(exc).__name__)  # fmt: skip
            raise ToolFailure("Internal error.") from exc
        audit(request_id=rid, tool="list_tables", decision="allow", args={}, started=started)
        return {"tables": tables}

    async def describe_table(self, table: str, schema: str = "public") -> dict[str, Any]:
        rid, started = new_request_id(), time.monotonic()
        raw = {"table": table, "schema_name": schema}
        inp = self._parse(DescribeTableInput, "describe_table", raw, rid, started)
        try:
            cols = await self._connector.describe_table(inp.schema_name, inp.table)
        except ConnectorError as exc:
            audit(request_id=rid, tool="describe_table", decision="error", args=raw,
                  started=started, reason=exc.detail)  # fmt: skip
            raise ToolFailure(exc.safe_message) from exc
        except Exception as exc:
            audit(request_id=rid, tool="describe_table", decision="error", args=raw,
                  started=started, reason=type(exc).__name__)  # fmt: skip
            raise ToolFailure("Internal error.") from exc
        audit(request_id=rid, tool="describe_table", decision="allow", args=raw, started=started)
        return {"schema": inp.schema_name, "table": inp.table, "columns": cols}

    async def run_query(self, sql: str, limit: int | None = None) -> dict[str, Any]:
        rid, started = new_request_id(), time.monotonic()
        raw = {"sql": sql, "limit": limit}
        inp = self._parse(RunQueryInput, "run_query", raw, rid, started)
        try:
            ensure_single_select(inp.sql)
        except GuardError as exc:
            audit(request_id=rid, tool="run_query", decision="deny", args=raw,
                  started=started, reason=exc.reason)  # fmt: skip
            raise ToolFailure("Only a single read-only SELECT is allowed.") from exc
        try:
            res = await self._connector.run_query(inp.sql, limit=inp.limit)
        except ConnectorError as exc:
            audit(request_id=rid, tool="run_query", decision="error", args=raw,
                  started=started, reason=exc.detail)  # fmt: skip
            raise ToolFailure(exc.safe_message) from exc
        except Exception as exc:
            audit(request_id=rid, tool="run_query", decision="error", args=raw,
                  started=started, reason=type(exc).__name__)  # fmt: skip
            raise ToolFailure("Internal error.") from exc
        audit(request_id=rid, tool="run_query", decision="allow", args=raw, started=started)
        return {
            "columns": res.columns,
            "rows": res.rows,
            "row_count": len(res.rows),
            "truncated": res.truncated,
        }
