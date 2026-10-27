"""Tool handlers. Pipeline: role -> policy -> validate -> guard/rewrite -> connector -> audit.

Authentication arrives in Phase 3; until then the role is server-side config (never a tool
argument). Every outcome (allow, deny, error) writes an audit record. Errors returned to the
client are short and safe; details go to the audit log only.
"""

import time
from typing import Any

from pydantic import BaseModel, ValidationError

from mcp_gateway.audit.logging import audit, new_request_id
from mcp_gateway.connectors.postgres import ConnectorError, PostgresReadConnector
from mcp_gateway.policy import Policy
from mcp_gateway.policy.evaluator import AllowedTables, tool_allowed
from mcp_gateway.sqlguard import GuardError
from mcp_gateway.sqlguard.analyze import rewrite_for_policy
from mcp_gateway.tools.schemas import DescribeTableInput, ListTablesInput, RunQueryInput


class ToolFailure(Exception):
    """Safe, client-visible failure."""


class ToolService:
    def __init__(
        self,
        connector: PostgresReadConnector,
        policy: Policy,
        role: str,
        allowed: AllowedTables,
    ) -> None:
        self._connector = connector
        self._policy = policy
        self._role = role
        self._allowed = allowed

    def _audit(
        self,
        rid: str,
        tool: str,
        decision: str,
        args: dict[str, Any],
        started: float,
        reason: str = "",
    ) -> None:
        audit(
            request_id=rid,
            tool=tool,
            decision=decision,
            args=args,
            started=started,
            reason=reason,
            role=self._role,
        )

    def _authorize(self, tool: str, rid: str, args: dict[str, Any], started: float) -> None:
        if not tool_allowed(self._policy, self._role, tool):
            self._audit(rid, tool, "deny", args, started, "tool not allowed for role")
            raise ToolFailure("Not permitted.")

    def _parse[M: BaseModel](
        self, model: type[M], tool: str, raw: dict[str, Any], rid: str, started: float
    ) -> M:
        try:
            return model.model_validate(raw)
        except ValidationError as exc:
            self._audit(rid, tool, "deny", raw, started, f"invalid_input: {exc.error_count()}")
            raise ToolFailure("Invalid input.") from exc

    async def list_tables(self) -> dict[str, Any]:
        rid, started = new_request_id(), time.monotonic()
        self._authorize("list_tables", rid, {}, started)
        self._parse(ListTablesInput, "list_tables", {}, rid, started)
        tables = [{"schema": s, "table": t} for (s, t) in sorted(self._allowed)]
        self._audit(rid, "list_tables", "allow", {}, started)
        return {"tables": tables}

    async def describe_table(self, table: str, schema: str = "public") -> dict[str, Any]:
        rid, started = new_request_id(), time.monotonic()
        raw = {"table": table, "schema_name": schema}
        self._authorize("describe_table", rid, raw, started)
        inp = self._parse(DescribeTableInput, "describe_table", raw, rid, started)
        cols = self._allowed.get((inp.schema_name, inp.table))
        if cols is None:
            # Same answer for "missing" and "not permitted": existence is not disclosed.
            self._audit(rid, "describe_table", "deny", raw, started, "table not allowed")
            raise ToolFailure("Unknown table.")
        self._audit(rid, "describe_table", "allow", raw, started)
        return {
            "schema": inp.schema_name,
            "table": inp.table,
            "columns": [{"column": c, "type": i.type, "masked": i.masked} for c, i in cols.items()],
        }

    async def run_query(self, sql: str, limit: int | None = None) -> dict[str, Any]:
        rid, started = new_request_id(), time.monotonic()
        raw = {"sql": sql, "limit": limit}
        self._authorize("run_query", rid, raw, started)
        inp = self._parse(RunQueryInput, "run_query", raw, rid, started)
        max_rows = self._policy.defaults.max_rows
        effective = min(inp.limit or max_rows, max_rows)
        try:
            safe_sql = rewrite_for_policy(inp.sql, self._allowed, max_rows=effective)
        except GuardError as exc:
            self._audit(rid, "run_query", "deny", raw, started, exc.reason)
            raise ToolFailure("Query not permitted.") from exc
        except Exception as exc:  # parser/analyzer bug: fail closed, never run the raw SQL
            self._audit(rid, "run_query", "error", raw, started, type(exc).__name__)
            raise ToolFailure("Internal error.") from exc
        try:
            res = await self._connector.run_query(safe_sql, limit=effective)
        except ConnectorError as exc:
            self._audit(rid, "run_query", "error", raw, started, exc.detail)
            raise ToolFailure(exc.safe_message) from exc
        except Exception as exc:
            self._audit(rid, "run_query", "error", raw, started, type(exc).__name__)
            raise ToolFailure("Internal error.") from exc
        self._audit(rid, "run_query", "allow", raw, started)
        return {
            "columns": res.columns,
            "rows": res.rows,
            "row_count": len(res.rows),
            "truncated": res.truncated,
        }
