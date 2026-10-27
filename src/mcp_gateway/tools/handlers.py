"""Tool handlers. Pipeline: identity -> policy -> validate -> guard/rewrite -> connector -> audit.

Identity comes from `identity_source`: the validated token over HTTP, or the fixed local user
over stdio. It is never read from tool arguments. No identity means denied. Every outcome
(allow, deny, error) writes an audit record. Errors returned to the client are short and
safe; details go to the audit log only.
"""

import time
from collections.abc import Callable
from typing import Any

from pydantic import BaseModel, ValidationError

from mcp_gateway.audit.logging import audit, new_request_id
from mcp_gateway.auth.roles import Identity
from mcp_gateway.connectors.postgres import ConnectorError, PostgresReadConnector
from mcp_gateway.policy import Policy
from mcp_gateway.policy.evaluator import AllowedTables, tool_allowed
from mcp_gateway.sqlguard import GuardError
from mcp_gateway.sqlguard.analyze import rewrite_for_policy
from mcp_gateway.tools.schemas import DescribeTableInput, ListTablesInput, RunQueryInput

IdentitySource = Callable[[], Identity | None]


class ToolFailure(Exception):
    """Safe, client-visible failure."""


class ToolService:
    def __init__(
        self,
        connector: PostgresReadConnector,
        policy: Policy,
        allowed_by_role: dict[str, AllowedTables],
        identity_source: IdentitySource,
    ) -> None:
        self._connector = connector
        self._policy = policy
        self._allowed_by_role = allowed_by_role
        self._identity_source = identity_source

    def _audit(
        self,
        rid: str,
        tool: str,
        decision: str,
        args: dict[str, Any],
        started: float,
        ident: Identity | None,
        reason: str = "",
    ) -> None:
        audit(
            request_id=rid,
            tool=tool,
            decision=decision,
            args=args,
            started=started,
            reason=reason,
            role=ident.role if ident else "",
            subject=ident.subject if ident else "",
        )

    def _authorize(
        self, tool: str, rid: str, args: dict[str, Any], started: float
    ) -> tuple[Identity, AllowedTables]:
        ident = self._identity_source()
        if ident is None:
            self._audit(rid, tool, "deny", args, started, None, "no identity")
            raise ToolFailure("Not permitted.")
        if not tool_allowed(self._policy, ident.role, tool):
            self._audit(rid, tool, "deny", args, started, ident, "tool not allowed for role")
            raise ToolFailure("Not permitted.")
        # Unknown role gets an empty map: nothing is readable.
        return ident, self._allowed_by_role.get(ident.role, {})

    def ping(self, message: str) -> str:
        """Health check: any authenticated identity, no policy tier, but still audited."""
        rid, started = new_request_id(), time.monotonic()
        ident = self._identity_source()
        if ident is None:
            self._audit(rid, "ping", "deny", {}, started, None, "no identity")
            raise ToolFailure("Not permitted.")
        self._audit(rid, "ping", "allow", {}, started, ident)
        return message

    def _parse[M: BaseModel](
        self,
        model: type[M],
        tool: str,
        raw: dict[str, Any],
        rid: str,
        started: float,
        ident: Identity,
    ) -> M:
        try:
            return model.model_validate(raw)
        except ValidationError as exc:
            reason = f"invalid_input: {exc.error_count()}"
            self._audit(rid, tool, "deny", raw, started, ident, reason)
            raise ToolFailure("Invalid input.") from exc

    async def list_tables(self) -> dict[str, Any]:
        rid, started = new_request_id(), time.monotonic()
        ident, allowed = self._authorize("list_tables", rid, {}, started)
        self._parse(ListTablesInput, "list_tables", {}, rid, started, ident)
        tables = [{"schema": s, "table": t} for (s, t) in sorted(allowed)]
        self._audit(rid, "list_tables", "allow", {}, started, ident)
        return {"tables": tables}

    async def describe_table(self, table: str, schema: str = "public") -> dict[str, Any]:
        rid, started = new_request_id(), time.monotonic()
        raw = {"table": table, "schema_name": schema}
        ident, allowed = self._authorize("describe_table", rid, raw, started)
        inp = self._parse(DescribeTableInput, "describe_table", raw, rid, started, ident)
        cols = allowed.get((inp.schema_name, inp.table))
        if cols is None:
            # Same answer for "missing" and "not permitted": existence is not disclosed.
            self._audit(rid, "describe_table", "deny", raw, started, ident, "table not allowed")
            raise ToolFailure("Unknown table.")
        self._audit(rid, "describe_table", "allow", raw, started, ident)
        return {
            "schema": inp.schema_name,
            "table": inp.table,
            "columns": [{"column": c, "type": i.type, "masked": i.masked} for c, i in cols.items()],
        }

    async def run_query(self, sql: str, limit: int | None = None) -> dict[str, Any]:
        rid, started = new_request_id(), time.monotonic()
        raw = {"sql": sql, "limit": limit}
        ident, allowed = self._authorize("run_query", rid, raw, started)
        inp = self._parse(RunQueryInput, "run_query", raw, rid, started, ident)
        max_rows = self._policy.defaults.max_rows
        effective = min(inp.limit or max_rows, max_rows)
        try:
            safe_sql = rewrite_for_policy(inp.sql, allowed, max_rows=effective)
        except GuardError as exc:
            self._audit(rid, "run_query", "deny", raw, started, ident, exc.reason)
            raise ToolFailure("Query not permitted.") from exc
        except Exception as exc:  # parser/analyzer bug: fail closed, never run the raw SQL
            self._audit(rid, "run_query", "error", raw, started, ident, type(exc).__name__)
            raise ToolFailure("Internal error.") from exc
        try:
            res = await self._connector.run_query(safe_sql, limit=effective)
        except ConnectorError as exc:
            self._audit(rid, "run_query", "error", raw, started, ident, exc.detail)
            raise ToolFailure(exc.safe_message) from exc
        except Exception as exc:
            self._audit(rid, "run_query", "error", raw, started, ident, type(exc).__name__)
            raise ToolFailure("Internal error.") from exc
        self._audit(rid, "run_query", "allow", raw, started, ident)
        return {
            "columns": res.columns,
            "rows": res.rows,
            "row_count": len(res.rows),
            "truncated": res.truncated,
        }
