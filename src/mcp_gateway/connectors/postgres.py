"""Read-only Postgres connector.

Defense in depth (CLAUDE.md rule 3): the URL must point at a SELECT-only role, the session
defaults to read-only, every call opens an explicit READ ONLY transaction, and a
statement_timeout bounds runtime. Application checks are never the only layer.
"""

import base64
import datetime as dt
import decimal
import uuid
from dataclasses import dataclass
from typing import Any

import asyncpg
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

ALLOWED_SCHEMAS = frozenset({"public"})
MAX_RESPONSE_CHARS = 1_000_000


class ConnectorError(Exception):
    """Failure with a short, client-safe message. `detail` is for the audit log only."""

    def __init__(self, safe_message: str, detail: str = "") -> None:
        super().__init__(safe_message)
        self.safe_message = safe_message
        self.detail = detail


@dataclass(frozen=True)
class QueryResult:
    columns: list[str]
    rows: list[list[Any]]
    truncated: bool


def _json_safe(value: Any) -> Any:
    """Make a DB value JSON-serialisable without losing meaning."""
    if value is None or isinstance(value, bool | int | float | str):
        return value
    if isinstance(value, decimal.Decimal):
        return str(value)
    if isinstance(value, dt.datetime | dt.date | dt.time):
        return value.isoformat()
    if isinstance(value, dt.timedelta):
        return value.total_seconds()
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, bytes | bytearray | memoryview):
        return base64.b64encode(bytes(value)).decode("ascii")
    if isinstance(value, list | tuple):
        return [_json_safe(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    return str(value)


def _row_size(row: Any) -> int:
    # Row.__str__ truncates long values, so measure the values themselves.
    return sum(len(str(v)) for v in row)


def _map_error(exc: Exception) -> ConnectorError:
    orig = getattr(exc, "orig", None)
    sqlstate = (
        getattr(exc, "sqlstate", None)
        or getattr(orig, "sqlstate", None)
        or getattr(getattr(orig, "__cause__", None), "sqlstate", None)
    )
    # Never str(exc): SQLAlchemy embeds the full SQL and parameters, asyncpg may embed values.
    detail = f"{type(exc).__name__} sqlstate={sqlstate}"
    if sqlstate == "57014":
        return ConnectorError("Query timed out.", detail)
    if sqlstate == "42501":
        return ConnectorError("Permission denied.", detail)
    if sqlstate == "25006":
        return ConnectorError("Read-only: writes are not allowed.", detail)
    if sqlstate and sqlstate.startswith("42"):
        return ConnectorError("Invalid query.", detail)
    return ConnectorError("Database error.", detail)


class PostgresReadConnector:
    def __init__(self, engine: AsyncEngine, *, max_rows: int, statement_timeout_ms: int) -> None:
        self._engine = engine
        self._max_rows = max_rows
        self._timeout_ms = statement_timeout_ms

    @classmethod
    def from_url(
        cls, url: str, *, max_rows: int, statement_timeout_ms: int
    ) -> "PostgresReadConnector":
        engine = create_async_engine(
            url,
            pool_pre_ping=True,
            connect_args={"server_settings": {"default_transaction_read_only": "on"}},
        )
        return cls(engine, max_rows=max_rows, statement_timeout_ms=statement_timeout_ms)

    async def close(self) -> None:
        await self._engine.dispose()

    async def _run(
        self, sql: str, params: dict[str, Any], *, limit: int | None = None, raw: bool = False
    ) -> QueryResult:
        cap = min(limit, self._max_rows) if limit is not None else self._max_rows
        try:
            async with self._engine.connect() as conn, conn.begin():
                await conn.execute(text("SET TRANSACTION READ ONLY"))
                # SET does not take bind params; set_config does. Value is an int we own.
                await conn.execute(
                    text("SELECT set_config('statement_timeout', :ms, true)"),
                    {"ms": str(int(self._timeout_ms))},
                )
                # text() treats ":name" as a bind; escape colons for caller-supplied SQL.
                stmt = text(sql.replace(":", "\\:")) if raw else text(sql)
                result = await conn.stream(stmt, params)
                try:
                    columns = list(result.keys())
                    fetched: list[Any] = []
                    size = 0
                    while len(fetched) < cap + 1 and size <= MAX_RESPONSE_CHARS:
                        batch = await result.fetchmany(min(100, cap + 1 - len(fetched)))
                        if not batch:
                            break
                        fetched.extend(batch)
                        size += sum(_row_size(r) for r in batch)
                finally:
                    await result.close()
        except (SQLAlchemyError, asyncpg.PostgresError) as exc:
            raise _map_error(exc) from exc
        except OSError as exc:
            raise ConnectorError("Database unavailable.", type(exc).__name__) from exc
        truncated = len(fetched) > cap or size > MAX_RESPONSE_CHARS
        rows = [[_json_safe(v) for v in row] for row in fetched[:cap]]
        if size > MAX_RESPONSE_CHARS:  # bound response size, not just row count
            while rows and sum(_row_size(r) for r in rows) > MAX_RESPONSE_CHARS:
                rows.pop()
        return QueryResult(columns=columns, rows=rows, truncated=truncated)

    async def verify_read_only_role(self) -> None:
        """Refuse a privileged role: the DB layer of defense must be real, not assumed."""
        res = await self._run(
            "SELECT r.rolsuper, r.rolcreaterole, r.rolcreatedb, r.rolreplication, r.rolbypassrls, "
            "((SELECT count(*) FROM information_schema.role_table_grants g "
            "  WHERE g.grantee = current_user "
            "  AND g.privilege_type IN ('INSERT','UPDATE','DELETE','TRUNCATE')) "
            " + (SELECT count(*) FROM information_schema.column_privileges c "
            "  WHERE c.grantee = current_user "
            "  AND c.privilege_type IN ('INSERT','UPDATE'))) "
            "FROM pg_roles r WHERE r.rolname = current_user",
            {},
        )
        if not res.rows or any(res.rows[0]):
            raise ConnectorError("Database role is not read-only.", "privileged role")

    async def run_query(self, sql: str, *, limit: int | None = None) -> QueryResult:
        return await self._run(sql, {}, limit=limit, raw=True)

    async def list_tables(self) -> list[dict[str, str]]:
        # information_schema only shows objects the role has privileges on.
        res = await self._run(
            "SELECT table_schema, table_name, table_type FROM information_schema.tables "
            "WHERE table_schema = ANY(:schemas) ORDER BY table_schema, table_name",
            {"schemas": sorted(ALLOWED_SCHEMAS)},
        )
        return [{"schema": r[0], "table": r[1], "type": r[2]} for r in res.rows]

    async def describe_table(self, schema: str, table: str) -> list[dict[str, Any]]:
        if schema not in ALLOWED_SCHEMAS:
            raise ConnectorError("Unknown table.", f"schema not allowed: {schema!r}")
        res = await self._run(
            "SELECT column_name, data_type, is_nullable FROM information_schema.columns "
            "WHERE table_schema = :schema AND table_name = :table ORDER BY ordinal_position",
            {"schema": schema, "table": table},
        )
        if not res.rows:
            raise ConnectorError("Unknown table.", f"no visible columns for {schema}.{table}")
        return [{"column": r[0], "type": r[1], "nullable": r[2] == "YES"} for r in res.rows]


__all__ = ["ConnectorError", "PostgresReadConnector", "QueryResult"]
