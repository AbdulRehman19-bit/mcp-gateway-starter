"""Write connector for update_record / delete_record.

Hard rules honoured here:
 - no SQL string building: statements come from SQLAlchemy Core constructs, so identifiers are
   quoted by the dialect and every value is a bound parameter;
 - identifiers are never taken on trust: the handler validates table, columns and primary key
   against the policy and catalog before they reach this module;
 - exactly one row or nothing: anything else rolls back;
 - dry_run executes then rolls back, so the effect is measured but never persisted.
Uses the limited read-write DB role (column-level UPDATE grants), never an admin role.
"""

from typing import Any

import asyncpg
import sqlalchemy as sa
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from mcp_gateway.connectors.postgres import ConnectorError, _map_error

# Column types we know how to bind safely. Anything else is refused (fail closed).
SUPPORTED_TYPES: dict[str, sa.types.TypeEngine[Any]] = {
    "text": sa.Text(),
    "character varying": sa.String(),
    "integer": sa.Integer(),
    "bigint": sa.BigInteger(),
    "smallint": sa.SmallInteger(),
    "numeric": sa.Numeric(),
    "boolean": sa.Boolean(),
}


class PostgresWriteConnector:
    def __init__(self, engine: AsyncEngine, *, statement_timeout_ms: int) -> None:
        self._engine = engine
        self._timeout_ms = statement_timeout_ms

    @classmethod
    def from_url(cls, url: str, *, statement_timeout_ms: int) -> "PostgresWriteConnector":
        return cls(
            create_async_engine(url, pool_pre_ping=True), statement_timeout_ms=statement_timeout_ms
        )

    async def close(self) -> None:
        await self._engine.dispose()

    async def verify_limited_role(self) -> None:
        """The write role may write, but must not be an admin-style role."""
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(
                    text(
                        "SELECT rolsuper, rolcreaterole, rolcreatedb, rolreplication, "
                        "rolbypassrls, "
                        # An owner can do anything to its tables regardless of grants.
                        "(SELECT count(*) FROM pg_tables WHERE tableowner = current_user) "
                        "FROM pg_roles WHERE rolname = current_user"
                    )
                )
            ).first()
        if row is None or any(row):
            raise ConnectorError("Write role is too privileged.", "privileged write role")

    @staticmethod
    def _table(
        schema: str, table: str, pk_col: str, pk_type: str, cols: dict[str, str]
    ) -> sa.TableClause:
        def typed(name: str, sql_type: str) -> sa.ColumnClause[Any]:
            if sql_type not in SUPPORTED_TYPES:
                raise ConnectorError("Unsupported column type.", f"{name}: {sql_type}")
            return sa.column(name, SUPPORTED_TYPES[sql_type])

        columns = [typed(pk_col, pk_type), *[typed(c, t) for c, t in cols.items()]]
        return sa.table(table, *columns, schema=schema)

    async def _execute(self, stmt: Any, *, dry_run: bool) -> int:
        try:
            async with self._engine.connect() as conn:
                trans = await conn.begin()
                try:
                    await conn.execute(text("SET TRANSACTION READ WRITE"))
                    await conn.execute(
                        text(
                            "SELECT set_config('statement_timeout', :ms, true), "
                            "set_config('lock_timeout', :lock, true), "
                            "set_config('search_path', 'public', true)"
                        ),
                        # A short lock_timeout keeps repeated dry runs from queueing on a hot row.
                        {"ms": str(int(self._timeout_ms)), "lock": "2000"},
                    )
                    affected = int((await conn.execute(stmt)).rowcount)
                except BaseException:
                    await trans.rollback()
                    raise
                if affected != 1 or dry_run:
                    await trans.rollback()  # wrong row count, or a dry run: persist nothing
                else:
                    await trans.commit()
        except (SQLAlchemyError, asyncpg.PostgresError) as exc:
            raise _map_error(exc) from exc
        except OSError as exc:
            raise ConnectorError("Database unavailable.", type(exc).__name__) from exc
        if affected != 1:
            raise ConnectorError("No single matching row.", f"rowcount={affected}")
        return affected

    async def update_row(
        self,
        *,
        schema: str,
        table: str,
        pk_col: str,
        pk_type: str,
        pk_value: Any,
        changes: dict[str, Any],
        column_types: dict[str, str],
        dry_run: bool,
    ) -> int:
        t = self._table(schema, table, pk_col, pk_type, {c: column_types[c] for c in changes})
        stmt = sa.update(t).where(t.c[pk_col] == pk_value).values(**changes)
        return await self._execute(stmt, dry_run=dry_run)

    async def delete_row(
        self,
        *,
        schema: str,
        table: str,
        pk_col: str,
        pk_type: str,
        pk_value: Any,
        dry_run: bool,
    ) -> int:
        t = self._table(schema, table, pk_col, pk_type, {})
        stmt = sa.delete(t).where(t.c[pk_col] == pk_value)
        return await self._execute(stmt, dry_run=dry_run)
