"""Write connector against the real demo DB, using a throwaway orders row."""

import os
from collections.abc import AsyncIterator

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from mcp_gateway.connectors.postgres import ConnectorError
from mcp_gateway.connectors.postgres_write import PostgresWriteConnector

pytestmark = pytest.mark.integration

RW = os.environ.get(
    "TARGET_DB_RW_URL", "postgresql+asyncpg://gateway_rw:change-me-rw@localhost:5432/demo"
)
ADMIN = os.environ.get(
    "TARGET_DB_ADMIN_URL", "postgresql+asyncpg://postgres:postgres-dev-only@localhost:5432/demo"
)
ROW = 9001
COMMON = {"schema": "public", "table": "orders", "pk_col": "id", "pk_type": "integer"}
TYPES = {"status": "text", "notes": "text", "total_cents": "integer"}


@pytest.fixture
async def admin() -> AsyncIterator[AsyncEngine]:
    engine = create_async_engine(ADMIN)
    async with engine.begin() as conn:
        await conn.execute(text("DELETE FROM orders WHERE id = :i"), {"i": ROW})
        await conn.execute(
            text(
                "INSERT INTO orders (id, customer_id, total_cents, status) "
                "VALUES (:i, 1, 100, 'new')"
            ),
            {"i": ROW},
        )
    yield engine
    async with engine.begin() as conn:
        await conn.execute(text("DELETE FROM orders WHERE id = :i"), {"i": ROW})
    await engine.dispose()


@pytest.fixture
async def writer() -> AsyncIterator[PostgresWriteConnector]:
    w = PostgresWriteConnector.from_url(RW, statement_timeout_ms=5000)
    yield w
    await w.close()


async def status_of(admin: AsyncEngine, row: int = ROW) -> str | None:
    async with admin.connect() as conn:
        r = (
            await conn.execute(text("SELECT status FROM orders WHERE id = :i"), {"i": row})
        ).first()
    return None if r is None else str(r[0])


async def test_write_role_is_limited(writer: PostgresWriteConnector) -> None:
    await writer.verify_limited_role()


async def test_update_commits_one_row(admin: AsyncEngine, writer: PostgresWriteConnector) -> None:
    n = await writer.update_row(
        **COMMON, pk_value=ROW, changes={"status": "paid", "notes": "it's \"quoted\"; --"},
        column_types=TYPES, dry_run=False,
    )  # fmt: skip
    assert n == 1
    assert await status_of(admin) == "paid"
    async with admin.connect() as conn:
        notes = (
            await conn.execute(text("SELECT notes FROM orders WHERE id = :i"), {"i": ROW})
        ).scalar()
    assert notes == 'it\'s "quoted"; --'  # values are bound parameters, stored verbatim


async def test_dry_run_rolls_back(admin: AsyncEngine, writer: PostgresWriteConnector) -> None:
    n = await writer.update_row(
        **COMMON, pk_value=ROW, changes={"status": "dry"}, column_types=TYPES, dry_run=True
    )
    assert n == 1
    assert await status_of(admin) == "new"
    assert await writer.delete_row(**COMMON, pk_value=ROW, dry_run=True) == 1
    assert await status_of(admin) == "new"


async def test_missing_row_changes_nothing(
    admin: AsyncEngine, writer: PostgresWriteConnector
) -> None:
    with pytest.raises(ConnectorError, match="No single matching row"):
        await writer.update_row(
            **COMMON, pk_value=424242, changes={"status": "x"}, column_types=TYPES, dry_run=False
        )
    with pytest.raises(ConnectorError, match="No single matching row"):
        await writer.delete_row(**COMMON, pk_value=424242, dry_run=False)
    assert await status_of(admin) == "new"


async def test_delete_removes_exactly_one_row(
    admin: AsyncEngine, writer: PostgresWriteConnector
) -> None:
    assert await writer.delete_row(**COMMON, pk_value=ROW, dry_run=False) == 1
    assert await status_of(admin) is None
    assert await status_of(admin, 1) is not None  # other demo rows untouched


async def test_db_grants_are_the_second_layer(
    admin: AsyncEngine, writer: PostgresWriteConnector
) -> None:
    # Even if the app let it through, the DB role has UPDATE only on (status, notes).
    with pytest.raises(ConnectorError, match="Permission denied"):
        await writer.update_row(
            **COMMON, pk_value=ROW, changes={"total_cents": 1}, column_types=TYPES, dry_run=False
        )
    assert await status_of(admin) == "new"


async def test_hostile_identifiers_are_quoted_not_executed(
    admin: AsyncEngine, writer: PostgresWriteConnector
) -> None:
    evil = {**COMMON, "table": 'orders"; DROP TABLE orders; --'}
    with pytest.raises(ConnectorError):
        await writer.delete_row(**evil, pk_value=ROW, dry_run=False)
    with pytest.raises(ConnectorError):
        await writer.update_row(
            **{**COMMON, "pk_col": 'id" OR 1=1 --'}, pk_value=ROW,
            changes={"status": "x"}, column_types=TYPES, dry_run=False,
        )  # fmt: skip
    with pytest.raises(ConnectorError):
        await writer.update_row(
            **COMMON, pk_value=ROW, changes={'status" = \'x\', "notes': "y"},
            column_types={'status" = \'x\', "notes': "text"}, dry_run=False,
        )  # fmt: skip
    assert await status_of(admin) == "new"  # table intact, row untouched


async def test_unsupported_types_are_refused(writer: PostgresWriteConnector) -> None:
    with pytest.raises(ConnectorError, match="Unsupported column type"):
        await writer.update_row(
            **COMMON, pk_value=ROW, changes={"created_at": "2020-01-01"},
            column_types={"created_at": "timestamp with time zone"}, dry_run=False,
        )  # fmt: skip


async def test_privileged_or_owner_roles_are_refused_as_write_role() -> None:
    admin_writer = PostgresWriteConnector.from_url(ADMIN, statement_timeout_ms=1000)
    try:
        with pytest.raises(ConnectorError, match="too privileged"):
            await admin_writer.verify_limited_role()
    finally:
        await admin_writer.close()
