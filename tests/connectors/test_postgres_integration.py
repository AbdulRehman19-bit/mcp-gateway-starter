import os
from collections.abc import AsyncIterator

import pytest

from mcp_gateway.connectors.postgres import ConnectorError, PostgresReadConnector

pytestmark = pytest.mark.integration

RO_URL = os.environ.get(
    "TARGET_DB_RO_URL", "postgresql+asyncpg://gateway_ro:change-me-ro@localhost:5432/demo"
)


@pytest.fixture
async def conn() -> AsyncIterator[PostgresReadConnector]:
    c = PostgresReadConnector.from_url(RO_URL, max_rows=500, statement_timeout_ms=1000)
    yield c
    await c.close()


async def test_list_tables(conn: PostgresReadConnector) -> None:
    names = {t["table"] for t in await conn.list_tables()}
    assert names == {"customers", "orders", "users"}


async def test_describe_users_hides_ungranted_columns(conn: PostgresReadConnector) -> None:
    cols = {c["column"] for c in await conn.describe_table("public", "users")}
    assert cols == {"id", "created_at"}


async def test_describe_unknown_and_bad_schema(conn: PostgresReadConnector) -> None:
    with pytest.raises(ConnectorError):
        await conn.describe_table("public", "nope")
    with pytest.raises(ConnectorError):
        await conn.describe_table("pg_catalog", "pg_class")


async def test_select_rows(conn: PostgresReadConnector) -> None:
    res = await conn.run_query("SELECT id, status FROM orders ORDER BY id")
    assert res.columns == ["id", "status"]
    assert len(res.rows) == 3
    assert not res.truncated


async def test_row_cap_truncates(conn: PostgresReadConnector) -> None:
    res = await conn.run_query("SELECT g FROM generate_series(1, 2000) g")
    assert len(res.rows) == 500
    assert res.truncated
    res = await conn.run_query("SELECT g FROM generate_series(1, 2000) g", limit=10)
    assert len(res.rows) == 10
    assert res.truncated


async def test_statement_timeout(conn: PostgresReadConnector) -> None:
    with pytest.raises(ConnectorError) as ei:
        await conn.run_query("SELECT pg_sleep(10)")
    assert ei.value.safe_message == "Query timed out."


@pytest.mark.parametrize(
    "sql",
    [
        "INSERT INTO orders (customer_id, total_cents) VALUES (1, 1)",
        "UPDATE orders SET status = 'x'",
        "DELETE FROM orders",
        "DROP TABLE orders",
        "SELECT email FROM users",
        "SELECT password_hash FROM users",
    ],
)
async def test_db_layer_blocks_even_without_app_guard(
    conn: PostgresReadConnector, sql: str
) -> None:
    with pytest.raises(ConnectorError) as ei:
        await conn.run_query(sql)
    assert "password" not in ei.value.safe_message.lower()


async def test_error_messages_are_safe(conn: PostgresReadConnector) -> None:
    with pytest.raises(ConnectorError) as ei:
        await conn.run_query("SELECT * FROM does_not_exist")
    assert "does_not_exist" not in ei.value.safe_message


async def test_colon_in_user_sql_is_not_a_bind(conn: PostgresReadConnector) -> None:
    res = await conn.run_query("SELECT ':foo' AS s, 1::int AS n")
    assert res.rows == [[":foo", 1]]


async def test_error_detail_has_no_sql_or_values(conn: PostgresReadConnector) -> None:
    with pytest.raises(ConnectorError) as ei:
        await conn.run_query("SELECT 'top-secret-value'::int")
    assert "top-secret-value" not in ei.value.detail
    assert "SELECT" not in ei.value.detail


async def test_response_size_is_bounded(conn: PostgresReadConnector) -> None:
    res = await conn.run_query("SELECT repeat('x', 400000) FROM generate_series(1, 100)")
    assert res.truncated
    assert len(res.rows) < 100


async def test_ro_role_passes_startup_check(conn: PostgresReadConnector) -> None:
    await conn.verify_read_only_role()


async def test_privileged_role_fails_startup_check() -> None:
    rw_url = RO_URL.replace("gateway_ro:change-me-ro", "gateway_rw:change-me-rw")
    c = PostgresReadConnector.from_url(rw_url, max_rows=10, statement_timeout_ms=1000)
    try:
        with pytest.raises(ConnectorError):
            await c.verify_read_only_role()
    finally:
        await c.close()
