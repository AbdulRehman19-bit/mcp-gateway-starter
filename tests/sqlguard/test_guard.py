import pytest

from mcp_gateway.sqlguard import GuardError, ensure_single_select

OK = [
    "SELECT 1",
    "select * from orders where id = 1",
    "SELECT o.id FROM orders o JOIN customers c ON c.id = o.customer_id LIMIT 5",
    "WITH t AS (SELECT 1 AS a) SELECT a FROM t",
    "SELECT 'a;b' AS s",
    "SELECT 1 -- trailing comment",
    "SELECT count(*) AS n, sum(total_cents) FROM orders",
    "SELECT ':foo' AS s, 1::int AS n",
]

BAD = [
    "",
    "   ",
    "SELECT 1; SELECT 2",
    "SELECT 1; DROP TABLE orders",
    "SELECT 1;\nDELETE FROM orders",
    "INSERT INTO orders (customer_id, total_cents) VALUES (1, 1)",
    "UPDATE orders SET status = 'x'",
    "DELETE FROM orders",
    "DROP TABLE orders",
    "TRUNCATE orders",
    "CREATE TABLE t (a int)",
    "ALTER TABLE orders ADD COLUMN x int",
    "COPY orders TO '/tmp/x'",
    "COPY (SELECT 1) TO PROGRAM 'id'",
    "SELECT * INTO newt FROM orders",
    "SELECT * FROM orders FOR UPDATE",
    "WITH d AS (DELETE FROM orders RETURNING *) SELECT * FROM d",
    "WITH u AS (UPDATE orders SET status='x' RETURNING *) SELECT * FROM u",
    "WITH i AS (INSERT INTO orders(customer_id,total_cents) VALUES (1,1) RETURNING *) SELECT 1",
    "SET ROLE gateway_rw",
    "BEGIN",
    "COMMIT",
    "CALL do_something()",
    "DO $$ BEGIN PERFORM 1; END $$",
    "VACUUM",
    "EXPLAIN ANALYZE DELETE FROM orders",
    "SELECT 1 /* ; */ ; DROP TABLE orders",
    "/* SELECT */ DROP TABLE orders",
    "ＤＲＯＰ TABLE orders",  # fullwidth "DROP"
    "SELECT pg_sleep(10)",
    "SELECT set_config('statement_timeout', '0', true), pg_sleep(100000)",
    "SELECT set_config('role', 'gateway_rw', false)",
    "SELECT pg_advisory_lock(1)",
    "SELECT pg_terminate_backend(1)",
    "SELECT lo_import('/etc/passwd')",
    "SELECT * FROM dblink('host=x', 'select 1') AS t(a int)",
    "SELECT (",
    pytest.param("SELECT " + "(" * 20000 + "1" + ")" * 20000, id="deep-nesting"),
    "\x00",
]


@pytest.mark.parametrize("sql", OK)
def test_allows_plain_selects(sql: str) -> None:
    ensure_single_select(sql)


@pytest.mark.parametrize("sql", BAD)
def test_rejects_everything_else(sql: str) -> None:
    with pytest.raises(GuardError):
        ensure_single_select(sql)
