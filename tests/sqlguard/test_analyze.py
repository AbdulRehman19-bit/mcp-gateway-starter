from pathlib import Path

import pytest

from mcp_gateway.policy import load_policy
from mcp_gateway.policy.evaluator import AllowedTables, Catalog, allowed_tables
from mcp_gateway.sqlguard import GuardError
from mcp_gateway.sqlguard.analyze import rewrite_for_policy

POLICY = Path(__file__).parents[2] / "policies" / "policy.example.yaml"

# What the DB shows gateway_ro, plus hidden columns the policy must still never expose.
CATALOG: Catalog = {
    ("public", "orders"): {
        "id": "integer",
        "customer_id": "integer",
        "total_cents": "integer",
        "status": "text",
        "notes": "text",
        "created_at": "timestamp with time zone",
    },
    ("public", "customers"): {
        "id": "integer",
        "name": "text",
        "country": "text",
        "created_at": "timestamp with time zone",
    },
    ("public", "users"): {
        "id": "integer",
        "email": "text",
        "phone": "text",
        "password_hash": "text",
        "created_at": "timestamp with time zone",
    },
}


@pytest.fixture(scope="module")
def allowed() -> AllowedTables:
    return allowed_tables(load_policy(POLICY), "analyst", CATALOG)


def rw(sql: str, allowed: AllowedTables, max_rows: int = 500) -> str:
    return rewrite_for_policy(sql, allowed, max_rows=max_rows)


OK = [
    "SELECT * FROM orders",
    "SELECT o.id, c.name FROM orders o JOIN customers c ON c.id = o.customer_id",
    "SELECT count(*) FROM orders",
    "SELECT status, sum(total_cents) FROM orders GROUP BY status ORDER BY status",
    "SELECT id FROM orders UNION SELECT id FROM customers",
    "WITH t AS (SELECT id, status FROM orders) SELECT * FROM t",
    "SELECT id, created_at FROM public.users",
    "SELECT * FROM users",
    "SELECT u.phone FROM users u",
    "SELECT * FROM (SELECT id FROM orders) s",
    "SELECT id FROM orders WHERE id IN (SELECT customer_id FROM orders)",
    "SELECT ':x' AS s FROM orders",
]

DENY = [
    # denied columns, every clause
    "SELECT email FROM users",
    "SELECT password_hash FROM users",
    "SELECT id FROM users WHERE email = 'a@example.com'",
    "SELECT id FROM users WHERE email LIKE 'a%'",
    "SELECT id FROM users ORDER BY email",
    "SELECT count(email) FROM users",
    "SELECT u.email FROM users u",
    "SELECT x.email FROM (SELECT * FROM users) x",
    "SELECT email FROM (SELECT id FROM users) x",
    "WITH t AS (SELECT * FROM users) SELECT email FROM t",
    "SELECT a.id FROM users a JOIN users b ON a.email = b.email",
    "SELECT id FROM users GROUP BY id, email",
    "SELECT public.users.email FROM public.users",
    'SELECT "email" FROM users',
    'SELECT "EMAIL" FROM users',
    "SELECT (SELECT email FROM users LIMIT 1) FROM orders",
    "SELECT id FROM orders WHERE EXISTS (SELECT 1 FROM users WHERE email = 'x')",
    # whole row / system columns / hidden tables
    "SELECT users FROM users",
    "SELECT to_jsonb(users) FROM users",
    "SELECT row_to_json(u) FROM users u",
    "SELECT ctid FROM orders",
    "SELECT xmin FROM orders",
    "SELECT tableoid FROM orders",
    "SELECT * FROM pg_roles",
    "SELECT * FROM pg_catalog.pg_roles",
    "SELECT * FROM pg_stat_activity",
    "SELECT * FROM information_schema.columns",
    "SELECT * FROM other.orders",
    'SELECT * FROM "Orders"',
    "SELECT * FROM generate_series(1, 10)",
    "SELECT * FROM unnest(ARRAY[1,2])",
    "SELECT * FROM orders, LATERAL (SELECT 1) l",
    "SELECT * FROM (VALUES (1)) v",
    "SELECT * FROM current_database.public.orders",
    # masked columns used as data, not just displayed
    "SELECT id FROM users WHERE phone = '+92-300-0000001'",
    "SELECT id FROM users WHERE phone LIKE '+92%'",
    "SELECT id FROM users ORDER BY phone",
    "SELECT upper(phone) FROM users",
    "SELECT length(phone) FROM users",
    "SELECT count(phone) FROM users",
    "SELECT phone || '' FROM users",
    "SELECT x.phone FROM (SELECT phone FROM users) x",
    "WITH t AS (SELECT phone FROM users) SELECT * FROM t",
    "SELECT a.id FROM users a JOIN users b ON a.phone = b.phone",
    "SELECT phone FROM users GROUP BY phone",
    "SELECT id FROM users u WHERE u.phone IS NOT NULL",
    "SELECT CASE WHEN phone LIKE '+92%' THEN 1 ELSE 0 END FROM users",
    # CTE tricks
    "WITH users AS (SELECT * FROM users) SELECT email FROM users",
    "WITH pg_roles AS (SELECT * FROM pg_roles) SELECT * FROM pg_roles",
    "WITH a AS (SELECT * FROM b), b AS (SELECT 1 AS x) SELECT * FROM a",
    "WITH RECURSIVE r AS (SELECT 1 AS n UNION ALL SELECT n + 1 FROM r) SELECT * FROM r",
    "SELECT * FROM (WITH pg_roles AS (SELECT 1) SELECT * FROM pg_roles) a, pg_roles",
    # column alias lists remap columns by position onto the real (wider) table
    "SELECT u.created_at FROM users AS u(id, created_at, phone)",
    "SELECT u.created_at FROM users AS u(a, created_at)",
    "SELECT * FROM users AS u(a, b, c)",
    "SELECT d FROM users AS u(a, b, c, d, e)",
    # typed functions and casts that disclose or burn resources
    "SELECT version() FROM orders",
    "SELECT current_user FROM orders",
    "SELECT session_user FROM orders",
    "SELECT current_database() FROM orders",
    "SELECT current_schema() FROM orders",
    "SELECT md5(notes) FROM orders",
    "SELECT repeat('a', 1000000000) FROM orders",
    "SELECT count(*) FROM (SELECT generate_series(1, 10000000000)) s",
    "SELECT id FROM orders WHERE id = ANY(ARRAY(SELECT generate_series(1, 100000000)))",
    "SELECT 'users'::regclass FROM orders",
    "SELECT CAST('orders' AS regclass) FROM orders",
    "SELECT 1::oid FROM orders",
    # joins on unnamed columns, sampling, cost
    "SELECT * FROM users NATURAL JOIN customers",
    "SELECT id FROM orders TABLESAMPLE SYSTEM (50)",
    "SELECT 1 FROM orders a, orders b, orders c, orders d, orders e, orders f",
    "SELECT 1 FROM " + "(SELECT 1 FROM " * 10 + "orders" + ") s" * 10,
    # writes / structure (belt and braces; sqlguard.guard covers these too)
    "SELECT 1; SELECT 2",
    "DELETE FROM orders",
    "WITH d AS (DELETE FROM orders RETURNING *) SELECT * FROM d",
    "SELECT * INTO t FROM orders",
    "SELECT * FROM orders FOR UPDATE",
    "SELECT pg_sleep(1) FROM orders",
    "SELECT set_config('statement_timeout', '0', true) FROM orders",
    "SELECT 1 FROM orders; DROP TABLE orders",
    "SELECT id FROM orders /* x */ ; DELETE FROM orders",
]


@pytest.mark.parametrize("sql", OK)
def test_allows(sql: str, allowed: AllowedTables) -> None:
    rw(sql, allowed)


@pytest.mark.parametrize("sql", DENY)
def test_denies(sql: str, allowed: AllowedTables) -> None:
    with pytest.raises(GuardError):
        rw(sql, allowed)


def test_star_expands_to_allowed_columns_only(allowed: AllowedTables) -> None:
    out = rw("SELECT * FROM users", allowed).lower()
    assert "email" not in out
    assert "password_hash" not in out
    assert '"id"' in out
    assert "'***'" in out


def test_qualified_star_expands(allowed: AllowedTables) -> None:
    out = rw("SELECT u.* FROM users u JOIN orders o ON o.customer_id = u.id", allowed).lower()
    assert "email" not in out
    assert "'***'" in out


def test_mask_in_projection_keeps_alias(allowed: AllowedTables) -> None:
    out = rw("SELECT phone AS p FROM users", allowed)
    assert "'***' AS \"p\"" in out


def test_mask_applies_in_every_union_branch(allowed: AllowedTables) -> None:
    out = rw("SELECT phone FROM users UNION ALL SELECT phone FROM users", allowed)
    assert out.count("'***'") == 2
    assert 'phone"' not in out.replace('AS "phone"', "")


@pytest.mark.parametrize(
    ("sql", "expected"),
    [
        ("SELECT id FROM orders", 500),
        ("SELECT id FROM orders LIMIT 10", 10),
        ("SELECT id FROM orders LIMIT 99999999", 500),
        ("SELECT id FROM orders LIMIT 500", 500),
        ("SELECT id FROM orders LIMIT ALL", 500),
        ("SELECT id FROM orders LIMIT -1", 500),
        ("SELECT id FROM orders FETCH FIRST 99999 ROWS ONLY", 500),
        ("SELECT id FROM orders FETCH FIRST 5 ROWS ONLY", 500),
        ("SELECT id FROM orders LIMIT (SELECT 99999)", 500),
        ("SELECT id FROM orders LIMIT 99999999999999999999", 500),
        ("SELECT id FROM orders UNION SELECT id FROM customers", 500),
    ],
)
def test_limit_is_clamped(sql: str, expected: int, allowed: AllowedTables) -> None:
    out = rw(sql, allowed)
    assert out.rstrip().upper().endswith(f"LIMIT {expected}")
    assert "FETCH" not in out.upper()


def test_limit_respects_smaller_max_rows(allowed: AllowedTables) -> None:
    assert rw("SELECT id FROM orders LIMIT 100", allowed, max_rows=25).endswith("LIMIT 25")


def test_no_allowed_tables_denies_everything() -> None:
    with pytest.raises(GuardError):
        rw("SELECT 1", {})


def test_output_is_revalidated_single_select(allowed: AllowedTables) -> None:
    out = rw("SELECT id FROM orders", allowed)
    assert ";" not in out
