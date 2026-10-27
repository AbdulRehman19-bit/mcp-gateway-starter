from mcp_gateway.audit.logging import redact_args


def test_sql_is_hashed_not_logged() -> None:
    out = redact_args({"sql": "SELECT email FROM users"})
    assert "SELECT" not in str(out)
    assert out["sql"]["length"] == 23


def test_secrets_redacted() -> None:
    out = redact_args({"password": "hunter2", "Token": "abc", "table": "orders"})
    assert out == {"password": "[redacted]", "Token": "[redacted]", "table": "orders"}


def test_substring_keys_and_long_values() -> None:
    out = redact_args({"db_password": "x", "api_token": "y", "table": "a" * 500})
    assert out["db_password"] == "[redacted]"
    assert out["api_token"] == "[redacted]"
    assert len(out["table"]) < 200
