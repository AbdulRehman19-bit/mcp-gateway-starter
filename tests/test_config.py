import pytest

from mcp_gateway.config import Settings


def test_db_url_not_in_repr(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TARGET_DB_RO_URL", "postgresql+asyncpg://u:supersecret@h/db")
    assert "supersecret" not in repr(Settings(_env_file=None))  # type: ignore[call-arg]


def test_db_url_defaults_to_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TARGET_DB_RO_URL", raising=False)
    assert Settings(_env_file=None).target_db_ro_url is None  # type: ignore[call-arg]
