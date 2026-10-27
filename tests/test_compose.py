"""Static checks on the one-command demo stack (no Docker needed)."""

from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).parents[1]
COMPOSE: dict[str, Any] = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
SERVICES: dict[str, Any] = COMPOSE["services"]


def test_plain_compose_up_starts_everything() -> None:
    assert set(SERVICES) == {"db", "keycloak", "migrate", "gateway"}
    for name, svc in SERVICES.items():
        assert "profiles" not in svc, f"{name} would not start with plain `docker compose up`"


def test_every_published_port_binds_to_loopback_only() -> None:
    published = [(n, p) for n, s in SERVICES.items() for p in s.get("ports", [])]
    assert published
    for name, port in published:
        assert str(port).startswith("127.0.0.1:"), f"{name} publishes {port} on all interfaces"


def test_no_env_file_is_needed_for_the_demo() -> None:
    for name, svc in SERVICES.items():
        assert "env_file" not in svc, f"{name} would fail on a fresh clone without .env"


def test_gateway_waits_for_migrations_and_uses_distinct_db_roles() -> None:
    gw = SERVICES["gateway"]
    assert gw["depends_on"]["migrate"]["condition"] == "service_completed_successfully"
    env = gw["environment"]
    users = {
        env[k].split("://")[1].split(":")[0]
        for k in ("TARGET_DB_RO_URL", "TARGET_DB_RW_URL", "GATEWAY_DB_URL", "GATEWAY_AUDIT_DB_URL")
    }
    assert len(users) == 4  # the gateway refuses to start if two roles share a user
    assert "GATEWAY_DB_ADMIN_URL" not in env  # the schema owner is for `migrate` only
    assert "GATEWAY_DB_ADMIN_URL" in SERVICES["migrate"]["environment"]


def test_jwks_over_plain_http_is_limited_to_the_keycloak_service() -> None:
    env = SERVICES["gateway"]["environment"]
    assert env["OAUTH_JWKS_HTTP_ALLOWED_HOSTS"] == "keycloak"
    assert env["OAUTH_JWKS_URL"].startswith("http://keycloak:")
    assert env["OAUTH_ISSUER"].startswith("http://localhost:")  # must equal the token `iss`


def test_migrate_runs_alembic_from_the_same_image() -> None:
    assert SERVICES["migrate"]["command"] == ["alembic", "upgrade", "head"]
    assert SERVICES["migrate"]["image"] == SERVICES["gateway"]["image"]


@pytest.mark.parametrize("needle", ["COPY migrations", "COPY alembic.ini", "USER gateway"])
def test_dockerfile_ships_migrations_and_runs_as_non_root(needle: str) -> None:
    assert needle in (ROOT / "Dockerfile").read_text(encoding="utf-8")


def test_dockerignore_keeps_secrets_out_of_the_image() -> None:
    lines = (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
    assert ".env" in lines
    assert ".git" in lines
