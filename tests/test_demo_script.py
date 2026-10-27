"""scripts/demo.py is the README demo: run it for real so it cannot rot.

Starts the gateway as a subprocess (like the other e2e tests) and runs the script against it.
Needs Postgres (migrated) and Keycloak; skips if Keycloak is not running.
"""

import os
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest

pytestmark = pytest.mark.integration

ROOT = Path(__file__).parents[1]
KC = "http://localhost:8080/realms/mcp-gateway"
PORT = 8767
HOST = "localhost:5432"
ENV = {
    "TARGET_DB_RO_URL": f"postgresql+asyncpg://gateway_ro:change-me-ro@{HOST}/demo",
    "TARGET_DB_RW_URL": f"postgresql+asyncpg://gateway_rw:change-me-rw@{HOST}/demo",
    "GATEWAY_DB_URL": f"postgresql+asyncpg://gateway_app:change-me-app@{HOST}/gateway",
    "GATEWAY_AUDIT_DB_URL": f"postgresql+asyncpg://gateway_audit:change-me-audit@{HOST}/gateway",
    "GATEWAY_READ_ONLY": "false",
    "OAUTH_ISSUER": KC,
    "OAUTH_JWKS_URL": f"{KC}/protocol/openid-connect/certs",
    "GATEWAY_PORT": str(PORT),
}


@pytest.fixture(scope="module")
def gateway(tmp_path_factory: pytest.TempPathFactory) -> Iterator[None]:
    try:
        httpx.get(f"{KC}/.well-known/openid-configuration", timeout=5).raise_for_status()
    except httpx.HTTPError:
        pytest.skip("Keycloak not running (docker compose up -d keycloak)")
    log = tmp_path_factory.mktemp("demo") / "gateway.log"
    with log.open("wb") as fh:
        proc = subprocess.Popen(
            [sys.executable, "-m", "mcp_gateway.server", "--transport", "http"],
            env={**os.environ, **ENV},
            stdout=fh,
            stderr=subprocess.STDOUT,
        )
        try:
            deadline = time.monotonic() + 40
            while time.monotonic() < deadline:
                with socket.socket() as s:
                    if s.connect_ex(("127.0.0.1", PORT)) == 0:
                        break
                assert proc.poll() is None, log.read_text()
                time.sleep(0.3)
            else:
                pytest.fail("gateway did not start")
            yield
        finally:
            proc.terminate()
            proc.wait(timeout=10)


def test_the_readme_demo_runs_clean_against_a_live_gateway(gateway: None) -> None:
    result = subprocess.run(  # noqa: S603
        [
            sys.executable,
            str(ROOT / "scripts" / "demo.py"),
            "--gateway",
            f"http://127.0.0.1:{PORT}/mcp",
        ],
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    out = result.stdout + result.stderr
    assert result.returncode == 0, out
    assert "Demo complete" in out
    assert "UNEXPECTED" not in out
    for expected in ("pending_approval", "masked", "refused", "replay"):
        assert expected in out, expected
