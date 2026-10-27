import time
from pathlib import Path
from typing import Any

import jwt
import structlog
from cryptography.hazmat.primitives.asymmetric import rsa

from mcp_gateway.auth.verifier import JwtTokenVerifier
from mcp_gateway.policy import load_policy

POLICY = load_policy(Path(__file__).parents[2] / "policies" / "policy.example.yaml")
ISS, AUD = "http://idp.test/realms/gw", "mcp-gateway"
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


class FakeKeys:
    def __init__(self, key: Any = KEY.public_key()) -> None:  # noqa: B008
        self.key = key

    async def get_key(self, kid: str) -> Any | None:
        return self.key if kid == "k1" else None


def token(**over: Any) -> str:
    now = int(time.time())
    payload = {
        "iss": ISS, "aud": AUD, "sub": "alice-id", "iat": now, "exp": now + 300,
        "scope": "openid db:read", "azp": "dev",
    }  # fmt: skip
    payload.update(over)
    return jwt.encode({k: v for k, v in payload.items() if v is not None}, KEY, "RS256",
                      headers={"kid": "k1"})  # fmt: skip


def verifier(keys: Any = None) -> JwtTokenVerifier:
    return JwtTokenVerifier(POLICY, keys or FakeKeys(), issuer=ISS, audience=AUD)  # type: ignore[arg-type]


async def test_valid_token_accepted_and_audited_with_subject_and_role() -> None:
    tok = token()
    with structlog.testing.capture_logs() as logs:
        out = await verifier().verify_token(tok)
    assert out is not None
    assert out.subject == "alice-id"
    assert "db:read" in out.scopes
    assert logs[0]["decision"] == "allow"
    assert (logs[0]["subject"], logs[0]["role"]) == ("alice-id", "analyst")
    assert tok not in str(logs)


async def test_denials_are_audited_and_never_leak_the_token() -> None:
    cases = {
        "empty": "",
        "garbage": "not-a-jwt",
        "expired": token(exp=int(time.time()) - 3600),
        "wrong_aud": token(aud="other"),
        "wrong_iss": token(iss="http://evil"),
        "no_scope": token(scope="openid profile"),
        "ambiguous": token(scope="db:read db:write"),
        "unknown_scope": token(scope="admin"),
    }
    for name, tok in cases.items():
        with structlog.testing.capture_logs() as logs:
            assert await verifier().verify_token(tok) is None, name
        assert logs[0]["decision"] == "deny", name
        assert logs[0]["tool"] == "authenticate"
        if tok:
            assert tok not in str(logs), name


async def test_unknown_kid_or_missing_key_denied() -> None:
    class NoKeys:
        async def get_key(self, kid: str) -> Any | None:
            return None

    with structlog.testing.capture_logs() as logs:
        assert await verifier(NoKeys()).verify_token(token()) is None
    assert logs[0]["reason"] == "signing key unavailable"


async def test_wrong_signing_key_denied() -> None:
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
    assert await verifier(FakeKeys(other)).verify_token(token()) is None


async def test_internal_error_fails_closed() -> None:
    class Boom:
        async def get_key(self, kid: str) -> Any:
            raise RuntimeError("secret detail")

    with structlog.testing.capture_logs() as logs:
        assert await verifier(Boom()).verify_token(token()) is None
    assert logs[0]["decision"] == "error"
    assert "secret detail" not in str(logs)
