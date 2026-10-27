import base64
import hashlib
import hmac
import json
import time
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from mcp_gateway.auth.validator import (
    TokenError,
    parse_scopes,
    peek_header,
    validate_token,
)

ISS = "http://idp.test/realms/gw"
AUD = "mcp-gateway"

RSA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER_RSA = rsa.generate_private_key(public_exponent=65537, key_size=2048)
EC_KEY = ec.generate_private_key(ec.SECP256R1())


def claims(**over: Any) -> dict[str, Any]:
    now = int(time.time())
    base: dict[str, Any] = {
        "iss": ISS,
        "aud": AUD,
        "sub": "user-1",
        "iat": now,
        "exp": now + 300,
        "scope": "openid db:read",
        "azp": "client-1",
    }
    base.update(over)
    return {k: v for k, v in base.items() if v is not None}


def sign(payload: dict[str, Any], key: Any = RSA_KEY, alg: str = "RS256", kid: str = "k1") -> str:
    return jwt.encode(payload, key, algorithm=alg, headers={"kid": kid})


RSA_PUB = RSA_KEY.public_key()


def check(token: str, key: Any = None, alg: str = "RS256", **kw: Any) -> Any:
    key = RSA_PUB if key is None else key
    return validate_token(token, key, alg=alg, issuer=ISS, audience=AUD, **kw)


def test_valid_token() -> None:
    v = check(sign(claims()))
    assert v.subject == "user-1"
    assert v.client_id == "client-1"
    assert v.scopes == {"openid", "db:read"}


def test_valid_es256_token() -> None:
    tok = sign(claims(), key=EC_KEY, alg="ES256")
    assert check(tok, key=EC_KEY.public_key(), alg="ES256").subject == "user-1"


@pytest.mark.parametrize(
    ("payload", "reason"),
    [
        (claims(exp=int(time.time()) - 3600), "expired"),
        (claims(iss="http://evil.test"), "wrong issuer"),
        (claims(aud="someone-else"), "wrong audience"),
        (claims(aud=["a", "b"]), "wrong audience"),
        (claims(exp=None), "missing claim: exp"),
        (claims(iat=None), "missing claim: iat"),
        (claims(iss=None), "missing claim: iss"),
        (claims(aud=None), "missing claim: aud"),
        (claims(sub=None), "missing claim: sub"),
        (claims(nbf=int(time.time()) + 3600), "invalid token: ImmatureSignatureError"),
    ],
)
def test_bad_claims_denied(payload: dict[str, Any], reason: str) -> None:
    with pytest.raises(TokenError) as ei:
        check(sign(payload))
    assert ei.value.reason == reason


def test_audience_list_containing_ours_is_ok() -> None:
    assert check(sign(claims(aud=["other", AUD]))).subject == "user-1"


def test_wrong_signature_denied() -> None:
    with pytest.raises(TokenError):
        check(sign(claims(), key=OTHER_RSA))


def test_tampered_payload_denied() -> None:
    head, _body, sig = sign(claims()).split(".")
    forged = sign(claims(scope="db:write")).split(".")[1]
    with pytest.raises(TokenError):
        check(f"{head}.{forged}.{sig}")


def test_clock_skew_is_small_and_fixed() -> None:
    just_expired = sign(claims(exp=int(time.time()) - 10))
    assert check(just_expired).subject == "user-1"  # inside 30s leeway
    with pytest.raises(TokenError):
        check(sign(claims(exp=int(time.time()) - 120)))
    with pytest.raises(TokenError):
        check(just_expired, leeway_seconds=0)


def test_alg_none_rejected_at_header() -> None:
    tok = jwt.encode(claims(), None, algorithm="none", headers={"kid": "k1"})
    with pytest.raises(TokenError, match="algorithm not allowed"):
        peek_header(tok)


def hs256_by_hand(payload: dict[str, Any], secret: bytes) -> str:
    def b64(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    head = b64(json.dumps({"alg": "HS256", "typ": "JWT", "kid": "k1"}).encode())
    body = b64(json.dumps(payload).encode())
    sig = hmac.new(secret, f"{head}.{body}".encode(), hashlib.sha256).digest()
    return f"{head}.{body}.{b64(sig)}"


def test_hs256_with_public_key_confusion_rejected() -> None:
    pem = RSA_KEY.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    tok = hs256_by_hand(claims(), pem)  # PyJWT itself refuses to build this; an attacker would
    with pytest.raises(TokenError, match="algorithm not allowed"):
        peek_header(tok)
    with pytest.raises(TokenError):  # and even if a caller passed the header alg through
        check(tok, key=pem, alg="HS256")


def test_alg_key_type_mismatch_denied() -> None:
    tok = sign(claims(), key=EC_KEY, alg="ES256")
    with pytest.raises(TokenError):
        check(tok, key=RSA_KEY.public_key(), alg="ES256")


def test_token_must_have_kid() -> None:
    tok = jwt.encode(claims(), RSA_KEY, algorithm="RS256")
    with pytest.raises(TokenError, match="no kid"):
        peek_header(tok)


@pytest.mark.parametrize("tok", ["", "abc", "a.b.c", "x" * 9000, "Bearer abc", "...."])
def test_garbage_tokens_denied(tok: str) -> None:
    with pytest.raises(TokenError):
        peek_header(tok)


def test_error_reasons_never_contain_token() -> None:
    tok = sign(claims(exp=int(time.time()) - 3600))
    with pytest.raises(TokenError) as ei:
        check(tok)
    assert tok not in ei.value.reason


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("a b  c", {"a", "b", "c"}),
        (["a", "b c"], {"a", "b", "c"}),
        (None, set()),
        (5, set()),
        ({"a": 1}, set()),
        (["a", 1], set()),
        ("", set()),
    ],
)
def test_parse_scopes(raw: Any, expected: set[str]) -> None:
    assert parse_scopes(raw) == expected
