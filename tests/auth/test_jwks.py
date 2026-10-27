import json
from typing import Any

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from mcp_gateway.auth.jwks import JwksKeySource, validate_jwks_url

URL = "http://localhost:8080/certs"


def jwk_for(key: Any, kid: str) -> dict[str, Any]:
    data = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    return {**data, "kid": kid, "use": "sig", "alg": "RS256"}


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class Idp:
    """Fake JWKS endpoint that counts requests and can be switched off."""

    def __init__(self, keys: list[dict[str, Any]]) -> None:
        self.keys = keys
        self.calls = 0
        self.fail = False

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        if self.fail:
            return httpx.Response(500)
        return httpx.Response(200, json={"keys": self.keys})


def source(idp: Idp, clock: Clock) -> JwksKeySource:
    client = httpx.AsyncClient(transport=httpx.MockTransport(idp.handler))
    return JwksKeySource(URL, client=client, ttl_seconds=300, min_refresh_seconds=60, clock=clock)


K1 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
K2 = rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.mark.parametrize(
    "url",
    ["https://idp.example.com/certs", "http://localhost:8080/certs", "http://127.0.0.1/c"],
)
def test_url_ok(url: str) -> None:
    assert validate_jwks_url(url) == url


@pytest.mark.parametrize(
    "url",
    [
        "http://idp.example.com/certs",
        "http://169.254.169.254/latest",
        "file:///etc/passwd",
        "ftp://x/y",
        "//idp/certs",
        "",
        "http://localhost.evil.com/certs",
        "https://user:pw@evil.com/certs",
        "https://localhost@evil.com/certs",
        "https://169.254.169.254/latest",
        "https://10.0.0.5/certs",
        "https://192.168.1.1/certs",
        "https://[::ffff:10.0.0.1]/certs",
        "https://0.0.0.0/certs",
    ],
)
def test_url_rejected(url: str) -> None:
    with pytest.raises(ValueError):
        validate_jwks_url(url)


async def test_fetches_once_and_caches() -> None:
    idp, clock = Idp([jwk_for(K1, "k1")]), Clock()
    src = source(idp, clock)
    assert await src.get_key("k1") is not None
    assert await src.get_key("k1") is not None
    assert idp.calls == 1


async def test_unknown_kid_refresh_is_rate_limited() -> None:
    idp, clock = Idp([jwk_for(K1, "k1")]), Clock()
    src = source(idp, clock)
    await src.get_key("k1")
    for _ in range(20):  # attacker spraying random kids must not hammer the IdP
        assert await src.get_key("nope") is None
    assert idp.calls == 1
    clock.now += 61
    assert await src.get_key("nope") is None
    assert idp.calls == 2


async def test_rotation_picks_up_new_key_after_interval() -> None:
    idp, clock = Idp([jwk_for(K1, "k1")]), Clock()
    src = source(idp, clock)
    await src.get_key("k1")
    idp.keys = [jwk_for(K1, "k1"), jwk_for(K2, "k2")]
    clock.now += 61
    assert await src.get_key("k2") is not None


async def test_fetch_failure_fails_closed_when_no_keys() -> None:
    idp, clock = Idp([]), Clock()
    idp.fail = True
    assert await source(idp, clock).get_key("k1") is None


async def test_failure_keeps_recent_keys_but_not_stale_ones() -> None:
    idp, clock = Idp([jwk_for(K1, "k1")]), Clock()
    src = source(idp, clock)
    await src.get_key("k1")
    idp.fail = True
    clock.now += 400  # past ttl, refresh fails, keys still young enough to trust
    assert await src.get_key("k1") is not None
    clock.now += 4000  # far too old (> 10 min): deny rather than trust a possibly revoked key
    assert await src.get_key("k1") is None


async def test_bad_entries_are_skipped() -> None:
    good = jwk_for(K1, "good")
    junk: list[Any] = [
        "str",
        {"kty": "oct", "kid": "sym", "k": "AAAA"},
        {"kty": "RSA", "kid": "enc", "use": "enc", "n": "AQAB", "e": "AQAB"},
        {"kty": "RSA", "n": "AQAB", "e": "AQAB"},  # no kid
        {"kty": "RSA", "kid": "broken", "n": "!!", "e": "!!"},
    ]
    idp, clock = Idp([*junk, good]), Clock()
    src = source(idp, clock)
    assert await src.get_key("good") is not None
    for kid in ("sym", "enc", "broken"):
        assert await src.get_key(kid) is None


async def test_oversized_response_is_rejected() -> None:
    def big(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b'{"keys": []}' + b" " * (300 * 1024))

    client = httpx.AsyncClient(transport=httpx.MockTransport(big))
    assert await JwksKeySource(URL, client=client, clock=Clock()).get_key("k1") is None


async def test_redirects_are_not_followed() -> None:
    def redirect(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "http://169.254.169.254/"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(redirect), follow_redirects=False)
    src = JwksKeySource(URL, client=client, clock=Clock())
    assert await src.get_key("k1") is None
