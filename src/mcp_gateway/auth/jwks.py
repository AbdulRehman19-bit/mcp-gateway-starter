"""JWKS key source: fetch the IdP's signing keys, cache them, fail closed.

- the URL must be https, or http on loopback (local Keycloak) only: no SSRF to arbitrary hosts;
- no redirects, short timeout, bounded response size;
- unknown `kid` triggers at most one refresh per `min_refresh_seconds`;
- if keys cannot be fetched, `get_key` returns None and the caller denies.
"""

import asyncio
import ipaddress
import json
import time
from typing import Any
from urllib.parse import urlparse

import httpx
import jwt
import structlog

_LOOPBACK = frozenset({"localhost", "127.0.0.1", "::1"})
_MAX_BYTES = 256 * 1024
# A cached key outlives its TTL only briefly if the IdP is unreachable; a revoked key must not
# stay trusted for long.
_MAX_STALE_SECONDS = 600
_FETCH_DEADLINE_SECONDS = 10
_log = structlog.get_logger("jwks")


def validate_jwks_url(url: str) -> str:
    """https, or http on loopback. No credentials in the URL, no private/link-local IP literals."""
    parsed = urlparse(url)
    host = parsed.hostname
    if not host or parsed.username or parsed.password:
        raise ValueError("URL must have a host and no credentials")
    if parsed.scheme == "http" and host in _LOOPBACK:
        return url
    if parsed.scheme != "https":
        raise ValueError("URL must be https (http allowed only on loopback)")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return url  # a DNS name
    if ip.is_loopback:
        return url
    if ip.is_private or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
        raise ValueError("URL must not point at a private or link-local address")
    return url


class JwksKeySource:
    def __init__(
        self,
        url: str,
        *,
        client: httpx.AsyncClient | None = None,
        ttl_seconds: int = 300,
        min_refresh_seconds: int = 60,
        clock: Any = time.monotonic,
    ) -> None:
        self._url = validate_jwks_url(url)
        self._client = client or httpx.AsyncClient(timeout=5.0, follow_redirects=False)
        self._ttl = ttl_seconds
        self._min_refresh = min_refresh_seconds
        self._clock = clock
        self._keys: dict[str, Any] = {}
        self._fetched_at: float | None = None
        self._last_attempt: float | None = None
        self._lock = asyncio.Lock()

    async def get_key(self, kid: str) -> Any | None:
        now = self._clock()
        expired = self._fetched_at is None or now - self._fetched_at > self._ttl
        if kid in self._keys and not expired:
            return self._keys[kid]
        async with self._lock:
            now = self._clock()
            expired = self._fetched_at is None or now - self._fetched_at > self._ttl
            if kid in self._keys and not expired:
                return self._keys[kid]
            can_try = self._last_attempt is None or now - self._last_attempt >= self._min_refresh
            if can_try:
                await self._refresh(now)
            if self._fetched_at is None or self._clock() - self._fetched_at > _MAX_STALE_SECONDS:
                self._keys = {}  # too old to trust: fail closed
            return self._keys.get(kid)

    async def _refresh(self, now: float) -> None:
        self._last_attempt = now
        try:
            async with asyncio.timeout(_FETCH_DEADLINE_SECONDS):  # total, not per-read
                body = await self._read_capped()
            keys = self._parse(json.loads(body))
        except (httpx.HTTPError, ValueError, TimeoutError) as exc:
            _log.warning("jwks_fetch_failed", error=type(exc).__name__)
            return
        if keys:
            self._keys, self._fetched_at = keys, now

    async def _read_capped(self) -> bytes:
        async with self._client.stream("GET", self._url) as resp:
            if resp.status_code != 200:
                raise ValueError(f"bad JWKS response: {resp.status_code}")
            body = bytearray()
            async for chunk in resp.aiter_bytes():
                body.extend(chunk)
                if len(body) > _MAX_BYTES:
                    raise ValueError("JWKS response too large")
            return bytes(body)

    @staticmethod
    def _parse(doc: Any) -> dict[str, Any]:
        out: dict[str, Any] = {}
        raw_keys = doc.get("keys") if isinstance(doc, dict) else None
        if not isinstance(raw_keys, list):
            raise ValueError("no keys array")
        for jwk in raw_keys:
            if not isinstance(jwk, dict) or jwk.get("use", "sig") != "sig":
                continue
            if jwk.get("kty") not in ("RSA", "EC") or not isinstance(jwk.get("kid"), str):
                continue
            try:
                out[jwk["kid"]] = jwt.PyJWK.from_dict(jwk).key
            except (jwt.PyJWTError, ValueError, TypeError):
                continue
        return out

    async def aclose(self) -> None:
        await self._client.aclose()
