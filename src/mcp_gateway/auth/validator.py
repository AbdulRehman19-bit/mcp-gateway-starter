"""JWT validation (pure: the verification key is an argument, no I/O).

We are a resource server only. Every property below is checked on purpose:
 - the algorithm comes from our allow-list, never from the token (blocks `alg: none` and
   HS256-with-public-key confusion);
 - signature, issuer, audience, `exp`, `iat` and `sub` are all required;
 - `nbf` is enforced when present, with a small fixed clock skew.
Reasons go to the audit log; callers only learn "denied".
"""

from dataclasses import dataclass
from typing import Any

import jwt

ALLOWED_ALGORITHMS: tuple[str, ...] = ("RS256", "ES256")
MAX_TOKEN_CHARS = 8192
_REQUIRED_CLAIMS = ["exp", "iat", "iss", "aud", "sub"]


class TokenError(Exception):
    """Token rejected. `reason` is for the audit log only; it never contains the token."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class ValidatedToken:
    subject: str
    client_id: str
    scopes: frozenset[str]
    expires_at: int
    issuer: str


def peek_header(token: str) -> tuple[str, str]:
    """Return (alg, kid) from the unverified header, or raise. Used only to pick the key."""
    if not token or len(token) > MAX_TOKEN_CHARS:
        raise TokenError("token missing or too large")
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as exc:
        raise TokenError(f"malformed token: {type(exc).__name__}") from exc
    alg = header.get("alg")
    if alg not in ALLOWED_ALGORITHMS:
        raise TokenError(f"algorithm not allowed: {str(alg)[:16]}")
    kid = header.get("kid")
    if not isinstance(kid, str) or not kid:
        raise TokenError("token has no kid")
    return str(alg), kid


def parse_scopes(raw: Any) -> frozenset[str]:
    """OAuth `scope` is a space-separated string; some IdPs send a list. Anything else: none."""
    if isinstance(raw, str):
        return frozenset(raw.split())
    if isinstance(raw, list) and all(isinstance(s, str) for s in raw):
        return frozenset(s for item in raw for s in item.split())
    return frozenset()


def validate_token(
    token: str,
    key: Any,
    *,
    alg: str,
    issuer: str,
    audience: str,
    leeway_seconds: int = 30,
) -> ValidatedToken:
    if alg not in ALLOWED_ALGORITHMS:
        raise TokenError("algorithm not allowed")
    try:
        claims = jwt.decode(
            token,
            key,
            algorithms=[alg],
            issuer=issuer,
            audience=audience,
            leeway=leeway_seconds,
            options={"require": _REQUIRED_CLAIMS, "verify_signature": True},
        )
    except jwt.ExpiredSignatureError as exc:
        raise TokenError("expired") from exc
    except jwt.InvalidAudienceError as exc:
        raise TokenError("wrong audience") from exc
    except jwt.InvalidIssuerError as exc:
        raise TokenError("wrong issuer") from exc
    except jwt.MissingRequiredClaimError as exc:
        raise TokenError(f"missing claim: {exc.claim}") from exc
    except (jwt.PyJWTError, TypeError, ValueError) as exc:
        # InvalidSignature, ImmatureSignature, InvalidKey (key/alg mismatch), ...
        raise TokenError(f"invalid token: {type(exc).__name__}") from exc

    subject = claims.get("sub")
    if not isinstance(subject, str) or not subject:
        raise TokenError("bad subject")
    exp = claims["exp"]
    if isinstance(exp, bool) or not isinstance(exp, int | float):
        raise TokenError("bad exp")
    client = claims.get("azp") or claims.get("client_id") or subject
    return ValidatedToken(
        subject=subject,
        client_id=str(client),
        scopes=parse_scopes(claims.get("scope", claims.get("scp"))),
        expires_at=int(exp),
        issuer=str(claims["iss"]),
    )
