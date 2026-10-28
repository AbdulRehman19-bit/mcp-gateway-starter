"""MCP TokenVerifier: validate the bearer JWT, resolve the role, audit the outcome.

Returning None makes the SDK answer 401. Denials are audited here with a precise reason;
the client only ever sees the generic 401. Tokens are never logged.

Audit volume: every outcome is written to the JSON log unthrottled. Database rows are budgeted
for two flood-prone paths so they cannot be used to bloat or bury the audit table:
  - denials of tokens that never proved a valid signature (anyone can send garbage): one shared
    budget; the rest are counted and summarised in the next stored denial's reason;
  - successful logins: a small per-subject budget (each tool call's own audit row already
    records who called).
Denials of tokens WITH a valid signature (wrong audience, no role, ambiguous scopes) are rare,
come only from holders of real credentials, and are always stored.
"""

import time

from mcp.server.auth.provider import AccessToken

from mcp_gateway.audit.logging import new_request_id
from mcp_gateway.audit.sink import Auditor
from mcp_gateway.auth.jwks import JwksKeySource
from mcp_gateway.auth.roles import resolve_role
from mcp_gateway.auth.validator import TokenError, peek_header, validate_token
from mcp_gateway.policy import Policy
from mcp_gateway.ratelimit import Limit, RateLimiter

_DENY_AUDIT_LIMIT = Limit(per_minute=600, burst=100)
_ALLOW_AUDIT_LIMIT = Limit(per_minute=12, burst=5)  # per subject


class JwtTokenVerifier:
    def __init__(
        self,
        policy: Policy,
        keys: JwksKeySource,
        *,
        issuer: str,
        audience: str,
        leeway_seconds: int = 30,
        auditor: Auditor | None = None,
        deny_limiter: RateLimiter | None = None,
        allow_limiter: RateLimiter | None = None,
    ) -> None:
        self._policy = policy
        self._keys = keys
        self._issuer = issuer
        self._audience = audience
        self._leeway = leeway_seconds
        self._auditor = Auditor() if auditor is None else auditor
        self._deny_limiter = RateLimiter(max_keys=8) if deny_limiter is None else deny_limiter
        self._allow_limiter = (
            RateLimiter(max_keys=5_000) if allow_limiter is None else allow_limiter
        )
        self._suppressed = 0

    async def _audit(
        self,
        rid: str,
        started: float,
        decision: str,
        reason: str,
        subject: str,
        role: str = "",
        *,
        signed: bool = False,
    ) -> None:
        persist = True
        if decision == "allow":
            persist = self._allow_limiter.check(subject, _ALLOW_AUDIT_LIMIT).allowed
        elif not signed:
            if self._deny_limiter.check("auth-deny", _DENY_AUDIT_LIMIT).allowed:
                if self._suppressed:
                    reason = f"{reason} (+{self._suppressed} similar denials not stored)"
                    self._suppressed = 0
            else:
                self._suppressed += 1  # still logged as JSON, just not stored as a row
                persist = False
        await self._auditor.record(
            request_id=rid, tool="authenticate", decision=decision, args={}, started=started,
            reason=reason, subject=subject, role=role, persist=persist,
        )  # fmt: skip

    async def verify_token(self, token: str) -> AccessToken | None:
        rid, started = new_request_id(), time.monotonic()
        subject = ""
        signed = False  # becomes True once the signature has been verified
        try:
            alg, kid = peek_header(token)
            key = await self._keys.get_key(kid)
            if key is None:
                raise TokenError("signing key unavailable")
            claims = validate_token(
                token,
                key,
                alg=alg,
                issuer=self._issuer,
                audience=self._audience,
                leeway_seconds=self._leeway,
            )
            subject, signed = claims.subject, True
            identity = resolve_role(self._policy, claims.subject, claims.scopes)
            if identity is None:
                raise TokenError("no single role for token scopes")
        except TokenError as exc:
            await self._audit(
                rid, started, "deny", exc.reason, subject or exc.subject,
                signed=signed or exc.signed,
            )  # fmt: skip
            return None
        except Exception as exc:  # never let a bug authenticate anyone
            await self._audit(rid, started, "error", type(exc).__name__, subject, signed=signed)
            return None
        await self._audit(rid, started, "allow", "", identity.subject, identity.role)
        return AccessToken(
            token=token,
            client_id=claims.client_id,
            scopes=sorted(claims.scopes),
            expires_at=claims.expires_at,
            resource=self._audience,
            subject=claims.subject,
            claims={"iss": claims.issuer},
        )
