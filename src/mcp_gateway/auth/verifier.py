"""MCP TokenVerifier: validate the bearer JWT, resolve the role, audit the outcome.

Returning None makes the SDK answer 401. Denials are audited here with a precise reason;
the client only ever sees the generic 401. Tokens are never logged.
"""

import time

from mcp.server.auth.provider import AccessToken

from mcp_gateway.audit.logging import audit, new_request_id
from mcp_gateway.auth.jwks import JwksKeySource
from mcp_gateway.auth.roles import resolve_role
from mcp_gateway.auth.validator import TokenError, peek_header, validate_token
from mcp_gateway.policy import Policy


class JwtTokenVerifier:
    def __init__(
        self,
        policy: Policy,
        keys: JwksKeySource,
        *,
        issuer: str,
        audience: str,
        leeway_seconds: int = 30,
    ) -> None:
        self._policy = policy
        self._keys = keys
        self._issuer = issuer
        self._audience = audience
        self._leeway = leeway_seconds

    async def verify_token(self, token: str) -> AccessToken | None:
        rid, started = new_request_id(), time.monotonic()
        subject = ""
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
            subject = claims.subject
            identity = resolve_role(self._policy, claims.subject, claims.scopes)
            if identity is None:
                raise TokenError("no single role for token scopes")
        except TokenError as exc:
            audit(request_id=rid, tool="authenticate", decision="deny", args={},
                  started=started, reason=exc.reason, subject=subject)  # fmt: skip
            return None
        except Exception as exc:  # never let a bug authenticate anyone
            audit(request_id=rid, tool="authenticate", decision="error", args={},
                  started=started, reason=type(exc).__name__, subject=subject)  # fmt: skip
            return None
        audit(request_id=rid, tool="authenticate", decision="allow", args={},
              started=started, role=identity.role, subject=identity.subject)  # fmt: skip
        return AccessToken(
            token=token,
            client_id=claims.client_id,
            scopes=sorted(claims.scopes),
            expires_at=claims.expires_at,
            resource=self._audience,
            subject=claims.subject,
            claims={"iss": claims.issuer},
        )
