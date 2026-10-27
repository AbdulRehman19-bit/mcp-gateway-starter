"""Approval persistence. Every transition is ONE atomic UPDATE with its guards in the WHERE.

That is what makes approvals single-use and race-free: two concurrent consumers both run
`UPDATE ... WHERE status = 'approved'`, and Postgres lets exactly one of them match. Expiry
uses the database clock (now()), not the gateway's. Self-approval is refused in the UPDATE
and again by a CHECK constraint on the table.

All SQL below is a static constant; every value is a bound parameter. The only substitution is
the fixed column list into `{cols}`, never anything from a caller.
"""

import json
from collections.abc import Sequence
from typing import Any

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from mcp_gateway.approvals.state import ApprovalRow
from mcp_gateway.db_probe import probe_privileges

_COLS = (
    "id::text AS id, requester, requester_role, tool, args_hash, args, status, created_at, "
    "expires_at, decided_by, decision_reason"
)


def _q(sql: str) -> Any:
    return text(sql.replace("{cols}", _COLS))


_FIND_LIVE = _q(
    "SELECT {cols} FROM approvals WHERE requester = :r AND args_hash = :h "
    "AND status IN ('pending', 'approved') AND expires_at > now() "
    "ORDER BY created_at DESC LIMIT 1"
)
_EXPIRE_STALE = text(
    "UPDATE approvals SET status = 'denied', decision_reason = 'expired', args = '{}'::jsonb "
    "WHERE requester = :r AND args_hash = :h AND status IN ('pending', 'approved') "
    "AND expires_at <= now()"
)
_COUNT_LIVE = text(
    "SELECT count(*) FROM approvals WHERE requester = :r "
    "AND status IN ('pending', 'approved') AND expires_at > now()"
)
_INSERT = _q(
    "INSERT INTO approvals (expires_at, requester, requester_role, tool, args_hash, args) "
    "VALUES (now() + make_interval(mins => :ttl), :r, :role, :tool, :h, CAST(:args AS jsonb)) "
    "ON CONFLICT (requester, args_hash) WHERE status IN ('pending', 'approved') DO NOTHING "
    "RETURNING {cols}"
)
_CANCEL = text(
    "UPDATE approvals SET status = 'denied', decision_reason = 'audit unavailable', "
    "args = '{}'::jsonb WHERE id = CAST(:id AS uuid) AND requester = :r AND status = 'pending'"
)
_LIST_PENDING = _q(
    "SELECT {cols} FROM approvals WHERE status = 'pending' AND expires_at > now() "
    "AND requester_role = ANY(:roles) ORDER BY created_at, id LIMIT :n OFFSET :o"
)
_COUNT_PENDING = text(
    "SELECT count(*) FROM approvals WHERE status = 'pending' AND expires_at > now() "
    "AND requester_role = ANY(:roles)"
)
_GET = _q("SELECT {cols} FROM approvals WHERE id = CAST(:id AS uuid)")
_DECIDE = _q(
    "UPDATE approvals SET status = :new, decided_by = :a, decided_at = now(), "
    "decision_reason = :reason, "
    "args = CASE WHEN :new = 'approved' THEN args ELSE '{}'::jsonb END "
    "WHERE id = CAST(:id AS uuid) AND status = 'pending' "
    "AND expires_at > now() AND requester <> :a AND requester_role = ANY(:roles) "
    "RETURNING {cols}"
)
_CONSUME = text(
    "UPDATE approvals SET status = 'used', used_at = now(), args = '{}'::jsonb "
    "WHERE id = CAST(:id AS uuid) AND status = 'approved' AND expires_at > now() "
    "AND requester = :r AND tool = :t AND args_hash = :h RETURNING 1"
)
_VERSION = text("SELECT version_num FROM alembic_version")


# A requester may hold at most this many live (pending or approved) approvals, so one user
# cannot flood the queue and push legitimate requests out of an approver's view.
MAX_LIVE_PER_REQUESTER = 5


class ApprovalStoreError(Exception):
    """Storage failure. Callers treat it as a denial (fail closed)."""


class ApprovalLimitError(ApprovalStoreError):
    """The requester already has too many live approvals."""


def _row(m: Any) -> ApprovalRow:
    args = m["args"]
    return ApprovalRow(
        id=m["id"],
        requester=m["requester"],
        requester_role=m["requester_role"],
        tool=m["tool"],
        args_hash=m["args_hash"],
        args=json.loads(args) if isinstance(args, str) else dict(args),
        status=m["status"],
        created_at=m["created_at"],
        expires_at=m["expires_at"],
        decided_by=m["decided_by"],
        decision_reason=m["decision_reason"],
    )


class ApprovalStore:
    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    @classmethod
    def from_url(cls, url: str) -> "ApprovalStore":
        return cls(create_async_engine(url, pool_pre_ping=True))

    async def close(self) -> None:
        await self._engine.dispose()

    async def schema_version(self) -> str | None:
        try:
            async with self._engine.connect() as conn:
                row = (await conn.execute(_VERSION)).first()
                return str(row[0]) if row else None
        except SQLAlchemyError as exc:
            raise ApprovalStoreError(type(exc).__name__) from exc

    async def create(
        self,
        *,
        requester: str,
        requester_role: str,
        tool: str,
        args_hash: str,
        args: dict[str, Any],
        ttl_minutes: int,
    ) -> ApprovalRow:
        """Create a pending approval, or return the identical live one (idempotent re-ask)."""
        try:
            async with self._engine.begin() as conn:
                key = {"r": requester, "h": args_hash}
                await conn.execute(_EXPIRE_STALE, key)  # frees the unique slot of dead rows
                live = (await conn.execute(_FIND_LIVE, key)).mappings().first()
                if live:
                    return _row(live)
                count = (await conn.execute(_COUNT_LIVE, {"r": requester})).scalar_one()
                if int(count) >= MAX_LIVE_PER_REQUESTER:
                    raise ApprovalLimitError("too many live approvals")
                created = (
                    (
                        await conn.execute(
                            _INSERT,
                            {
                                "ttl": ttl_minutes,
                                "r": requester,
                                "role": requester_role,
                                "tool": tool,
                                "h": args_hash,
                                "args": json.dumps(args),
                            },
                        )
                    )
                    .mappings()
                    .first()
                )
                if created is None:  # lost a race to an identical concurrent request
                    created = (await conn.execute(_FIND_LIVE, key)).mappings().one()
                return _row(created)
        except SQLAlchemyError as exc:
            raise ApprovalStoreError(type(exc).__name__) from exc

    async def cancel(self, approval_id: str, *, requester: str) -> None:
        """Withdraw a pending approval (used when its audit record could not be written)."""
        try:
            async with self._engine.begin() as conn:
                await conn.execute(_CANCEL, {"id": approval_id, "r": requester})
        except SQLAlchemyError as exc:
            raise ApprovalStoreError(type(exc).__name__) from exc

    async def verify_privileges(self) -> dict[str, Any]:
        return await probe_privileges(self._engine)

    async def list_pending(
        self, roles: Sequence[str], limit: int = 50, offset: int = 0
    ) -> list[ApprovalRow]:
        """Pending requests made by `roles` only: an approver sees just what it may decide."""
        try:
            async with self._engine.connect() as conn:
                res = await conn.execute(
                    _LIST_PENDING, {"n": limit, "o": offset, "roles": list(roles)}
                )
                return [_row(m) for m in res.mappings()]
        except SQLAlchemyError as exc:
            raise ApprovalStoreError(type(exc).__name__) from exc

    async def count_pending(self, roles: Sequence[str]) -> int:
        try:
            async with self._engine.connect() as conn:
                res = await conn.execute(_COUNT_PENDING, {"roles": list(roles)})
                return int(res.scalar_one())
        except SQLAlchemyError as exc:
            raise ApprovalStoreError(type(exc).__name__) from exc

    async def get(self, approval_id: str) -> ApprovalRow | None:
        try:
            async with self._engine.connect() as conn:
                m = (await conn.execute(_GET, {"id": approval_id})).mappings().first()
                return _row(m) if m else None
        except SQLAlchemyError as exc:
            raise ApprovalStoreError(type(exc).__name__) from exc

    async def decide(
        self,
        approval_id: str,
        *,
        approver: str,
        approve: bool,
        reason: str | None,
        roles: Sequence[str],
    ) -> ApprovalRow | None:
        """Approve or deny. None means refused: not pending, expired, self-approval, or the
        requester's role is outside the approver's scope (`roles`)."""
        try:
            async with self._engine.begin() as conn:
                m = (
                    (
                        await conn.execute(
                            _DECIDE,
                            {
                                "new": "approved" if approve else "denied",
                                "a": approver,
                                "reason": reason,
                                "roles": list(roles),
                                "id": approval_id,
                            },
                        )
                    )
                    .mappings()
                    .first()
                )
                return _row(m) if m else None
        except SQLAlchemyError as exc:
            raise ApprovalStoreError(type(exc).__name__) from exc

    async def consume(self, approval_id: str, *, requester: str, tool: str, args_hash: str) -> bool:
        """Spend an approved approval exactly once, only for the exact call it was granted for."""
        try:
            async with self._engine.begin() as conn:
                res = await conn.execute(
                    _CONSUME, {"id": approval_id, "r": requester, "t": tool, "h": args_hash}
                )
                return res.first() is not None
        except SQLAlchemyError as exc:
            raise ApprovalStoreError(type(exc).__name__) from exc
