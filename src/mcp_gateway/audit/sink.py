"""Audit sinks and the Auditor that feeds them.

Policy: a `critical` record (before a write executes, or when an approval is created) must be
persisted, otherwise `AuditUnavailable` is raised and the caller must NOT proceed: no audit
trail, no write. Non-critical records (reads, denials) fall back to the JSON log alone if the
database is down, so an audit outage cannot take reads offline.
"""

import json
from typing import Any, Protocol

import structlog
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from mcp_gateway.audit.logging import audit
from mcp_gateway.db_probe import probe_privileges


class AuditUnavailable(Exception):
    """The audit trail could not be written for a record that must be persisted."""


class AuditSink(Protocol):
    async def write(self, record: dict[str, Any]) -> None: ...


class DbAuditSink:
    """INSERT-only writer. Its DB role has no SELECT/UPDATE/DELETE on audit_log."""

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    @classmethod
    def from_url(cls, url: str) -> "DbAuditSink":
        return cls(create_async_engine(url, pool_pre_ping=True))

    async def write(self, record: dict[str, Any]) -> None:
        async with self._engine.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO audit_log (request_id, subject, role, tool, args_redacted, "
                    "risk, decision, reason, duration_ms) VALUES (:request_id, :subject, :role, "
                    ":tool, CAST(:args AS jsonb), :risk, :decision, :reason, :duration_ms)"
                ),
                {
                    **{k: v for k, v in record.items() if k != "args"},
                    "args": json.dumps(record["args"], default=str),
                },
            )

    async def schema_version(self) -> str | None:
        async with self._engine.connect() as conn:
            row = (await conn.execute(text("SELECT version_num FROM alembic_version"))).first()
            return str(row[0]) if row else None

    async def verify_privileges(self) -> dict[str, Any]:
        return await probe_privileges(self._engine)

    async def close(self) -> None:
        await self._engine.dispose()


class MemorySink:
    """Test double that keeps records in a list."""

    def __init__(self, *, fail: bool = False) -> None:
        self.records: list[dict[str, Any]] = []
        self.fail = fail

    async def write(self, record: dict[str, Any]) -> None:
        if self.fail:
            raise RuntimeError("sink down")
        self.records.append(record)


class Auditor:
    def __init__(self, sink: AuditSink | None = None) -> None:
        self._sink = sink

    async def record(
        self,
        *,
        request_id: str,
        tool: str,
        decision: str,
        args: dict[str, Any],
        started: float,
        reason: str = "",
        role: str = "",
        subject: str = "",
        risk: str = "",
        critical: bool = False,
    ) -> None:
        rec = audit(
            request_id=request_id, tool=tool, decision=decision, args=args, started=started,
            reason=reason, role=role, subject=subject, risk=risk,
        )  # fmt: skip
        if self._sink is None:
            if critical:
                raise AuditUnavailable("no audit sink configured")
            return
        try:
            await self._sink.write(rec)
        except (SQLAlchemyError, OSError, RuntimeError) as exc:
            structlog.get_logger("audit").error("audit_write_failed", error=type(exc).__name__)
            if critical:
                raise AuditUnavailable(type(exc).__name__) from exc
