"""Structured JSON audit logging with argument redaction (rule 8).

Every record goes to the JSON log (stderr); `sink.Auditor` also writes it to the audit_log table.
"""

import hashlib
import logging
import sys
import time
import uuid
from typing import Any

import structlog

_SENSITIVE_KEYS = frozenset({"password", "token", "secret", "authorization", "dsn", "url"})


def configure_logging(level: str = "INFO") -> None:
    # stdout is the MCP stdio channel, so logs MUST go to stderr.
    logging.basicConfig(stream=sys.stderr, level=level.upper(), format="%(message)s", force=True)
    structlog.configure(
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(),
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
    )


def redact_args(args: dict[str, Any]) -> dict[str, Any]:
    """Never log SQL text or secrets verbatim: SQL becomes a hash + length."""
    out: dict[str, Any] = {}
    for key, value in args.items():
        if any(k in key.lower() for k in _SENSITIVE_KEYS):
            out[key] = "[redacted]"
        elif key in ("sql", "body") and isinstance(value, str):
            out[key] = {
                "sha256": hashlib.sha256(value.encode()).hexdigest()[:16],
                "length": len(value),
            }
        elif key == "body":  # free text from the caller: never stored, even if malformed
            out[key] = "[redacted]"
        elif key == "changes":
            # Column names only, never values. Anything that is not a dict (a malformed call)
            # is fully redacted, since we cannot tell names from values.
            out[key] = (
                {str(c): "[redacted]" for c in value} if isinstance(value, dict) else "[redacted]"
            )
        elif isinstance(value, str) and len(value) > 128:
            out[key] = value[:128] + "...[truncated]"
        else:
            out[key] = value
    return out


def audit(
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
) -> dict[str, Any]:
    """Log one audit event as JSON and return exactly what was logged (for the DB sink)."""
    record: dict[str, Any] = {
        "request_id": request_id,
        "subject": subject,
        "role": role,
        "tool": tool,
        "risk": risk,
        "decision": decision,
        "args": redact_args(args),
        "reason": reason[:500],
        "duration_ms": round((time.monotonic() - started) * 1000, 2),
    }
    structlog.get_logger("audit").info("tool_call", **record)
    return record


def new_request_id() -> str:
    return uuid.uuid4().hex
