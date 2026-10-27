"""Approval state machine (pure): why a transition was refused.

The database performs the transitions atomically (see store.py); this module only explains a
refusal for the audit log, so reasons never depend on a second racy read deciding anything.

    pending --approve--> approved --consume--> used
       \\--deny--> denied              (pending/approved past expires_at are "expired")
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any

PENDING, APPROVED, DENIED, USED = "pending", "approved", "denied", "used"


@dataclass(frozen=True)
class ApprovalRow:
    id: str
    requester: str
    requester_role: str
    tool: str
    args_hash: str
    args: dict[str, Any]
    status: str
    created_at: datetime
    expires_at: datetime
    decided_by: str | None = None
    decision_reason: str | None = None


def why_not_decidable(row: ApprovalRow | None, approver: str, now: datetime) -> str:
    if row is None:
        return "approval not found"
    if row.requester == approver:
        return "requester cannot decide own request"
    if row.status != PENDING:
        return f"already {row.status}"
    if row.expires_at <= now:
        return "expired"
    return "not decidable"


def why_not_consumable(
    row: ApprovalRow | None, requester: str, tool: str, args_hash: str, now: datetime
) -> str:
    if row is None:
        return "approval not found"
    if row.requester != requester:
        return "approval belongs to another requester"
    if row.tool != tool or row.args_hash != args_hash:
        return "approval does not match this call"
    if row.status == USED:
        return "already used"
    if row.status == DENIED:
        return "denied"
    if row.status == PENDING:
        return "still pending"
    if row.expires_at <= now:
        return "expired"
    return "not consumable"
