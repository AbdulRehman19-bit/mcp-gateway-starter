"""Tool handlers. Pipeline: identity -> policy -> validate -> risk -> approval -> execute -> audit.

Identity comes from `identity_source`: the validated token over HTTP, or the fixed local user
over stdio. It is never read from tool arguments. No identity means denied. Every outcome
(allow, deny, error, pending_approval) writes an audit record. Errors returned to the client
are short and safe; details go to the audit log only.

Writes are fail-closed on audit: the "allow" record is persisted BEFORE the write runs, and if
it cannot be persisted the write does not happen.
"""

import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ValidationError

from mcp_gateway.approvals.hashing import args_hash
from mcp_gateway.approvals.state import why_not_consumable, why_not_decidable
from mcp_gateway.approvals.store import ApprovalLimitError, ApprovalStore, ApprovalStoreError
from mcp_gateway.audit.logging import new_request_id
from mcp_gateway.audit.sink import Auditor, AuditUnavailable
from mcp_gateway.auth.roles import Identity
from mcp_gateway.connectors.github import GithubConnector
from mcp_gateway.connectors.postgres import ConnectorError, PostgresReadConnector
from mcp_gateway.connectors.postgres_write import SUPPORTED_TYPES, PostgresWriteConnector
from mcp_gateway.policy import Policy
from mcp_gateway.policy.evaluator import (
    AllowedTables,
    effective_read_only,
    is_deletable,
    tool_allowed,
    writable_columns,
)
from mcp_gateway.policy.models import APPROVER_TOOLS
from mcp_gateway.ratelimit import Limit, RateLimiter
from mcp_gateway.risk import classify, needs_approval
from mcp_gateway.sqlguard import GuardError
from mcp_gateway.sqlguard.analyze import rewrite_for_policy
from mcp_gateway.tools.schemas import (
    DecideApprovalInput,
    DeleteRecordInput,
    DescribeTableInput,
    GithubAddCommentInput,
    GithubGetIssueInput,
    GithubListIssuesInput,
    ListApprovalsInput,
    ListTablesInput,
    RunQueryInput,
    UpdateRecordInput,
)

IdentitySource = Callable[[], Identity | None]
_INTEGER_TYPES = frozenset({"integer", "bigint", "smallint"})
_AUDIT_DOWN = "Audit unavailable; request refused."
PAGE_SIZE = 50


class ToolFailure(Exception):
    """Safe, client-visible failure."""


class ToolService:
    def __init__(
        self,
        connector: PostgresReadConnector,
        policy: Policy,
        allowed_by_role: dict[str, AllowedTables],
        identity_source: IdentitySource,
        *,
        auditor: Auditor | None = None,
        global_read_only: bool = True,
        writer: PostgresWriteConnector | None = None,
        approvals: ApprovalStore | None = None,
        primary_keys: dict[tuple[str, str], str] | None = None,
        limiter: RateLimiter | None = None,
        github: GithubConnector | None = None,
    ) -> None:
        self._connector = connector
        self._policy = policy
        self._allowed_by_role = allowed_by_role
        self._identity_source = identity_source
        self._auditor = Auditor() if auditor is None else auditor
        self._global_ro = global_read_only
        self._writer = writer
        self._approvals = approvals
        self._pks = primary_keys or {}
        # `is None`, not `or`: an empty RateLimiter is falsy (it has __len__)
        self._limiter = RateLimiter() if limiter is None else limiter
        self._github = github
        gh_policy = policy.connectors.github
        self._github_repos = frozenset(gh_policy.repos) if gh_policy else frozenset()

    # ---- plumbing -------------------------------------------------------------------------

    def _risk(self, tool: str) -> str:
        if tool in APPROVER_TOOLS or tool == "ping":
            return ""
        return classify(self._policy, tool)

    async def _audit(
        self,
        rid: str,
        tool: str,
        decision: str,
        args: dict[str, Any],
        started: float,
        ident: Identity | None,
        reason: str = "",
        *,
        critical: bool = False,
    ) -> None:
        try:
            await self._auditor.record(
                request_id=rid,
                tool=tool,
                decision=decision,
                args=args,
                started=started,
                reason=reason,
                role=ident.role if ident else "",
                subject=ident.subject if ident else "",
                risk=self._risk(tool),
                critical=critical,
            )
        except AuditUnavailable as exc:
            raise ToolFailure(_AUDIT_DOWN) from exc

    async def _rate_limit(
        self, tool: str, rid: str, args: dict[str, Any], started: float, ident: Identity
    ) -> None:
        """One bucket per (subject, tool); limits come from the policy. Runs right after
        identity so a flood is cut off before any policy, DB or upstream work."""
        rl = self._policy.limits.tools.get(tool, self._policy.limits.default)
        decision = self._limiter.check(
            (ident.subject, tool), Limit(per_minute=rl.per_minute, burst=rl.burst)
        )
        if not decision.allowed:
            reason = f"rate_limited retry_after={decision.retry_after:.1f}s"
            await self._audit(rid, tool, "deny", args, started, ident, reason)
            raise ToolFailure(f"Rate limit exceeded. Retry in {decision.retry_after_seconds} s.")

    async def _authorize(
        self, tool: str, rid: str, args: dict[str, Any], started: float
    ) -> tuple[Identity, AllowedTables]:
        ident = self._identity_source()
        if ident is None:
            await self._audit(rid, tool, "deny", args, started, None, "no identity")
            raise ToolFailure("Not permitted.")
        await self._rate_limit(tool, rid, args, started, ident)
        if not tool_allowed(self._policy, ident.role, tool):
            await self._audit(rid, tool, "deny", args, started, ident, "tool not allowed for role")
            raise ToolFailure("Not permitted.")
        # Unknown role gets an empty map: nothing is readable.
        return ident, self._allowed_by_role.get(ident.role, {})

    async def _parse[M: BaseModel](
        self,
        model: type[M],
        tool: str,
        raw: dict[str, Any],
        rid: str,
        started: float,
        ident: Identity,
    ) -> M:
        try:
            return model.model_validate(raw)
        except ValidationError as exc:
            reason = f"invalid_input: {exc.error_count()}"
            await self._audit(rid, tool, "deny", raw, started, ident, reason)
            raise ToolFailure("Invalid input.") from exc

    async def ping(self, message: str) -> str:
        """Health check: any authenticated identity, no policy tier, but still audited."""
        rid, started = new_request_id(), time.monotonic()
        ident = self._identity_source()
        if ident is None:
            await self._audit(rid, "ping", "deny", {}, started, None, "no identity")
            raise ToolFailure("Not permitted.")
        await self._rate_limit("ping", rid, {}, started, ident)
        await self._audit(rid, "ping", "allow", {}, started, ident)
        return message

    # ---- read tools -----------------------------------------------------------------------

    async def list_tables(self) -> dict[str, Any]:
        rid, started = new_request_id(), time.monotonic()
        ident, allowed = await self._authorize("list_tables", rid, {}, started)
        await self._parse(ListTablesInput, "list_tables", {}, rid, started, ident)
        tables = [{"schema": s, "table": t} for (s, t) in sorted(allowed)]
        await self._audit(rid, "list_tables", "allow", {}, started, ident)
        return {"tables": tables}

    async def describe_table(self, table: str, schema: str = "public") -> dict[str, Any]:
        rid, started = new_request_id(), time.monotonic()
        raw = {"table": table, "schema_name": schema}
        ident, allowed = await self._authorize("describe_table", rid, raw, started)
        inp = await self._parse(DescribeTableInput, "describe_table", raw, rid, started, ident)
        cols = allowed.get((inp.schema_name, inp.table))
        if cols is None:
            # Same answer for "missing" and "not permitted": existence is not disclosed.
            await self._audit(
                rid, "describe_table", "deny", raw, started, ident, "table not allowed"
            )
            raise ToolFailure("Unknown table.")
        await self._audit(rid, "describe_table", "allow", raw, started, ident)
        return {
            "schema": inp.schema_name,
            "table": inp.table,
            "columns": [{"column": c, "type": i.type, "masked": i.masked} for c, i in cols.items()],
        }

    async def run_query(self, sql: str, limit: int | None = None) -> dict[str, Any]:
        rid, started = new_request_id(), time.monotonic()
        raw = {"sql": sql, "limit": limit}
        ident, allowed = await self._authorize("run_query", rid, raw, started)
        inp = await self._parse(RunQueryInput, "run_query", raw, rid, started, ident)
        max_rows = self._policy.defaults.max_rows
        effective = min(inp.limit or max_rows, max_rows)
        try:
            safe_sql = rewrite_for_policy(inp.sql, allowed, max_rows=effective)
        except GuardError as exc:
            await self._audit(rid, "run_query", "deny", raw, started, ident, exc.reason)
            raise ToolFailure("Query not permitted.") from exc
        except Exception as exc:  # parser/analyzer bug: fail closed, never run the raw SQL
            await self._audit(rid, "run_query", "error", raw, started, ident, type(exc).__name__)
            raise ToolFailure("Internal error.") from exc
        try:
            res = await self._connector.run_query(safe_sql, limit=effective)
        except ConnectorError as exc:
            await self._audit(rid, "run_query", "error", raw, started, ident, exc.detail)
            raise ToolFailure(exc.safe_message) from exc
        except Exception as exc:
            await self._audit(rid, "run_query", "error", raw, started, ident, type(exc).__name__)
            raise ToolFailure("Internal error.") from exc
        await self._audit(rid, "run_query", "allow", raw, started, ident)
        return {
            "columns": res.columns,
            "rows": res.rows,
            "row_count": len(res.rows),
            "truncated": res.truncated,
        }

    # ---- write tools ----------------------------------------------------------------------

    async def update_record(
        self,
        table: str,
        pk: Any,
        changes: dict[str, Any],
        schema: str = "public",
        dry_run: bool = False,
        approval_id: str | None = None,
    ) -> dict[str, Any]:
        rid, started = new_request_id(), time.monotonic()
        raw = {"table": table, "schema_name": schema, "pk": pk, "changes": changes,
               "dry_run": dry_run, "approval_id": approval_id}  # fmt: skip
        ident, allowed = await self._authorize("update_record", rid, raw, started)
        inp = await self._parse(UpdateRecordInput, "update_record", raw, rid, started, ident)
        return await self._write(
            "update_record", rid, started, ident, allowed, raw,
            inp.schema_name, inp.table, inp.pk, dict(inp.changes), inp.dry_run, inp.approval_id,
        )  # fmt: skip

    async def delete_record(
        self,
        table: str,
        pk: Any,
        schema: str = "public",
        dry_run: bool = False,
        approval_id: str | None = None,
    ) -> dict[str, Any]:
        rid, started = new_request_id(), time.monotonic()
        raw = {"table": table, "schema_name": schema, "pk": pk, "dry_run": dry_run,
               "approval_id": approval_id}  # fmt: skip
        ident, allowed = await self._authorize("delete_record", rid, raw, started)
        inp = await self._parse(DeleteRecordInput, "delete_record", raw, rid, started, ident)
        return await self._write(
            "delete_record", rid, started, ident, allowed, raw,
            inp.schema_name, inp.table, inp.pk, None, inp.dry_run, inp.approval_id,
        )  # fmt: skip

    async def _write(
        self,
        tool: str,
        rid: str,
        started: float,
        ident: Identity,
        allowed: AllowedTables,
        raw: dict[str, Any],
        schema: str,
        table: str,
        pk: Any,
        changes: dict[str, Any] | None,
        dry_run: bool,
        approval_id: str | None,
    ) -> dict[str, Any]:
        async def deny(reason: str, message: str = "Not permitted.") -> ToolFailure:
            await self._audit(rid, tool, "deny", raw, started, ident, reason)
            return ToolFailure(message)

        if effective_read_only(self._policy, ident.role, self._global_ro):
            raise await deny("read-only mode", "Writes are disabled.")
        cols = allowed.get((schema, table))
        if cols is None:
            raise await deny("table not allowed", "Unknown table.")
        pk_col = self._pks.get((schema, table))
        if pk_col is None or pk_col not in cols:
            raise await deny("no usable single-column primary key", "Unsupported table.")
        pk_type = cols[pk_col].type
        if pk_type not in SUPPORTED_TYPES:
            raise await deny(f"unsupported pk type {pk_type}", "Unsupported table.")
        if (pk_type in _INTEGER_TYPES) != isinstance(pk, int):
            raise await deny("pk type mismatch", "Invalid input.")
        if changes is not None:
            writable = writable_columns(self._policy, ident.role, schema, table)
            bad = sorted(c for c in changes if c not in writable or c not in cols or c == pk_col)
            if bad:
                raise await deny(f"columns not writable: {bad}")
            unsupported = sorted(c for c in changes if cols[c].type not in SUPPORTED_TYPES)
            if unsupported:
                raise await deny(f"unsupported column types: {unsupported}")
        elif not is_deletable(self._policy, ident.role, schema, table):
            raise await deny("table not deletable")
        if self._writer is None:
            raise await deny("write connector not configured", "Writes are not configured.")

        bound = {"schema_name": schema, "table": table, "pk": pk}
        if changes is not None:
            bound["changes"] = changes
        reason = "dry_run" if dry_run else ""
        audited = False
        if not dry_run and needs_approval(self._policy, ident.role, tool):
            if approval_id is not None:
                # Durable BEFORE the approval is spent: an audit outage must not burn it.
                presented = f"approval {approval_id} presented"
                await self._audit(rid, tool, "allow", raw, started, ident, presented, critical=True)
                audited = True
            approved, pending = await self._approval_gate(
                tool, rid, started, ident, raw, bound, approval_id, deny
            )
            if pending is not None:  # a pending approval was created; nothing is executed
                return pending
            reason = f"approval {approved}"

        # Fail closed: the allow record must be durable BEFORE anything is written.
        if not audited:
            await self._audit(rid, tool, "allow", raw, started, ident, reason, critical=True)
        try:
            if changes is not None:
                n = await self._writer.update_row(
                    schema=schema, table=table, pk_col=pk_col, pk_type=pk_type, pk_value=pk,
                    changes=changes, column_types={c: cols[c].type for c in changes},
                    dry_run=dry_run,
                )  # fmt: skip
            else:
                n = await self._writer.delete_row(
                    schema=schema, table=table, pk_col=pk_col, pk_type=pk_type, pk_value=pk,
                    dry_run=dry_run,
                )  # fmt: skip
        except ConnectorError as exc:
            await self._audit(rid, tool, "error", raw, started, ident, exc.detail)
            raise ToolFailure(exc.safe_message) from exc
        except Exception as exc:
            await self._audit(rid, tool, "error", raw, started, ident, type(exc).__name__)
            raise ToolFailure("Internal error.") from exc
        await self._audit(rid, tool, "success", raw, started, ident, reason)
        return {"status": "dry_run" if dry_run else "ok", "rows_affected": n}

    async def _approval_gate(
        self,
        tool: str,
        rid: str,
        started: float,
        ident: Identity,
        raw: dict[str, Any],
        bound: dict[str, Any],
        approval_id: str | None,
        deny: Callable[..., Any],
    ) -> tuple[str | None, dict[str, Any] | None]:
        """(consumed approval id, None) to proceed, or (None, response) for a new pending one."""
        if self._approvals is None:
            raise await deny("approvals not configured", "Approvals are not configured.")
        digest = args_hash(tool, bound)
        try:
            if approval_id is None:
                try:
                    row = await self._approvals.create(
                        requester=ident.subject,
                        requester_role=ident.role,
                        tool=tool,
                        args_hash=digest,
                        args=bound,
                        ttl_minutes=self._policy.approvals.ttl_minutes,
                    )
                except ApprovalLimitError as exc:
                    raise await deny(
                        "too many live approvals", "Too many pending approvals."
                    ) from exc
                try:
                    await self._audit(
                        rid, tool, "pending_approval", raw, started, ident,
                        f"approval {row.id}", critical=True,
                    )  # fmt: skip
                except ToolFailure:
                    # An approval nobody can see in the audit trail must not stay approvable.
                    await self._approvals.cancel(row.id, requester=ident.subject)
                    raise
                return None, {
                    "status": "pending_approval",
                    "approval_id": row.id,
                    "expires_at": row.expires_at.isoformat(),
                    "message": "A different user must approve this; then repeat the call "
                    "with the same arguments and this approval_id.",
                }
            if await self._approvals.consume(
                approval_id, requester=ident.subject, tool=tool, args_hash=digest
            ):
                return approval_id, None
            current = await self._approvals.get(approval_id)
            why = why_not_consumable(current, ident.subject, tool, digest, datetime.now(UTC))
        except ApprovalStoreError as exc:
            await self._audit(rid, tool, "error", raw, started, ident, f"approvals: {exc}")
            raise ToolFailure("Approval service unavailable.") from exc
        raise await deny(f"approval refused: {why}", "Approval not valid.")

    # ---- GitHub connector -----------------------------------------------------------------

    async def _github_gate(
        self, tool: str, rid: str, started: float, ident: Identity, raw: dict[str, Any], repo: str
    ) -> GithubConnector:
        """Connector configured and repo allow-listed, or a denial. Runs before any request."""
        if self._github is None:
            await self._audit(rid, tool, "deny", raw, started, ident, "github not configured")
            raise ToolFailure("GitHub is not configured.")
        if repo not in self._github_repos:
            # Same answer for "unknown" and "not allowed": no probing of private repos.
            await self._audit(rid, tool, "deny", raw, started, ident, "repo not allow-listed")
            raise ToolFailure("Unknown repository.")
        return self._github

    async def _github_read(
        self, tool: str, rid: str, started: float, ident: Identity, raw: dict[str, Any], call: Any
    ) -> dict[str, Any]:
        try:
            result: dict[str, Any] = await call
        except ConnectorError as exc:
            await self._audit(rid, tool, "error", raw, started, ident, exc.detail)
            raise ToolFailure(exc.safe_message) from exc
        except Exception as exc:
            await self._audit(rid, tool, "error", raw, started, ident, type(exc).__name__)
            raise ToolFailure("Internal error.") from exc
        await self._audit(rid, tool, "allow", raw, started, ident)
        return result

    async def github_list_issues(
        self, repo: str, state: str = "open", limit: int = 20
    ) -> dict[str, Any]:
        tool = "github_list_issues"
        rid, started = new_request_id(), time.monotonic()
        raw = {"repo": repo, "state": state, "limit": limit}
        ident, _ = await self._authorize(tool, rid, raw, started)
        inp = await self._parse(GithubListIssuesInput, tool, raw, rid, started, ident)
        gh = await self._github_gate(tool, rid, started, ident, raw, inp.repo)
        call = gh.list_issues(inp.repo, inp.state, inp.limit)
        return await self._github_read(tool, rid, started, ident, raw, call)

    async def github_get_issue(self, repo: str, number: int) -> dict[str, Any]:
        tool = "github_get_issue"
        rid, started = new_request_id(), time.monotonic()
        raw = {"repo": repo, "number": number}
        ident, _ = await self._authorize(tool, rid, raw, started)
        inp = await self._parse(GithubGetIssueInput, tool, raw, rid, started, ident)
        gh = await self._github_gate(tool, rid, started, ident, raw, inp.repo)
        return await self._github_read(
            tool, rid, started, ident, raw, gh.get_issue(inp.repo, inp.number)
        )

    async def github_add_comment(
        self,
        repo: str,
        number: int,
        body: str,
        dry_run: bool = False,
        approval_id: str | None = None,
    ) -> dict[str, Any]:
        tool = "github_add_comment"
        rid, started = new_request_id(), time.monotonic()
        raw = {
            "repo": repo,
            "number": number,
            "body": body,
            "dry_run": dry_run,
            "approval_id": approval_id,
        }
        ident, _ = await self._authorize(tool, rid, raw, started)
        inp = await self._parse(GithubAddCommentInput, tool, raw, rid, started, ident)

        async def deny(reason: str, message: str = "Not permitted.") -> ToolFailure:
            await self._audit(rid, tool, "deny", raw, started, ident, reason)
            return ToolFailure(message)

        if effective_read_only(self._policy, ident.role, self._global_ro):
            raise await deny("read-only mode", "Writes are disabled.")
        gh = await self._github_gate(tool, rid, started, ident, raw, inp.repo)
        if not gh.can_write:
            raise await deny("no github write token", "GitHub writes are not configured.")

        if inp.dry_run:  # nothing leaves the gateway: report what would be posted
            await self._audit(rid, tool, "allow", raw, started, ident, "dry_run", critical=True)
            await self._audit(rid, tool, "success", raw, started, ident, "dry_run")
            return {"status": "dry_run", "would_post_chars": len(inp.body)}

        bound = {"repo": inp.repo, "number": inp.number, "body": inp.body}
        audited = False
        reason = ""
        if needs_approval(self._policy, ident.role, tool):  # always: github_add_comment is high
            if inp.approval_id is not None:
                presented = f"approval {inp.approval_id} presented"
                await self._audit(rid, tool, "allow", raw, started, ident, presented, critical=True)
                audited = True
            approved, pending = await self._approval_gate(
                tool, rid, started, ident, raw, bound, inp.approval_id, deny
            )
            if pending is not None:
                return pending
            reason = f"approval {approved}"
        if not audited:
            await self._audit(rid, tool, "allow", raw, started, ident, reason, critical=True)
        try:
            posted = await gh.add_comment(inp.repo, inp.number, inp.body)
        except ConnectorError as exc:
            await self._audit(rid, tool, "error", raw, started, ident, exc.detail)
            raise ToolFailure(exc.safe_message) from exc
        except Exception as exc:
            await self._audit(rid, tool, "error", raw, started, ident, type(exc).__name__)
            raise ToolFailure("Internal error.") from exc
        await self._audit(rid, tool, "success", raw, started, ident, reason)
        return {"status": "ok", **posted}

    # ---- approver tools -------------------------------------------------------------------

    def _approver_scope(self, ident: Identity) -> list[str]:
        """Roles whose requests this approver may see and decide. Empty = none (fail closed)."""
        rp = self._policy.roles.get(ident.role)
        return list(rp.approves_roles) if rp else []

    async def list_approvals(self, offset: int = 0) -> dict[str, Any]:
        rid, started = new_request_id(), time.monotonic()
        raw = {"offset": offset}
        ident, _ = await self._authorize("list_approvals", rid, raw, started)
        inp = await self._parse(ListApprovalsInput, "list_approvals", raw, rid, started, ident)
        if self._approvals is None:
            await self._audit(rid, "list_approvals", "error", raw, started, ident, "not configured")
            raise ToolFailure("Approvals are not configured.")
        try:
            scope = self._approver_scope(ident)
            rows = await self._approvals.list_pending(scope, PAGE_SIZE, inp.offset)
            total = await self._approvals.count_pending(scope)
        except ApprovalStoreError as exc:
            await self._audit(rid, "list_approvals", "error", raw, started, ident, str(exc))
            raise ToolFailure("Approval service unavailable.") from exc
        await self._audit(rid, "list_approvals", "allow", raw, started, ident)
        next_offset = inp.offset + len(rows)
        return {
            "total_pending": total,
            "next_offset": next_offset if next_offset < total else None,
            "approvals": [
                {
                    "approval_id": r.id,
                    "requester": r.requester,
                    "requester_role": r.requester_role,
                    "tool": r.tool,
                    "args": r.args,
                    "created_at": r.created_at.isoformat(),
                    "expires_at": r.expires_at.isoformat(),
                    "own_request": r.requester == ident.subject,
                }
                for r in rows
            ],
        }

    async def decide_approval(
        self, approval_id: str, decision: str, reason: str | None = None
    ) -> dict[str, Any]:
        rid, started = new_request_id(), time.monotonic()
        raw = {"approval_id": approval_id, "decision": decision, "reason": reason}
        ident, _ = await self._authorize("decide_approval", rid, raw, started)
        inp = await self._parse(DecideApprovalInput, "decide_approval", raw, rid, started, ident)
        if self._approvals is None:
            await self._audit(
                rid, "decide_approval", "error", raw, started, ident, "not configured"
            )
            raise ToolFailure("Approvals are not configured.")
        approve = inp.decision == "approve"
        await self._audit(
            rid, "decide_approval", "allow", raw, started, ident, f"{inp.decision} attempt",
            critical=True,
        )  # fmt: skip
        try:
            scope = self._approver_scope(ident)
            row = await self._approvals.decide(
                inp.approval_id,
                approver=ident.subject,
                approve=approve,
                reason=inp.reason,
                roles=scope,
            )
            if row is None:
                current = await self._approvals.get(inp.approval_id)
                why = why_not_decidable(current, ident.subject, datetime.now(UTC), scope)
        except ApprovalStoreError as exc:
            await self._audit(rid, "decide_approval", "error", raw, started, ident, str(exc))
            raise ToolFailure("Approval service unavailable.") from exc
        if row is None:
            await self._audit(rid, "decide_approval", "deny", raw, started, ident, why)
            raise ToolFailure("Cannot decide this approval.")
        status = "approved" if approve else "denied"
        await self._audit(
            rid, "decide_approval", status, raw, started, ident,
            f"approval {row.id} for {row.tool} by {row.requester}",
        )  # fmt: skip
        return {"approval_id": row.id, "status": status}
