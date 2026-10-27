# Roadmap (about 4 weeks)

Each phase ends with a tagged release (`v0.1`, `v0.2`, ...), green CI, and an updated
"Current phase" line in `CLAUDE.md`. Use `/plan-phase <n>` to start each one.

**Status: all phases complete.** Phase 0 = `v0.1`, Phase 1 = `v0.2`, Phase 2 = `v0.3`,
Phase 3 = `v0.4`, Phase 4 = `v0.5`, Phase 5 = `v1.0`. Open items live in the residual-risk
register in [THREAT_MODEL.md](THREAT_MODEL.md) §5.

## Phase 0 — Setup (day 1–2)
- Repo, uv project, Docker Compose Postgres with demo data and RO/RW roles, CI, CLAUDE.md
- **Done when:** `uv run pytest` and CI are green; `docker compose up -d db` works;
  Inspector connects and `ping` returns.

## Phase 1 — Core read-only server (week 1)
- Tools: `list_tables`, `describe_table`, `run_query` (stdio, no auth yet)
- Postgres connector using the SELECT-only role, row limit, statement timeout
- **Done when:** all three tools work in the Inspector against demo data.

## Phase 2 — Safety layer (week 2)
- `sqlguard`: sqlglot validation (single SELECT only, default deny)
- Policy engine: roles, schemas, tables, columns, deny and mask columns
- Global read-only switch plus per-role read-only
- **Done when:** an adversarial test suite passes (multi-statement, comment tricks, CTE-wrapped
  writes, `COPY`, `SELECT INTO`, `pg_sleep`, alias/`SELECT *` column-deny bypasses, huge LIMIT).

## Phase 3 — Authentication (week 3)
- Switch to Streamable HTTP; Keycloak in Compose; JWT validation (issuer, audience, signature,
  expiry, pinned algorithm); scope -> role mapping
- **Done when:** unauthenticated and wrong-scope calls are denied and audited; role comes only
  from the token.

## Phase 4 — Approvals and audit (week 3–4)
- Risk classifier, `update_record` (medium) and `delete_record` (high)
- Approval queue: pending -> approved/denied/expired, single-use, bound to an args hash,
  requester cannot self-approve
- Structured JSON logs plus an `audit_log` table (who, tool, redacted args, decision, duration, request id)
- Dry-run mode for writes (transaction rollback)
- **Done when:** a high-risk call returns `pending_approval`, a different user approves it via
  the approver tools, and it executes exactly once.

## Phase 5 — Polish (week 4)
- Second connector (GitHub or Jira, read-mostly), rate limiting
- README with architecture diagram and demo GIF, finalized `THREAT_MODEL.md`
- Tag `v1.0`
- **Done when:** a new developer can clone, run `docker compose up`, and follow the README demo.
