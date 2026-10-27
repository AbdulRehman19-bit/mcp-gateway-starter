# Architecture

```
AI client
   │  MCP: stdio (local, trusted user)  |  Streamable HTTP + Bearer JWT (remote)
   ▼
server.py                  FastMCP app and tool registration. Thin: no business logic.
   ▼
auth/                      validate the JWT (alg, iss, aud, exp, signature via JWKS) -> identity
   ▼                       scope -> exactly one role, or deny. Role comes ONLY from the token.
ratelimit/                 token bucket per (subject, tool); limits from the policy
   ▼
policy/                    tool allowed for role? table/column allowed? read-only? (pure functions)
   ▼
risk/                      low | medium | high (unknown = high; destructive tools floored to high)
   ▼
approvals/                 high risk -> pending_approval; a DIFFERENT user approves; single-use
   ▼
sqlguard/                  sqlglot: one SELECT; resolve every column against the role's allowed
   ▼                       columns; expand stars; mask; clamp LIMIT; run the REWRITTEN SQL
connectors/                postgres.py (read-only role), postgres_write.py (limited RW role),
   ▼                       github.py (allow-listed repos, fixed base URL)
Target systems             PostgreSQL, GitHub

audit/                     every stage: JSON log (stderr) + append-only audit_log row
```

Every stage writes an audit record, including denials and errors. Writes are fail-closed on
audit: the `allow` record is persisted *before* the write runs, and if it cannot be, the write
does not happen. Reads and denials degrade to the JSON log if the audit database is down.

## Layout

```
src/mcp_gateway/
  server.py          tool registration, startup checks, wiring
  config.py          Settings (env vars, secrets as SecretStr)
  auth/              validator (pure), jwks (key source), roles (scope->role), verifier (MCP hook)
  policy/            models (YAML schema), evaluator (pure)
  risk/              classifier (pure)
  ratelimit/         token-bucket limiter (in-memory, bounded)
  sqlguard/          guard (single SELECT, function/cast allow-list), analyze (policy-aware rewrite)
  approvals/         hashing (canonical args), state (why refused), store (atomic SQL)
  connectors/        postgres, postgres_write, github     <- all I/O lives here
  tools/             schemas (Pydantic inputs), handlers (the pipeline)
  audit/             logging (redaction), sink (DB writer, Auditor)
  db_probe.py        startup check of what each DB role can actually do
migrations/          Alembic: audit_log, approvals, hardening (trigger, grants, unique index)
policies/            example policy
scripts/demo.py      the guided demo
tests/               mirrors src/; integration tests need Postgres (and Keycloak for e2e)
```

## Database roles (defence in depth)

The gateway refuses to start unless these are four *different* database users with exactly the
privileges below (checked at startup by `db_probe.py` and the connectors):

| Role | Database | Can | Cannot |
|---|---|---|---|
| `gateway_ro` | target | `SELECT` on granted tables/columns, inside a `READ ONLY` transaction with `statement_timeout` | write anything; see ungranted columns |
| `gateway_rw` | target | `UPDATE` on listed columns, `DELETE` on `orders`; one row per call | be superuser/createrole/owner; touch anything else |
| `gateway_app` | gateway | `SELECT/INSERT` and column-limited `UPDATE` on `approvals` | touch `audit_log`; delete approvals; edit identity columns |
| `gateway_audit` | gateway | `INSERT` into `audit_log` | read, update, delete or truncate history |

Application checks are never the only layer: even if the SQL analyzer were bypassed, the
database role would still refuse a write, a hidden column, or an edit of the audit trail.

## Data model (gateway DB)

- `audit_log(id, ts, request_id, subject, role, tool, args_redacted, risk, decision, reason, duration_ms)`:
  arguments are redacted before storage (SQL is hashed, `changes` keeps column names only,
  comment `body` is dropped, secrets are masked).
- `approvals(id, created_at, expires_at, requester, requester_role, tool, args_hash, args, status,
  decided_by, decided_at, decision_reason, used_at)`:
  `status` is `pending | approved | denied | used`. A trigger allows only
  `pending -> approved|denied` and `approved -> used|denied`, forbids editing identity columns,
  and a CHECK forbids `decided_by = requester`. A partial unique index allows one live approval
  per (requester, exact call). `args` is cleared once an approval is used or denied.

## Approval flow

1. A high-risk call (or a medium one the role marks `approval_required`) creates a `pending`
   approval holding the exact arguments and returns `pending_approval` + `approval_id`.
2. An approver whose role lists the requester's role in `approves_roles` sees it
   (`list_approvals`, paged) and decides (`decide_approval`). One atomic `UPDATE ... WHERE
   status='pending' AND expires_at > now() AND requester <> approver AND requester_role = ANY(scope)`.
3. The requester repeats the *same* call with `approval_id`. One atomic `UPDATE ... WHERE
   status='approved' AND not expired AND requester, tool and args hash match` spends it; exactly
   one concurrent caller wins. Consume happens before execute (at-most-once): if the write then
   fails, a new approval is needed.

## Request pipeline details worth knowing

- **Identity** is resolved per request from that request's own token (the HTTP transport is
  stateless, so a session can never inherit a stale identity). Expiry is re-checked at call time.
- **SQL**: the analyzer does not trust the caller's text. It parses, qualifies every column against
  the role's allowed columns (denied columns are simply absent from the schema it sees), expands
  `*`, rewrites masked projections to `'***'`, clamps `LIMIT`, re-validates, and executes the
  regenerated SQL. Anything it cannot positively resolve is denied.
- **Untrusted data**: tool inputs, database content and GitHub text are data. They are capped,
  cleaned and (for GitHub) wrapped in an `untrusted_content` envelope; they can never change a
  permission, skip an approval or alter the policy.
- **Secrets** (`SecretStr`) never appear in `repr`, logs, errors or audit rows.

## Transports

- **stdio:** local development and the Inspector. The local user is trusted and gets
  `GATEWAY_ROLE`. There is no token, so there is no approver identity: approvals cannot be decided
  over stdio.
- **Streamable HTTP:** remote use. OAuth bearer tokens are required on every request; the server
  refuses to start without `OAUTH_ISSUER` and `OAUTH_JWKS_URL` (https, or http only on loopback or
  an explicitly allowed private host such as `keycloak` in Compose).

## Deployment

`docker compose up --build` runs `db`, `keycloak`, a one-shot `migrate` (Alembic as the schema
owner) and the `gateway` (non-root). The Compose file is a **demo**: placeholder credentials,
writes enabled, loopback-only ports. For production run the gateway behind TLS, provision the
four database roles with real secrets, run `alembic upgrade head` as a privileged job
(`GATEWAY_MIGRATE_CREATE_ROLES=0`), and use your own identity provider.

## Adding a connector

1. `connectors/<name>.py`: all I/O, fixed base URL, strict input validation, safe errors.
2. Pydantic input models in `tools/schemas.py`; handlers in `tools/handlers.py` that go through
   `_authorize` (identity + rate limit + role) and the audit calls.
3. Register the tools in `server.py`, add them to a risk tier and to roles in the policy, and give
   anything that sends data out of the gateway the `high` tier (add it to `DESTRUCTIVE_TOOLS`).
4. Tests: allow, deny, invalid input, upstream error, secret never leaks, hostile content.
