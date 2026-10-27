# Threat model (living document)

**Assets:** target-database contents (especially PII), the ability to write data, the gateway's
audit trail, OAuth tokens.

**Actors:** a legitimate but over-trusting AI assistant, a prompt-injected assistant (instructions
hidden in data it read), a malicious or compromised client, a curious insider.

| # | Threat | Mitigation | Test |
|---|--------|------------|------|
| 1 | Write or DDL hidden in `run_query` (multi-statement, CTE writes, `SELECT INTO`, `COPY`) | sqlglot allow-only-SELECT, default deny, SELECT-only DB role, READ ONLY transaction | Phase 2 adversarial suite |
| 2 | Reading denied columns via `SELECT *`, aliases, joins, subqueries | Column-level policy evaluation on the parsed AST; DB column grants as second layer | Phase 2 |
| 3 | Resource exhaustion (huge result, `pg_sleep`, heavy joins) | Row cap, statement timeout, function deny-list | Phase 2 |
| 4 | Prompt injection via DB content causing a risky tool call | Risky tools need human approval; permissions come from the token, never from content | Phase 4 |
| 5 | Privilege escalation by claiming a role in tool args | Role derived only from validated token scopes | Phase 3 |
| 6 | Token theft or replay | Short-lived tokens, audience check, TLS, no token logging | Phase 3 |
| 7 | Self-approval or approval replay | Different approver required; approvals single-use, expiring, bound to args hash | Phase 4 |
| 8 | Sensitive data leaking into logs | Argument redaction, never log rows or tokens | Phase 4 |
| 9 | Audit tampering | Append-only table, separate DB role with INSERT-only rights | Phase 4 |
| 10 | Misconfigured policy widens access | Strict schema (`extra=forbid`), fail closed on load error, policy review in PRs | Phase 0 |

## Phase 1 residual risks (read-only server, no auth)
- No identity: the role comes from server config (`GATEWAY_ROLE`), not a token, until Phase 3.
  Audit records carry that role but no subject. The http transport refuses to start without
  `--insecure-dev` on a loopback host.
- `run_query` denies unknown functions (timeout overrides, advisory locks, `dblink`, `lo_*`).
  Responses are capped by rows and ~1 MB, but one huge value is still read into memory.
- Startup refuses a DB role with superuser, create-role/db, replication, bypass-RLS or any
  INSERT/UPDATE/DELETE/TRUNCATE grant.

## Phase 4 writes, approvals and audit
- Writes are OFF by default (`GATEWAY_READ_ONLY=true`). Turning them on requires the write
  role, the approval store and the durable audit trail (startup refuses otherwise). A write is
  refused if the global switch OR the role is read-only, and the DB role is a second layer
  (column-level UPDATE grants; DELETE only on `orders`; no superuser/createrole/bypassrls).
- `update_record` / `delete_record`: one row by single-column primary key, policy-listed
  `writable_columns` / `deletable` tables only, supported column types only. SQL comes from
  SQLAlchemy Core constructs (identifiers quoted, values bound). Anything but exactly one
  affected row rolls back. `dry_run` executes then rolls back; sequences/triggers are not
  rolled back, and it still needs the write role and policy checks.
- Risk: unknown tool = high. High risk always needs approval; a role may also require it for
  lower tiers (`approval_required`).
- Approvals: bound to SHA-256 of canonical {tool, args}, the requester and the exact call;
  expire by the DB clock; single-use. Every transition is one atomic `UPDATE ... WHERE
  <guards> RETURNING`, so concurrent consumers or deciders get exactly one winner (tested with
  25 concurrent consumers). The requester cannot decide: refused in the UPDATE and again by a
  CHECK constraint, and `require_different_approver` cannot be disabled in policy.
- Consume happens BEFORE execute (at-most-once): if the write then fails, the approval is
  spent and a new one is needed. An approval can never run twice.
- Approvers see the real arguments (stored in the gateway DB, access-controlled). Logs and
  audit rows keep column NAMES only for `changes`; SQL is hashed; secrets are redacted.
- Audit: JSON log plus `audit_log` row for every stage. The `allow` record is persisted before
  a write runs; if it cannot be, the write is refused. Reads/denials degrade to the JSON log
  if the audit DB is down. The audit role is INSERT-only (tested), so a compromised gateway
  cannot rewrite history; approvals role cannot touch audit_log or delete approvals.
- Hardening from review (migration 0002): `gateway_app` may update only the decision/usage
  columns of `approvals` (never `args_hash`, `requester`, `tool`, `expires_at`); a trigger
  allows only pending->approved|denied and approved->used|denied, binds the table owner too,
  and forbids editing identity columns; a partial unique index allows one live approval per
  (requester, exact call), so concurrent identical requests collapse to one row. A requester
  may hold at most 5 live approvals (queue flooding); stale rows are retired on the next
  create. Stored arguments are cleared once an approval is used or denied. A pending approval
  whose audit record cannot be written is cancelled; an audit outage before execution does not
  spend an approval (the record is written before the approval is consumed).
- Policy: a tool in two risk tiers is a load error; `delete_record`/`bulk_update` must be high
  and are floored to high in code; the highest tier wins on any overlap. The primary key is
  never a writable column.
- Startup refuses to run unless the schema is at the Alembic head, ro/rw/approvals/audit are
  four different DB users, the audit role can only INSERT into `audit_log`, the approvals role
  has no rights on `audit_log` and cannot DELETE/TRUNCATE approvals, none of them is a
  superuser/owner, and the write role is not an admin or table owner. Dry runs set a 2 s
  `lock_timeout` so repeated calls cannot queue on a hot row.
- Residual (decisions for later): approvers see real arguments of every pending request and any
  `decide_approval` holder can decide any request (no per-role/table approver scoping yet);
  `dry_run` still fires triggers/sequences and is an existence oracle for a primary key, and
  has no rate limit (Phase 5); failed-auth audit inserts are unthrottled; `success`/`error`
  outcome records are best effort if the audit DB drops after the durable `allow` record;
  audit rows are not hash-chained, so a DB superuser can still edit them; migration 0001
  creates dev login roles with placeholder passwords unless `GATEWAY_MIGRATE_CREATE_ROLES=0`.
- `approval_id` is a UUID; error text is generic ("Approval not valid") and the reason goes to
  the audit log only. A medium tool ignores an unrelated `approval_id` (it does not consume it).

## Phase 3 authentication (resource server only)
- Tokens: RS256/ES256 only, algorithm taken from our allow-list (never the token), signature,
  `iss`, exact `aud`, `exp`, `iat`, `sub` required, `nbf` enforced, 30 s skew, 8 KB cap, `kid`
  required. `alg: none`, HS256-with-public-key and key/alg mismatches are denied (tested).
- Keys: JWKS and issuer URLs must be https (http only on loopback), no credentials in the URL,
  no private/link-local IP literals; no redirects, 10 s total deadline, 256 KB streamed cap;
  cached 5 min; an unknown `kid` refreshes at most once per 60 s; unreachable and >10 min
  stale keys deny.
- Sessions: the HTTP transport is stateless. Every request is authenticated and its identity
  resolved from its own token, and expiry is re-checked at call time. (Stateful mode let a
  tool call inherit the identity of the request that opened the session, so a downgraded or
  expired token kept its old role; a regression test pins this.)
- Role: only from token scopes via `scope_to_role`. No mapped scope, or scopes mapping to more
  than one role, is denied (roles are not strictly ordered, so we do not guess). Tool arguments
  and headers never choose a role.
- Every request carries its own identity (contextvar set by the SDK's bearer middleware);
  no identity means deny. Audit records carry `subject` and `role`; tokens are never logged.
- stdio remains the only no-token mode: the local user is trusted and gets `GATEWAY_ROLE`.
  The http transport refuses to start without `OAUTH_ISSUER` and `OAUTH_JWKS_URL`.
- Residual: the dev Keycloak realm uses the password grant and lets any client request any
  optional scope. Production must bind scopes to users/roles at the IdP. Revocation is only
  as fast as token expiry (5 min in the dev realm). Unmapped-scope tokens get 401, not 403.
- Residual: requests with a missing or non-Bearer Authorization header are rejected by the SDK
  (401) before our verifier runs, so they are not audited; failed-auth audit lines are not
  rate limited. With `GATEWAY_HOST=0.0.0.0` the SDK's DNS-rebinding protection is off, so put
  TLS and a trusted proxy in front.

## Phase 2 safety layer (policy enforcement in `sqlguard/analyze.py`)
- Every query is re-qualified by sqlglot against the role's allowed columns and the SQL that
  runs is regenerated from the validated AST. Tables outside the policy (including
  `pg_catalog`, `information_schema`, other schemas), table functions, `LATERAL`/`VALUES`/
  `UNNEST`, recursive CTEs and whole-row references (`SELECT users FROM users`) are denied.
- Denied columns are absent from the schema the analyzer sees, so they cannot be referenced in
  any clause. `SELECT *` is expanded to allowed columns only.
- Masked columns are rewritten to `'***'` in the outermost projection; any other use
  (predicate, join, aggregate, function, subquery) is denied, which closes oracle attacks.
- `LIMIT` is always replaced by `min(requested, max_rows)`; `LIMIT ALL`, `FETCH FIRST` and
  negative or non-literal limits become the cap.
- Functions are default-deny by type and name (no `version()`, `current_user`, `repeat()`,
  `generate_series()`, `pg_*`, `set_config`); casts only to a short list of plain types (so
  no `::regclass` existence oracle). Column alias lists on tables (`users AS u(a,b,c)`),
  `NATURAL JOIN`, `TABLESAMPLE`, more than 4 joins and deep nesting are denied.
  `statement_timeout` remains the backstop for cost.
- Residual: `(SELECT ...) UNION (SELECT ...)` with parenthesised branches is denied (usability).
- Residual: the catalog is read once at startup, so a column added later is unknown and
  therefore denied until restart. Masked values are text (`'***'`) whatever the column type.
  An alias shared by several tables over-denies rather than risk a leak.

## Out of scope (v1)
Multi-tenant isolation, network-level DDoS, compromised host or IdP.

## Review checklist
Run `/security-review` before every merge that touches `auth/`, `policy/`, `sqlguard/`,
`approvals/`, `connectors/`, or `audit/`.
