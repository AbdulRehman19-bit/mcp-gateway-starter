# Threat model (v1.0)

This is the single, consolidated model for the gateway. Every mitigation names the tests that
pin it, so a regression fails the build. Section 5 is the honest list of what is **not**
protected. Read it before deploying.

## 1. Assets, actors, trust boundaries

**Assets:** target-database contents (especially PII), the ability to write or delete data, the
ability to post to GitHub, the audit trail, OAuth tokens and the GitHub token.

**Actors**
- A legitimate but over-trusting AI assistant.
- A **prompt-injected** assistant: instructions hidden in data it read (database rows, GitHub
  issues) trying to make it call tools.
- A malicious or compromised MCP client holding a valid but low-privilege token.
- A curious or malicious insider (including an approver or a requester).
- A network attacker against the HTTP transport.

**Trust boundaries**
- *Trusted:* the gateway process, its policy file, the identity provider's signing keys, the
  database roles' grants, the operator.
- *Untrusted data:* tool arguments, tool results, database content, GitHub text. They can never
  change permissions, skip approval, or alter the policy (rule 5 in `CLAUDE.md`).
- *Identity* comes only from the validated token (HTTP) or server config (stdio). Never from
  arguments or prompts.

## 2. Threats, mitigations and the tests that prove them

Test paths are relative to `tests/`.

### SQL and data access
| # | Threat | Mitigation | Tests |
|---|---|---|---|
| T1 | Write, DDL or side effect smuggled into `run_query` (multi-statement, CTE-wrapped DML, `SELECT INTO`, `COPY`, `FOR UPDATE`) | Single-statement `SELECT` only (sqlglot), default deny; DB role is SELECT-only; `READ ONLY` transaction | `sqlguard/test_guard.py`, `sqlguard/test_analyze.py`, `connectors/test_postgres_integration.py` (writes blocked even without the guard) |
| T2 | Reading a denied column via `SELECT *`, aliases, joins, subqueries, CTEs, `ORDER BY`/`WHERE` oracles, whole-row refs (`SELECT users FROM users`), system columns | Columns are resolved against the role's allowed set (denied columns are absent); stars expanded; whole-row, `ctid`/`xmin` denied; alias column lists denied; the **rewritten** SQL is what runs | `sqlguard/test_analyze.py`, `test_e2e_stdio.py`, `test_e2e_http_auth.py` |
| T3 | Reading unmasked values of a masked column | Masked columns rewritten to `'***'` in the outermost projection only; any other use (predicate, join, aggregate, function) denied | `sqlguard/test_analyze.py`, `test_e2e_approvals.py` |
| T4 | Reading tables or schemas outside the policy (`pg_catalog`, `information_schema`, other schemas, table functions, `LATERAL`, `VALUES`, CTE shadowing) | Every table must resolve to an allowed `schema.table`; function/cast allow-list; recursive CTEs denied | `sqlguard/test_analyze.py` |
| T5 | Resource exhaustion (`pg_sleep`, `generate_series`, `repeat`, huge `LIMIT`, deep nesting, many joins, huge responses) | Function and cast allow-list; join/nesting caps; `LIMIT` clamped (`ALL`, `FETCH`, negatives included); statement timeout; 1 MB response cap | `sqlguard/test_guard.py`, `sqlguard/test_analyze.py`, `connectors/test_postgres_integration.py` |
| T6 | Overriding protections from inside a query (`set_config('statement_timeout',...)`, advisory locks, `dblink`, `lo_*`, `::regclass`) | Typed and untyped functions default-deny; casts limited to plain types | `sqlguard/test_guard.py`, `sqlguard/test_analyze.py` |

### Writes
| # | Threat | Mitigation | Tests |
|---|---|---|---|
| T7 | Writing a column or table the role may not, SQL/identifier injection in writes | Policy `writable_columns`/`deletable`; primary key never writable; one row by single-column PK; SQLAlchemy Core (quoted identifiers, bound values); supported types only; DB role has column-level grants as a second layer | `test_write_tools.py`, `connectors/test_write_integration.py` (hostile identifiers, DB grants) |
| T8 | Writes while read-only is on | Refused if the global switch OR the role is read-only; writes need the RW role, the approval store and the audit DB configured or the server will not start | `test_write_tools.py`, startup checks in `server.py` |
| T9 | A write that touches more than one row or half-applies | Exactly one affected row or rollback; `dry_run` rolls back | `connectors/test_write_integration.py` |

### Authentication and identity
| # | Threat | Mitigation | Tests |
|---|---|---|---|
| T10 | Forged, tampered, expired or wrong-audience token; `alg: none`; HS256-with-public-key; key/alg mismatch | RS256/ES256 only, algorithm from our allow-list; signature, `iss`, exact `aud`, `exp`, `iat`, `sub` required; `nbf` enforced; 30 s skew; 8 KB cap; `kid` required | `auth/test_validator.py`, `auth/test_verifier.py`, `test_e2e_http_auth.py` |
| T11 | Malicious or unavailable JWKS (SSRF, redirects, oversized or slow responses, kid spraying, revoked-key reuse) | https (http only on loopback or an explicitly allowed host); no credentials or private IP literals; no redirects; 10 s deadline; 256 KB streamed cap; ≤1 refresh/min; keys unusable after 10 min if the IdP is unreachable | `auth/test_jwks.py` |
| T12 | Privilege escalation by claiming a role (arguments, headers, ambiguous scopes) | Role = exactly one mapped scope from the validated token; none or several = denied | `auth/test_roles.py`, `test_e2e_http_auth.py` |
| T13 | Stale or shared identity (a downgraded/expired token keeps working; one user's role leaks to another) | Stateless HTTP; identity resolved from each request's own token; expiry re-checked at call time | `test_server.py` (regression: fails in stateful mode), `test_e2e_http_auth.py` (concurrent users) |
| T14 | Unauthenticated access over HTTP | Bearer token required on every request; server refuses to start without IdP settings; failed auth is audited | `test_e2e_http_auth.py` |

### Approvals
| # | Threat | Mitigation | Tests |
|---|---|---|---|
| T15 | Requester approves their own request | Refused in the atomic `UPDATE` **and** by a table CHECK constraint; policy cannot disable it | `test_write_tools.py`, `db/test_gateway_db.py`, `test_e2e_approvals.py` |
| T16 | Approval replay, reuse for other arguments/tool/user, use after expiry or denial | Bound to SHA-256 of canonical `{tool,args}` plus requester; single-use; DB-clock expiry; trigger allows only legal transitions (a spent approval cannot be revived) | `approvals/test_hashing_and_state.py`, `db/test_gateway_db.py`, `test_write_tools.py`, `test_github_tools.py` |
| T17 | Race: two callers spend or decide the same approval | One atomic `UPDATE ... WHERE <guards> RETURNING`; exactly one winner | `db/test_gateway_db.py` (25 concurrent consumers, 20 concurrent deciders, 15 concurrent creators) |
| T18 | An approver decides requests they should not | `approves_roles` scoping enforced in the SQL and in listing; a decider role with no scope is a policy error | `test_write_tools.py`, `db/test_gateway_db.py` |
| T19 | A compromised gateway rewrites approvals (hash, requester, expiry, state) | Column-limited `UPDATE` grant plus a guard trigger that also binds the table owner | `db/test_gateway_db.py` |
| T20 | Queue flooding hides legitimate requests | ≤5 live approvals per requester; paged `list_approvals` with totals; rate limits | `test_write_tools.py`, `db/test_gateway_db.py` |
| T21 | High-risk action without approval via policy mistakes | Unknown tool = high; `delete_record`, `bulk_update`, `github_add_comment` floored to high in code; a tool in two tiers is a load error; highest tier wins | `risk/test_classifier.py`, `test_github_tools.py` |

### Audit, logging and secrets
| # | Threat | Mitigation | Tests |
|---|---|---|---|
| T22 | Sensitive data in logs or audit rows (tokens, SQL text, written values, comment bodies, DSNs) | Redaction before logging and storage; SQL hashed; `changes` keeps names only; `body` dropped; secrets are `SecretStr`; errors carry only exception types | `audit/test_logging.py`, `test_write_tools.py`, `test_github_tools.py`, `test_e2e_approvals.py`, `connectors/test_github.py` |
| T23 | Audit tampering or silent loss | Audit role is INSERT-only (no read/update/delete/truncate); app role cannot touch `audit_log`; `allow` record durable **before** a write runs, else the write is refused; pending approvals that cannot be audited are cancelled | `db/test_gateway_db.py`, `test_write_tools.py` |
| T24 | Misconfigured database roles silently defeat the above | Startup refuses unless ro/rw/approvals/audit are four distinct users with exactly the expected privileges (no superuser, no table owner) and the schema is at the Alembic head | `test_startup_checks.py`, `db/test_gateway_db.py` (probes against the real roles) |

### Abuse and external systems
| # | Threat | Mitigation | Tests |
|---|---|---|---|
| T25 | A runaway or malicious client hammers the DB, GitHub or the approval queue | Per-user, per-tool token buckets from the policy (dry runs count); bounded memory | `ratelimit/test_limiter.py`, `test_rate_limit.py` |
| T26 | Flood of bad tokens fills the audit table | Failed-auth audit writes budgeted (burst 100, 600/min) and summarised; successful logins never throttled | `test_rate_limit.py` |
| T27 | Prompt injection through issue text or database content causing a risky call | All third-party text is capped, cleaned and wrapped in an `untrusted_content` envelope; it cannot change permissions, approvals or policy; risky tools still need a different human | `connectors/test_github.py`, `test_github_tools.py` |
| T28 | Data exfiltration through `github_add_comment` | High risk (always approved by a different human who sees the exact text); body bound into the approval hash; comment body never audited; repo allow-list | `test_github_tools.py` |
| T29 | Access to repositories outside the allow-list, SSRF or path tricks via `owner/repo` | Exact allow-list checked before any request; strict name regex in schema, policy and connector; fixed API base URL; path segments encoded; redirects never followed; probing looks identical to "unknown" | `connectors/test_github.py`, `test_github_tools.py` |
| T30 | Misconfigured policy widens access | Strict schema (`extra=forbid`), validation of references, fail closed on load error, `require_different_approver` not configurable | `test_policy.py`, `risk/test_classifier.py`, `test_rate_limit.py` |
| T31 | The demo stack mistaken for a safe deployment | Loopback-only ports, no `.env` needed, placeholder credentials clearly labelled, README and `SECURITY.md` warnings; tested statically | `test_compose.py` |

## 3. Defence in depth, in one picture

A write has to clear, independently: a valid token with one mapped scope, the rate limit, the
role's tool list, read-only mode, the table/column policy, the risk tier, a human's approval
bound to these exact arguments, a durable audit record, and finally a database role that
itself refuses anything outside its grants. Reads clear the same chain minus approval, then hit a
SELECT-only role in a `READ ONLY` transaction with a timeout.

## 4. Review process

- `/security-review` (the `security-reviewer` agent) after every change touching `auth/`,
  `policy/`, `sqlguard/`, `approvals/`, `connectors/`, `audit/` or the migrations. Each phase had
  an independent adversarial review; findings and fixes are in the git history. Examples of what
  those reviews caught: a whole-row reference bypassing column deny, the statement timeout being
  overridable from inside a query, stale identity inside a session, the approvals table being
  fully writable by the app role, and approvers unable to see requests past the first page.
- CI runs lint, types, unit tests, a Postgres integration job, and `pip-audit` on the
  dependencies.

## 5. Residual risks (not protected, or only partly)

Decide consciously about each before production.

| # | Risk | Why it remains | Mitigation / next step |
|---|---|---|---|
| R1 | **Single process, in-memory rate limits.** Several gateway replicas each enforce their own limits; limiter state resets on restart. | No shared store in v1. | Put a shared limiter (Redis) or front proxy limits in front; keep one replica. |
| R2 | **Approvers see real arguments** of every request in their scope, and those are stored in `approvals.args` until used/denied (and for expired rows). | An approver cannot judge what they cannot see. | Keep `approves_roles` narrow; the gateway DB is access-controlled; stored args are cleared on use/denial. |
| R3 | **No server-side revocation.** A revoked user keeps access until the access token expires (5 min in the demo realm). | Stateless JWT validation by design. | Short token lifetimes; revoke at the IdP. |
| R4 | **IdP scopes are not bound to users in the demo realm** (any client may request any optional scope; password grant). | Dev convenience. | In production bind scopes to users/roles at your IdP. |
| R5 | **`dry_run` has side effects** the database does not roll back (sequence values, trigger side effects) and is an existence oracle for a primary key. | It runs the real statement, then rolls back. | Rate-limited; restrict who has write tools; avoid side-effecting triggers on writable tables. |
| R6 | **Audit rows are not hash-chained.** A database superuser can edit them. | INSERT-only roles stop the gateway, not the DBA. | Ship `audit_log` and the JSON logs to storage the gateway and DBA cannot alter. |
| R7 | **Outcome audit records are best-effort.** After the durable `allow` record, the `success`/`error` record can be lost if the audit DB drops mid-call. | Availability trade-off for reads/denials. | The JSON log still has it; monitor `audit_write_failed`. |
| R8 | **Requests with a missing/invalid Authorization header** are rejected by the MCP SDK before our verifier runs, so they are not individually audited. | SDK behaviour. | Log at your reverse proxy. |
| R9 | **At-most-once execution:** the approval is spent before the write runs; if the write fails, a new approval is required. | Prevents double execution. | Documented behaviour. |
| R10 | **Masked values are text** (`'***'`) regardless of column type; the table catalog is read at startup, so new columns are denied until restart. | Simplicity and fail-closed. | Restart after schema changes. |
| R11 | **Prompt injection is mitigated, not solved.** Marking text untrusted helps a well-behaved client; a model can still be talked into *asking* for something. | Models cannot be made injection-proof. | The controls bound the damage: role limits, read-only default, approval by a human who sees the exact action, rate limits. |
| R12 | **One human with two accounts** can approve their own request. | Identity is whatever the IdP says. | Enforce one account per person at the IdP; review approval logs. |
| R13 | **GitHub token scope** is outside the gateway's control. | A broad PAT is broader than the repo allow-list implies. | Use a fine-grained token limited to the listed repositories (Issues only). |
| R14 | **DNS-rebinding protection is off when binding to `0.0.0.0`** (the container default). | MCP SDK behaviour for non-loopback hosts. | Publish on loopback or put TLS and a trusted proxy in front. |
| R15 | **The demo migration creates login roles with placeholder passwords** unless `GATEWAY_MIGRATE_CREATE_ROLES=0`. | Dev convenience. | Pre-create the roles with real secrets in production. |

## 6. Out of scope (v1)

Multi-tenant isolation, network-level DDoS, a compromised host, database superuser or identity
provider, side channels (timing), and protection of data once an authorized user has read it.

## 7. Review checklist for changes

Run `/security-review` before merging anything that touches `auth/`, `policy/`, `sqlguard/`,
`approvals/`, `connectors/`, `audit/`, or `migrations/`. A new tool needs: a Pydantic input
model, a risk tier (anything that sends data out is `high`), a policy entry, an audit record on
allow/deny/error, and tests for the allow, deny, invalid-input and error paths.
