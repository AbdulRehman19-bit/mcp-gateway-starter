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
