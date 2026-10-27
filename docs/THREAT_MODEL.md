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
