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
- `run_query` is not yet restricted to policy tables/schemas: it can read `pg_catalog` and any
  schema the DB role can see. The role's grants are the only limit until Phase 2.
- No identity: audit records carry no subject until Phase 3. The http transport refuses to start
  without `--insecure-dev` on a loopback host.
- `run_query` denies unknown functions (timeout overrides, advisory locks, `dblink`, `lo_*`).
  Responses are capped by rows and ~1 MB, but one huge value is still read into memory.
- Startup refuses a DB role with superuser, create-role/db, replication, bypass-RLS or any
  INSERT/UPDATE/DELETE/TRUNCATE grant.
- `UNION`/`INTERSECT` are denied (root must be a plain SELECT) until Phase 2.

## Out of scope (v1)
Multi-tenant isolation, network-level DDoS, compromised host or IdP.

## Review checklist
Run `/security-review` before every merge that touches `auth/`, `policy/`, `sqlguard/`,
`approvals/`, `connectors/`, or `audit/`.
