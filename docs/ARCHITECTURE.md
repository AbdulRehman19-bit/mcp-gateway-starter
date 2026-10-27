# Architecture

```
AI client
   │  MCP (stdio locally, Streamable HTTP remotely)
   ▼
FastMCP server (server.py)            thin: registration only
   ▼
Auth middleware (auth/)               validate JWT -> identity + scopes
   ▼
Policy engine (policy/)               scopes -> role -> allowed tools / schemas / tables / columns
   ▼
Risk classifier (risk/)               low | medium | high
   ▼
Approval gate (approvals/)            high risk -> pending_approval, stored, needs a different human
   ▼
SQL guard (sqlguard/)                 sqlglot: single SELECT only for reads; identifier allow-list
   ▼
Connector (connectors/postgres.py)    RO role for reads, RW role for allowed writes
   ▼
Target database

Audit logger (audit/) records every stage: allow, deny, error, approval events.
```

## Design principles
- **Default deny.** Unknown role, tool, table, or column means denied.
- **Defense in depth.** App-level SQL checks, a SELECT-only DB role, READ ONLY transactions,
  statement timeouts, and row limits all apply independently.
- **Identity from the token only.**
- **Pure core, impure edges.** Policy, risk, and sqlguard are pure functions and easy to test.
- **Everything is audited**, including denials.

## Data model (gateway DB)
- `audit_log(id, ts, request_id, subject, role, tool, args_redacted, risk, decision, reason, duration_ms)`
- `approvals(id, created_at, expires_at, requester, tool, args_hash, args_redacted, status,
  decided_by, decided_at, used_at)`

## Transports
- **stdio:** local development and the Inspector. No OAuth (the local user is trusted).
- **Streamable HTTP:** remote use. OAuth required.
