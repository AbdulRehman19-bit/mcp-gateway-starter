# mcp-gateway

A secure **MCP gateway** that lets AI assistants interact with a PostgreSQL database (and later
business APIs) under strict control:

- **Scoped permissions:** YAML policy maps OAuth scopes to roles, then to schemas, tables and columns
- **Read-only mode:** global switch and per-role, enforced at the SQL and database level
- **Approval for risky actions:** high-risk calls wait for a different human to approve
- **Structured audit logs:** every allow, deny, and error is recorded with a request ID

> Status: Phase 0 (scaffolding). See [docs/ROADMAP.md](docs/ROADMAP.md).

## Quick start
```bash
uv sync
docker compose up -d db
cp .env.example .env
uv run pytest -q
npx @modelcontextprotocol/inspector uv run mcp-gateway --transport stdio
```

## Tools
`list_tables`, `describe_table` and `run_query` (single SELECT, row and size capped, statement
timeout) over stdio, using the SELECT-only `gateway_ro` role. What each call may see is decided
by the policy for `GATEWAY_ROLE` (default `analyst`): tables and columns outside it are
denied, `deny_columns` are unreachable and `mask_columns` come back as `***`.
Set `TARGET_DB_RO_URL` (see `.env.example`), run `docker compose up -d db`, then the Inspector
command above. If your DB volume predates Phase 2, run
`docker compose down -v && docker compose up -d db` so `gateway_ro` gets `SELECT (phone)`.

### HTTP + OAuth (Keycloak)
```bash
docker compose --profile auth up -d keycloak     # imports docker/keycloak/realm-mcp-gateway.json
uv run mcp-gateway --transport http              # needs OAUTH_ISSUER / OAUTH_JWKS_URL (.env.example)
TOKEN=$(curl -s http://localhost:8080/realms/mcp-gateway/protocol/openid-connect/token \
  -d grant_type=password -d client_id=mcp-gateway-dev \
  -d username=alice -d password=alice-dev-only -d scope=db:read | python -c "import sys,json;print(json.load(sys.stdin)['access_token'])")
```
Send it as `Authorization: Bearer $TOKEN` to `http://127.0.0.1:8000/mcp`. Dev users:
alice (`db:read` -> analyst), bob (`db:write` -> operator), carol (`approvals:decide` -> approver).
Dev only: the realm enables the password grant. A token must carry exactly one mapped scope.

## Docs
- [Architecture](docs/ARCHITECTURE.md) · [Threat model](docs/THREAT_MODEL.md) · [Roadmap](docs/ROADMAP.md)
- [Git workflow](docs/GIT_WORKFLOW.md) · [Using Claude Code](docs/CLAUDE_CODE_GUIDE.md)
- Developer rules for Claude Code: [CLAUDE.md](CLAUDE.md)

## Security
The demo credentials in `docker/initdb/` and `.env.example` are for local development only.
Never commit `.env` or real credentials.
