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

## Docs
- [Architecture](docs/ARCHITECTURE.md) · [Threat model](docs/THREAT_MODEL.md) · [Roadmap](docs/ROADMAP.md)
- [Git workflow](docs/GIT_WORKFLOW.md) · [Using Claude Code](docs/CLAUDE_CODE_GUIDE.md)
- Developer rules for Claude Code: [CLAUDE.md](CLAUDE.md)

## Security
The demo credentials in `docker/initdb/` and `.env.example` are for local development only.
Never commit `.env` or real credentials.
