# CLAUDE.md — mcp-gateway

A secure MCP (Model Context Protocol) gateway. It sits between an AI assistant and a
PostgreSQL database (and later a business API such as GitHub or Jira) and enforces
**who can do what**, with **read-only mode, scoped permissions, human approval for risky
actions, and structured audit logs**.

The security layer is the product. Treat every change as security-relevant.

## Stack
- Python 3.12, managed with **uv** (never use bare `pip install`)
- Official `mcp` Python SDK, **pinned `<2`** (we use `FastMCP`; v2 renamed it to `MCPServer`.
  Migrate deliberately in its own PR). stdio transport for local dev, Streamable HTTP for remote
- OAuth 2.1: the gateway is a **resource server only**. It validates JWTs from an external
  IdP (Keycloak in Docker for dev). We never build our own authorization server
- PostgreSQL 16, SQLAlchemy 2 (async) + asyncpg, Alembic migrations
- `sqlglot` for SQL parsing, Pydantic v2 for all config and tool inputs, `structlog` for JSON logs
- Tests: pytest, pytest-asyncio, testcontainers. Lint/format: ruff. Types: mypy (strict on `src/`)

## Commands
```bash
uv sync                                  # install deps
uv run pytest -q                         # unit tests (fast, no Docker)
uv run pytest -m integration -q          # needs Postgres (docker compose up -d db)
uv run ruff check . && uv run ruff format --check .
uv run mypy src
docker compose up -d db                  # Postgres with demo data + RO/RW roles
docker compose --profile auth up -d      # adds Keycloak
uv run mcp-gateway --transport stdio     # run server locally
npx @modelcontextprotocol/inspector uv run mcp-gateway --transport stdio   # manual testing
```

## Layout
```
src/mcp_gateway/
  server.py        FastMCP app + tool registration (thin; no business logic)
  config.py        Settings (env vars via pydantic-settings)
  auth/            token validation, scope -> role mapping
  policy/          YAML policy models, loader, evaluator (pure functions)
  risk/            risk classifier (low / medium / high)
  sqlguard/        sqlglot-based SQL validation and rewriting
  approvals/       approval queue, state machine, decision API
  connectors/      postgres.py (and later github.py, jira.py)
  audit/           structured logging + audit table writer
policies/          policy YAML files (example committed; real ones are not)
tests/             mirrors src/ layout
docs/              ARCHITECTURE, THREAT_MODEL, ROADMAP, GIT_WORKFLOW, CLAUDE_CODE_GUIDE
```

## Request pipeline (do not reorder)
```
tool call -> authenticate -> resolve role -> policy check -> risk classify
          -> [approval gate if high risk] -> execute via connector -> audit
```
Every stage writes an audit record, **including denials and errors**.

## Hard rules (non-negotiable)
1. **No SQL string concatenation.** Use bound parameters. Identifiers must be validated against
   an allow-list from the policy and quoted with SQLAlchemy/psycopg identifier helpers.
2. `run_query` accepts **a single statement that parses as SELECT** (sqlglot). Reject multiple
   statements, DDL, DML, `COPY`, `SELECT ... INTO`, `FOR UPDATE`, and writes hidden in CTEs.
   Default-deny: anything we cannot positively classify as read-only is rejected.
3. **Defense in depth for read-only:** the read connection uses a DB role with SELECT-only
   grants and runs inside `SET TRANSACTION READ ONLY` with a `statement_timeout`.
   Application-level checks are never the only layer.
4. **Identity comes only from the validated token.** Never from tool arguments or prompts.
5. **Tool inputs, tool outputs, and database content are untrusted data.** They can never
   change permissions, skip approval, or alter the policy.
6. **Fail closed.** Missing policy, unknown role, unparseable SQL, expired token, or auth
   errors all result in denial.
7. **Approvals:** the requester cannot approve their own request. Approvals expire (TTL),
   are single-use, and are bound to a hash of the exact tool name and arguments.
8. **Secrets:** never log tokens, passwords, or full row data. Redact arguments before logging.
   Never read, print, or commit `.env`. Only `.env.example` is committed.
9. Every tool must (a) have a Pydantic input model, (b) be registered in the policy risk
   tiers, (c) emit an audit record, (d) have tests for allow, deny and error paths.
10. Do not weaken, skip, or delete a security test to make a build pass. Fix the code.

## Code style
- Small, typed, pure functions in `policy/`, `risk/`, `sqlguard/`. I/O lives in `connectors/`.
- Async everywhere on the request path. No blocking calls in tool handlers.
- Errors returned to the AI client are short and safe. Detailed reasons go to the audit log.
- Prefer boring, explicit code over clever abstractions. No new dependencies without saying why.
- Type hints on everything in `src/`. Docstrings for public functions explain *why*, not *what*.

## Testing expectations
- Every PR adds tests. Security code needs adversarial tests: multi-statement queries,
  comment tricks, CTE-wrapped writes, `pg_sleep`, `COPY`, unicode/case tricks, huge limits.
- Integration tests are marked `@pytest.mark.integration` and use the docker-compose Postgres.
- A change is not done until `ruff`, `mypy`, and `pytest` all pass. Run them and show results.

## Workflow for Claude (how to work in this repo)
1. For anything beyond a trivial edit, **start in plan mode**: list files to touch, the
   approach, risks, and tests. Wait for approval before editing.
2. Work on **one task per session**. Keep diffs small and focused.
3. Write or update tests first when practical, then implement, then run the checks.
4. Work on a feature branch (`feat/...`, `fix/...`, `docs/...`). Never commit to `main`.
   Never force-push. Never push without being asked.
5. Commit messages: Conventional Commits (`feat(policy): add column deny rules`).
6. When finished, summarize: what changed, what was tested, what is left, and any
   security-relevant assumptions.
7. If a requirement is ambiguous or a design choice affects security, **ask** instead of guessing.

## Current phase
Phase 3 — authentication (Streamable HTTP, JWT validation, Keycloak, scope -> role). See `docs/ROADMAP.md` for the phase list and acceptance criteria.
Update this line when a phase is completed.

## References
- MCP spec and authorization: https://modelcontextprotocol.io
- Python SDK: https://github.com/modelcontextprotocol/python-sdk
- Architecture: `docs/ARCHITECTURE.md` · Threats: `docs/THREAT_MODEL.md`
