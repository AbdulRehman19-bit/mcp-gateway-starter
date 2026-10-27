# mcp-gateway

A secure **MCP gateway** that sits between an AI assistant and your systems (PostgreSQL and
GitHub today) and enforces **who can do what**:

- **Scoped permissions:** a YAML policy maps OAuth scopes to roles, then to tools, schemas,
  tables and columns. Default deny.
- **Read-only by default:** a global switch plus per-role read-only, enforced in the SQL
  analyzer *and* by a SELECT-only database role inside a `READ ONLY` transaction.
- **Column deny and masking:** denied columns cannot be reached by any query shape; masked
  columns come back as `***` (rewritten in the SQL, so the real value never leaves the database).
- **Human approval for risky actions:** a high-risk call returns `pending_approval`; a
  *different* person approves; it then runs exactly once, only for those exact arguments.
- **Structured audit trail:** every allow, deny and error is logged as JSON and stored in an
  append-only `audit_log` table (who, tool, redacted arguments, risk, decision, duration).
- **Rate limits** per user and per tool, set in the policy.

> **Status: v1.0.** The gateway is a *resource server only*: it validates JWTs from your
> identity provider (Keycloak in the demo) and never issues tokens. Read
> [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) before putting it in front of real data: it lists
> exactly what is and is not protected.

## Architecture

```mermaid
flowchart LR
    AI["AI client<br/>(Claude, Inspector, ...)"] -->|"MCP over stdio<br/>or Streamable HTTP + Bearer JWT"| GW

    subgraph GW["mcp-gateway"]
        direction TB
        A["1 Authenticate<br/>JWT: alg, iss, aud, exp, signature"] --> R["2 Resolve role<br/>scope → role (token only)"]
        R --> L["3 Rate limit<br/>per user + tool"]
        L --> P["4 Policy<br/>tool, table, column"]
        P --> K["5 Risk classify<br/>low / medium / high"]
        K --> G{"6 Approval gate<br/>high risk?"}
        G -->|"pending_approval"| Q[("approvals<br/>single-use, expiring,<br/>bound to args hash")]
        G -->|"approved or low/medium"| X["7 Execute via connector"]
        X --> U["8 Audit"]
    end

    IDP["Identity provider<br/>(Keycloak)"] -. "JWKS (signing keys)" .-> A
    X -->|"SELECT-only role,<br/>READ ONLY txn, timeout"| PG[("Target PostgreSQL")]
    X -->|"limited RW role, 1 row,<br/>bound params"| PG
    X -->|"allow-listed repos only"| GH["GitHub API"]
    U --> AL[("gateway DB<br/>audit_log: INSERT-only")]
    Q --- GDB[("gateway DB<br/>approvals")]
```

Every stage writes an audit record, **including denials and errors**. Details:
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Quick start (about 3 minutes)

You need [Docker](https://docs.docker.com/get-docker/) and [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/AbdulRehman19-bit/mcp-gateway-starter.git
cd mcp-gateway-starter

docker compose up --build -d     # Postgres, Keycloak, migrations, the gateway
# Keycloak needs ~40 s on first start. Wait until this prints 200:
curl -s -o /dev/null -w "%{http_code}\n" \
  http://localhost:8080/realms/mcp-gateway/.well-known/openid-configuration

uv sync
uv run python scripts/demo.py    # the guided demo (below)
```

No `.env` file is needed: the Compose stack carries dev-only placeholder credentials, publishes
every port on `127.0.0.1` only, and enables writes so the approval demo works. **Do not reuse it
for anything real.** Stop and wipe it with `docker compose down -v`.

### What the demo shows

It logs in as three Keycloak users and calls the gateway over HTTP with real bearer tokens:

| User | Role | What happens |
|---|---|---|
| **alice** | analyst | Reads orders; `users.phone` comes back as `***`; `SELECT email`, `SELECT users FROM users` and `SELECT * FROM pg_roles` are all denied. |
| **bob** | operator | A dry-run delete changes nothing. A real `delete_record` returns `pending_approval`, and the row is still there. He cannot approve his own request. |
| **carol** | approver | Lists the pending request with its real arguments and approves it. Approving executes nothing by itself. |
| **bob** again | operator | Repeats the *same* call with the `approval_id`: it executes once. A different `pk`, or a replay, is refused. |

Finally it prints the audit trail for those calls. The script exits non-zero if any step behaves
differently from what is documented here, so it also works as a smoke test. To record the GIF
yourself: `vhs docs/demo.tape` (needs [vhs](https://github.com/charmbracelet/vhs)).

### Try it by hand

```bash
# a token for alice (analyst); users: alice db:read, bob db:write, carol approvals:decide
TOKEN=$(curl -s http://localhost:8080/realms/mcp-gateway/protocol/openid-connect/token \
  -d grant_type=password -d client_id=mcp-gateway-dev \
  -d username=alice -d password=alice-dev-only -d scope=db:read \
  | python -c "import sys,json;print(json.load(sys.stdin)['access_token'])")

npx @modelcontextprotocol/inspector   # URL http://127.0.0.1:8000/mcp,
                                      # header  Authorization: Bearer <TOKEN>
```

A token must carry **exactly one** mapped scope; the role comes only from the token, never from
tool arguments. For a quick local run without a token, use stdio (a trusted local user with the
`GATEWAY_ROLE` from `.env`, read-only by default):

```bash
cp .env.example .env && docker compose up -d db
npx @modelcontextprotocol/inspector uv run mcp-gateway --transport stdio
```

## Tools

| Tool | Risk | What it does |
|---|---|---|
| `list_tables`, `describe_table` | low | What your role may see (masked columns are flagged). |
| `run_query` | low | One `SELECT`, rewritten to your allowed columns, row- and size-capped, with a statement timeout. |
| `update_record` | medium | Update **one** row by primary key, only policy-listed columns. `dry_run` rolls back. |
| `delete_record` | **high** | Delete one row. Always needs a different human's approval. |
| `list_approvals`, `decide_approval` | approver | Review and decide requests from the roles you cover (`approves_roles`). Never your own. |
| `github_list_issues`, `github_get_issue` | low | Read issues of allow-listed repos. Text is marked **untrusted** and capped. |
| `github_add_comment` | **high** | Comment on an issue. Always needs approval (a comment can publish data). |
| `ping` | n/a | Health check for an authenticated caller. |

GitHub needs a `GITHUB_TOKEN` (fine-grained, limited to the policy's repos); reads of public
repos work without one, writes do not.

## Configuration

Everything about *who can do what* lives in [policies/policy.example.yaml](policies/policy.example.yaml)
(copy it, point `GATEWAY_POLICY_PATH` at your copy): scope→role mapping, per-role tools and
tables/columns (`deny_columns`, `mask_columns`, `writable_columns`, `deletable`), risk tiers,
approval TTL, `approves_roles`, rate limits and the GitHub repo allow-list. A bad policy stops
the server from starting. Environment variables are listed in [.env.example](.env.example); the
safe defaults are read-only mode and no write credentials.

For real use, bring your own identity provider (`OAUTH_ISSUER`, `OAUTH_JWKS_URL`, exact
`OAUTH_AUDIENCE`), real secrets, TLS in front, and run migrations as a separate privileged step:

```bash
GATEWAY_DB_ADMIN_URL=postgresql+asyncpg://<owner>@<host>/gateway uv run alembic upgrade head
```

## Develop

```bash
uv sync
uv run pytest -q                          # unit tests, no Docker (500+)
docker compose up -d db keycloak          # then:
GATEWAY_DB_ADMIN_URL=postgresql+asyncpg://postgres:postgres-dev-only@localhost:5432/gateway \
  uv run alembic upgrade head
uv run pytest -m integration -q           # real Postgres + Keycloak end-to-end tests
uv run ruff check . && uv run ruff format --check . && uv run mypy src
```

Security code gets adversarial tests (multi-statement queries, CTE-wrapped writes, whole-row
references, alias lists, `pg_sleep`, `::regclass`, algorithm confusion, replayed and tampered
approvals, concurrent consumers, ...). Do not weaken or delete one to make a build pass; see
[CLAUDE.md](CLAUDE.md) for the project rules.

## Docs

- [Architecture](docs/ARCHITECTURE.md) · [Threat model](docs/THREAT_MODEL.md) · [Roadmap](docs/ROADMAP.md)
- [Git workflow](docs/GIT_WORKFLOW.md) · [Using Claude Code](docs/CLAUDE_CODE_GUIDE.md)
- [Security policy](SECURITY.md) · [License](LICENSE) (MIT)

## Security

The demo credentials in `docker-compose.yml`, `docker/initdb/` and `.env.example` are for local
development only. Never commit `.env` or real credentials. Report vulnerabilities privately; see
[SECURITY.md](SECURITY.md).
