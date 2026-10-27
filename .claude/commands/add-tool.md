---
description: Add a new MCP tool following the project's security checklist
argument-hint: <tool_name> <one-line purpose>
---
Add a new MCP tool: $ARGUMENTS

Follow this checklist and report each item at the end:
1. Pydantic input model with strict validation and sensible length/size limits.
2. Register the tool in `server.py` (thin wrapper only) and implement logic in the right module.
3. Add it to a risk tier in `policies/policy.example.yaml` and to the roles that may call it.
4. Run it through the full pipeline: auth, policy, risk, approval gate (if high risk), connector, audit.
5. Audit record on allow, deny, and error. Arguments redacted.
6. Tests: allow path, deny path (wrong role, wrong table/column), invalid input, error path.
7. Run `uv run ruff check . && uv run mypy src && uv run pytest -q` and show the output.

Plan first and wait for my approval before editing.
