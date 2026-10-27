---
description: Run the full verification suite and summarize
---
Run, in order, and show the real output of each:
1. `uv run ruff check .`
2. `uv run ruff format --check .`
3. `uv run mypy src`
4. `uv run pytest -q`

If anything fails, fix the root cause (never weaken or delete a test), then re-run until clean.
Finish with a short summary: what failed, what you changed, and the final status.
