# Git workflow

## One-time setup
```bash
cd mcp-gateway
git init -b main
git add . && git commit -m "chore: initial scaffold"
# create an EMPTY repo on GitHub first (no README), then:
git remote add origin git@github.com:AbdulRehman19-bit/mcp-gateway.git
git push -u origin main
```
Or with the GitHub CLI: `gh repo create mcp-gateway --private --source=. --push`

Before the first commit, confirm `git status` does not list `.env` or any `*.pem`.

## Daily loop
```bash
git switch -c feat/sqlguard-select-only     # one branch per task
# ... work with Claude Code ...
uv run ruff check . && uv run mypy src && uv run pytest -q
git add -p && git commit -m "feat(sqlguard): reject multi-statement input"
git push -u origin feat/sqlguard-select-only
gh pr create --fill                         # open a PR even when working solo
```
Merge via squash after CI is green, then `git switch main && git pull`.

## Conventions
- Branches: `feat/...`, `fix/...`, `docs/...`, `chore/...`
- Commits: Conventional Commits
- Tag each finished phase: `git tag -a v0.2 -m "Phase 2: safety layer" && git push --tags`
- Commit **before** each big Claude Code prompt so you can roll back with `git restore` / `git switch`.
- Protect `main` on GitHub: require PR + passing CI.
- Never commit secrets. If one leaks, rotate it; deleting the commit is not enough.
