# Using Claude Code on this project

## Setup
1. Install Claude Code and run `claude` inside the repo root. It reads `CLAUDE.md` automatically
   every session, so keep that file accurate and short.
2. `.claude/settings.json` is committed: it pre-approves safe commands (tests, lint, git status/diff),
   denies reading `.env` and `*.pem`, denies `rm -rf`, force-push and `curl`, and runs `ruff` after edits.
   Put personal overrides in `.claude/settings.local.json` (git-ignored).
3. Slash commands live in `.claude/commands/`: `/plan-phase <n>`, `/add-tool <name> <purpose>`,
   `/security-review`, `/verify`. The `security-reviewer` subagent lives in `.claude/agents/`.

## The loop for every task
1. **Clean start.** `git switch -c feat/<task>` and commit anything pending. `/clear` if the previous
   task was unrelated.
2. **Plan mode** (Shift+Tab to cycle modes). Ask for the plan: files, approach, risks, tests.
   Read it, correct it, approve it.
3. **Implement with a verification loop.** Tell it how to check itself:
   "write the tests first, implement, run `uv run pytest -q` and `uv run mypy src`, fix failures."
4. **Review the diff** (`git diff`). Treat output like a junior developer's PR, especially in
   `auth/`, `sqlguard/`, `policy/`, `approvals/`.
5. **Run `/security-review`** on security-sensitive changes.
6. **Commit, push, open a PR.** Merge when CI is green.

## Habits that matter
- **One task per session.** `/clear` between tasks; `/compact` if a long session slows down.
- **Be specific:** name files, inputs, outputs, and acceptance criteria. "Build auth" is too vague;
  "add JWT validation in `auth/tokens.py` (issuer, audience, signature, expiry, RS256 only) with tests
  for each rejection case" works.
- **Give it examples of what must be rejected.** Adversarial cases are the best prompts for security code.
- **Commit before every big prompt** so any bad run is one `git restore` away.
- **Keep permissions tight.** Approve prompts for anything that deletes, pushes, or touches the network.
  Never let it read real secrets.
- **Update `CLAUDE.md` when it repeats a mistake.** Add the rule once instead of correcting it every time.
- **Don't trust, verify.** Passing tests do not prove the security properties; check the adversarial cases yourself.

## Useful prompts
- Start: `/plan-phase 0`
- Feature: "Implement `sqlguard/validate.py` per CLAUDE.md rule 2. Write the adversarial tests first
  (multi-statement, CTE writes, COPY, SELECT INTO, pg_sleep). Then implement and run `/verify`."
- Debug: "`test_x` fails with <paste error>. Find the root cause before changing code; explain it first."
- Review: `/security-review`
- Docs: "Update `docs/THREAT_MODEL.md` to reflect what Phase 2 now covers."

## First session checklist
- [ ] `uv sync` and `uv run pytest -q` pass
- [ ] `docker compose up -d db` is healthy
- [ ] `npx @modelcontextprotocol/inspector uv run mcp-gateway --transport stdio` connects and `ping` works
- [ ] Repo pushed to GitHub, CI green, `main` protected
- [ ] Run `/plan-phase 1`
