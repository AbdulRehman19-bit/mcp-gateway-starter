# Security policy

## Reporting a vulnerability

Please report security problems **privately**, not in a public issue:

- Use GitHub's private vulnerability reporting: the repository's **Security** tab →
  **Report a vulnerability**.

Include what you found, how to reproduce it (a failing test is ideal), and the impact you
expect. You should get an acknowledgement within a few days. Please give us reasonable time to
fix the problem before disclosing it.

## Scope

In scope: the gateway code in `src/`, the migrations, the policy engine and SQL analyzer, the
approval workflow, authentication, the audit trail, and the connectors.

Out of scope: the demo stack's placeholder credentials and password-grant realm (they are for
local development only and documented as such), denial-of-service by an authenticated user
beyond the documented rate limits, and a compromised host, database superuser or identity
provider. See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for what is and is not protected.

## Supported versions

Only the latest release receives security fixes.

## Hardening checklist for operators

- Run behind TLS; never expose the Compose demo stack.
- Use your own identity provider; require an exact `aud`; keep access-token lifetimes short.
- Create the four database roles with real secrets and least privilege (see
  `docs/ARCHITECTURE.md`); run migrations as a separate privileged step.
- Keep `GATEWAY_READ_ONLY=true` unless you need writes; give the GitHub token access to the
  listed repositories only.
- Ship the JSON logs and the `audit_log` table somewhere the gateway cannot alter.
