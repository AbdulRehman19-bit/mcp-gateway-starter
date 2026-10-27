"""audit_log and approvals

Revision ID: 0001
Revises:

Why two app roles: gateway_audit can ONLY insert audit rows (no read, update or delete), so a
compromised gateway process cannot rewrite history. gateway_app owns the approval workflow
and cannot touch audit_log at all.
"""

import os

from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

_STATEMENTS = [
    # Dev defaults; in production create these roles beforehand with real secrets.
    """DO $$ BEGIN
        IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'gateway_audit') THEN
            CREATE ROLE gateway_audit LOGIN PASSWORD 'change-me-audit';
        END IF;
        IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'gateway_app') THEN
            CREATE ROLE gateway_app LOGIN PASSWORD 'change-me-app';
        END IF;
    END $$""",
    """CREATE TABLE audit_log (
        id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        ts            timestamptz NOT NULL DEFAULT now(),
        request_id    text NOT NULL,
        subject       text NOT NULL DEFAULT '',
        role          text NOT NULL DEFAULT '',
        tool          text NOT NULL,
        args_redacted jsonb NOT NULL DEFAULT '{}'::jsonb,
        risk          text NOT NULL DEFAULT '',
        decision      text NOT NULL,
        reason        text NOT NULL DEFAULT '',
        duration_ms   numeric NOT NULL DEFAULT 0
    )""",
    "CREATE INDEX audit_log_ts_idx ON audit_log (ts)",
    "CREATE INDEX audit_log_request_idx ON audit_log (request_id)",
    "CREATE INDEX audit_log_subject_idx ON audit_log (subject)",
    """CREATE TABLE approvals (
        id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        created_at      timestamptz NOT NULL DEFAULT now(),
        expires_at      timestamptz NOT NULL,
        requester       text NOT NULL,
        requester_role  text NOT NULL,
        tool            text NOT NULL,
        args_hash       text NOT NULL,
        args            jsonb NOT NULL,
        status          text NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending', 'approved', 'denied', 'used')),
        decided_by      text,
        decided_at      timestamptz,
        decision_reason text,
        used_at         timestamptz,
        -- Last line of defence for rule 7: even a buggy app cannot self-approve.
        CONSTRAINT approvals_no_self_approval CHECK (decided_by IS NULL OR decided_by <> requester)
    )""",
    "CREATE INDEX approvals_status_idx ON approvals (status, expires_at)",
    "GRANT INSERT ON audit_log TO gateway_audit",
    "GRANT SELECT, INSERT, UPDATE ON approvals TO gateway_app",
    # Startup schema-version check reads this one row; nothing else.
    "GRANT SELECT ON alembic_version TO gateway_audit, gateway_app",
]


def upgrade() -> None:
    # Dev convenience only: the roles below get well-known placeholder passwords. In production
    # create them beforehand with real secrets and run with GATEWAY_MIGRATE_CREATE_ROLES=0.
    skip_roles = os.environ.get("GATEWAY_MIGRATE_CREATE_ROLES", "1") == "0"
    for i, stmt in enumerate(_STATEMENTS):
        if i == 0 and skip_roles:
            continue
        op.execute(stmt)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS approvals")
    op.execute("DROP TABLE IF EXISTS audit_log")
