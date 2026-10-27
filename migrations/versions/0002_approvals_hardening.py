"""approvals hardening: column grants, state-machine trigger, no duplicate live approvals

Revision ID: 0002
Revises: 0001

Why: 0001 let gateway_app UPDATE every column of approvals, so a compromised gateway could
rewrite args_hash, requester or expiry. Now it may only touch the decision/usage columns, and a
trigger (which also binds the table owner) enforces the only legal transitions:

    pending -> approved | denied        approved -> used | denied

Everything else, including editing identity columns or reviving a used/denied row, is refused.
"""

from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

_FUNCTION = """CREATE FUNCTION approvals_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.status <> 'pending' OR NEW.decided_by IS NOT NULL OR NEW.used_at IS NOT NULL THEN
            RAISE EXCEPTION 'approvals must be created pending';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
       OR NEW.requester IS DISTINCT FROM OLD.requester
       OR NEW.requester_role IS DISTINCT FROM OLD.requester_role
       OR NEW.tool IS DISTINCT FROM OLD.tool
       OR NEW.args_hash IS DISTINCT FROM OLD.args_hash THEN
        RAISE EXCEPTION 'approval identity columns are immutable';
    END IF;
    IF (OLD.status, NEW.status) NOT IN
       (('pending', 'approved'), ('pending', 'denied'), ('approved', 'used'),
        ('approved', 'denied')) THEN
        RAISE EXCEPTION 'invalid approval transition % -> %', OLD.status, NEW.status;
    END IF;
    IF NEW.status = 'approved' AND NEW.decided_by IS NULL THEN
        RAISE EXCEPTION 'an approval needs a decider';
    END IF;
    RETURN NEW;
END $$"""

_STATEMENTS = [
    "REVOKE UPDATE ON approvals FROM gateway_app",
    "GRANT UPDATE (status, decided_by, decided_at, decision_reason, used_at, args) "
    "ON approvals TO gateway_app",
    _FUNCTION,
    "CREATE TRIGGER approvals_guard_trg BEFORE INSERT OR UPDATE ON approvals "
    "FOR EACH ROW EXECUTE FUNCTION approvals_guard()",
    # One live approval per (requester, exact call): concurrent creates cannot duplicate it.
    "CREATE UNIQUE INDEX approvals_live_uniq ON approvals (requester, args_hash) "
    "WHERE status IN ('pending', 'approved')",
]


def upgrade() -> None:
    for stmt in _STATEMENTS:
        op.execute(stmt)


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS approvals_live_uniq")
    op.execute("DROP TRIGGER IF EXISTS approvals_guard_trg ON approvals")
    op.execute("DROP FUNCTION IF EXISTS approvals_guard()")
    op.execute("GRANT UPDATE ON approvals TO gateway_app")
