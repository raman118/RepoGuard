"""Enforce idempotent exact patch identities."""

from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("proposals") as batch:
        batch.create_unique_constraint("uq_proposals_scan_digest", ["scan_id", "digest"])


def downgrade() -> None:
    with op.batch_alter_table("proposals") as batch:
        batch.drop_constraint("uq_proposals_scan_digest", type_="unique")
