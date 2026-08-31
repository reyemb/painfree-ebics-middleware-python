"""The operator's confirmation that they hold the custody secret.

One table, no backfill, and the absence is the point again.

An existing deployment migrates to *unacknowledged*, which is the honest state:
nobody has told this service that a copy of the custody secret exists anywhere,
and it has no way to find out. The consequence is a banner and a gate on
generating new keys, not a service that stops working -- connections already
initialised keep submitting payments, because their keys are already sealed and
the acknowledgement would not make them safer.

Backfilling an acknowledgement here would be worse than useless: it would record
a confirmation nobody made, about a file nobody looked for, and the one operator
it matters to would never see the question.

Revision ID: 0016_custody_acknowledgement
Revises: 0015_payment_schemes
Create Date: 2026-08-31
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

from painfree.schema import Sequence64, UtcDateTime

revision = "0016_custody_acknowledgement"
down_revision = "0015_payment_schemes"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "custody_acknowledgement",
        sa.Column("seq", Sequence64, primary_key=True, autoincrement=True),
        sa.Column("key_id", sa.String(32), nullable=True),
        sa.Column("acknowledged_at", UtcDateTime, nullable=False),
        sa.Column("acknowledged_by", sa.String(255), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("custody_acknowledgement")
