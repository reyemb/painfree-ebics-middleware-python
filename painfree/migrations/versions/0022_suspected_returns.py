"""A booking that looks like a return and that a person has to confirm.

Six nullable columns on `payment_order`, and no backfill: `NULL` means nothing
is suspected, which is what every existing row means. A suspicion raised by a
statement already stored is found by re-reading it.

Revision ID: 0022_suspected_returns
Revises: 0021_returned_payments
Create Date: 2026-10-15
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

from painfree.schema import UtcDateTime

revision = "0022_suspected_returns"
down_revision = "0021_returned_payments"
branch_labels = None
depends_on = None

COLUMNS = (
    ("return_suspected_at", UtcDateTime),
    ("return_suspected_booked_at", UtcDateTime),
    ("return_suspected_statement_id", sa.String(36)),
    ("return_suspected_entry_ref", sa.String(128)),
    ("return_suspected_text", sa.String(1024)),
    ("return_suspicion_dismissed_at", UtcDateTime),
)


def upgrade() -> None:
    for name, kind in COLUMNS:
        op.add_column("payment_order", sa.Column(name, kind, nullable=True))


def downgrade() -> None:
    for name, _ in reversed(COLUMNS):
        op.drop_column("payment_order", name)
