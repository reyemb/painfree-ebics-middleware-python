"""An order whose money came back: the `returned` state and what said so.

Six nullable columns on `payment_order`, and no backfill. `NULL` means the
order has not been returned, which is what every existing row means. An order
already returned before this ran is found by re-reading the stored statements
(`python -m painfree reconcile`), not by a migration that would need its own
copy of the matching rules.

`returned` is a new value of the existing `state` column, which is a string
with no check constraint, so the state itself needs nothing here.

Revision ID: 0021_returned_payments
Revises: 0020_schedule_cron
Create Date: 2026-10-15
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

from painfree.schema import UtcDateTime

revision = "0021_returned_payments"
down_revision = "0020_schedule_cron"
branch_labels = None
depends_on = None

COLUMNS = (
    ("returned_at", UtcDateTime),
    ("return_statement_id", sa.String(36)),
    ("return_entry_ref", sa.String(128)),
    ("return_reason_code", sa.String(35)),
    ("return_reason_text", sa.String(1024)),
    ("return_matched_by", sa.String(16)),
)


def upgrade() -> None:
    for name, kind in COLUMNS:
        op.add_column("payment_order", sa.Column(name, kind, nullable=True))


def downgrade() -> None:
    for name, _ in reversed(COLUMNS):
        op.drop_column("payment_order", name)
