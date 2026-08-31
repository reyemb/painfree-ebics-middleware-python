"""The columns the upload worker claims and retries with.

Six columns and one index on `payment_order`. Nothing is rewritten: `attempts`
lands with a server default of `0` so the rows already accepted are claimed as
first attempts rather than as exhausted ones.

`worker_id`, `claimed_at` and `state='submitting'` together are the claim.
`attempts` and `next_attempt_at` are the retry policy. `transaction_id` is the
handle on an open EBICS transaction, and `last_error` is why the last attempt
stopped.

Revision ID: 0004_upload_claim
Revises: 0003_payment_orders
Create Date: 2026-08-29
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

from painfree.schema import UtcDateTime

revision = "0004_upload_claim"
down_revision = "0003_payment_orders"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("payment_order",
                  sa.Column("transaction_id", sa.String(64), nullable=True))
    op.add_column("payment_order",
                  sa.Column("worker_id", sa.String(64), nullable=True))
    op.add_column("payment_order",
                  sa.Column("claimed_at", UtcDateTime, nullable=True))
    # Not nullable, so the claim can increment it without a coalesce; the
    # server default is what makes that safe on a table that already has rows.
    op.add_column("payment_order",
                  sa.Column("attempts", sa.Integer, nullable=False,
                            server_default="0"))
    op.add_column("payment_order",
                  sa.Column("next_attempt_at", UtcDateTime, nullable=True))
    op.add_column("payment_order",
                  sa.Column("last_error", sa.String(512), nullable=True))
    op.create_index("ix_payment_order_state_next_attempt_at", "payment_order",
                    ["state", "next_attempt_at"])


def downgrade() -> None:
    op.drop_index("ix_payment_order_state_next_attempt_at",
                  table_name="payment_order")
    for column in ("last_error", "next_attempt_at", "attempts", "claimed_at",
                   "worker_id", "transaction_id"):
        op.drop_column("payment_order", column)
