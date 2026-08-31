"""Payment orders, and the constraint that makes idempotency a guarantee.

One table. Its two unique constraints are the point: `(connection_id,
idempotency_key)` turns a duplicate submission into a constraint violation the
database decides, rather than a read-then-write that two concurrent requests
can both pass; and `msg_id` is unique because a bank deduplicates on it.

The columns are written from ``painfree.schema`` so the two cannot drift.

Revision ID: 0003_payment_orders
Revises: 0002_connections_and_keyring
Create Date: 2026-08-29
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

from painfree.schema import Sequence64, UtcDateTime

revision = "0003_payment_orders"
down_revision = "0002_connections_and_keyring"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "payment_order",
        sa.Column("seq", Sequence64, primary_key=True, autoincrement=True),
        sa.Column("order_id", sa.String(36), nullable=False),
        sa.Column("connection_id", sa.String(64), nullable=False),
        sa.Column("idempotency_key", sa.String(255), nullable=False),
        sa.Column("request_fingerprint", sa.String(64), nullable=False),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column("msg_id", sa.String(35), nullable=False),
        sa.Column("payment_information_id", sa.String(35), nullable=False),
        sa.Column("message_type", sa.String(32), nullable=False),
        sa.Column("document", sa.LargeBinary, nullable=False),
        sa.Column("transaction_count", sa.Integer, nullable=False),
        sa.Column("control_sum", sa.String(32), nullable=False),
        sa.Column("currency", sa.String(3), nullable=False),
        sa.Column("requested_execution_date", sa.String(10), nullable=False),
        sa.Column("bank_order_id", sa.String(16), nullable=True),
        sa.Column("return_code", sa.String(16), nullable=True),
        sa.Column("report_text", sa.String(1024), nullable=True),
        sa.Column("accepted_at", UtcDateTime, nullable=False),
        sa.Column("updated_at", UtcDateTime, nullable=False),
        sa.PrimaryKeyConstraint("seq", name="pk_payment_order"),
        sa.UniqueConstraint("order_id", name="uq_payment_order_order_id"),
        sa.UniqueConstraint("msg_id", name="uq_payment_order_msg_id"),
        sa.UniqueConstraint("connection_id", "idempotency_key",
                            name="uq_payment_order_connection_id_idempotency_key"),
        sa.ForeignKeyConstraint(
            ["connection_id"], ["bank_connection.connection_id"],
            name="fk_payment_order_connection_id_bank_connection",
            ondelete="RESTRICT",
        ),
    )
    op.create_index("ix_payment_order_state_seq", "payment_order",
                    ["state", "seq"])
    op.create_index("ix_payment_order_connection_id", "payment_order",
                    ["connection_id"])


def downgrade() -> None:
    op.drop_index("ix_payment_order_connection_id", table_name="payment_order")
    op.drop_index("ix_payment_order_state_seq", table_name="payment_order")
    op.drop_table("payment_order")
