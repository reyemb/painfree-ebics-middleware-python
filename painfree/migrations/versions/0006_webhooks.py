"""The two tables the webhook dispatcher needs.

`webhook_subscription` is where events go and what each endpoint's signature is
made with; `webhook_delivery` is one event owed to one subscription, written in
the same transaction as the fact it reports.

Nothing existing is touched. Both tables are additive, so a deployment with no
subscription registered is unaffected by this revision.

Revision ID: 0006_webhooks
Revises: 0005_downloads
Create Date: 2026-08-30
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

from painfree.schema import JsonBlob, Sequence64, UtcDateTime

revision = "0006_webhooks"
down_revision = "0005_downloads"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "webhook_subscription",
        sa.Column("seq", Sequence64, primary_key=True, autoincrement=True),
        sa.Column("subscription_id", sa.String(36), nullable=False, unique=True),
        sa.Column("connection_id", sa.String(64),
                  sa.ForeignKey("bank_connection.connection_id",
                                ondelete="CASCADE"), nullable=True),
        sa.Column("url", sa.String(1024), nullable=False),
        sa.Column("event_types", JsonBlob, nullable=False),
        sa.Column("sealed_secret", sa.LargeBinary, nullable=False),
        sa.Column("custody_key_id", sa.String(32), nullable=False),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default="1"),
        sa.Column("parked_at", UtcDateTime, nullable=True),
        sa.Column("consecutive_failures", sa.Integer, nullable=False,
                  server_default="0"),
        sa.Column("last_delivery_at", UtcDateTime, nullable=True),
        sa.Column("last_status", sa.Integer, nullable=True),
        sa.Column("last_error", sa.String(512), nullable=True),
        sa.Column("created_at", UtcDateTime, nullable=False),
        sa.Column("updated_at", UtcDateTime, nullable=False),
    )
    op.create_index("ix_webhook_subscription_enabled_connection_id",
                    "webhook_subscription", ["enabled", "connection_id"])

    op.create_table(
        "webhook_delivery",
        sa.Column("seq", Sequence64, primary_key=True, autoincrement=True),
        sa.Column("delivery_id", sa.String(36), nullable=False, unique=True),
        sa.Column("subscription_id", sa.String(36),
                  sa.ForeignKey("webhook_subscription.subscription_id",
                                ondelete="CASCADE"), nullable=False),
        sa.Column("event_id", sa.String(36), nullable=False),
        sa.Column("event_type", sa.String(64), nullable=False),
        sa.Column("connection_id", sa.String(64), nullable=True),
        sa.Column("order_id", sa.String(64), nullable=True),
        sa.Column("idempotency_key", sa.String(255), nullable=True),
        sa.Column("occurred_at", UtcDateTime, nullable=False),
        sa.Column("payload", JsonBlob, nullable=False),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("attempts", sa.Integer, nullable=False, server_default="0"),
        sa.Column("next_attempt_at", UtcDateTime, nullable=True),
        sa.Column("worker_id", sa.String(64), nullable=True),
        sa.Column("claimed_at", UtcDateTime, nullable=True),
        sa.Column("last_status", sa.Integer, nullable=True),
        sa.Column("last_error", sa.String(512), nullable=True),
        sa.Column("delivered_at", UtcDateTime, nullable=True),
        sa.Column("created_at", UtcDateTime, nullable=False),
        sa.Column("updated_at", UtcDateTime, nullable=False),
        sa.UniqueConstraint("subscription_id", "event_id",
                            name="uq_webhook_delivery_subscription_id_event_id"),
    )
    op.create_index("ix_webhook_delivery_state_seq", "webhook_delivery",
                    ["state", "seq"])
    op.create_index("ix_webhook_delivery_subscription_id_state",
                    "webhook_delivery", ["subscription_id", "state"])
    op.create_index("ix_webhook_delivery_event_id", "webhook_delivery",
                    ["event_id"])


def downgrade() -> None:
    op.drop_index("ix_webhook_delivery_event_id", table_name="webhook_delivery")
    op.drop_index("ix_webhook_delivery_subscription_id_state",
                  table_name="webhook_delivery")
    op.drop_index("ix_webhook_delivery_state_seq", table_name="webhook_delivery")
    op.drop_table("webhook_delivery")
    op.drop_index("ix_webhook_subscription_enabled_connection_id",
                  table_name="webhook_subscription")
    op.drop_table("webhook_subscription")
