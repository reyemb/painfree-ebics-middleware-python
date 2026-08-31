"""The columns webhook subscriptions need to be managed rather than written in code.

One new table and five nullable-or-defaulted columns.

`webhook_wrapping_key` holds the public half of the keypair a signing secret is
sealed to, so the API process -- which holds no custody key -- can register an
endpoint and still store its secret in a form only the worker can open. It is
published by the worker at startup, not by this migration: a migration has no
custody secret and could not derive the private half.

`sealed_secret_previous`, `secret_generation` and `secret_rotated_at` are the
rotation overlap: while a rotation is in flight both secrets sign every
delivery, so a consumer keeps verifying with the value it still has.

`idempotency_key` is unique, so a retried `POST /v1/webhooks` returns the
subscription it already made instead of a second endpoint receiving one
payment's events.

Additive throughout: an existing subscription is correct with `NULL` in all of
them and `secret_generation` at 1, which is what "never rotated" means.

Revision ID: 0010_webhook_management
Revises: 0009_status_reports
Create Date: 2026-08-30
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

from painfree.schema import UtcDateTime


revision = "0010_webhook_management"
down_revision = "0009_status_reports"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "webhook_wrapping_key",
        sa.Column("seq", sa.BigInteger().with_variant(sa.Integer(), "sqlite"),
                  primary_key=True, autoincrement=True),
        sa.Column("custody_key_id", sa.String(32), nullable=False),
        sa.Column("public_key", sa.LargeBinary, nullable=False),
        sa.Column("created_at", UtcDateTime, nullable=False),
        sa.UniqueConstraint("custody_key_id",
                            name="uq_webhook_wrapping_key_custody_key_id"),
    )
    op.add_column("webhook_subscription",
                  sa.Column("description", sa.String(255), nullable=True))
    op.add_column("webhook_subscription",
                  sa.Column("sealed_secret_previous", sa.LargeBinary,
                            nullable=True))
    op.add_column("webhook_subscription",
                  sa.Column("secret_generation", sa.Integer, nullable=False,
                            server_default="1"))
    op.add_column("webhook_subscription",
                  sa.Column("secret_rotated_at", UtcDateTime, nullable=True))
    # The unique constraint is what makes a retried registration idempotent, so
    # it is a constraint and not a check. SQLite cannot ALTER a table to add
    # one; a unique *index* on the same column is the same guarantee there, and
    # it is what SQLAlchemy's `unique=True` would have emitted at create time.
    op.add_column("webhook_subscription",
                  sa.Column("idempotency_key", sa.String(255), nullable=True))
    if op.get_bind().dialect.name == "postgresql":
        op.create_unique_constraint(
            "uq_webhook_subscription_idempotency_key",
            "webhook_subscription", ["idempotency_key"])
    else:
        op.create_index("uq_webhook_subscription_idempotency_key",
                        "webhook_subscription", ["idempotency_key"],
                        unique=True)


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.drop_constraint("uq_webhook_subscription_idempotency_key",
                           "webhook_subscription", type_="unique")
    else:
        op.drop_index("uq_webhook_subscription_idempotency_key",
                      table_name="webhook_subscription")
    op.drop_column("webhook_subscription", "idempotency_key")
    op.drop_column("webhook_subscription", "secret_rotated_at")
    op.drop_column("webhook_subscription", "secret_generation")
    op.drop_column("webhook_subscription", "sealed_secret_previous")
    op.drop_column("webhook_subscription", "description")
    op.drop_table("webhook_wrapping_key")
