"""Payment schemes: what a connection can send, and every attempt at an order.

One table and four columns, and the one thing worth reading is what the
defaults do: **nothing**.

`bank_connection.payment_schemes` is nullable and every existing row keeps
`NULL`, which `painfree.schemes.SchemeProfiles.parse` reads as the default
set -- `MCT` in scope `CH` with no `PmtTpInf` at all, which is byte for byte
what this service emitted before schemes existed. `payment_order.scheme` and
`requested_scheme` default to `normal` for the same reason. An upgrade
therefore changes no document and no BTF until somebody configures a
connection, which is the only safe shape for a migration on a table of
payments.

`payment_attempt` is created empty and **nothing is backfilled into it**. The
obvious convenience would be one attempt row per existing order, copying its
document across; it is declined because the copy would be a second stored
duplicate of every payment this deployment has ever made, written by a
migration, to describe attempts that are already over. The worker reads the
connection's profile when an order has no attempt row, and for an order
accepted before this revision that profile resolves to exactly the BTF it was
uploaded under.

Revision ID: 0015_payment_schemes
Revises: 0014_basic_accounts
Create Date: 2026-08-30
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

from painfree.schema import JsonBlob, Sequence64, UtcDateTime

revision = "0015_payment_schemes"
down_revision = "0014_basic_accounts"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("bank_connection",
                  sa.Column("payment_schemes", JsonBlob, nullable=True))

    # `server_default` rather than a data migration: the column has to be
    # non-null on a table that already has rows, and "every payment made before
    # schemes existed was a normal credit transfer" is true by construction
    # rather than by a guess.
    op.add_column("payment_order",
                  sa.Column("requested_scheme", sa.String(20), nullable=False,
                            server_default="normal"))
    op.add_column("payment_order",
                  sa.Column("scheme", sa.String(20), nullable=False,
                            server_default="normal"))
    op.add_column("payment_order",
                  sa.Column("scheme_reason", sa.String(64), nullable=True))

    op.create_table(
        "payment_attempt",
        sa.Column("seq", Sequence64, primary_key=True, autoincrement=True),
        sa.Column("attempt_id", sa.String(36), nullable=False, unique=True),
        sa.Column("order_id", sa.String(36),
                  sa.ForeignKey("payment_order.order_id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("attempt_no", sa.Integer, nullable=False),
        sa.Column("scheme", sa.String(20), nullable=False),
        sa.Column("state", sa.String(16), nullable=False),
        # Unique across every attempt of every order. The bank deduplicates on
        # `MsgId`, so two attempts sharing one would be the second payment the
        # whole design exists to prevent.
        sa.Column("msg_id", sa.String(35), nullable=False, unique=True),
        sa.Column("payment_information_id", sa.String(35), nullable=False),
        sa.Column("document", sa.LargeBinary, nullable=False),
        sa.Column("btf_service_name", sa.String(3), nullable=False),
        sa.Column("btf_service_option", sa.String(10), nullable=True),
        sa.Column("btf_scope", sa.String(3), nullable=True),
        sa.Column("payment_type", sa.String(255), nullable=True),
        sa.Column("reason", sa.String(255), nullable=True),
        sa.Column("return_code", sa.String(16), nullable=True),
        sa.Column("report_text", sa.String(1024), nullable=True),
        sa.Column("created_at", UtcDateTime, nullable=False),
        sa.Column("updated_at", UtcDateTime, nullable=False),
        sa.UniqueConstraint("order_id", "attempt_no",
                            name="uq_payment_attempt_order_id_attempt_no"),
    )
    op.create_index("ix_payment_attempt_order_id_state", "payment_attempt",
                    ["order_id", "state"])


def downgrade() -> None:
    op.drop_index("ix_payment_attempt_order_id_state",
                  table_name="payment_attempt")
    op.drop_table("payment_attempt")
    op.drop_column("payment_order", "scheme_reason")
    op.drop_column("payment_order", "scheme")
    op.drop_column("payment_order", "requested_scheme")
    op.drop_column("bank_connection", "payment_schemes")
