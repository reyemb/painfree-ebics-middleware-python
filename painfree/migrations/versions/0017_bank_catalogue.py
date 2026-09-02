"""What the bank says about itself, as HAA, HTD and HPD answered it.

One table, no backfill, and no way to backfill one: nothing in this database
knows what a bank's catalogue is until the bank is asked, and asking needs the
worker, the custody key and a round trip. An existing deployment therefore
migrates to *nothing fetched yet*, which is honest -- and the console says so
rather than showing an empty catalogue, because an empty catalogue and an
unasked bank are different facts and only one of them means the bank offers
nothing.

The document is stored beside the parse deliberately. What a bank publishes is
the authority for whether a payment will be accepted; a parse is this service's
reading of it. Keeping the bytes means a later disagreement is settled against
what actually arrived.

Revision ID: 0017_bank_catalogue
Revises: 0016_custody_acknowledgement
Create Date: 2026-09-02
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

from painfree.schema import JsonBlob, Sequence64, UtcDateTime

revision = "0017_bank_catalogue"
down_revision = "0016_custody_acknowledgement"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "bank_catalogue",
        sa.Column("seq", Sequence64, primary_key=True, autoincrement=True),
        sa.Column("connection_id", sa.String(64), nullable=False),
        sa.Column("order_type", sa.String(3), nullable=False),
        sa.Column("fetched_at", UtcDateTime, nullable=False),
        sa.Column("return_code", sa.String(6), nullable=True),
        sa.Column("report_text", sa.String(1024), nullable=True),
        sa.Column("document", sa.LargeBinary, nullable=False),
        sa.Column("summary", JsonBlob, nullable=True),
        sa.UniqueConstraint("connection_id", "order_type",
                            name="uq_bank_catalogue_connection_id_order_type"),
    )


def downgrade() -> None:
    op.drop_table("bank_catalogue")
