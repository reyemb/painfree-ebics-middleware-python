"""Keep the EBICS request a bank refused, and what the schemas say about it.

Two nullable columns, no backfill and no way to make one: the requests that
were already refused are gone, and nothing in this database ever held them.
An existing deployment migrates to *not captured*, which the console says in
those words rather than showing an empty document.

Why this is worth a table change at all: `091113 EBICS_INVALID_REQUEST_CONTENT`
names no element. An operator holding one has no next step inside the product,
because the request is discarded the moment the exchange ends and the only
party who can still see it is the bank. Keeping it makes the first question --
*is this well-formed EBICS?* -- answerable without a telephone call.

Nothing sensitive lands here. An upload's initialisation carries the electronic
signature and the transaction key wrapped to the bank's public half; the
payment file goes in the transfer phase, which a refusal at initialisation
never reaches.

Revision ID: 0018_refused_request
Revises: 0017_bank_catalogue
Create Date: 2026-09-02
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

from painfree.schema import JsonBlob

revision = "0018_refused_request"
down_revision = "0017_bank_catalogue"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("payment_order",
                  sa.Column("refused_request", sa.LargeBinary, nullable=True))
    op.add_column("payment_order",
                  sa.Column("refused_request_errors", JsonBlob, nullable=True))


def downgrade() -> None:
    op.drop_column("payment_order", "refused_request_errors")
    op.drop_column("payment_order", "refused_request")
