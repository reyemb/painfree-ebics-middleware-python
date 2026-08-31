"""Bank connections and the encrypted keyring.

Two tables. `bank_connection` is the registry -- who we are to which bank, and
how far its initialisation has got. `key_material` is the keyring: public halves
in the clear because they are public, private halves only as the sealed envelope
`painfree.sealing` produces.

The columns are written from ``painfree.schema`` so the two cannot drift.

Revision ID: 0002_connections_and_keyring
Revises: 0001_audit_log
Create Date: 2026-08-29
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

from painfree.schema import JsonBlob, Sequence64, UtcDateTime

revision = "0002_connections_and_keyring"
down_revision = "0001_audit_log"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "bank_connection",
        sa.Column("seq", Sequence64, primary_key=True, autoincrement=True),
        sa.Column("connection_id", sa.String(64), nullable=False),
        sa.Column("host_id", sa.String(35), nullable=False),
        sa.Column("partner_id", sa.String(35), nullable=False),
        sa.Column("user_id", sa.String(35), nullable=False),
        sa.Column("host_url", sa.String(1024), nullable=False),
        sa.Column("product_name", sa.String(64), nullable=True),
        sa.Column("product_language", sa.String(2), nullable=True),
        sa.Column("product_institute", sa.String(64), nullable=True),
        sa.Column("ebics_version", sa.String(8), nullable=False),
        sa.Column("key_state", sa.String(32), nullable=False),
        sa.Column("ini_sent", sa.Boolean, nullable=False),
        sa.Column("hia_sent", sa.Boolean, nullable=False),
        sa.Column("ini_order_id", sa.String(16), nullable=True),
        sa.Column("hia_order_id", sa.String(16), nullable=True),
        sa.Column("letter_digest", sa.String(16), nullable=False),
        sa.Column("bank_fingerprints", JsonBlob, nullable=True),
        sa.Column("created_at", UtcDateTime, nullable=False),
        sa.Column("updated_at", UtcDateTime, nullable=False),
        sa.PrimaryKeyConstraint("seq", name="pk_bank_connection"),
        sa.UniqueConstraint("connection_id", name="uq_bank_connection_connection_id"),
        sa.UniqueConstraint("host_id", "partner_id", "user_id",
                            name="uq_bank_connection_host_id_partner_id_user_id"),
    )
    op.create_table(
        "key_material",
        sa.Column("seq", Sequence64, primary_key=True, autoincrement=True),
        sa.Column("connection_id", sa.String(64), nullable=False),
        sa.Column("holder", sa.String(16), nullable=False),
        sa.Column("version", sa.String(8), nullable=False),
        sa.Column("generation", sa.Integer, nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("certificate_fingerprint", sa.String(64), nullable=True),
        sa.Column("public_pem", sa.LargeBinary, nullable=False),
        sa.Column("certificate_der", sa.LargeBinary, nullable=True),
        sa.Column("sealed_private", sa.LargeBinary, nullable=True),
        sa.Column("custody_key_id", sa.String(32), nullable=True),
        sa.Column("created_at", UtcDateTime, nullable=False),
        sa.Column("updated_at", UtcDateTime, nullable=False),
        sa.PrimaryKeyConstraint("seq", name="pk_key_material"),
        sa.ForeignKeyConstraint(
            ["connection_id"], ["bank_connection.connection_id"],
            name="fk_key_material_connection_id_bank_connection",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint(
            "connection_id", "holder", "version", "generation",
            name="uq_key_material_connection_id_holder_version_generation"),
    )
    op.create_index("ix_key_material_connection_id_status", "key_material",
                    ["connection_id", "status"])
    op.create_index("ix_key_material_fingerprint", "key_material", ["fingerprint"])


def downgrade() -> None:
    op.drop_index("ix_key_material_fingerprint", table_name="key_material")
    op.drop_index("ix_key_material_connection_id_status", table_name="key_material")
    op.drop_table("key_material")
    op.drop_table("bank_connection")
