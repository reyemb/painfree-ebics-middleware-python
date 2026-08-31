"""Prove that this deployment's sealed keys still open, and produce the evidence.

Run it inside the worker container after a restore, after a custody rotation, or
whenever "is the keyring still readable" is a question somebody is asking:

    podman-compose exec -T worker python /opt/painfree/verify-keys.py
    # or, without copying it in:
    podman-compose exec -T worker python - < deploy/verify-keys.py

For every registered bank connection it opens the sealed `X002` key -- the one
decryption point, in the one process allowed to do it -- and uses it to sign a
real `HPB` request. It prints one JSON object per connection carrying the key's
fingerprint and that signed request, base64-encoded.

**What makes this evidence rather than self-congratulation:** the printed XML is
meant to be handed to an *independent* EBICS implementation, which is asked
whether the digest and the signature verify. A round trip checked by the code
that performed it proves only that the code agrees with itself; a signature a
different implementation accepts proves the key survived intact.

Nothing here writes to the database, and nothing here prints key material: the
private half is used to sign and then dropped, and what reaches stdout is a
public request document, a public fingerprint and a custody key *id*.
"""

from __future__ import annotations

import base64
import json
import sys

from sqlalchemy import select

from painfree import db, ebics3
from painfree.audit import AuditLog
from painfree.config import load_settings
from painfree.keyring import KeyCustodian
from painfree.logging import configure_logging
from painfree.schema import bank_connection


def main() -> int:
    settings = load_settings()
    # Without this the root logger has no handler, and Python's last-resort
    # handler prints the bare event name to stderr -- so `custody.key_mismatch`,
    # the line that names both key ids, would arrive as five unstructured
    # words. Every line this container writes is JSON or it is a defect.
    configure_logging(settings.log_level)
    engine = db.build_engine(settings)
    try:
        custodian = KeyCustodian(engine, AuditLog(engine),
                                 settings.custody_key())
        with engine.connect() as connection:
            rows = connection.execute(
                select(bank_connection.c.connection_id,
                       bank_connection.c.host_id,
                       bank_connection.c.partner_id,
                       bank_connection.c.user_id)
                .order_by(bank_connection.c.connection_id)).mappings().all()

        if not rows:
            print(json.dumps({"event": "verify.no_connections"}))
            return 1

        failures = 0
        for row in rows:
            connection_id = row["connection_id"]
            try:
                key = custodian.open(connection_id, ebics3.KeyVersion.X002)
                request = ebics3.serialize_request(ebics3.build_hpb_request(
                    ebics3.RequestContext(row["host_id"], row["partner_id"],
                                          row["user_id"]), key))
            except Exception as exc:  # reported, not swallowed
                failures += 1
                print(json.dumps({
                    "event": "verify.failed",
                    "connection_id": connection_id,
                    "exception": type(exc).__name__,
                    "message": str(exc),
                }))
                continue
            print(json.dumps({
                "event": "verify.signed",
                "connection_id": connection_id,
                "custody_key_id": custodian.key_id,
                "key_version": "X002",
                "fingerprint": key.fingerprint_hex,
                "public_key_pem": key.public_pem().decode("ascii"),
                "signed_hpb_request_base64":
                    base64.b64encode(request).decode("ascii"),
            }))
        return 1 if failures else 0
    finally:
        engine.dispose()


if __name__ == "__main__":
    sys.exit(main())
