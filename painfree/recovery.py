"""What an operator needs to know to survive losing this host, and nothing more.

The custody secret is the most destructive thing a deployment can lose: every
stored EBICS private key is sealed under it, no database backup contains it, and
without it a connection needs new keys, an INI letter signed on paper and posted
to the bank, and days before it can move money again.

Until this module existed the product said so in exactly one place -- a block of
stderr from `deploy/init-secrets.sh`, printed once, at provisioning, when there
are no keys yet and nothing is at stake. By the time it mattered, nothing
repeated it.

**Nothing here is a secret, and nothing here can be.** This runs in the process
that serves the console, which is refused the custody secret and would not start
if it were handed one. What it can read is which key id the *sealed rows* name,
because that is a hash stored beside the ciphertext. So the card names the key,
says where the file lives on the host, and says what to run. It never carries
the value, and there is no route here that could: a download that contained the
custody secret would put the key to every bank connection behind a browser
session, which is the boundary this service is built around.

The acknowledgement is the other half. An operator confirms they hold a copy,
against the key id it is a copy *of*, and until they have, generating a
connection's first keys is refused. That is the one irreversible action here
whose cost is somebody else's calendar, and a confirmation before it is
proportionate -- the same shape as the fingerprint comparison, which refuses to
pre-fill anything and makes declining as easy as accepting.
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass

from sqlalchemy import Engine, desc, select

from painfree.audit import Actor, AuditLog, SYSTEM_ACTOR
from painfree.rekey import survey
from painfree.schema import custody_acknowledgement

#: Where `deploy/init-secrets.sh` writes the custody secret, and therefore what
#: the card tells an operator to go and copy. A path rather than a value.
SECRET_PATH = "deploy/secrets/custody_secret"

#: What writes the archive that carries it off this host.
BACKUP_COMMAND = "deploy/backup-secrets.sh"


@dataclass(frozen=True)
class Acknowledgement:
    """One operator's confirmation, and which key it was made against."""

    key_id: str | None
    acknowledged_at: _dt.datetime
    acknowledged_by: str


@dataclass(frozen=True)
class RecoveryCard:
    """Everything the console knows about surviving the loss of this host.

    Safe to print, safe to download, safe to leave on a desk: the key id is a
    hash of a public half and identifies which secret is the right one without
    being any part of it.
    """

    key_ids: list[str]
    acknowledgement: Acknowledgement | None
    version: str
    git_sha: str
    secret_path: str = SECRET_PATH
    backup_command: str = BACKUP_COMMAND

    @property
    def key_id(self) -> str | None:
        """The key the stored material is sealed under, when there is one.

        More than one means a rotation stopped halfway, which is worth saying
        rather than hiding behind whichever came first.
        """
        return self.key_ids[0] if len(self.key_ids) == 1 else None

    @property
    def rotation_unfinished(self) -> bool:
        return len(self.key_ids) > 1

    @property
    def acknowledged(self) -> bool:
        """Whether somebody has confirmed a copy exists, of *this* key.

        An acknowledgement made before any key existed still counts: that is the
        ordinary path, because the point is to have the backup before the first
        key is generated. What does not count is an acknowledgement of a key a
        rotation has since replaced.
        """
        if self.acknowledgement is None:
            return False
        against = self.acknowledgement.key_id
        return against is None or not self.key_ids or against in self.key_ids


class CustodyRecovery:
    """Reads the card, and records the acknowledgement. Opens nothing."""

    def __init__(self, engine: Engine, audit: AuditLog | None = None) -> None:
        self._engine = engine
        self._audit = audit or AuditLog(engine)

    def latest(self) -> Acknowledgement | None:
        with self._engine.connect() as connection:
            row = connection.execute(
                select(custody_acknowledgement)
                .order_by(desc(custody_acknowledgement.c.seq))
                .limit(1)).mappings().first()
        if row is None:
            return None
        return Acknowledgement(key_id=row["key_id"],
                               acknowledged_at=row["acknowledged_at"],
                               acknowledged_by=row["acknowledged_by"])

    def card(self, *, version: str, git_sha: str) -> RecoveryCard:
        return RecoveryCard(key_ids=sorted(survey(self._engine)),
                            acknowledgement=self.latest(),
                            version=version, git_sha=git_sha)

    def acknowledge(self, *, actor: Actor = SYSTEM_ACTOR) -> Acknowledgement:
        """Record that a copy of the custody secret exists somewhere else.

        Against the key id the sealed rows name, so a rotation asks again: the
        archive somebody took last year opens nothing after the secret changed,
        and a confirmation that quietly carried over would say it did.
        """
        key_ids = sorted(survey(self._engine))
        now = _dt.datetime.now(_dt.timezone.utc)
        made = Acknowledgement(
            key_id=key_ids[0] if len(key_ids) == 1 else None,
            acknowledged_at=now, acknowledged_by=actor.id)
        with self._engine.begin() as connection:
            connection.execute(custody_acknowledgement.insert().values(
                key_id=made.key_id, acknowledged_at=now,
                acknowledged_by=actor.id))
        self._audit.record("custody.backup_acknowledged", actor=actor,
                           detail={"key_id": made.key_id})
        return made
