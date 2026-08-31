"""The keyring: EBICS keys at rest, and the boundary around the private halves.

Two classes over one table, and the split between them **is** the custody
boundary:

:class:`Keyring`
    What the request-handling path gets. Fingerprints, key states, public keys,
    certificates, and the INI letter -- everything the UI and the API need. It
    has no method that returns private material: not a guarded one, not one
    that checks a flag. None.

:class:`KeyCustodian`
    What the worker gets. It cannot be constructed without a
    :class:`~painfree.sealing.CustodyKey`, it refuses to be constructed inside a
    request at all (:mod:`painfree.custody`), and it is the only thing in this
    service that turns a sealed blob back into an RSA private key.

The public halves are stored in the clear on purpose. They are public, and an
operator comparing a fingerprint against a bank's letter should not need the
ability to decrypt anything in order to do it -- that would put the custody key
on the path of a read-only screen.

Renewal mints a **new generation** rather than overwriting. The key the bank
still has on file has to stay readable until the bank confirms the replacement,
and a keyring that overwrites is a keyring that strands a connection halfway
through a key roll.

Every key operation goes through :mod:`painfree.audit`, which is the same
chokepoint everything else in the service records through. Log lines carry the
key's **fingerprint**, never the key: `EbicsKey.__repr__` is built that way for
the same reason.
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass
from typing import Any, Iterable

from sqlalchemy import Engine, select

from painfree import custody, ebics3
from painfree.audit import FAILURE, Actor, AuditLog, SYSTEM_ACTOR
from painfree.connections import BankConnection, ConnectionRegistry
from painfree.errors import ConflictError, NotFoundError
from painfree.logging import get_logger
from painfree.schema import key_material
from painfree.sealing import CustodyKey

log = get_logger("painfree.keyring")

SUBSCRIBER = "subscriber"
BANK = "bank"

ACTIVE = "active"
SUSPENDED = "suspended"
SUPERSEDED = "superseded"

#: A bank key `HPB` delivered that **nobody has vouched for yet**.
#:
#: `HPB` is unsigned, so a parsed bank key is evidence of what arrived and
#: nothing more. Between the download and the operator's comparison against the
#: bank's letter it has to live somewhere, and it must not be somewhere that
#: anything uses: :meth:`Keyring.bank_keys` resolves `active` and never this,
#: so a staged key cannot authenticate a response or encrypt a payment file
#: however long it sits there.
PENDING = "pending"

#: The three keys a subscriber registers. `A006` (RSASSA-PSS) is preferred for
#: EBICS 3.0; a bank that still requires `A005` gets it by asking for it.
SUBSCRIBER_VERSIONS = (ebics3.KeyVersion.A006, ebics3.KeyVersion.X002,
                       ebics3.KeyVersion.E002)


@dataclass(frozen=True, slots=True)
class StoredKey:
    """One keyring row, without its private half.

    This is what leaves the keyring on the request path. ``has_private`` says
    whether a private half exists at all; there is no accessor for it here, and
    that absence is the point.
    """

    connection_id: str
    holder: str
    version: ebics3.KeyVersion
    generation: int
    status: str
    fingerprint: str
    certificate_fingerprint: str | None
    has_private: bool
    custody_key_id: str | None
    created_at: _dt.datetime
    updated_at: _dt.datetime
    _public_pem: bytes
    _certificate_der: bytes | None

    def public_key(self) -> ebics3.EbicsKey:
        """The key as the engine wants it -- public half and certificate only."""
        certificate = (ebics3.load_certificate(self._certificate_der)
                       if self._certificate_der else None)
        return ebics3.EbicsKey.from_public_pem(
            self.version, self._public_pem, certificate)


class Keyring:
    """The public view of the keyring. Safe to hand a request handler."""

    __slots__ = ("_engine",)

    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    def entries(self, connection_id: str, *, holder: str | None = None,
                status: str | None = ACTIVE) -> list[StoredKey]:
        query = select(key_material).where(
            key_material.c.connection_id == connection_id)
        if holder is not None:
            query = query.where(key_material.c.holder == holder)
        if status is not None:
            query = query.where(key_material.c.status == status)
        with self._engine.connect() as connection:
            rows = connection.execute(
                query.order_by(key_material.c.holder, key_material.c.version,
                               key_material.c.generation)
            ).mappings().all()
        return [_stored(row) for row in rows]

    def entry(self, connection_id: str, version: ebics3.KeyVersion | str, *,
              holder: str = SUBSCRIBER, status: str | None = ACTIVE) -> StoredKey:
        """The current generation of one key, or :class:`NotFoundError`."""
        version = ebics3.KeyVersion.parse(version)
        query = (select(key_material)
                 .where(key_material.c.connection_id == connection_id,
                        key_material.c.holder == holder,
                        key_material.c.version == version.value)
                 .order_by(key_material.c.generation.desc())
                 .limit(1))
        if status is not None:
            query = query.where(key_material.c.status == status)
        with self._engine.connect() as connection:
            row = connection.execute(query).mappings().one_or_none()
        if row is None:
            raise NotFoundError(
                f"connection {connection_id!r} has no {status or 'stored'} "
                f"{holder} {version.value} key")
        return _stored(row)

    def public_key(self, connection_id: str, version: ebics3.KeyVersion | str, *,
                   holder: str = SUBSCRIBER) -> ebics3.EbicsKey:
        return self.entry(connection_id, version, holder=holder).public_key()

    def fingerprints(self, connection_id: str) -> dict[str, str]:
        """Every active key's fingerprint, keyed ``holder/version``.

        The value a UI shows next to a letter, and the value a log line quotes.
        """
        return {f"{key.holder}/{key.version.value}": key.fingerprint
                for key in self.entries(connection_id)}

    def staged_bank_keys(self, connection_id: str) -> list[StoredKey]:
        """Bank keys that arrived over `HPB` and have not been compared yet.

        Public material, deliberately readable without a custody key: the
        screen where an operator holds the bank's letter next to these
        fingerprints is a read-only screen, and putting it on the custody path
        is the pressure that eventually widens the boundary.
        """
        return self.entries(connection_id, holder=BANK, status=PENDING)

    def staged_fingerprints(self, connection: BankConnection) -> dict[str, str]:
        """The two values to compare, keyed ``authentication``/``encryption``.

        Computed with the digest convention *this connection's* letter uses --
        the classic key digest or the certificate's -- because comparing a
        value against a digest it can never equal reads as a mismatch for a key
        that is fine.
        """
        roles = {ebics3.KeyVersion.X002: "authentication",
                 ebics3.KeyVersion.E002: "encryption"}
        return {roles[key.version]: ebics3.ini_letter_hash(
                    key.public_key(), connection.letter_digest)
                for key in self.staged_bank_keys(connection.connection_id)
                if key.version in roles}

    def bank_keys(self, connection_id: str) -> ebics3.BankKeys:
        """The bank's `X002` and `E002` keys as the engine's :class:`BankKeys`.

        Holding these means `HPB` delivered them *and* they were checked against
        the bank's letter -- nothing else is ever written to a `bank` row.
        """
        authentication = self.entry(connection_id, ebics3.KeyVersion.X002,
                                    holder=BANK).public_key()
        encryption = self.entry(connection_id, ebics3.KeyVersion.E002,
                                holder=BANK).public_key()
        return ebics3.BankKeys(authentication=authentication,
                               encryption=encryption)

    def letter(self, connection: BankConnection) -> ebics3.IniLetter:
        """The INI letter for this subscriber's keys.

        Public material only, which is why it lives here rather than on the
        custodian: printing the letter is the one key-lifecycle step a human
        does, and it must not require the ability to decrypt anything.
        """
        return ebics3.build_ini_letter(
            connection.context,
            self.public_key(connection.connection_id,
                            self.signature_version(connection.connection_id)),
            self.public_key(connection.connection_id, ebics3.KeyVersion.X002),
            self.public_key(connection.connection_id, ebics3.KeyVersion.E002),
            digest=connection.letter_digest,
        )

    def signature_version(self, connection_id: str) -> ebics3.KeyVersion:
        for version in (ebics3.KeyVersion.A006, ebics3.KeyVersion.A005):
            try:
                self.entry(connection_id, version)
            except NotFoundError:
                continue
            return version
        raise NotFoundError(
            f"connection {connection_id!r} has no active signature key")


class KeyCustodian:
    """The worker's view: the only thing that opens a sealed private key.

    Constructing one is itself a custody event -- it is refused on the
    request-handling path before any key is touched, so the failure happens
    where the mistake is rather than at the first signature.
    """

    __slots__ = ("_engine", "_audit", "_custody", "_keyring", "_registry")

    def __init__(self, engine: Engine, audit: AuditLog,
                 custody_key: CustodyKey) -> None:
        custody.assert_outside_request_path("building a key custodian")
        self._engine = engine
        self._audit = audit
        self._custody = custody_key
        self._keyring = Keyring(engine)
        self._registry = ConnectionRegistry(engine, audit)

    @property
    def key_id(self) -> str:
        """Which custody key this custodian holds. A hash; safe to log."""
        return self._custody.key_id

    # --- creating ----------------------------------------------------------

    def create_subscriber_keys(
        self,
        connection_id: str,
        *,
        subject: Any,
        versions: Iterable[ebics3.KeyVersion | str] = SUBSCRIBER_VERSIONS,
        key_size: int = 2048,
    ) -> dict[str, ebics3.EbicsKey]:
        """Mint this subscriber's keys, seal the private halves, store them.

        Generation happens here rather than on the request path because a key
        that the request path minted is a key the request path held in the
        clear, which is the property ``D-003`` exists to prevent.
        """
        connection = self._registry.get(connection_id)
        if self._keyring.entries(connection_id, holder=SUBSCRIBER):
            raise ConflictError(
                f"connection {connection_id!r} already has keys; renew them "
                f"rather than creating a second set")
        if connection.key_state is not ebics3.KeyState.CREATED:
            raise ConflictError(
                f"connection {connection_id!r} is at {connection.key_state.value}; "
                f"keys can only be created before initialisation starts")

        created: dict[str, ebics3.EbicsKey] = {}
        for version in versions:
            key = ebics3.EbicsKey.generate(version, subject=subject,
                                           key_size=key_size)
            self._write(connection_id, key, holder=SUBSCRIBER, generation=1,
                        action="key.created")
            created[key.version.value] = key
        return created

    # --- opening: the one place a private key is decrypted -----------------

    def open(self, connection_id: str, version: ebics3.KeyVersion | str, *,
             holder: str = SUBSCRIBER) -> ebics3.EbicsKey:
        """The sealed private half, opened. The single decryption point.

        Everything that needs to sign, authenticate or decrypt comes through
        here, so "where can a private key be decrypted" has one answer and one
        line of code.
        """
        custody.assert_outside_request_path("opening a private key")
        stored = self._keyring.entry(connection_id, version, holder=holder)
        if not stored.has_private:
            raise NotFoundError(
                f"the {holder} {stored.version.value} key of connection "
                f"{connection_id!r} has no private half")

        row = self._row(connection_id, stored.holder, stored.version,
                        stored.generation)
        pem = self._custody.open(row["sealed_private"],
                                 context=_seal_context(stored))
        certificate = (ebics3.load_certificate(row["certificate_der"])
                       if row["certificate_der"] else None)
        key = ebics3.EbicsKey.from_private_pem(stored.version, pem,
                                               certificate=certificate)
        log.info("keyring.opened", connection_id=connection_id,
                 key_version=stored.version.value, holder=stored.holder,
                 generation=stored.generation, fingerprint=key.fingerprint_hex)
        return key

    # --- the bank's keys ---------------------------------------------------

    def accept_bank_keys(self, connection_id: str, bank_keys: ebics3.BankKeys,
                         fingerprints: dict[str, str]) -> None:
        """Store the bank's keys, but only once they have been checked.

        ``fingerprints`` is what :meth:`ebics3.Initialisation.confirm_bank_keys`
        returns, and it is required: `HPB` is unsigned, so the comparison
        against the bank's letter is the only control there is, and a keyring
        that would store an unverified bank key makes skipping it possible.
        """
        custody.assert_outside_request_path("accepting the bank's keys")
        if not fingerprints.get("authentication") or not fingerprints.get("encryption"):
            raise ConflictError(
                "the bank's keys have not been checked against its letter; "
                "confirm them before they are stored")

        generation = self._next_generation(connection_id, BANK)
        for key in (bank_keys.authentication, bank_keys.encryption):
            self._supersede(connection_id, BANK, key.version)
            # Reduced to the public half before it is written. A key that came
            # from `HPB` never has a private one, but the reduction is done
            # here rather than assumed, so a test fixture or a future caller
            # cannot make this service hold a private key it has no business
            # holding.
            self._write(connection_id, _public_only(key), holder=BANK,
                        generation=generation, action="key.bank_keys_accepted")

    def stage_bank_keys(self, connection_id: str,
                        bank_keys: ebics3.BankKeys) -> dict[str, str]:
        """Store what `HPB` delivered, marked as vouched for by nobody.

        The counterpart of :meth:`accept_bank_keys`, and the reason that method
        can keep demanding fingerprints. A download and a comparison are two
        events separated by a human walking to a filing cabinet, so the keys
        have to survive in between -- as ``PENDING`` rows, which
        :meth:`Keyring.bank_keys` does not resolve and nothing therefore uses.

        Re-fetching supersedes whatever was staged before. A second `HPB` is an
        ordinary thing to do -- the operator lost the letter, or the bank rolled
        its keys -- and two competing staged sets would make the comparison
        ambiguous at exactly the wrong moment.
        """
        custody.assert_outside_request_path("staging the bank's keys")
        connection = self._registry.get(connection_id)
        for stale in self._keyring.staged_bank_keys(connection_id):
            self._set_status(connection_id, stale, SUPERSEDED)

        generation = self._next_generation(connection_id, BANK)
        for key in (bank_keys.authentication, bank_keys.encryption):
            self._write(connection_id, _public_only(key), holder=BANK,
                        generation=generation, action="key.bank_keys_staged",
                        status=PENDING,
                        extra={"trusted": False,
                               "reason": "HPB carries no signature; these keys "
                                         "are evidence of what arrived and are "
                                         "not usable until the letter is checked"})
        return self._keyring.staged_fingerprints(connection)

    def confirm_bank_keys(self, connection_id: str, *, authentication: str,
                          encryption: str,
                          actor: Actor = SYSTEM_ACTOR) -> BankConnection:
        """The operator vouched for the staged keys. Compare, then trust them.

        The comparison is the engine's -- constant time, over all 64 hex
        characters, both keys required -- and it is the entire trust decision
        for `HPB`. A mismatch raises and changes nothing: the staged rows stay
        staged, the connection stays unusable, and the evidence of what the bank
        actually sent is still there to investigate.
        """
        custody.assert_outside_request_path("confirming the bank's keys")
        connection = self._registry.get(connection_id)
        staged = self._staged_bank_keys(connection_id)
        initialisation = self.resume_initialisation(connection_id)
        # Whatever this connection already trusted is not what is being checked.
        initialisation.bank_keys = staged
        initialisation.bank_fingerprints = None
        fingerprints = initialisation.confirm_bank_keys(
            authentication=authentication, encryption=encryption,
            digest=connection.letter_digest)

        for version in (ebics3.KeyVersion.X002, ebics3.KeyVersion.E002):
            self._supersede(connection_id, BANK, version)
        for key in self._keyring.staged_bank_keys(connection_id):
            self._set_status(connection_id, key, ACTIVE)
        self._audit.record(
            "key.bank_keys_accepted", actor=actor,
            connection_id=connection_id,
            detail={"holder": BANK, "digest": connection.letter_digest.value,
                    "fingerprints": fingerprints,
                    "reason": "compared against the bank's letter by a named "
                              "operator; HPB has no signature to check"})
        return self._registry.save_progress(connection_id, initialisation)

    def decline_bank_keys(self, connection_id: str, *, reason: str,
                          actor: Actor = SYSTEM_ACTOR) -> list[StoredKey]:
        """The operator would not vouch for the staged keys. Discard them.

        A first-class outcome, not the absence of one. The connection is left
        exactly as unusable as it was, the refusal is in the audit trail with
        the fingerprints that were refused, and the rows are superseded rather
        than deleted -- a bank key somebody rejected is the most interesting
        row in the table.
        """
        custody.assert_outside_request_path("declining the bank's keys")
        staged = self._keyring.staged_bank_keys(connection_id)
        if not staged:
            raise NotFoundError(
                f"connection {connection_id!r} has no staged bank keys to decline")
        for key in staged:
            self._set_status(connection_id, key, SUPERSEDED)
        self._audit.record(
            "key.bank_keys_declined", actor=actor, outcome=FAILURE,
            connection_id=connection_id,
            detail={"reason": reason,
                    "fingerprints": {key.version.value: key.fingerprint
                                     for key in staged}})
        log.warning("keyring.bank_keys_declined", connection_id=connection_id,
                    reason=reason,
                    fingerprints=[key.fingerprint for key in staged])
        return staged

    def _staged_bank_keys(self, connection_id: str) -> ebics3.BankKeys:
        """The staged pair as the engine's :class:`BankKeys`, or a `404`."""
        staged = {key.version: key
                  for key in self._keyring.staged_bank_keys(connection_id)}
        missing = [version.value for version in
                   (ebics3.KeyVersion.X002, ebics3.KeyVersion.E002)
                   if version not in staged]
        if missing:
            raise NotFoundError(
                f"connection {connection_id!r} has no staged bank "
                f"{', '.join(missing)} key; fetch HPB first")
        return ebics3.BankKeys(
            authentication=staged[ebics3.KeyVersion.X002].public_key(),
            encryption=staged[ebics3.KeyVersion.E002].public_key())

    # --- lifecycle ---------------------------------------------------------

    def suspend(self, connection_id: str, *,
                version: ebics3.KeyVersion | str | None = None,
                reason: str) -> list[StoredKey]:
        """Take a key -- or the whole subscriber -- out of service.

        A suspended key is still stored and still openable by an explicit
        status; it is simply no longer what `active` resolves to. Deleting it
        would destroy the evidence of what was registered with the bank.
        """
        custody.assert_outside_request_path("suspending a key")
        affected = [key for key in self._keyring.entries(
            connection_id, holder=SUBSCRIBER)
            if version is None
            or key.version is ebics3.KeyVersion.parse(version)]
        if not affected:
            raise NotFoundError(
                f"connection {connection_id!r} has no active key to suspend")
        for key in affected:
            self._set_status(connection_id, key, SUSPENDED)
            self._audit.record(
                "key.suspended", connection_id=connection_id,
                detail={"key_version": key.version.value,
                        "generation": key.generation,
                        "fingerprint": key.fingerprint, "reason": reason},
            )
        return affected

    def renew(self, connection_id: str, version: ebics3.KeyVersion | str, *,
              subject: Any, key_size: int = 2048) -> ebics3.EbicsKey:
        """Mint the next generation of one key; the old one becomes superseded.

        The new key is not registered with the bank by this call. It is a new
        `INI` or `HIA`, which is the worker's job -- the keyring only makes the
        replacement exist without losing the key the bank still has on file.
        """
        custody.assert_outside_request_path("renewing a key")
        version = ebics3.KeyVersion.parse(version)
        current = self._keyring.entry(connection_id, version)
        key = ebics3.EbicsKey.generate(version, subject=subject,
                                       key_size=key_size)
        self._set_status(connection_id, current, SUPERSEDED)
        self._write(connection_id, key, holder=SUBSCRIBER,
                    generation=current.generation + 1, action="key.renewed",
                    extra={"supersedes": current.fingerprint,
                           "generation_before": current.generation})
        return key

    # --- the resumable initialisation --------------------------------------

    def resume_initialisation(self, connection_id: str) -> ebics3.Initialisation:
        """Rebuild the engine's state machine from what was persisted.

        This is why the key state is a column. The engine models `INI`, `HIA`
        and `HPB` and stores nothing; put the three keys and the two booleans
        back and the machine asks for exactly the exchange that is still
        outstanding, instead of starting again with keys the bank has never
        seen.
        """
        custody.assert_outside_request_path("resuming an initialisation")
        connection = self._registry.get(connection_id)
        initialisation = ebics3.Initialisation(
            context=connection.context,
            signature_key=self.open(connection_id,
                                    self._keyring.signature_version(connection_id)),
            authentication_key=self.open(connection_id, ebics3.KeyVersion.X002),
            encryption_key=self.open(connection_id, ebics3.KeyVersion.E002),
            ini_sent=connection.ini_sent,
            hia_sent=connection.hia_sent,
            ini_order_id=connection.ini_order_id,
            hia_order_id=connection.hia_order_id,
        )
        if connection.bank_fingerprints:
            # `HPB` can always be repeated, so the bank's keys are restored only
            # to keep the state machine's answer honest about what is done.
            try:
                initialisation.bank_keys = self._keyring.bank_keys(connection_id)
                initialisation.bank_fingerprints = connection.bank_fingerprints
            except NotFoundError:
                log.warning("keyring.bank_keys_missing",
                            connection_id=connection_id,
                            key_state=connection.key_state.value)
        log.info("keyring.initialisation_resumed", connection_id=connection_id,
                 key_state=initialisation.state.value,
                 next_step=getattr(initialisation.next_step, "value", None))
        return initialisation

    def save_initialisation(self, connection_id: str,
                            initialisation: ebics3.Initialisation) -> BankConnection:
        """Persist one pass of the state machine, keys included."""
        custody.assert_outside_request_path("saving an initialisation")
        if initialisation.bank_keys is not None and initialisation.bank_fingerprints:
            try:
                self._keyring.bank_keys(connection_id)
            except NotFoundError:
                self.accept_bank_keys(connection_id, initialisation.bank_keys,
                                      initialisation.bank_fingerprints)
        return self._registry.save_progress(connection_id, initialisation)

    # --- storage -----------------------------------------------------------

    def _write(self, connection_id: str, key: ebics3.EbicsKey, *, holder: str,
               generation: int, action: str, status: str = ACTIVE,
               extra: dict[str, Any] | None = None) -> None:
        """Insert one key. The private half, if any, is sealed on the way in."""
        if holder == BANK and key.has_private:
            raise ConflictError(
                "a bank key is public material; refusing to store a private half")
        now = _dt.datetime.now(_dt.timezone.utc)
        stored = StoredKey(
            connection_id=connection_id, holder=holder, version=key.version,
            generation=generation, status=status,
            fingerprint=key.fingerprint_hex,
            certificate_fingerprint=(
                ebics3.certificate_fingerprint(key.certificate)
                if key.certificate else None),
            has_private=key.has_private, custody_key_id=self._custody.key_id,
            created_at=now, updated_at=now, _public_pem=key.public_pem(),
            _certificate_der=key.certificate_der() if key.certificate else None,
        )
        sealed = (self._custody.seal(key.private_pem(),
                                     context=_seal_context(stored))
                  if key.has_private else None)
        values = {
            "connection_id": connection_id, "holder": holder,
            "version": key.version.value, "generation": generation,
            "status": status, "fingerprint": stored.fingerprint,
            "certificate_fingerprint": stored.certificate_fingerprint,
            "public_pem": stored._public_pem,
            "certificate_der": stored._certificate_der,
            "sealed_private": sealed,
            "custody_key_id": self._custody.key_id if sealed else None,
            "created_at": now, "updated_at": now,
        }
        with self._engine.begin() as connection:
            connection.execute(key_material.insert().values(**values))

        self._audit.record(
            action, connection_id=connection_id,
            detail={"holder": holder, "key_version": key.version.value,
                    "generation": generation, "status": status,
                    "fingerprint": stored.fingerprint,
                    "certificate_fingerprint": stored.certificate_fingerprint,
                    "sealed": sealed is not None,
                    "custody_key_id": self._custody.key_id if sealed else None,
                    **(extra or {})},
        )
        log.info("keyring.stored", connection_id=connection_id, holder=holder,
                 key_version=key.version.value, generation=generation,
                 status=status, fingerprint=stored.fingerprint,
                 sealed=sealed is not None)

    def _row(self, connection_id: str, holder: str,
             version: ebics3.KeyVersion, generation: int):
        with self._engine.connect() as connection:
            return connection.execute(
                select(key_material).where(
                    key_material.c.connection_id == connection_id,
                    key_material.c.holder == holder,
                    key_material.c.version == version.value,
                    key_material.c.generation == generation)
            ).mappings().one()

    def _next_generation(self, connection_id: str, holder: str) -> int:
        rows = self._keyring.entries(connection_id, holder=holder, status=None)
        return max((row.generation for row in rows), default=0) + 1

    def _supersede(self, connection_id: str, holder: str,
                   version: ebics3.KeyVersion) -> None:
        with self._engine.begin() as connection:
            connection.execute(
                key_material.update().where(
                    key_material.c.connection_id == connection_id,
                    key_material.c.holder == holder,
                    key_material.c.version == version.value,
                    key_material.c.status == ACTIVE,
                ).values(status=SUPERSEDED,
                         updated_at=_dt.datetime.now(_dt.timezone.utc))
            )

    def _set_status(self, connection_id: str, key: StoredKey,
                    status: str) -> None:
        with self._engine.begin() as connection:
            connection.execute(
                key_material.update().where(
                    key_material.c.connection_id == connection_id,
                    key_material.c.holder == key.holder,
                    key_material.c.version == key.version.value,
                    key_material.c.generation == key.generation,
                ).values(status=status,
                         updated_at=_dt.datetime.now(_dt.timezone.utc))
            )


def _public_only(key: ebics3.EbicsKey) -> ebics3.EbicsKey:
    """The same key with the private half dropped, certificate kept."""
    if not key.has_private:
        return key
    return ebics3.EbicsKey.from_public_pem(key.version, key.public_pem(),
                                           key.certificate)


def seal_context(connection_id: str, holder: str, version: str,
                 generation: int) -> bytes:
    """The associated data every seal is bound to: which row it belongs in.

    A ciphertext lifted into another row -- another connection, another key
    version, another generation -- then fails to open rather than decrypting as
    a key it is not.

    Public because a custody-secret rotation opens and re-seals these rows
    without going through :class:`KeyCustodian` (:mod:`painfree.rekey`), and a
    second transcription of this string would be a rotation that produces
    material nothing can open.
    """
    return (f"painfree/key/{connection_id}/{holder}/"
            f"{version}/{generation}").encode("utf-8")


def _seal_context(key: StoredKey) -> bytes:
    return seal_context(key.connection_id, key.holder, key.version.value,
                        key.generation)


def _stored(row) -> StoredKey:
    return StoredKey(
        connection_id=row["connection_id"], holder=row["holder"],
        version=ebics3.KeyVersion.parse(row["version"]),
        generation=row["generation"], status=row["status"],
        fingerprint=row["fingerprint"],
        certificate_fingerprint=row["certificate_fingerprint"],
        has_private=row["sealed_private"] is not None,
        custody_key_id=row["custody_key_id"],
        created_at=row["created_at"], updated_at=row["updated_at"],
        _public_pem=row["public_pem"], _certificate_der=row["certificate_der"],
    )


__all__ = ["ACTIVE", "BANK", "KeyCustodian", "Keyring", "PENDING", "SUBSCRIBER",
           "SUBSCRIBER_VERSIONS", "SUPERSEDED", "SUSPENDED", "StoredKey"]
