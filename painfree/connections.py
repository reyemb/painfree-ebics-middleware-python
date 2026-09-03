"""The bank connection registry: who we are to which bank, and how far we got.

One row per EBICS subscriber -- a `HostID`/`PartnerID`/`UserID` triple at one
host URL. Several coexist and are addressed by `connection_id`, the name that
also appears in every log line and every audit row for work done on that
connection.

The registry stores the engine's :class:`~painfree.ebics3.KeyState` and the two
booleans behind it. That is the point of persisting it at all: `INI` and `HIA`
each register a key the bank now has on file, and a service that forgot it sent
them would start again with fresh keys the bank has never seen -- against a
subscriber the bank considers already initialised. The engine models the state
machine and deliberately stores nothing (``painfree/ebics3/initialisation.py``);
this is where the state it hands back comes to rest.

No key material lives here. The keys belong to :mod:`painfree.keyring`, which is
where the custody boundary is enforced; this table holds identifiers, progress,
and the fingerprints that were accepted at `HPB` -- all of them public values.
"""

from __future__ import annotations

import datetime as _dt
import re
from dataclasses import dataclass
from typing import Any, Sequence

from sqlalchemy import Engine, select

from painfree import ebics3
from painfree.audit import Actor, AuditLog, SYSTEM_ACTOR
from painfree.errors import ConflictError, NotFoundError
from painfree.logging import get_logger
from painfree.schema import bank_connection
from painfree.schemes import SchemeProfiles

log = get_logger("painfree.connections")

#: Deliberately narrow: `connection_id` ends up in URLs, log lines and audit
#: rows, and a value that needs quoting in any of those is a value that will be
#: grepped for wrongly.
CONNECTION_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")

DEFAULT_EBICS_VERSION = ebics3.EBICS_VERSION


@dataclass(frozen=True, slots=True)
class BankConnection:
    """One registered connection, as the rest of the service sees it."""

    connection_id: str
    host_id: str
    partner_id: str
    user_id: str
    host_url: str
    ebics_version: str
    key_state: ebics3.KeyState
    ini_sent: bool
    hia_sent: bool
    ini_order_id: str | None
    hia_order_id: str | None
    letter_digest: ebics3.LetterDigest
    bank_fingerprints: dict[str, str] | None
    product: ebics3.Product | None
    #: Which BTF triplet and which ISO 20022 codes this bank means by each
    #: payment scheme. Resolved from the stored configuration with the defaults
    #: filling every gap, so a connection nobody has configured behaves exactly
    #: as it did before schemes existed (:mod:`painfree.schemes`).
    schemes: SchemeProfiles
    #: Whether an upload asks the bank to hold the payment for a human to
    #: release, rather than executing on this service's signature alone. Sets
    #: `BTUOrderParams/SignatureFlag/@requestEDS`.
    request_eds: bool
    created_at: _dt.datetime
    updated_at: _dt.datetime

    @property
    def context(self) -> ebics3.RequestContext:
        """The engine's view of this connection: identifiers, and nothing else."""
        return ebics3.RequestContext(
            host_id=self.host_id, partner_id=self.partner_id,
            user_id=self.user_id, product=self.product,
        )

    @property
    def initialised(self) -> bool:
        return self.key_state is ebics3.KeyState.READY


class ConnectionRegistry:
    """Reads and writes ``bank_connection``. Safe on the request path."""

    __slots__ = ("_engine", "_audit")

    def __init__(self, engine: Engine, audit: AuditLog | None = None) -> None:
        self._engine = engine
        self._audit = audit or AuditLog(engine)

    # --- registration ------------------------------------------------------

    def register(
        self,
        connection_id: str,
        *,
        host_id: str,
        partner_id: str,
        user_id: str,
        host_url: str,
        product: ebics3.Product | None = None,
        letter_digest: ebics3.LetterDigest | str = ebics3.DEFAULT_LETTER_DIGEST,
        ebics_version: str = DEFAULT_EBICS_VERSION,
        request_eds: bool = True,
        actor: Actor = SYSTEM_ACTOR,
    ) -> BankConnection:
        """Add a connection in its initial state. No keys yet; that is the worker's.

        The identifiers are validated by the engine's own `RequestContext`
        rather than by a second set of rules here -- if the bank would refuse
        the value, registering it is not useful.
        """
        if not CONNECTION_ID.match(connection_id or ""):
            raise ConflictError(
                f"connection id {connection_id!r} must match {CONNECTION_ID.pattern}")
        # Raises `RequestError` for an identifier EBICS will not carry.
        ebics3.RequestContext(host_id=host_id, partner_id=partner_id,
                              user_id=user_id, product=product)
        if ebics_version != ebics3.EBICS_VERSION:
            raise ConflictError(
                f"this engine speaks {ebics3.EBICS_VERSION} only; "
                f"{ebics_version} is not supported")

        now = _dt.datetime.now(_dt.timezone.utc)
        values: dict[str, Any] = {
            "connection_id": connection_id,
            "host_id": host_id, "partner_id": partner_id, "user_id": user_id,
            "host_url": host_url,
            "product_name": product.name if product else None,
            "product_language": product.language if product else None,
            "product_institute": product.institute if product else None,
            "ebics_version": ebics_version,
            "key_state": ebics3.KeyState.CREATED.value,
            "ini_sent": False, "hia_sent": False,
            "ini_order_id": None, "hia_order_id": None,
            "letter_digest": ebics3.LetterDigest(letter_digest).value,
            "bank_fingerprints": None,
            # Unset, not defaulted into the row: the defaults live in
            # `painfree.schemes` and a copy written here at registration would
            # be the copy that stops following them.
            "payment_schemes": None,
            # True unless the mandate says otherwise: a payment waits for a
            # person rather than executing on this service's signature alone.
            "request_eds": request_eds,
            "created_at": now, "updated_at": now,
        }
        try:
            with self._engine.begin() as connection:
                connection.execute(bank_connection.insert().values(**values))
        except Exception as exc:
            log.exception("connection.register_failed", connection_id=connection_id)
            self._audit.record("connection.registered", outcome="failure",
                               connection_id=connection_id,
                               detail={"reason": type(exc).__name__})
            raise ConflictError(
                f"connection {connection_id!r} could not be registered; the id "
                f"or the host/partner/user triple is already in use"
            ) from exc

        self._audit.record(
            "connection.registered", actor=actor, connection_id=connection_id,
            detail={"host_id": host_id, "partner_id": partner_id,
                    "user_id": user_id, "host_url": host_url,
                    "ebics_version": ebics_version},
        )
        return self.get(connection_id)

    def update(self, connection_id: str, *, host_url: str,
               product: ebics3.Product | None = None,
               letter_digest: ebics3.LetterDigest | str | None = None,
               schemes: SchemeProfiles | None = None,
               request_eds: bool | None = None,
               actor: Actor = SYSTEM_ACTOR) -> BankConnection:
        """Change what an operator is allowed to change, and record what changed.

        The three EBICS identifiers are **not** editable. They are what the bank
        knows this subscriber as, and the keys on file are registered against
        them -- editing one would silently detach a connection from its own
        initialisation rather than move it.

        ``host_url`` is editable and is the one field on this table with a
        security consequence: a worker posts signed order data to whatever it
        says, which is an open gap and is named as one here. So the audit row
        carries the old value and the new one, and the log line does too -- a
        change here should be visible without a diff of the table.
        """
        before = self.get(connection_id)
        digest = (ebics3.LetterDigest(letter_digest) if letter_digest is not None
                  else before.letter_digest)
        values: dict[str, Any] = {
            "host_url": host_url,
            "product_name": product.name if product else None,
            "product_language": product.language if product else None,
            "product_institute": product.institute if product else None,
            "letter_digest": digest.value,
            "updated_at": _dt.datetime.now(_dt.timezone.utc),
        }
        if schemes is not None:
            # Stored as the resolved set rather than as a patch, so that
            # reading the row answers "what will this connection send" without
            # having to know which defaults were in force when it was written.
            values["payment_schemes"] = schemes.as_json()
        if request_eds is not None:
            values["request_eds"] = request_eds
        with self._engine.begin() as connection:
            connection.execute(
                bank_connection.update()
                .where(bank_connection.c.connection_id == connection_id)
                .values(**values))

        after = self.get(connection_id)
        changed = {name: {"from": getattr(before, name), "to": getattr(after, name)}
                   for name in ("host_url",)
                   if getattr(before, name) != getattr(after, name)}
        if before.letter_digest is not after.letter_digest:
            changed["letter_digest"] = {"from": before.letter_digest.value,
                                        "to": after.letter_digest.value}
        if before.request_eds != after.request_eds:
            # Whether a payment executes on this service's signature or waits
            # for a person is the sharpest thing about a connection, so it goes
            # in the trail by name rather than being recoverable from a diff.
            changed["request_eds"] = {"from": before.request_eds,
                                      "to": after.request_eds}
        if before.schemes != after.schemes:
            # The BTF and the scheme codes decide what a bank is told about a
            # payment, so a change to them belongs in the trail beside the host
            # URL rather than being recoverable only from a diff of the table.
            changed["payment_schemes"] = {"from": before.schemes.as_json(),
                                          "to": after.schemes.as_json()}
        self._audit.record("connection.updated", actor=actor,
                           connection_id=connection_id,
                           detail={"changed": changed,
                                   "product": product.name if product else None})
        log.info("connection.updated", connection_id=connection_id,
                 changed=sorted(changed), host_url=after.host_url)
        return after

    # --- reading -----------------------------------------------------------

    def get(self, connection_id: str) -> BankConnection:
        with self._engine.connect() as connection:
            row = connection.execute(
                select(bank_connection).where(
                    bank_connection.c.connection_id == connection_id)
            ).mappings().one_or_none()
        if row is None:
            raise NotFoundError(f"no such bank connection: {connection_id!r}")
        return _from_row(row)

    def all(self, connection_ids: Sequence[str] | None = None
            ) -> list[BankConnection]:
        """Every connection this caller may see, oldest first.

        ``connection_ids`` is :func:`painfree.access.restrict`'s answer: ``None``
        for an administrator, the granted ids for a member, and an empty
        sequence for a member who holds none -- which is no rows rather than
        every row. Narrowing here rather than after the query is what keeps
        "the console shows only your connections" true of the query and not
        only of the page.
        """
        query = select(bank_connection).order_by(bank_connection.c.seq)
        if connection_ids is not None:
            query = query.where(
                bank_connection.c.connection_id.in_(list(connection_ids)))
        with self._engine.connect() as connection:
            rows = connection.execute(query).mappings().all()
        return [_from_row(row) for row in rows]

    # --- the state a half-finished initialisation resumes from -------------

    def save_progress(self, connection_id: str,
                      initialisation: ebics3.Initialisation) -> BankConnection:
        """Write back what one pass of the engine's state machine achieved.

        Called after every exchange rather than at the end: the failure this
        prevents is `INI` succeeding, `HIA` failing, and a restart re-sending
        `INI` with a key the bank has already accepted -- which a bank answers
        with `EBICS_INVALID_USER_STATE` and a support call.
        """
        before = self.get(connection_id)
        state = initialisation.state
        values = {
            "key_state": state.value,
            "ini_sent": initialisation.ini_sent,
            "hia_sent": initialisation.hia_sent,
            "ini_order_id": initialisation.ini_order_id,
            "hia_order_id": initialisation.hia_order_id,
            "bank_fingerprints": initialisation.bank_fingerprints,
            "updated_at": _dt.datetime.now(_dt.timezone.utc),
        }
        with self._engine.begin() as connection:
            connection.execute(
                bank_connection.update()
                .where(bank_connection.c.connection_id == connection_id)
                .values(**values)
            )

        for step, was, is_now, order_id in (
            ("INI", before.ini_sent, initialisation.ini_sent,
             initialisation.ini_order_id),
            ("HIA", before.hia_sent, initialisation.hia_sent,
             initialisation.hia_order_id),
        ):
            if is_now and not was:
                # The bank now has a key on file. That is the fact an auditor
                # asks about, and it is not recoverable from the key state
                # alone once both steps are done.
                self._audit.record(
                    "key.sent", connection_id=connection_id,
                    detail={"step": step, "order_id": order_id},
                )
        if before.key_state is not state:
            # One audit row per transition, not one per save: a retry that
            # achieved nothing should not read as progress.
            self._audit.record(
                "connection.key_state_changed", connection_id=connection_id,
                detail={"from": before.key_state.value, "to": state.value,
                        "ini_order_id": initialisation.ini_order_id,
                        "hia_order_id": initialisation.hia_order_id},
            )
        log.info("connection.progress", connection_id=connection_id,
                 key_state=state.value, ini_sent=initialisation.ini_sent,
                 hia_sent=initialisation.hia_sent)
        return self.get(connection_id)


def _from_row(row) -> BankConnection:
    product = (ebics3.Product(row["product_name"], row["product_language"],
                              row["product_institute"])
               if row["product_name"] else None)
    return BankConnection(
        connection_id=row["connection_id"], host_id=row["host_id"],
        partner_id=row["partner_id"], user_id=row["user_id"],
        host_url=row["host_url"], ebics_version=row["ebics_version"],
        key_state=ebics3.KeyState(row["key_state"]),
        ini_sent=bool(row["ini_sent"]), hia_sent=bool(row["hia_sent"]),
        ini_order_id=row["ini_order_id"], hia_order_id=row["hia_order_id"],
        letter_digest=ebics3.LetterDigest(row["letter_digest"]),
        bank_fingerprints=row["bank_fingerprints"], product=product,
        schemes=SchemeProfiles.parse(row["payment_schemes"]),
        request_eds=bool(row["request_eds"]),
        created_at=row["created_at"], updated_at=row["updated_at"],
    )


__all__ = ["BankConnection", "CONNECTION_ID", "ConnectionRegistry"]
