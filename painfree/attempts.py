"""Every attempt at one order: what was built, what was sent, what is in reserve.

One idempotency key is one order. An **attempt** is one message built for that
order: its own ``MsgId``, its own document, and the BTF that announces it.
Ordinarily an order has exactly one. An order the caller asked to send as
``instant_or_normal`` has two from the moment it is accepted -- the instant one
live, the normal one ``planned`` and dormant -- and the fallback promotes the
second rather than building anything new.

**Both documents are built at accept time, and that is the safety property.**
The alternative is to rebuild a normal message in the worker when the bank
refuses instant, which means the worker holds the parsed instruction, runs the
Swiss rules and the XSD after a key is already open, and produces a document
nobody validated before signing. Here both messages are validated against the
vendored schema on the request path, before anything is signed, and the
fallback is a state transition over rows that already exist.

**At most one attempt is live.** ``live`` is the one the worker sends;
``planned`` has never been near a socket; ``superseded`` was refused and
replaced. The transitions are made by :mod:`painfree.queue` inside the same
transaction as the order's own, because the pair *order state, live attempt*
is one fact and a reader that could see half of it would see an order sending a
message no row admits to.

Nothing in this module decides anything. It reads and writes rows; the rules are
in :mod:`painfree.schemes` and the promotion is in :mod:`painfree.queue`.
"""

from __future__ import annotations

import datetime as _dt
import uuid
from dataclasses import dataclass
from typing import Any, Sequence

from sqlalchemy import Connection, Engine, select

from painfree import ebics3
from painfree.schemes import PaymentScheme, SchemeProfile
from painfree.schema import payment_attempt

__all__ = ["ATTEMPT_ID_PREFIX", "Attempt", "AttemptStore", "LIVE", "PLANNED",
           "SUPERSEDED", "new_attempt_id", "service_for_attempt"]

ATTEMPT_ID_PREFIX = "att_"

#: Built and validated, never sent. The reserve half of `instant_or_normal`.
PLANNED = "planned"
#: The attempt this order is on: what the worker sends, and what it last sent.
#: At most one per order, and every order has one. It keeps this state after the
#: order is terminal, because a replay re-sends exactly this attempt.
LIVE = "live"
#: Refused definitively and replaced by a fallback. Kept rather than deleted,
#: because *what did we actually send, and what did the bank say to it* is the
#: question an operator has after a payment went out under a scheme nobody
#: asked for.
SUPERSEDED = "superseded"


def new_attempt_id() -> str:
    return f"{ATTEMPT_ID_PREFIX}{uuid.uuid4().hex}"


@dataclass(frozen=True, slots=True)
class Attempt:
    """One message built for one order, and how it went."""

    attempt_id: str
    order_id: str
    attempt_no: int
    scheme: PaymentScheme
    state: str
    msg_id: str
    payment_information_id: str
    btf_service_name: str
    btf_service_option: str | None
    btf_scope: str | None
    payment_type: str | None
    reason: str | None
    return_code: str | None
    report_text: str | None
    created_at: _dt.datetime
    updated_at: _dt.datetime
    document: bytes

    @property
    def btf_summary(self) -> str:
        """The triplet as one line, the way the console shows it."""
        parts = [self.btf_service_name]
        if self.btf_service_option:
            parts.append(self.btf_service_option)
        if self.btf_scope:
            parts.append(self.btf_scope)
        return "/".join(parts)

    def as_response(self) -> dict[str, Any]:
        """What a caller is told about one attempt. Never the document.

        The BTF and the `PmtTpInf` are both here because the pair is the answer
        to the only interesting question about a scheme: did the announcement
        and the message agree.
        """
        body: dict[str, Any] = {
            "attempt": self.attempt_no,
            "scheme": self.scheme.value,
            "state": self.state,
            "msg_id": self.msg_id,
            "btf": self.btf_summary,
            "created_at": self.created_at.isoformat(),
        }
        if self.payment_type:
            body["payment_type_information"] = self.payment_type
        if self.reason:
            body["reason"] = self.reason
        if self.return_code:
            body["return_code"] = self.return_code
            body["report_text"] = self.report_text
        return body


def service_for_attempt(attempt: Attempt, message_type: str) -> ebics3.Service:
    """The BTF for this attempt: its stored triplet, and the message type.

    ``MsgName`` and its version are read off the message type rather than
    stored beside it -- they are two halves of one fact, and a service whose
    ``MsgName`` disagrees with the document it carries is refused by the bank
    with a code that does not say so. Everything the *bank* varies is in the
    row; everything the *document* fixes is derived from the document.
    """
    parts = message_type.split(".")
    if len(parts) < 4:
        raise ValueError(
            f"{message_type!r} is not an ISO 20022 message type; a BTF cannot "
            f"be derived from it")
    return ebics3.Service(
        name=attempt.btf_service_name, option=attempt.btf_service_option,
        scope=attempt.btf_scope, msg_name=".".join(parts[:2]),
        msg_version=parts[3])


class AttemptStore:
    """Reads and writes ``payment_attempt``. No keys, no decisions."""

    __slots__ = ("_engine",)

    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    # --- writing -----------------------------------------------------------

    @staticmethod
    def values(order_id: str, *, attempt_no: int, scheme: PaymentScheme,
               state: str, msg_id: str, payment_information_id: str,
               document: bytes, profile: SchemeProfile, now: _dt.datetime,
               reason: str | None = None) -> dict[str, Any]:
        """One row, ready to insert. Static so the accept path can batch it.

        The BTF triplet comes off the same :class:`SchemeProfile` that produced
        the ``PmtTpInf`` in ``document``, in one call, which is what makes the
        announcement and the message impossible to compute separately.
        """
        return {
            "attempt_id": new_attempt_id(),
            "order_id": order_id,
            "attempt_no": attempt_no,
            "scheme": scheme.value,
            "state": state,
            "msg_id": msg_id,
            "payment_information_id": payment_information_id,
            "document": document,
            "btf_service_name": profile.service_name,
            "btf_service_option": profile.service_option,
            "btf_scope": profile.scope,
            "payment_type": profile.payment_type_summary(),
            "reason": reason,
            "return_code": None,
            "report_text": None,
            "created_at": now,
            "updated_at": now,
        }

    def record(self, connection: Connection, rows: Sequence[dict[str, Any]]
               ) -> None:
        """Insert attempt rows on a caller's transaction, never on its own.

        The order and its attempts are one fact, so they are written by one
        ``begin()`` -- an order that existed for an instant with no live attempt
        would be an order the worker could claim and find nothing to send.
        """
        if rows:
            connection.execute(payment_attempt.insert(), list(rows))

    # --- reading -----------------------------------------------------------

    def live(self, order_id: str) -> Attempt | None:
        return self._one(order_id, LIVE)

    def planned(self, order_id: str) -> Attempt | None:
        return self._one(order_id, PLANNED)

    def _one(self, order_id: str, state: str) -> Attempt | None:
        with self._engine.connect() as connection:
            row = connection.execute(
                select(payment_attempt)
                .where(payment_attempt.c.order_id == order_id,
                       payment_attempt.c.state == state)
                .order_by(payment_attempt.c.attempt_no)
            ).mappings().first()
        return None if row is None else from_row(row)

    def all(self, order_id: str) -> list[Attempt]:
        """Every attempt at this order, oldest first. What the console lists."""
        with self._engine.connect() as connection:
            rows = connection.execute(
                select(payment_attempt)
                .where(payment_attempt.c.order_id == order_id)
                .order_by(payment_attempt.c.attempt_no)).mappings().all()
        return [from_row(row) for row in rows]

    def order_id_for(self, msg_id: str) -> str | None:
        """Which order sent this ``MsgId``, including a superseded attempt.

        A `pain.002` naming a message this service replaced still belongs to
        the order that sent it. Resolving only the live attempt would file that
        report as unmatched, which is the one outcome that loses the bank's own
        words about a payment.
        """
        with self._engine.connect() as connection:
            return connection.execute(
                select(payment_attempt.c.order_id)
                .where(payment_attempt.c.msg_id == msg_id)).scalar_one_or_none()


def from_row(row: Any) -> Attempt:
    return Attempt(
        attempt_id=row["attempt_id"], order_id=row["order_id"],
        attempt_no=row["attempt_no"], scheme=PaymentScheme(row["scheme"]),
        state=row["state"], msg_id=row["msg_id"],
        payment_information_id=row["payment_information_id"],
        btf_service_name=row["btf_service_name"],
        btf_service_option=row["btf_service_option"],
        btf_scope=row["btf_scope"], payment_type=row["payment_type"],
        reason=row["reason"], return_code=row["return_code"],
        report_text=row["report_text"], created_at=row["created_at"],
        updated_at=row["updated_at"], document=row["document"],
    )
