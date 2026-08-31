"""The event contract: what an event *is*, how it is signed, and where it is owed.

This is the writing half of the dispatcher. :mod:`painfree.dispatcher` claims
the rows this module creates and posts them; nothing here opens a socket.

**An event is an audit row.** The audit log is already the append-only record
of what this service did, written by one writer, with the correlation ids
attached and the detail redacted. Building a second event table beside it would
mean two records of one fact that can disagree, and the way they disagree is
that one of them is missing an event -- which is precisely the failure
at-least-once delivery exists to rule out. So :func:`fan_out` runs **inside**
:meth:`painfree.audit.AuditLog.record`'s transaction: the row that says a
payment was rejected and the row that owes that fact to a consumer commit
together or not at all.

That is the analogue of the download worker's ordering, one step earlier.
Store, then tell: a crash between the two costs a redelivery the consumer
deduplicates, and the other ordering costs the event.

**The envelope's `event_id` is the audit event's id.** It is stable across
redeliveries because it is stored, and it is the same string an operator greps
in the audit log and in the log stream. Consumers deduplicate on it: at-least-
once means duplicates *will* arrive, and the contract's answer is that they are
detectable rather than absent.

**The signature is over the bytes that are sent.** HMAC-SHA256 over
``timestamp || "." || body`` with the subscription's own secret, in a header
alongside the timestamp, so a receiver can both authenticate the payload and
refuse a replayed one. The scheme is transcribed in
``tests/test_service_webhooks.py`` so a consumer can implement the check
without reading this file -- and it is verified there by a verifier written
from that transcription rather than by calling :func:`sign`, which would prove
nothing.

**The secret is a secret, and the process that creates it cannot read it back.**
It is generated when an endpoint is registered, shown to the registering caller
once, and sealed to the public half of a keypair whose private half only a
process holding the custody secret can derive (:mod:`painfree.wrapping`). The
API process registers endpoints and cannot open one afterwards -- not through a
route, not through a traceback, not through a bug. Every secret that passes
through this module is registered with :func:`painfree.logging.register_secret`
the moment it exists, so no exception message that interpolated it reaches the
log stream either.

**A secret is rotated with an overlap, never swapped.** Issuing a new one keeps
the old one in ``sealed_secret_previous``, and every delivery is then signed
with *both*: the signature header carries a comma-separated list and a consumer
accepts if any entry verifies. The operator ends the overlap once their
receiver has the new value, which is the step that makes rotation something an
endpoint survives rather than something it misses events during.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import hmac
import json
import secrets
import uuid
from dataclasses import dataclass
from typing import Any, Iterable, Sequence

from sqlalchemy import Connection, Engine, select
from sqlalchemy.exc import IntegrityError

from painfree import wrapping
from painfree.errors import ConflictError, NotFoundError, NotReadyError
from painfree.logging import get_logger, register_secret
from painfree.schema import webhook_delivery, webhook_subscription
from painfree.sealing import CustodyKey

log = get_logger("painfree.webhooks")

SUBSCRIPTION_ID_PREFIX = "whs_"
DELIVERY_ID_PREFIX = "whd_"

#: The envelope's own version, carried in every event. Fields may be *added*
#: within a version -- a consumer that ignores what it does not know keeps
#: working -- and anything that would break such a consumer is version 2.
ENVELOPE_VERSION = 1

#: Which audit actions are events a consumer is owed, and what they are called
#: on the wire. The audit action is an internal name and the event type is a
#: contract, so the mapping is explicit: renaming a log line must not silently
#: rename a public event, and an action that is *not* here emits nothing.
#:
#: `payment.acknowledged` and the second writer of `payment.rejected` are
#: :mod:`painfree.reconcile`, which matches a `pain.002` back to the order it
#: reports on. Both terminal words therefore have two sources and one meaning
#: each: the bank refused at submission, or it refused in its status report.
#: The `data` says which, in `source`.
#:
#: The status-report actions that do *not* change an order -- an interim
#: `PDNG`, a report for a `MsgId` this service never sent, a report for an
#: order already terminal -- are audited under names that are deliberately
#: absent here. They are facts worth a row and not events a consumer is owed:
#: nothing about the order changed.
EVENT_TYPES: dict[str, str] = {
    "payment.accepted": "order.accepted",
    "payment.submitted": "order.submitted",
    "payment.rejected": "order.rejected",
    "payment.acknowledged": "order.acknowledged",
    "payment.failed": "order.failed",
    "statement.available": "statement.available",
}

#: Every type a subscription may ask for.
EVENT_TYPE_NAMES = frozenset(EVENT_TYPES.values())

#: What a test delivery is called on the wire. Deliberately **not** in
#: :data:`EVENT_TYPE_NAMES`: a ping is not something an endpoint subscribes to,
#: it is something an operator aims at one subscription. So there is no
#: configuration under which a consumer receives one it did not ask for, and no
#: bank event can ever be mistaken for a test.
PING_EVENT_TYPE = "webhook.ping"

#: Delivery states. `parked` is not `failed`: a failed delivery gave up on its
#: own merits, a parked one was never tried because its subscription was.
PENDING = "pending"
DELIVERING = "delivering"
DELIVERED = "delivered"
FAILED = "failed"
PARKED = "parked"

#: Header names, fixed here so the dispatcher and the contract cannot drift.
EVENT_HEADER = "X-Painfree-Event"
EVENT_ID_HEADER = "X-Painfree-Event-Id"
DELIVERY_HEADER = "X-Painfree-Delivery"
ATTEMPT_HEADER = "X-Painfree-Attempt"
TIMESTAMP_HEADER = "X-Painfree-Timestamp"
SIGNATURE_HEADER = "X-Painfree-Signature"

#: The signature scheme's name, so a second one can be added later without a
#: consumer having to guess which it is looking at.
SIGNATURE_SCHEME = "v1"

MAX_ERROR_LENGTH = 512

#: Long enough that a generated value is not guessable, and it is generated:
#: ``python -m painfree new-secret`` prints one of the same shape.
MIN_SECRET_LENGTH = 32


def utcnow() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def new_webhook_secret() -> str:
    return secrets.token_urlsafe(32)


# --- the envelope -----------------------------------------------------------

def envelope(*, event_id: str, event_type: str, occurred_at: _dt.datetime,
             connection_id: str | None = None, order_id: str | None = None,
             idempotency_key: str | None = None,
             data: dict[str, Any] | None = None) -> dict[str, Any]:
    """One event, in the shape the webhook envelope fixes.

    Correlation is at the top level and the type-specific rest is in ``data``,
    so a consumer routes on four fields it can read without knowing the type.
    An id that is not known is **absent** rather than null, for the same reason
    a log line never writes ``"order_id": null``.
    """
    body: dict[str, Any] = {
        "version": ENVELOPE_VERSION,
        "event_id": event_id,
        "event_type": event_type,
        "occurred_at": _iso(occurred_at),
    }
    for name, value in (("connection_id", connection_id),
                        ("order_id", order_id),
                        ("idempotency_key", idempotency_key)):
        if value is not None:
            body[name] = value
    body["data"] = data or {}
    return body


def canonical_body(event: dict[str, Any]) -> bytes:
    """The exact bytes that are signed and sent.

    Keys sorted and separators fixed, so the body a redelivery signs is the
    body the first attempt signed. A consumer verifies over the raw bytes it
    received and never over a re-serialisation of its own parse -- that is
    said in the contract, and this is why it has to be.
    """
    return json.dumps(event, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def sign(secret: str, timestamp: int, body: bytes) -> str:
    """``v1=<hex>`` -- HMAC-SHA256 over ``"<timestamp>.<body>"``.

    The timestamp is inside the MAC rather than beside it, so a receiver that
    checks the age of a request is checking a value an attacker cannot change
    without invalidating the signature.
    """
    signed = str(timestamp).encode("ascii") + b"." + body
    digest = hmac.new(secret.encode("utf-8"), signed, hashlib.sha256).hexdigest()
    return f"{SIGNATURE_SCHEME}={digest}"


def sign_all(secrets_in_use: Sequence[str], timestamp: int,
             body: bytes) -> str:
    """The signature header's value: one entry per secret that is still live.

    Ordinarily one. Two while a rotation is in flight, newest first, so an
    endpoint that has been switched over verifies on the first entry and one
    that has not verifies on the second. A consumer accepts if **any** entry
    verifies -- which is what lets a secret change without a delivery being
    refused by a receiver that has not been reconfigured yet.
    """
    return ",".join(sign(secret, timestamp, body) for secret in secrets_in_use)


def delivery_headers(*, event_type: str, event_id: str, delivery_id: str,
                     attempt: int, timestamp: int, signature: str) -> dict[str, str]:
    """What accompanies the body. The signature and its timestamp, and enough
    correlation that a consumer's own log can be joined to this service's."""
    return {
        "Content-Type": "application/json; charset=utf-8",
        EVENT_HEADER: event_type,
        EVENT_ID_HEADER: event_id,
        DELIVERY_HEADER: delivery_id,
        ATTEMPT_HEADER: str(attempt),
        TIMESTAMP_HEADER: str(timestamp),
        SIGNATURE_HEADER: signature,
    }


def _iso(moment: _dt.datetime) -> str:
    return moment.astimezone(_dt.timezone.utc).isoformat(
        timespec="milliseconds").replace("+00:00", "Z")


# --- subscriptions ----------------------------------------------------------

@dataclass(frozen=True, slots=True)
class Subscription:
    """One consumer endpoint. Never carries the secret -- only its custody id."""

    subscription_id: str
    connection_id: str | None
    url: str
    event_types: tuple[str, ...]
    enabled: bool
    parked_at: _dt.datetime | None
    consecutive_failures: int
    last_status: int | None
    last_error: str | None
    custody_key_id: str
    description: str | None = None
    secret_generation: int = 1
    secret_rotated_at: _dt.datetime | None = None
    rotating: bool = False
    last_delivery_at: _dt.datetime | None = None
    created_at: _dt.datetime | None = None
    updated_at: _dt.datetime | None = None

    @property
    def parked(self) -> bool:
        return self.parked_at is not None

    @property
    def health(self) -> str:
        """One word for a list of six endpoints. The reason this page exists.

        `parked` outranks everything: a parked endpoint is receiving nothing,
        and that is what an operator opened the page to find out.
        """
        if self.parked:
            return "parked"
        if not self.enabled:
            return "paused"
        if self.consecutive_failures:
            return "failing"
        if self.last_delivery_at is None:
            return "untested"
        return "healthy"

    def wants(self, event_type: str, connection_id: str | None) -> bool:
        if event_type not in self.event_types:
            return False
        return self.connection_id is None or self.connection_id == connection_id

    def as_response(self) -> dict[str, Any]:
        """The JSON shape. **Never the secret**, in any generation.

        There is no field here a secret could occupy, and no code path that
        could fill one: this process cannot open the seal it stored.
        `secret_generation` is how a consumer confirms which value is current
        without the value being repeated.
        """
        return {
            "subscription_id": self.subscription_id,
            "connection_id": self.connection_id,
            "url": self.url,
            "event_types": list(self.event_types),
            "description": self.description,
            "enabled": self.enabled,
            "parked": self.parked,
            "parked_at": _at(self.parked_at),
            "health": self.health,
            "consecutive_failures": self.consecutive_failures,
            "last_delivery_at": _at(self.last_delivery_at),
            "last_status": self.last_status,
            "last_error": self.last_error,
            "secret_generation": self.secret_generation,
            "secret_rotating": self.rotating,
            "secret_rotated_at": _at(self.secret_rotated_at),
            "created_at": _at(self.created_at),
            "updated_at": _at(self.updated_at),
        }


@dataclass(frozen=True, slots=True)
class Delivery:
    """One event owed to one endpoint, as a screen or a caller reads it back.

    Carries the envelope's correlation and the delivery's own bookkeeping, and
    not the payload: what was in the event is the audit log's business, and an
    order's own page already shows it.
    """

    delivery_id: str
    subscription_id: str
    event_id: str
    event_type: str
    connection_id: str | None
    order_id: str | None
    state: str
    attempts: int
    last_status: int | None
    last_error: str | None
    occurred_at: _dt.datetime
    next_attempt_at: _dt.datetime | None
    delivered_at: _dt.datetime | None

    def as_response(self) -> dict[str, Any]:
        return {"delivery_id": self.delivery_id, "event_id": self.event_id,
                "event_type": self.event_type, "state": self.state,
                "attempts": self.attempts, "last_status": self.last_status,
                "last_error": self.last_error,
                "connection_id": self.connection_id, "order_id": self.order_id,
                "occurred_at": _at(self.occurred_at),
                "next_attempt_at": _at(self.next_attempt_at),
                "delivered_at": _at(self.delivered_at)}


def _at(moment: _dt.datetime | None) -> str | None:
    return moment.isoformat() if moment else None


class WebhookSubscriptions:
    """Registering endpoints, managing them, and the one door to their secrets.

    **Registering needs no custody key and opening does.** That asymmetry is
    the whole point: the request path seals a new secret to the published
    wrapping key (:mod:`painfree.wrapping`) and cannot undo it, while the
    dispatcher -- constructed with a :class:`~painfree.sealing.CustodyKey` --
    derives the private half and opens. So the API process can register an
    endpoint, show its secret once and manage it afterwards, without ever being
    able to read a stored one or forge a signature.

    Everything that is not a secret -- listing, pausing, resuming, retiring a
    rotated secret, queueing a ping -- works with no key at all.
    """

    __slots__ = ("_engine", "_custody_key")

    def __init__(self, engine: Engine,
                 custody_key: CustodyKey | None = None) -> None:
        self._engine = engine
        self._custody_key = custody_key

    # --- registration and the secret ---------------------------------------

    def register(self, url: str, event_types: Iterable[str], *,
                 connection_id: str | None = None,
                 secret: str | None = None,
                 description: str | None = None,
                 idempotency_key: str | None = None,
                 ) -> tuple[Subscription, str]:
        """Add an endpoint and return it with its secret, **once**.

        The secret is returned here and nowhere else. After this call it exists
        only sealed to a public key this process cannot invert, so no later
        request -- and no later bug -- can produce it again. A caller that
        loses it rotates rather than re-reads (:meth:`rotate_secret`).
        """
        types = _validated_types(event_types)
        _validated_url(url)
        secret = _validated_secret(secret)
        recipient = self._recipient()

        subscription_id = SUBSCRIPTION_ID_PREFIX + uuid.uuid4().hex
        now = utcnow()
        try:
            with self._engine.begin() as connection:
                connection.execute(webhook_subscription.insert().values(
                    subscription_id=subscription_id,
                    connection_id=connection_id, url=url,
                    event_types=list(types), description=description,
                    sealed_secret=recipient.seal(
                        secret.encode("utf-8"),
                        context=_context(subscription_id)),
                    sealed_secret_previous=None, secret_generation=1,
                    secret_rotated_at=None,
                    custody_key_id=recipient.custody_key_id,
                    idempotency_key=idempotency_key, enabled=True,
                    consecutive_failures=0, created_at=now, updated_at=now))
        except IntegrityError:
            # The unique constraint on `idempotency_key` did its job: this key
            # already registered an endpoint. The winner is returned, and the
            # secret is *not* -- it was shown once, and this is not that once.
            existing = (self.by_idempotency_key(idempotency_key)
                        if idempotency_key else None)
            if existing is None:
                raise
            log.info("webhook.subscription_replayed",
                     subscription_id=existing.subscription_id,
                     idempotency_key=idempotency_key)
            raise Replayed(existing) from None
        log.info("webhook.subscription_registered",
                 subscription_id=subscription_id, connection_id=connection_id,
                 url=url, event_types=list(types),
                 custody_key_id=recipient.custody_key_id)
        return self.get(subscription_id), secret

    def rotate_secret(self, subscription_id: str, *,
                      secret: str | None = None) -> tuple[Subscription, str]:
        """Issue a new signing secret, keeping the old one live meanwhile.

        Returned once, like the first one. The retiring secret stays in the row
        and keeps signing every delivery beside the new one until
        :meth:`retire_previous_secret` ends the overlap -- so an endpoint that
        has not been reconfigured yet still verifies what it receives, and
        nothing is dropped on the floor while a human copies a value between
        two systems.

        A second rotation while the first is still open is refused. Allowing it
        would silently discard the secret the endpoint is *actually* using, and
        the point of the overlap is that no such moment exists.
        """
        current = self.get(subscription_id)
        if current.rotating:
            raise ConflictError(
                f"webhook subscription {subscription_id} is already rotating "
                f"its secret; finish that rotation before starting another, "
                f"or the endpoint's current secret would be dropped",
                detail={"secret_generation": current.secret_generation})
        secret = _validated_secret(secret)
        recipient = self._recipient()
        now = utcnow()
        with self._engine.begin() as connection:
            row = connection.execute(
                select(webhook_subscription.c.sealed_secret)
                .where(webhook_subscription.c.subscription_id
                       == subscription_id)).one_or_none()
            if row is None:
                raise NotFoundError(
                    f"no such webhook subscription: {subscription_id}")
            connection.execute(
                webhook_subscription.update()
                .where(webhook_subscription.c.subscription_id == subscription_id)
                .values(
                    sealed_secret=recipient.seal(
                        secret.encode("utf-8"),
                        context=_context(subscription_id)),
                    sealed_secret_previous=row[0],
                    secret_generation=(
                        webhook_subscription.c.secret_generation + 1),
                    secret_rotated_at=now,
                    custody_key_id=recipient.custody_key_id, updated_at=now))
        rotated = self.get(subscription_id)
        log.info("webhook.secret_rotated", subscription_id=subscription_id,
                 secret_generation=rotated.secret_generation,
                 custody_key_id=recipient.custody_key_id)
        return rotated, secret

    def retire_previous_secret(self, subscription_id: str) -> Subscription:
        """End a rotation: the old secret stops signing and is dropped."""
        current = self.get(subscription_id)
        if not current.rotating:
            raise ConflictError(
                f"webhook subscription {subscription_id} has no previous "
                f"secret to retire")
        self._update(subscription_id, sealed_secret_previous=None,
                     secret_rotated_at=None)
        log.info("webhook.previous_secret_retired",
                 subscription_id=subscription_id,
                 secret_generation=current.secret_generation)
        return self.get(subscription_id)

    def signing_secrets(self, subscription_id: str) -> tuple[str, ...]:
        """Every secret a delivery must be signed with, newest first.

        One, or two during a rotation. The dispatcher is the only caller.
        """
        key = self._require_key("open a signing secret")
        row = self._row(subscription_id)
        if row is None:
            raise NotFoundError(f"no such webhook subscription: {subscription_id}")
        sealed = [row["sealed_secret"]]
        if row["sealed_secret_previous"] is not None:
            sealed.append(row["sealed_secret_previous"])
        opened = tuple(self._open(key, subscription_id, blob)
                       for blob in sealed)
        for secret in opened:
            # Taught to the log stream on every open, not only on registration:
            # a dispatcher restarted after the secret was created in another
            # process would otherwise be able to interpolate it into a
            # traceback.
            register_secret(secret)
        return opened

    def open_secret(self, subscription_id: str) -> str:
        """The current signing secret, opened."""
        return self.signing_secrets(subscription_id)[0]

    # --- reading ------------------------------------------------------------

    def get(self, subscription_id: str) -> Subscription:
        row = self._row(subscription_id)
        if row is None:
            raise NotFoundError(f"no such webhook subscription: {subscription_id}")
        return _subscription(row)

    def all(self, connection_id: str | None = None,
            connection_ids: Sequence[str] | None = None) -> list[Subscription]:
        """Subscriptions, optionally narrowed twice.

        ``connection_ids`` is what the caller may see. A subscription whose
        ``connection_id`` is `NULL` receives *every* connection's events, so it
        belongs to the deployment rather than to any one bank and is therefore
        excluded by any restriction at all -- an administrator, whose
        restriction is ``None``, is the only caller a connection-less
        subscription is listed to.
        """
        query = select(webhook_subscription).order_by(webhook_subscription.c.seq)
        if connection_id is not None:
            query = query.where(
                webhook_subscription.c.connection_id == connection_id)
        if connection_ids is not None:
            query = query.where(
                webhook_subscription.c.connection_id.in_(list(connection_ids)))
        with self._engine.connect() as connection:
            return [_subscription(row)
                    for row in connection.execute(query).mappings()]

    def by_idempotency_key(self, idempotency_key: str) -> Subscription | None:
        with self._engine.connect() as connection:
            row = connection.execute(
                select(webhook_subscription)
                .where(webhook_subscription.c.idempotency_key
                       == idempotency_key)).mappings().one_or_none()
        return None if row is None else _subscription(row)

    def deliveries(self, subscription_id: str, limit: int = 25
                   ) -> list[Delivery]:
        """This endpoint's recent deliveries, newest first."""
        with self._engine.connect() as connection:
            rows = connection.execute(
                select(webhook_delivery)
                .where(webhook_delivery.c.subscription_id == subscription_id)
                .order_by(webhook_delivery.c.seq.desc())
                .limit(limit)).mappings().all()
        return [_delivery(row) for row in rows]

    def owed(self, subscription_id: str) -> int:
        """How many events this endpoint has not received yet, parked included."""
        from sqlalchemy import func

        with self._engine.connect() as connection:
            return connection.execute(
                select(func.count()).select_from(webhook_delivery)
                .where(webhook_delivery.c.subscription_id == subscription_id,
                       webhook_delivery.c.state.in_(
                           (PENDING, DELIVERING, PARKED)))).scalar_one()

    # --- management ---------------------------------------------------------

    def update(self, subscription_id: str, *, url: str | None = None,
               event_types: Iterable[str] | None = None,
               description: str | None = None,
               connection_id: str | None = None,
               change_connection: bool = False) -> Subscription:
        """Change where events go, or which ones. The secret is untouched.

        Everything here is configuration a subscription can survive being
        changed under: a queued delivery is re-read at send time, so an
        endpoint whose URL is corrected receives what it was already owed at
        the new address rather than needing the events re-created.
        """
        self.get(subscription_id)
        values: dict[str, Any] = {}
        if url is not None:
            values["url"] = _validated_url(url)
        if event_types is not None:
            values["event_types"] = list(_validated_types(event_types))
        if description is not None:
            values["description"] = description.strip() or None
        if change_connection:
            values["connection_id"] = connection_id
        if not values:
            return self.get(subscription_id)
        self._update(subscription_id, **values)
        log.info("webhook.subscription_updated",
                 subscription_id=subscription_id, changed=sorted(values))
        return self.get(subscription_id)

    def delete(self, subscription_id: str) -> int:
        """Remove an endpoint, and the events still owed to it.

        Returns how many were owed, because that number is the cost of the
        decision: those events are not re-created, and a consumer that comes
        back has a gap. Pausing is the reversible operation; this is not.
        """
        owed = self.owed(subscription_id)
        self.get(subscription_id)
        with self._engine.begin() as connection:
            # Deleted explicitly rather than left to the foreign key: SQLite
            # only cascades with `foreign_keys=ON`, which `painfree.db` sets,
            # and a delete that silently depends on a PRAGMA is a delete that
            # behaves differently in a psql session.
            connection.execute(webhook_delivery.delete().where(
                webhook_delivery.c.subscription_id == subscription_id))
            connection.execute(webhook_subscription.delete().where(
                webhook_subscription.c.subscription_id == subscription_id))
        log.info("webhook.subscription_deleted",
                 subscription_id=subscription_id, owed_events_dropped=owed)
        return owed

    def enqueue_ping(self, subscription_id: str, *, actor_id: str | None = None
                     ) -> Delivery:
        """Owe this endpoint one test event, and let the dispatcher deliver it.

        A ping goes through the ordinary path -- claimed, signed, POSTed,
        retried, recorded -- because a test that took a shortcut would prove
        the shortcut works. So it queues behind whatever this subscription is
        already owed, which is itself the answer to "why has my ping not
        arrived": the endpoint is behind.

        Refused for an endpoint the dispatcher will not serve. A ping to a
        parked or paused subscription would sit in the queue for ever and read
        on screen as a failure of the endpoint rather than of its state.
        """
        subscription = self.get(subscription_id)
        if subscription.parked:
            raise ConflictError(
                f"webhook subscription {subscription_id} is parked; resume it "
                f"before testing it, or the ping is never attempted",
                detail={"health": subscription.health})
        if not subscription.enabled:
            raise ConflictError(
                f"webhook subscription {subscription_id} is paused; resume it "
                f"before testing it, or the ping is never attempted",
                detail={"health": subscription.health})

        now = utcnow()
        event_id = str(uuid.uuid4())
        delivery_id = DELIVERY_ID_PREFIX + uuid.uuid4().hex
        event = envelope(
            event_id=event_id, event_type=PING_EVENT_TYPE, occurred_at=now,
            connection_id=subscription.connection_id,
            data={"subscription_id": subscription_id,
                  "requested_by": actor_id,
                  "message": "This is a test delivery from painfree. No "
                             "payment or statement is involved."})
        with self._engine.begin() as connection:
            connection.execute(webhook_delivery.insert().values(
                delivery_id=delivery_id, subscription_id=subscription_id,
                event_id=event_id, event_type=PING_EVENT_TYPE,
                connection_id=subscription.connection_id, order_id=None,
                idempotency_key=None, occurred_at=now, payload=event,
                state=PENDING, attempts=0, next_attempt_at=now,
                created_at=now, updated_at=now))
        log.info("webhook.ping_queued", subscription_id=subscription_id,
                 delivery_id=delivery_id, event_id=event_id,
                 url=subscription.url, requested_by=actor_id)
        return self.deliveries(subscription_id, limit=1)[0]

    def set_enabled(self, subscription_id: str, enabled: bool) -> Subscription:
        """Pause or resume delivery. Queued events are kept either way."""
        self.get(subscription_id)
        self._update(subscription_id, enabled=enabled)
        log.info("webhook.subscription_paused" if not enabled
                 else "webhook.subscription_unpaused",
                 subscription_id=subscription_id)
        return self.get(subscription_id)

    def resume(self, subscription_id: str) -> int:
        """Un-park a subscription and return its parked deliveries to the queue.

        The operator's half of the parking decision: parking is automatic,
        resuming is not, because an endpoint that failed for two hours is one
        somebody has to have fixed.
        """
        now = utcnow()
        with self._engine.begin() as connection:
            connection.execute(
                webhook_subscription.update()
                .where(webhook_subscription.c.subscription_id == subscription_id)
                .values(parked_at=None, consecutive_failures=0, enabled=True,
                        updated_at=now))
            revived = connection.execute(
                webhook_delivery.update()
                .where(webhook_delivery.c.subscription_id == subscription_id,
                       webhook_delivery.c.state == PARKED)
                .values(state=PENDING, next_attempt_at=now, updated_at=now)
            ).rowcount
        log.info("webhook.subscription_resumed",
                 subscription_id=subscription_id, requeued=revived)
        return revived

    def _row(self, subscription_id: str):
        with self._engine.connect() as connection:
            return connection.execute(
                select(webhook_subscription)
                .where(webhook_subscription.c.subscription_id == subscription_id)
            ).mappings().one_or_none()

    def _update(self, subscription_id: str, **values: Any) -> None:
        values.setdefault("updated_at", utcnow())
        with self._engine.begin() as connection:
            connection.execute(
                webhook_subscription.update()
                .where(webhook_subscription.c.subscription_id == subscription_id)
                .values(**values))

    def _require_key(self, what: str) -> CustodyKey:
        if self._custody_key is None:
            raise ConflictError(
                f"this process holds no custody key and cannot {what}; webhook "
                f"signing secrets are opened only where private keys are")
        return self._custody_key

    def _recipient(self) -> wrapping.Recipient:
        """Who a new secret is sealed to.

        A process that holds the custody key publishes its own public half if
        nobody has -- which is what makes the worker's startup the only
        bootstrap there is, and a test that never runs one work anyway. A
        process that does not can only use what a worker published, and says
        so plainly when there is nothing: an operator whose first registration
        fails should be told to start a worker, not shown a stack trace.
        """
        recipient = wrapping.published(self._engine)
        if recipient is None and self._custody_key is not None:
            recipient = wrapping.publish(self._engine, self._custody_key)
        if recipient is None:
            raise NotReadyError(
                "no webhook wrapping key has been published yet, so a signing "
                "secret cannot be stored; start a worker process once and try "
                "again")
        return recipient

    def _open(self, key: CustodyKey, subscription_id: str,
              blob: bytes) -> str:
        """Open one sealed secret, whichever envelope it is in.

        Both shapes live in the same column and always will: a subscription
        registered before the request path could seal carries a symmetric
        :mod:`painfree.sealing` blob, and every one registered since carries a
        wrapped one. The magic distinguishes them, so nothing has to be
        rewritten and no operator has to know which is which.
        """
        context = _context(subscription_id)
        if wrapping.is_wrapped(blob):
            return wrapping.unseal(key, blob, context=context).decode("utf-8")
        return key.open(blob, context=context).decode("utf-8")


# --- fan-out ----------------------------------------------------------------

def fan_out(connection: Connection, *, event_id: str, action: str,
            occurred_at: _dt.datetime, ids: dict[str, Any],
            detail: dict[str, Any]) -> int:
    """Owe one audit event to every subscription that asked for it.

    Called by :meth:`painfree.audit.AuditLog.record` **on its own connection**,
    inside its transaction, so the event and the fact commit together. An
    action no subscription could want costs one dictionary lookup and no query.

    A failure here fails the audited operation, deliberately: an event that a
    consumer is owed is part of the record, and the alternative is a payment
    that is accepted and never reported.
    """
    event_type = EVENT_TYPES.get(action)
    if event_type is None:
        return 0

    connection_id = ids.get("connection_id")
    subscriptions = [
        row for row in connection.execute(
            select(webhook_subscription.c.subscription_id,
                   webhook_subscription.c.connection_id,
                   webhook_subscription.c.event_types)
            .where(webhook_subscription.c.enabled.is_(True),
                   webhook_subscription.c.parked_at.is_(None))
            .order_by(webhook_subscription.c.seq)).mappings()
        # The event-type filter is applied here rather than in SQL: the two
        # backends store a JSON array differently enough that a containment
        # predicate would be two queries, and the enabled set is small.
        if event_type in (row["event_types"] or ())
        and (row["connection_id"] is None
             or row["connection_id"] == connection_id)
    ]
    if not subscriptions:
        return 0

    event = envelope(event_id=event_id, event_type=event_type,
                     occurred_at=occurred_at, connection_id=connection_id,
                     order_id=ids.get("order_id"),
                     idempotency_key=ids.get("idempotency_key"),
                     data=dict(detail or {}))
    now = utcnow()
    rows = [{
        "delivery_id": DELIVERY_ID_PREFIX + uuid.uuid4().hex,
        "subscription_id": row["subscription_id"],
        "event_id": event_id, "event_type": event_type,
        "connection_id": connection_id, "order_id": ids.get("order_id"),
        "idempotency_key": ids.get("idempotency_key"),
        "occurred_at": occurred_at, "payload": event, "state": PENDING,
        "attempts": 0, "next_attempt_at": now,
        "created_at": now, "updated_at": now,
    } for row in subscriptions]
    try:
        connection.execute(webhook_delivery.insert(), rows)
    except IntegrityError:
        # `(subscription_id, event_id)` is unique, so this is the same audit
        # event being fanned out twice -- which cannot happen from one writer
        # and is worth seeing if it ever does. The caller's transaction is
        # already doomed; the log line is what says why.
        log.exception("webhook.fan_out_conflict", event_id=event_id,
                      event_type=event_type, connection_id=connection_id)
        raise
    log.info("webhook.event_recorded", event_id=event_id,
             event_type=event_type, connection_id=connection_id,
             subscriptions=len(rows))
    return len(rows)


def pending_count(engine: Engine, subscription_id: str | None = None) -> int:
    """How many events are owed. Used by the tests and by future diagnostics."""
    from sqlalchemy import func

    query = (select(func.count()).select_from(webhook_delivery)
             .where(webhook_delivery.c.state.in_((PENDING, DELIVERING))))
    if subscription_id is not None:
        query = query.where(
            webhook_delivery.c.subscription_id == subscription_id)
    with engine.connect() as connection:
        return connection.execute(query).scalar_one()


class Replayed(Exception):
    """A registration whose idempotency key had already registered something.

    Not a :class:`~painfree.errors.ServiceError`: it is not a failure. The
    caller is handed the subscription its key already made, and decides what
    that means for its response -- which for ``POST /v1/webhooks`` is the
    original resource and ``Idempotency-Replayed: true``, without the secret,
    because the secret was shown once and this is not that once.
    """

    def __init__(self, subscription: "Subscription") -> None:
        super().__init__(
            f"this idempotency key already registered "
            f"{subscription.subscription_id}")
        self.subscription = subscription


def _validated_secret(secret: str | None) -> str:
    secret = secret or new_webhook_secret()
    if len(secret) < MIN_SECRET_LENGTH:
        raise ConflictError(
            f"a webhook signing secret must be at least "
            f"{MIN_SECRET_LENGTH} characters")
    # Taught to the redactor before it is stored, so a failure between here and
    # the commit cannot put it in a traceback.
    register_secret(secret)
    return secret


def _validated_types(event_types: Iterable[str]) -> tuple[str, ...]:
    types = tuple(dict.fromkeys(event_types))
    if not types:
        raise ConflictError("a subscription must ask for at least one event type")
    unknown = [name for name in types if name not in EVENT_TYPE_NAMES]
    if unknown:
        raise ConflictError(
            "unknown webhook event types: " + ", ".join(sorted(unknown)),
            detail={"known": sorted(EVENT_TYPE_NAMES)})
    return types


def _validated_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        raise ConflictError(
            "a webhook endpoint must be an http or https URL")
    return url


def secret_context(subscription_id: str) -> bytes:
    """The AEAD associated data: a secret moved to another row will not open.

    Public for the same reason :func:`painfree.keyring.seal_context` is: a
    custody-secret rotation re-seals these blobs directly, and the binding has
    to be written down once.
    """
    return f"webhook:{subscription_id}".encode("ascii")


def _context(subscription_id: str) -> bytes:
    return secret_context(subscription_id)


def _subscription(row: Any) -> Subscription:
    return Subscription(
        subscription_id=row["subscription_id"],
        connection_id=row["connection_id"], url=row["url"],
        event_types=tuple(row["event_types"] or ()),
        enabled=bool(row["enabled"]), parked_at=row["parked_at"],
        consecutive_failures=row["consecutive_failures"],
        last_status=row["last_status"], last_error=row["last_error"],
        custody_key_id=row["custody_key_id"],
        description=row["description"],
        secret_generation=row["secret_generation"],
        secret_rotated_at=row["secret_rotated_at"],
        rotating=row["sealed_secret_previous"] is not None,
        last_delivery_at=row["last_delivery_at"],
        created_at=row["created_at"], updated_at=row["updated_at"])


def _delivery(row: Any) -> Delivery:
    return Delivery(
        delivery_id=row["delivery_id"],
        subscription_id=row["subscription_id"], event_id=row["event_id"],
        event_type=row["event_type"], connection_id=row["connection_id"],
        order_id=row["order_id"], state=row["state"],
        attempts=row["attempts"], last_status=row["last_status"],
        last_error=row["last_error"], occurred_at=row["occurred_at"],
        next_attempt_at=row["next_attempt_at"],
        delivered_at=row["delivered_at"])


def short(reason: str) -> str:
    reason = " ".join(str(reason).split())
    return reason if len(reason) <= MAX_ERROR_LENGTH else (
        reason[:MAX_ERROR_LENGTH - 1] + "…")


__all__: Sequence[str] = [
    "ATTEMPT_HEADER", "DELIVERED", "DELIVERING", "DELIVERY_HEADER",
    "DELIVERY_ID_PREFIX", "ENVELOPE_VERSION", "EVENT_HEADER",
    "EVENT_ID_HEADER", "EVENT_TYPES", "EVENT_TYPE_NAMES", "FAILED",
    "MIN_SECRET_LENGTH", "PARKED", "PENDING", "PING_EVENT_TYPE",
    "SIGNATURE_HEADER", "SIGNATURE_SCHEME", "SUBSCRIPTION_ID_PREFIX",
    "TIMESTAMP_HEADER", "Delivery", "Replayed", "Subscription",
    "WebhookSubscriptions", "canonical_body", "delivery_headers", "envelope",
    "fan_out", "new_webhook_secret", "pending_count", "short", "sign",
    "sign_all", "utcnow",
]
