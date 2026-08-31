"""The delivery half: claim an owed event, sign it, POST it, record what happened.

:mod:`painfree.webhooks` writes the rows; this claims them. The split is the
one :mod:`painfree.orders` and :mod:`painfree.queue` already use -- the path
that creates work and the path that performs it are different concerns and
neither can do the other's job.

**Nothing is ever delivered that was not stored first.** A claim is a
conditional ``UPDATE``, the body is rebuilt from the stored envelope, and the
outcome is written before the next claim. Kill the process at any point and the
event is either still `pending` or still `delivering` with an expired lease;
either way the next dispatcher sends it, carrying the same `event_id` it always
had. That is at-least-once, stated plainly: duplicates are a *consequence* of
never losing an event, and the contract's answer to them is the id.

**A subscription is served strictly in order, one event at a time.** Events for
one connection would otherwise overtake each other -- `order.submitted`
arriving before `order.accepted` is not a sequence anybody can act on. The
candidate query therefore takes a row only when nothing *earlier* for the same
subscription is still owed: not in flight, and not waiting out a backoff
either. The second half is the one worth stating, because skipping only the
in-flight row looks correct and lets the next event past a retrying one.

The same predicate is the isolation property. One subscription occupies one
thread, so a consumer that takes thirty seconds delays its own next event and
nothing else; the other subscriptions are claimed by the other threads
meanwhile.

**A dead endpoint stops rather than growing.** A delivery backs off and gives
up after :data:`MAX_ATTEMPTS`; a subscription whose deliveries keep giving up is
*parked* after :data:`PARK_AFTER` of them, its queued events marked `parked` and
no new ones created for it (:func:`painfree.webhooks.fan_out` skips it). An
operator un-parks it with :meth:`~painfree.webhooks.WebhookSubscriptions.resume`
once the endpoint is fixed, and every event it missed is still there.

**The secret never reaches the log stream.** It is opened per attempt, used, and
dropped; every open registers it with :func:`painfree.logging.register_secret`,
so even an exception message that interpolated it is scrubbed. What is logged is
the subscription id, the URL, the status and the attempt.

**A rotating subscription is signed with both of its secrets.** The endpoint has
one of them and this service does not know which, so the header carries an entry
for each and the consumer accepts if any verifies. The overlap is ended by an
operator, not by a timer: the moment to stop signing with the old value is the
moment their receiver stopped using it, and only they know it.
"""

from __future__ import annotations

import datetime as _dt
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

from sqlalchemy import Engine, and_, or_, select

from painfree import custody
from painfree.config import Settings
from painfree.logging import bind, get_logger
from painfree.schema import webhook_delivery, webhook_subscription
from painfree.sealing import CustodyKey
from painfree.webhooks import (DELIVERED, DELIVERING, FAILED, PARKED, PENDING,
                               WebhookSubscriptions, canonical_body,
                               delivery_headers, short, sign_all, utcnow)

log = get_logger("painfree.dispatcher")

#: How long an idle dispatcher waits before asking for work again.
POLL_INTERVAL = 2.0

#: How many delivery threads one worker process runs. More than one because a
#: consumer that takes thirty seconds must not be the reason another
#: subscription waits; small because the work is one HTTP request at a time.
DISPATCH_THREADS = 4

#: How long a claim is good for. Shorter than the upload queue's lease: a POST
#: to a consumer is seconds, not a multi-segment upload to a bank.
CLAIM_LEASE = _dt.timedelta(minutes=5)

#: Attempts per event before it is called undeliverable.
MAX_ATTEMPTS = 5

#: The wait before each subsequent attempt. The last entry is reused past its
#: length, so the two numbers do not have to be kept in step.
BACKOFF = (
    _dt.timedelta(seconds=10),
    _dt.timedelta(minutes=1),
    _dt.timedelta(minutes=5),
    _dt.timedelta(minutes=30),
)

#: Consecutive *exhausted* deliveries before the subscription itself is parked.
#: One is too few -- a consumer restarting behind a load balancer loses one
#: event's worth of attempts and should not be switched off for it.
PARK_AFTER = 3

#: A consumer is given this long to answer. Generous enough for an endpoint
#: that writes to its own database first, short enough that one slow consumer
#: is not holding a thread for a minute.
DEFAULT_TIMEOUT = 15.0

#: A consumer's response body is not something this service stores or logs. It
#: is read so the connection can be reused and closed, and discarded.
MAX_RESPONSE_BYTES = 4096


def backoff(attempts: int) -> _dt.timedelta:
    index = max(0, min(attempts, len(BACKOFF)) - 1)
    return BACKOFF[index]


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    """A webhook is never followed to a second host.

    urllib's default handler turns a redirected POST into a GET, which would
    make a misconfigured endpoint answer `200` to a request that carried no
    event at all. Refusing the redirect surfaces it as the configuration error
    it is.
    """

    def redirect_request(self, *args, **kwargs):  # noqa: D102 - urllib API
        return None


_opener = urllib.request.build_opener(_NoRedirects)


@dataclass(frozen=True, slots=True)
class DeliveryResult:
    """One attempt, as it was recorded."""

    delivery_id: str
    event_id: str
    state: str
    status: int | None = None
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.state == DELIVERED


@dataclass(frozen=True, slots=True)
class ClaimedDelivery:
    """One event this dispatcher now owns."""

    delivery_id: str
    subscription_id: str
    event_id: str
    event_type: str
    connection_id: str | None
    order_id: str | None
    payload: dict[str, Any]
    attempts: int


def post(url: str, body: bytes, headers: dict[str, str],
         timeout: float) -> tuple[int | None, str | None]:
    """One HTTP exchange with a consumer. Never raises; never retries.

    Returns ``(status, error)``. A status is what the endpoint answered, even
    when that is a failure; an error with no status is a request that never got
    an answer at all. Retrying belongs to the delivery, not to the socket.
    """
    request = urllib.request.Request(url, data=body, headers=headers,
                                     method="POST")
    try:
        with _opener.open(request, timeout=timeout) as response:
            response.read(MAX_RESPONSE_BYTES)
            return response.status, None
    except urllib.error.HTTPError as exc:
        try:
            exc.read(MAX_RESPONSE_BYTES)
        finally:
            exc.close()
        return exc.code, f"the endpoint answered HTTP {exc.code}"
    except urllib.error.URLError as exc:
        return None, f"the endpoint could not be reached: {exc.reason}"
    except (TimeoutError, OSError) as exc:
        return None, f"the exchange failed: {exc}"


class WebhookDispatcher:
    """Claims owed events and delivers them. Built once per worker process."""

    __slots__ = ("_engine", "_subscriptions", "_worker_id", "_timeout")

    def __init__(self, engine: Engine, custody_key: CustodyKey, *,
                 worker_id: str | None = None,
                 timeout: float = DEFAULT_TIMEOUT) -> None:
        self._engine = engine
        self._subscriptions = WebhookSubscriptions(engine, custody_key)
        self._worker_id = worker_id or "dispatcher"
        self._timeout = timeout

    @property
    def subscriptions(self) -> WebhookSubscriptions:
        return self._subscriptions

    # --- the loop ----------------------------------------------------------

    def run_once(self) -> DeliveryResult | None:
        """Deliver one owed event. ``None`` when there is nothing claimable."""
        with custody.worker_context():
            claimed = self.claim()
            if claimed is None:
                return None
            with bind(connection_id=claimed.connection_id,
                      order_id=claimed.order_id, job_id=claimed.delivery_id):
                return self._deliver(claimed)

    def run_forever(self, *, stop: threading.Event | None = None,
                    poll_interval: float = POLL_INTERVAL) -> None:
        """Claim, deliver, repeat, until ``stop`` is set.

        The loop never dies of one delivery: an unexpected exception is logged
        with its trace and the loop continues, because a dispatcher that exits
        on the first surprise stops every *other* consumer's events too. The
        claim's lease is what returns the delivery it was holding.
        """
        stop = stop or threading.Event()
        while not stop.is_set():
            try:
                result = self.run_once()
            except Exception:
                log.exception("webhook.iteration_failed",
                              worker_id=self._worker_id)
                result = None
            if result is None:
                stop.wait(poll_interval)

    # --- claiming ----------------------------------------------------------

    def claim(self, *, now: _dt.datetime | None = None,
              lease: _dt.timedelta = CLAIM_LEASE) -> ClaimedDelivery | None:
        """Take the oldest deliverable event, atomically. ``None`` if there is none."""
        now = now or utcnow()
        statement = (
            webhook_delivery.update()
            .where(webhook_delivery.c.seq
                   == self._candidate(now, now - lease).scalar_subquery())
            .values(state=DELIVERING, worker_id=self._worker_id, claimed_at=now,
                    attempts=webhook_delivery.c.attempts + 1, updated_at=now)
            .returning(*webhook_delivery.c)
        )
        with self._engine.begin() as connection:
            row = connection.execute(statement).mappings().one_or_none()
        if row is None:
            return None
        return ClaimedDelivery(
            delivery_id=row["delivery_id"],
            subscription_id=row["subscription_id"], event_id=row["event_id"],
            event_type=row["event_type"], connection_id=row["connection_id"],
            order_id=row["order_id"], payload=row["payload"],
            attempts=row["attempts"])

    def _candidate(self, now: _dt.datetime, expired: _dt.datetime):
        """The one row a claim will try to take, locked where the backend can.

        Three predicates, and each is one of the delivery guarantees: the row
        is due, its subscription is live, and that subscription has nothing
        else on the wire.
        """
        live = (
            select(webhook_subscription.c.seq)
            .where(webhook_subscription.c.subscription_id
                   == webhook_delivery.c.subscription_id,
                   webhook_subscription.c.enabled.is_(True),
                   webhook_subscription.c.parked_at.is_(None))
            .exists()
        )
        # The ordering predicate, and the one that took a bug to get right: it
        # is not enough to skip a subscription with a delivery *in flight*. An
        # event that failed and is waiting out its backoff is still owed, and
        # letting the next one past it delivers `order.submitted` before
        # `order.accepted`. So a row is claimable only when nothing earlier for
        # the same subscription is still owed at all -- which also means at
        # most one is ever in flight, because the head row is the only
        # candidate there is.
        earlier = webhook_delivery.alias("earlier")
        overtaking = (
            select(earlier.c.seq)
            .where(earlier.c.subscription_id == webhook_delivery.c.subscription_id,
                   earlier.c.seq < webhook_delivery.c.seq,
                   earlier.c.state.in_((PENDING, DELIVERING)))
            .exists()
        )
        query = (
            select(webhook_delivery.c.seq)
            .where(
                or_(
                    and_(webhook_delivery.c.state == PENDING,
                         or_(webhook_delivery.c.next_attempt_at.is_(None),
                             webhook_delivery.c.next_attempt_at <= now)),
                    # A dispatcher that died mid-POST. The consumer may have
                    # received it; that is what `event_id` is for.
                    and_(webhook_delivery.c.state == DELIVERING,
                         webhook_delivery.c.claimed_at.is_not(None),
                         webhook_delivery.c.claimed_at < expired),
                ),
                live, ~overtaking)
            .order_by(webhook_delivery.c.seq)
            .limit(1)
        )
        if self._engine.dialect.name == "postgresql":
            query = query.with_for_update(skip_locked=True,
                                          of=webhook_delivery)
        return query

    # --- one delivery ------------------------------------------------------

    def _deliver(self, claimed: ClaimedDelivery) -> DeliveryResult:
        """Sign and POST one claimed event, and record how it went."""
        subscription = self._subscriptions.get(claimed.subscription_id)
        body = canonical_body(claimed.payload)
        timestamp = int(utcnow().timestamp())
        # Every secret that is still live: one ordinarily, two mid-rotation.
        # Opened here, used on the next line, and dropped -- they are never
        # held on the dispatcher and never reach a field of anything.
        signing = self._subscriptions.signing_secrets(claimed.subscription_id)
        headers = delivery_headers(
            event_type=claimed.event_type, event_id=claimed.event_id,
            delivery_id=claimed.delivery_id, attempt=claimed.attempts,
            timestamp=timestamp, signature=sign_all(signing, timestamp, body))
        del signing

        log.info("webhook.delivering", event_id=claimed.event_id,
                 event_type=claimed.event_type, url=subscription.url,
                 subscription_id=claimed.subscription_id,
                 attempt=claimed.attempts, bytes=len(body),
                 secret_generation=subscription.secret_generation,
                 rotating=subscription.rotating)
        status, error = post(subscription.url, body, headers, self._timeout)
        if error is None and status is not None and 200 <= status < 300:
            return self._delivered(claimed, status)
        return self._retry_later(claimed, status, error
                                 or f"the endpoint answered HTTP {status}")

    def _delivered(self, claimed: ClaimedDelivery, status: int) -> DeliveryResult:
        now = utcnow()
        self._settle(claimed.delivery_id, state=DELIVERED, delivered_at=now,
                     last_status=status, last_error=None, updated_at=now)
        self._subscription_succeeded(claimed.subscription_id, status, now)
        log.info("webhook.delivered", event_id=claimed.event_id,
                 event_type=claimed.event_type,
                 subscription_id=claimed.subscription_id, status=status,
                 attempt=claimed.attempts)
        return DeliveryResult(claimed.delivery_id, claimed.event_id, DELIVERED,
                              status=status)

    def _retry_later(self, claimed: ClaimedDelivery, status: int | None,
                     reason: str) -> DeliveryResult:
        """Put the event back, or give up on it. The only place that decides."""
        now = utcnow()
        if claimed.attempts >= MAX_ATTEMPTS:
            self._settle(claimed.delivery_id, state=FAILED, last_status=status,
                         last_error=short(reason), updated_at=now)
            log.error("webhook.undeliverable", event_id=claimed.event_id,
                      event_type=claimed.event_type,
                      subscription_id=claimed.subscription_id, status=status,
                      attempts=claimed.attempts, reason=short(reason))
            self._subscription_failed(claimed.subscription_id, status,
                                      short(reason), now)
            return DeliveryResult(claimed.delivery_id, claimed.event_id, FAILED,
                                  status=status, error=short(reason))

        wait = backoff(claimed.attempts)
        self._settle(claimed.delivery_id, state=PENDING, worker_id=None,
                     claimed_at=None, next_attempt_at=now + wait,
                     last_status=status, last_error=short(reason),
                     updated_at=now)
        log.warning("webhook.retry_scheduled", event_id=claimed.event_id,
                    event_type=claimed.event_type,
                    subscription_id=claimed.subscription_id, status=status,
                    attempt=claimed.attempts,
                    next_attempt_in_s=int(wait.total_seconds()),
                    reason=short(reason))
        return DeliveryResult(claimed.delivery_id, claimed.event_id, PENDING,
                              status=status, error=short(reason))

    # --- storage -----------------------------------------------------------

    def _settle(self, delivery_id: str, **values: Any) -> None:
        values.setdefault("worker_id", None)
        values.setdefault("claimed_at", None)
        with self._engine.begin() as connection:
            connection.execute(
                webhook_delivery.update()
                .where(webhook_delivery.c.delivery_id == delivery_id)
                .values(**values))

    def _subscription_succeeded(self, subscription_id: str, status: int,
                                now: _dt.datetime) -> None:
        with self._engine.begin() as connection:
            connection.execute(
                webhook_subscription.update()
                .where(webhook_subscription.c.subscription_id == subscription_id)
                .values(consecutive_failures=0, last_delivery_at=now,
                        last_status=status, last_error=None, updated_at=now))

    def _subscription_failed(self, subscription_id: str, status: int | None,
                             reason: str, now: _dt.datetime) -> None:
        """Count the exhausted delivery, and park the endpoint if it keeps going.

        Counted in one statement so two dispatchers giving up at once cannot
        both read the same value and write the same increment.
        """
        with self._engine.begin() as connection:
            failures = connection.execute(
                webhook_subscription.update()
                .where(webhook_subscription.c.subscription_id == subscription_id)
                .values(
                    consecutive_failures=(
                        webhook_subscription.c.consecutive_failures + 1),
                    last_delivery_at=now, last_status=status,
                    last_error=reason, updated_at=now)
                .returning(webhook_subscription.c.consecutive_failures)
            ).scalar_one()
            if failures < PARK_AFTER:
                return
            connection.execute(
                webhook_subscription.update()
                .where(webhook_subscription.c.subscription_id == subscription_id,
                       webhook_subscription.c.parked_at.is_(None))
                .values(parked_at=now, updated_at=now))
            parked = connection.execute(
                webhook_delivery.update()
                .where(webhook_delivery.c.subscription_id == subscription_id,
                       webhook_delivery.c.state == PENDING)
                .values(state=PARKED, worker_id=None, claimed_at=None,
                        updated_at=now)
            ).rowcount
        # An operator has to see this: from here the endpoint receives nothing
        # until somebody resumes it, and the events are kept rather than lost.
        log.error("webhook.subscription_parked",
                  subscription_id=subscription_id, status=status,
                  consecutive_failures=failures, parked_events=parked,
                  reason=reason)


def build_dispatcher(settings: Settings, engine: Engine,
                     **kwargs) -> WebhookDispatcher:
    """A dispatcher from a resolved configuration, with the role checked first.

    Delivery runs where the custody key is, because signing needs a secret that
    is sealed under it -- so the same refusal the upload worker gets applies
    here.
    """
    if not settings.role.uploads:
        raise ValueError(
            f"PAINFREE_ROLE is {settings.role.value}; this process holds no "
            f"custody key and cannot sign a webhook")
    return WebhookDispatcher(engine, settings.custody_key(), **kwargs)


__all__ = ["BACKOFF", "CLAIM_LEASE", "DEFAULT_TIMEOUT", "DISPATCH_THREADS",
           "MAX_ATTEMPTS", "PARK_AFTER", "POLL_INTERVAL", "ClaimedDelivery",
           "DeliveryResult", "WebhookDispatcher", "backoff",
           "build_dispatcher", "post"]
