"""Sending an event again, for an endpoint that did not end up with it.

At-least-once delivery covers an endpoint that was down: the dispatcher retries
until it answers, then parks it, and resuming the subscription sends what was
queued. It does not cover an endpoint that answered `2xx` and then lost the
event, a delivery that ran out of retries before its endpoint was fixed, or an
endpoint registered after the event happened. Those three are what this module
is for.

**An event is sent again under its own ``event_id``.** It is the same fact, and
an endpoint that already has it drops the copy the way it drops any duplicate.

**An order is re-sent as its current state, not its history.** A delivery goes
back to the queue at the position it always had, and the dispatcher sends a
subscription's deliveries strictly in that order. Re-sending a whole history
to an endpoint that is missing part of it would put the missing part at the
end, after the events that followed it, and the endpoint would end up on an old
state. The newest event the order wrote is the one a consumer needs to be right,
and it can only ever arrive last.
"""

from __future__ import annotations

from typing import Sequence

from sqlalchemy import Engine, select

from painfree.errors import ConflictError, NotFoundError
from painfree.logging import get_logger
from painfree.schema import audit_log, webhook_delivery
from painfree.webhooks import (DELIVERED, EVENT_TYPES, FAILED, PENDING,
                               Delivery, Subscription, WebhookSubscriptions,
                               delivery_rows, live_subscriptions, utcnow)

log = get_logger("painfree.redelivery")

#: What may be sent again: a delivery that is over, either way. One still
#: queued or on the wire is already going to be sent.
REDELIVERABLE = (DELIVERED, FAILED)


class Redelivery:
    """Puts finished deliveries back in the queue, and owes missing ones."""

    __slots__ = ("_engine", "_subscriptions")

    def __init__(self, engine: Engine,
                 subscriptions: WebhookSubscriptions) -> None:
        self._engine = engine
        self._subscriptions = subscriptions

    def redeliver(self, subscription_id: str, delivery_id: str) -> Delivery:
        """Send one delivered or failed event again to the endpoint it went to.

        Named by its subscription as well as its own id, so a caller allowed to
        manage one endpoint cannot re-send another endpoint's delivery.
        """
        with self._engine.connect() as connection:
            row = connection.execute(
                select(webhook_delivery.c.subscription_id,
                       webhook_delivery.c.state, webhook_delivery.c.event_id,
                       webhook_delivery.c.event_type)
                .where(webhook_delivery.c.delivery_id == delivery_id,
                       webhook_delivery.c.subscription_id == subscription_id)
            ).mappings().one_or_none()
        if row is None:
            raise NotFoundError(
                f"no webhook delivery {delivery_id} on {subscription_id}")
        self.servable(row["subscription_id"])
        if row["state"] not in REDELIVERABLE:
            raise ConflictError(
                f"delivery {delivery_id} is {row['state']}; it is already "
                f"going to be sent")
        with self._engine.begin() as connection:
            self._requeue(connection, delivery_id)
        log.info("webhook.redelivery_queued", delivery_id=delivery_id,
                 subscription_id=row["subscription_id"],
                 event_id=row["event_id"], event_type=row["event_type"])
        return next(delivery for delivery in self._subscriptions.deliveries(
            row["subscription_id"], limit=200)
            if delivery.delivery_id == delivery_id)

    def resend_order(self, order_id: str) -> tuple[str, int]:
        """Send an order's newest event again to every endpoint that wants it.

        An endpoint that already has a row for that event gets the row back in
        the queue, unless it is still queued. One that has none -- registered
        later, or subscribed to that type since -- gets a new row. Returns the
        event type and how many deliveries were queued.
        """
        with self._engine.begin() as connection:
            event = connection.execute(
                select(audit_log)
                .where(audit_log.c.order_id == order_id,
                       audit_log.c.action.in_(list(EVENT_TYPES)))
                .order_by(audit_log.c.seq.desc()).limit(1)
            ).mappings().one_or_none()
            if event is None:
                raise NotFoundError(
                    f"order {order_id} has written no event to send again")
            event_type = EVENT_TYPES[event["action"]]
            held = {row["subscription_id"]: row for row in connection.execute(
                select(webhook_delivery.c.subscription_id,
                       webhook_delivery.c.delivery_id, webhook_delivery.c.state)
                .where(webhook_delivery.c.event_id == event["event_id"])
            ).mappings()}
            queued = 0
            missing = []
            for subscription in live_subscriptions(
                    connection, event_type, event["connection_id"]):
                existing = held.get(subscription["subscription_id"])
                if existing is None:
                    missing.append(subscription)
                elif existing["state"] in REDELIVERABLE:
                    self._requeue(connection, existing["delivery_id"])
                    queued += 1
            if missing:
                connection.execute(webhook_delivery.insert(), delivery_rows(
                    missing, event_id=event["event_id"], event_type=event_type,
                    occurred_at=event["occurred_at"],
                    ids={name: event[name] for name in
                         ("connection_id", "order_id", "idempotency_key")},
                    detail=event["detail"] or {}))
                queued += len(missing)
        log.info("webhook.order_resent", order_id=order_id,
                 event_id=event["event_id"], event_type=event_type,
                 deliveries=queued)
        return event_type, queued

    def servable(self, subscription_id: str) -> Subscription:
        """The subscription, if the dispatcher will serve it; refused otherwise.

        Queuing for a parked or paused endpoint would sit there for ever and
        read on screen as the endpoint failing rather than as its state.
        """
        subscription = self._subscriptions.get(subscription_id)
        if subscription.parked or not subscription.enabled:
            raise ConflictError(
                f"webhook subscription {subscription_id} is "
                f"{'parked' if subscription.parked else 'paused'}; resume it "
                f"before sending anything to it again",
                detail={"health": subscription.health})
        return subscription

    @staticmethod
    def _requeue(connection, delivery_id: str) -> None:
        now = utcnow()
        connection.execute(
            webhook_delivery.update()
            .where(webhook_delivery.c.delivery_id == delivery_id,
                   webhook_delivery.c.state.in_(REDELIVERABLE))
            .values(state=PENDING, attempts=0, next_attempt_at=now,
                    worker_id=None, claimed_at=None, delivered_at=None,
                    updated_at=now))


__all__: Sequence[str] = ["REDELIVERABLE", "Redelivery"]
