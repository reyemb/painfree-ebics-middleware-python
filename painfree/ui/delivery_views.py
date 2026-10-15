"""Sending an event again, from the two pages an operator finds it missing on.

On an endpoint's page, beside a delivery that went or failed: send that one
again. On an order's page: send its current state again to every endpoint that
wants it, including one registered after the order moved. The rules live in
:mod:`painfree.redelivery`; this module only asks for them.

Both need `webhooks:manage` on the connection concerned. Sending an event again
is something a consumer acts on, and it is the same privilege that decides
which consumers there are.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from painfree import access
from painfree.api import record_webhook_change
from painfree.authn import requires
from painfree.identity import Principal, Scope
from painfree.ui.views import PREFIX, _orders, _see, _webhooks

router = APIRouter(prefix=PREFIX, tags=["console"], include_in_schema=False)


@router.post("/webhooks/{subscription_id}/deliveries/{delivery_id}/redeliver")
def redeliver(request: Request, subscription_id: str, delivery_id: str,
              principal: Principal = Depends(requires(Scope.webhooks_manage))):
    """One delivery back in the queue, under the event id it always had."""
    subscription = _webhooks(request).get(subscription_id)
    access.require(principal, subscription.connection_id,
                   Scope.webhooks_manage, what="webhook subscription")
    delivery = request.app.state.redelivery.redeliver(subscription_id,
                                                       delivery_id)
    record_webhook_change(request, "webhook.redelivery_requested", principal,
                          subscription, delivery_id=delivery_id,
                          event_id=delivery.event_id,
                          event_type=delivery.event_type)
    return _see(f"{PREFIX}/webhooks/{subscription_id}")


@router.post("/orders/{order_id}/resend-events")
def resend_order(request: Request, order_id: str,
                 principal: Principal = Depends(requires(Scope.webhooks_manage))):
    """The order's newest event, again, to every endpoint that wants it."""
    order = _orders(request).get(order_id)
    access.require(principal, order.connection_id, Scope.webhooks_manage,
                   what="order")
    event_type, queued = request.app.state.redelivery.resend_order(order_id)
    request.app.state.audit.record(
        "webhook.order_resent", actor=principal.actor(), order_id=order_id,
        connection_id=order.connection_id,
        detail={"event_type": event_type, "deliveries": queued})
    return _see(f"{PREFIX}/orders/{order_id}")


__all__ = ["router"]
