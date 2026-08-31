"""The `/v1` HTTP surface: submit a payment, read an order back.

Thin on purpose. Everything that decides anything -- the Swiss rules, the
document, the idempotency constraint -- is in :mod:`painfree.orders` and the
modules under it, so the same guarantees hold for the UI form and the worker's
replay path without a second implementation of them.

Two things this layer owns:

**The idempotency header.** ``Idempotency-Key`` is required, not optional: the
one caller that omits it is the caller that double-pays. A retry gets the
*same* `202` and the same body as the original, plus
``Idempotency-Replayed: true``. The status does not change on a replay, because
the outcome has not changed -- a caller retrying should not have to handle two
success codes to find out that nothing happened twice.

**The privilege each route needs.** Declared next to the route, with
``Depends(requires(...))``. Submitting a payment and reading one back are two
different scopes on purpose: a reporting client that is allowed to see what was
paid is not, by that fact, allowed to pay anyone. The authenticated caller
comes back from the dependency and becomes the audit row's actor, so every
order in the log names who submitted it.

**Webhook subscriptions are managed here, and their secret is shown once.**
`POST /v1/webhooks` returns the signing secret in its `201`, and no later
request returns it -- not because a route declines to, but because this process
sealed it to a public key it cannot invert (:mod:`painfree.wrapping`). A caller
that lost it rotates: `POST /v1/webhooks/{id}/secret` issues a new one while
the old one keeps signing, and `DELETE /v1/webhooks/{id}/secret/previous` ends
the overlap once the consumer has been switched over. Managing subscriptions is
its own scope: it decides which third party receives every payment event, so
holding `payments:submit` does not confer it.

**Download schedules are managed here, and a run is asked for, never done.**
`POST /v1/schedules/{id}/run` and `POST /v1/schedules/{id}/refetch` answer
`202`: this process holds no custody key and a download decrypts with the
connection's `E002` private half, so the only thing a route can do is make the
schedule due and let the download worker claim it. Reading a schedule and
changing one are two scopes, for the same reason managing webhooks is one:
unlike a webhook, a schedule creates no recipient outside the deployment, so
`operator` holds `schedules:manage`.

**Who may do any of it is decided elsewhere.** The routes that hand out access
-- `/v1/grants`, `/v1/oversight`, `/v1/accounts` -- are in
:mod:`painfree.access_api`. They are `admin` alone and are not operations on a
bank connection at all, which is the seam this module was split along when it
reached the repository's 1 000-line cap.

**What `202` means.** Accepted for processing, and nothing more. The bank has
not seen it. `state` is `accepted`, and the caller polls
``GET /v1/orders/{order_id}`` or waits for the webhook this service sends.
Returning `200` here would be read downstream as "the payment was made", which
is the misreading the whole state machine exists to prevent.
"""

from __future__ import annotations

import datetime as _dt
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, Request, Response
from pydantic import BaseModel, ConfigDict, Field

from painfree import access, payments, schedule as schedules, sps, webhooks
from painfree.authn import requires, requires_on
from painfree.identity import Principal, Scope
from painfree.logging import get_logger
from painfree.logging import bind
from painfree.orders import OrderStore
from painfree.schedule import DownloadSchedules
from painfree.webhooks import Subscription, WebhookSubscriptions

log = get_logger("painfree.api")

router = APIRouter(prefix="/v1")

IDEMPOTENCY_HEADER = "Idempotency-Key"
REPLAYED_HEADER = "Idempotency-Replayed"

#: How many deliveries one page of a subscription's history returns.
DELIVERY_PAGE = 50
MAX_DELIVERY_PAGE = 500

#: How many runs one page of a schedule's ledger returns.
RUN_PAGE = 50
MAX_RUN_PAGE = 500


def _store(request: Request) -> OrderStore:
    return request.app.state.orders


def _order_body(store: OrderStore, order) -> dict[str, Any]:
    """One order, with every attempt this service made at it.

    The attempts are on the read path rather than in the row because they carry
    the BTF and the `PmtTpInf` of each message, which is the pair that answers
    *did the announcement and the document agree* -- and because an order that
    was downgraded has to be able to show the caller both halves of what
    happened.
    """
    body = order.as_response()
    body["scheme"]["attempts"] = [attempt.as_response()
                                  for attempt in store.attempts_for(
                                      order.order_id)]
    return body


def _webhooks(request: Request) -> WebhookSubscriptions:
    return request.app.state.webhooks


def _schedules(request: Request) -> DownloadSchedules:
    return request.app.state.schedules


def _held_subscription(request: Request, principal: Principal,
                       subscription_id: str, *scopes: Scope) -> Subscription:
    """Load a subscription and refuse it unless this caller holds its connection.

    One loader rather than a check copied into ten handlers: an opaque id names
    a connection only once the row is in hand, and the handler that forgets to
    look is the one that hands a member somebody else's endpoint. The `NULL`
    case falls out of it -- a subscription that names no connection is held by
    no grant, so only an `admin` gets past this line.
    """
    subscription = _webhooks(request).get(subscription_id)
    access.require(principal, subscription.connection_id, *scopes,
                   what="webhook subscription")
    return subscription


def _held_schedule(request: Request, principal: Principal,
                   schedule_id: str, *scopes: Scope) -> schedules.Schedule:
    """The same, for a download schedule."""
    schedule = _schedules(request).get(schedule_id)
    access.require(principal, schedule.connection_id, *scopes,
                   what="download schedule")
    return schedule


@router.post(
    "/connections/{connection_id}/payments",
    status_code=202,
    tags=["payments"],
    summary="Submit a payment instruction",
)
def submit_payment(
    connection_id: str,
    instruction: payments.PaymentInstruction,
    request: Request,
    response: Response,
    idempotency_key: Annotated[str | None, Header(alias=IDEMPOTENCY_HEADER)] = None,
    principal: Principal = Depends(requires_on(Scope.payments_submit)),
) -> dict[str, Any]:
    """Accept a payment for processing. `202`, with the order to poll.

    ``requires_on``, not ``requires``: the privilege that matters is
    `payments:submit` **at this bank**. A member holding it at one connection is
    refused here for every other one, and told nothing about a connection they
    were never granted.
    """
    if idempotency_key is None:
        raise sps.ValidationFailed([sps.RuleFailure(
            IDEMPOTENCY_HEADER, "idempotency_key.missing",
            f"the {IDEMPOTENCY_HEADER} header is required on every submission")])

    submission = _store(request).submit(
        connection_id,
        idempotency_key=idempotency_key,
        instruction=instruction,
        actor=principal.actor(),
        software_version=request.app.state.settings.version,
    )
    response.headers[REPLAYED_HEADER] = "true" if submission.replayed else "false"
    return _order_body(_store(request), submission.order)


@router.get("/orders/{order_id}", tags=["payments"], summary="Order state")
def read_order(order_id: str, request: Request,
               principal: Principal = Depends(requires(Scope.payments_read)),
               ) -> dict[str, Any]:
    """The order, its state, and the bank's return code once there is one.

    The scope check above says this caller may read orders *somewhere*. Which
    bank this particular order belongs to is only known once it is loaded, so
    the check that matters is made here, against the connection the row names.
    Without it, `payments:read` at one connection would be `payments:read`
    everywhere for anyone who could guess an order id.
    """
    with bind(order_id=order_id):
        order = _store(request).get(order_id)
        access.require(principal, order.connection_id, Scope.payments_read,
                       what="order")
        return _order_body(_store(request), order)


@router.get("/connections", tags=["connections"], summary="Bank connections")
def list_connections(request: Request,
                     principal: Principal = Depends(requires()),
                     ) -> dict[str, Any]:
    """The connections **this caller was granted**, and how far each got.

    Identifiers and key state only. No key material, not even a public half:
    the fingerprints an operator compares against a bank letter belong to the
    key-lifecycle screens, which is where the comparison is actually made.

    **This route demands no scope**, which is the second one that does not
    (`/auth/me` and `/ui/api` are the others). It is the answer to *what do I
    have access to*, and that is the one question a caller holding nothing has
    to be able to ask -- gating it on `connections:read` would mean the person
    with no grants is refused the list that would have told them so, and their
    console would look broken rather than empty. It discloses nothing either
    way: a caller with no grants gets an empty array.
    """
    allowed, _ = access.restrict(principal)
    return {"connections": [
        {"connection_id": row.connection_id, "host_id": row.host_id,
         "partner_id": row.partner_id, "user_id": row.user_id,
         "host_url": row.host_url, "ebics_version": row.ebics_version,
         "key_state": row.key_state.value, "initialised": row.initialised,
         # What this connection will send, resolved rather than raw: a caller
         # deciding whether to ask for `instant` needs the answer, not the
         # subset somebody happened to override (`painfree.schemes`).
         "payment_schemes": row.schemes.as_json(),
         "created_at": row.created_at.isoformat()}
        for row in request.app.state.connections.all(allowed)]}


#: How many audit events one page returns, and the cap on what may be asked for.
AUDIT_PAGE = 50
MAX_AUDIT_PAGE = 500


@router.get("/audit", tags=["audit"], summary="Recent audit events")
def read_audit(request: Request, limit: int = AUDIT_PAGE,
               connection_id: str | None = None, order_id: str | None = None,
               job_id: str | None = None, request_id: str | None = None,
               idempotency_key: str | None = None,
               actor_id: str | None = None, action: str | None = None,
               action_prefix: str | None = None, outcome: str | None = None,
               since: _dt.datetime | None = None,
               until: _dt.datetime | None = None,
               before_seq: int | None = None,
               principal: Principal = Depends(requires(Scope.audit_read)),
               ) -> dict[str, Any]:
    """Who did what, newest first, narrowed by any of the filters below.

    Its own scope, carried by both grant levels and by oversight. The trail
    names every caller, so reading it is a privilege in itself -- an operator
    who may submit payments is not thereby allowed to see everyone else's.

    **Paging is by `before_seq`, not by an offset.** `seq` is the append order;
    pass the `seq` of the last row of a page to get the next one. Rows arrive
    while a caller pages, and an offset would hand back one row twice and skip
    another.

    **A member sees the trail of the connections they hold, and nothing else.**
    Not the rows that name another connection, and not the rows that name none:
    a sign-in, a service start, a grant being made are facts about the whole
    deployment and about people this caller was never told exist. An `admin`
    sees everything, and so does a holder of the deployment-wide **oversight**
    grant -- reviewing who was given the ability to move money is the one thing
    that grant exists for.
    """
    allowed, possible = access.restrict(principal, connection_id)
    if not possible:
        return {"events": []}
    events = request.app.state.audit.search(
        limit=max(1, min(limit, MAX_AUDIT_PAGE)), connection_ids=allowed,
        order_id=order_id, job_id=job_id, request_id=request_id,
        idempotency_key=idempotency_key, actor_id=actor_id, action=action,
        action_prefix=action_prefix, outcome=outcome, since=since, until=until,
        before_seq=before_seq)
    return {"events": [_audit_response(row) for row in events]}


def _audit_response(row: dict[str, Any]) -> dict[str, Any]:
    """One row on the wire. Every correlation column, because the point of them
    is joining this row to a log line or to the thing it happened to."""
    return {"seq": row["seq"], "event_id": row["event_id"],
            "occurred_at": row["occurred_at"].isoformat(),
            "actor_type": row["actor_type"], "actor_id": row["actor_id"],
            "action": row["action"], "outcome": row["outcome"],
            "request_id": row["request_id"],
            "connection_id": row["connection_id"],
            "order_id": row["order_id"], "job_id": row["job_id"],
            "idempotency_key": row["idempotency_key"],
            "detail": row["detail"]}


# --- webhook subscriptions --------------------------------------------------

class WebhookRegistration(BaseModel):
    """What a caller sends to register an endpoint.

    ``extra="forbid"`` for the same reason a payment forbids it: a misspelled
    field silently dropped here is a subscription that quietly receives
    everything, or nothing.
    """

    model_config = ConfigDict(extra="forbid")

    url: Annotated[str, Field(min_length=8, max_length=1024)]
    event_types: Annotated[list[str], Field(min_length=1)]
    connection_id: Annotated[str, Field(max_length=64)] | None = None
    description: Annotated[str, Field(max_length=255)] | None = None
    #: A caller may bring its own secret -- some receivers are configured first
    #: and registered second. Generated when it is absent, which is the path
    #: every console registration takes.
    secret: Annotated[str, Field(min_length=webhooks.MIN_SECRET_LENGTH,
                                 max_length=255)] | None = None


class WebhookChange(BaseModel):
    """A partial update. Every field is optional and ``None`` means untouched."""

    model_config = ConfigDict(extra="forbid")

    url: Annotated[str, Field(min_length=8, max_length=1024)] | None = None
    event_types: Annotated[list[str], Field(min_length=1)] | None = None
    description: Annotated[str, Field(max_length=255)] | None = None
    enabled: bool | None = None


def _subscription_body(subscription: Subscription, *,
                       secret: str | None = None) -> dict[str, Any]:
    """The response. ``secret`` appears exactly where it was just created."""
    body = subscription.as_response()
    if secret is not None:
        body["secret"] = secret
        body["secret_shown_once"] = True
    return body


@router.get("/webhooks", tags=["webhooks"], summary="Webhook subscriptions")
def list_webhooks(request: Request, connection_id: str | None = None,
                  principal: Principal = Depends(requires(Scope.webhooks_read)),
                  ) -> dict[str, Any]:
    """Every registered endpoint, its event types and its delivery health.

    No secret, in any generation. `health` is the one word an operator reads
    first: a `parked` endpoint is receiving nothing until somebody resumes it.

    A member sees the subscriptions scoped to the connections they hold. A
    subscription that names **no** connection receives every connection's
    payment events, so it belongs to the deployment and is listed to an `admin`
    alone.
    """
    allowed, possible = access.restrict(principal, connection_id)
    if not possible:
        return {"webhooks": []}
    return {"webhooks": [row.as_response() for row
                         in _webhooks(request).all(
                             connection_ids=allowed)]}


@router.post("/webhooks", status_code=201, tags=["webhooks"],
             summary="Register a webhook endpoint")
def register_webhook(
    registration: WebhookRegistration,
    request: Request,
    response: Response,
    idempotency_key: Annotated[str | None, Header(alias=IDEMPOTENCY_HEADER)] = None,
    principal: Principal = Depends(requires(Scope.webhooks_manage)),
) -> dict[str, Any]:
    """Register an endpoint. **The signing secret is in this response only.**

    `Idempotency-Key` is required, because a retried registration that created
    a second subscription would silently double every event the first one
    receives. A replay returns the original subscription and
    `Idempotency-Replayed: true` -- **without** the secret, which was shown
    once and cannot be shown again by this process. A caller that lost it
    rotates.
    """
    if idempotency_key is None:
        raise sps.ValidationFailed([sps.RuleFailure(
            IDEMPOTENCY_HEADER, "idempotency_key.missing",
            f"the {IDEMPOTENCY_HEADER} header is required when registering a "
            f"webhook endpoint")])

    if registration.connection_id is not None:
        # Checked here so a connection id that names nothing is a `404` naming
        # it, rather than a foreign-key violation surfacing as `internal_error`.
        request.app.state.connections.get(registration.connection_id)

    store = _webhooks(request)
    try:
        subscription, secret = store.register(
            registration.url, registration.event_types,
            connection_id=registration.connection_id,
            secret=registration.secret,
            description=registration.description,
            idempotency_key=idempotency_key)
    except webhooks.Replayed as replay:
        response.status_code = 200
        response.headers[REPLAYED_HEADER] = "true"
        return _subscription_body(replay.subscription)

    response.headers[REPLAYED_HEADER] = "false"
    record_webhook_change(request, "webhook.subscription_registered", principal, subscription,
            url=subscription.url, event_types=list(subscription.event_types))
    return _subscription_body(subscription, secret=secret)


@router.get("/webhooks/{subscription_id}", tags=["webhooks"],
            summary="One webhook subscription")
def read_webhook(subscription_id: str, request: Request,
                 principal: Principal = Depends(requires(Scope.webhooks_read)),
                 ) -> dict[str, Any]:
    """One subscription -- if it belongs to a connection this caller holds.

    A connection-less subscription answers `404` to everyone but an `admin`:
    its `connection_id` is `NULL`, so there is no connection to hold a grant on.
    """
    subscription = _webhooks(request).get(subscription_id)
    access.require(principal, subscription.connection_id, Scope.webhooks_read,
                   what="webhook subscription")
    return subscription.as_response()


@router.patch("/webhooks/{subscription_id}", tags=["webhooks"],
              summary="Change an endpoint, or pause it")
def change_webhook(
    subscription_id: str, change: WebhookChange, request: Request,
    principal: Principal = Depends(requires(Scope.webhooks_manage)),
) -> dict[str, Any]:
    """Change the URL, the event types, the description, or pause delivery.

    Pausing keeps everything the endpoint is owed: `enabled: false` stops
    delivery and stops new events being created for it, and `true` starts both
    again. Un-**parking** is different and is `POST …/resume`, because parking
    also stranded the events that were queued.
    """
    store = _webhooks(request)
    _held_subscription(request, principal, subscription_id,
                       Scope.webhooks_manage)
    subscription = store.update(
        subscription_id, url=change.url, event_types=change.event_types,
        description=change.description)
    if change.enabled is not None:
        subscription = store.set_enabled(subscription_id, change.enabled)
    record_webhook_change(request, "webhook.subscription_updated", principal, subscription,
            changed=sorted(change.model_dump(exclude_none=True)))
    return subscription.as_response()


@router.post("/webhooks/{subscription_id}/resume", tags=["webhooks"],
             summary="Un-park an endpoint and re-queue what it missed")
def resume_webhook(
    subscription_id: str, request: Request,
    principal: Principal = Depends(requires(Scope.webhooks_manage)),
) -> dict[str, Any]:
    """Clear the park, and return every event it stranded to the queue.

    Parking is automatic and resuming is not: an endpoint that failed fifteen
    attempts in a row is one somebody has to have fixed, and the events it
    missed are still here.
    """
    store = _webhooks(request)
    _held_subscription(request, principal, subscription_id,
                       Scope.webhooks_manage)
    requeued = store.resume(subscription_id)
    subscription = store.get(subscription_id)
    record_webhook_change(request, "webhook.subscription_resumed", principal, subscription,
            requeued=requeued)
    return {**subscription.as_response(), "requeued": requeued}


@router.delete("/webhooks/{subscription_id}", tags=["webhooks"],
               summary="Remove an endpoint")
def delete_webhook(
    subscription_id: str, request: Request,
    principal: Principal = Depends(requires(Scope.webhooks_manage)),
) -> dict[str, Any]:
    """Delete the subscription and the events still owed to it.

    Reported rather than hidden: `owed_events_dropped` is what this cost. An
    endpoint that is coming back should be paused, not deleted.
    """
    store = _webhooks(request)
    subscription = _held_subscription(request, principal, subscription_id,
                                      Scope.webhooks_manage)
    dropped = store.delete(subscription_id)
    record_webhook_change(request, "webhook.subscription_deleted", principal, subscription,
            owed_events_dropped=dropped)
    return {"subscription_id": subscription_id, "deleted": True,
            "owed_events_dropped": dropped}


@router.post("/webhooks/{subscription_id}/secret", status_code=201,
             tags=["webhooks"], summary="Issue a new signing secret")
def rotate_webhook_secret(
    subscription_id: str, request: Request,
    principal: Principal = Depends(requires(Scope.webhooks_manage)),
) -> dict[str, Any]:
    """Rotate. The new secret is in this response only; the old one still signs.

    Until `DELETE …/secret/previous`, every delivery carries a signature under
    **both** secrets and a consumer accepts if either verifies -- so the
    endpoint keeps working while its operator copies the new value across, and
    no event is refused or dropped in between.
    """
    _held_subscription(request, principal, subscription_id,
                       Scope.webhooks_manage)
    subscription, secret = _webhooks(request).rotate_secret(subscription_id)
    record_webhook_change(request, "webhook.secret_rotated", principal, subscription,
            secret_generation=subscription.secret_generation)
    return _subscription_body(subscription, secret=secret)


@router.delete("/webhooks/{subscription_id}/secret/previous",
               tags=["webhooks"], summary="End a secret rotation")
def retire_previous_webhook_secret(
    subscription_id: str, request: Request,
    principal: Principal = Depends(requires(Scope.webhooks_manage)),
) -> dict[str, Any]:
    """Stop signing with the retiring secret. Do this once the consumer is switched."""
    _held_subscription(request, principal, subscription_id,
                       Scope.webhooks_manage)
    subscription = _webhooks(request).retire_previous_secret(subscription_id)
    record_webhook_change(request, "webhook.previous_secret_retired", principal, subscription,
            secret_generation=subscription.secret_generation)
    return subscription.as_response()


@router.post("/webhooks/{subscription_id}/ping", status_code=202,
             tags=["webhooks"], summary="Send a test event")
def ping_webhook(
    subscription_id: str, request: Request,
    principal: Principal = Depends(requires(Scope.webhooks_manage)),
) -> dict[str, Any]:
    """Owe this endpoint one `webhook.ping`, and let the dispatcher deliver it.

    `202`: the ping is queued, not sent. It goes out the ordinary way --
    claimed, signed, retried, recorded -- so what it proves is what a real
    event would do. Poll `GET …/deliveries` for the outcome.
    """
    _held_subscription(request, principal, subscription_id,
                       Scope.webhooks_manage)
    delivery = _webhooks(request).enqueue_ping(
        subscription_id, actor_id=principal.subject)
    subscription = _webhooks(request).get(subscription_id)
    record_webhook_change(request, "webhook.ping_requested", principal, subscription,
            delivery_id=delivery.delivery_id)
    return delivery.as_response()


@router.get("/webhooks/{subscription_id}/deliveries", tags=["webhooks"],
            summary="Recent deliveries to one endpoint")
def read_webhook_deliveries(
    subscription_id: str, request: Request, limit: int = DELIVERY_PAGE,
    principal: Principal = Depends(requires(Scope.webhooks_read)),
) -> dict[str, Any]:
    """What was sent, what came back, and what is still owed.

    Never the payload: the envelope is reconstructable from the audit log and
    the order it names, and a delivery history is not a second place to read
    what a payment said.
    """
    store = _webhooks(request)
    access.require(principal, store.get(subscription_id).connection_id,
                   Scope.webhooks_read, what="webhook subscription")
    rows = store.deliveries(subscription_id,
                            limit=max(1, min(limit, MAX_DELIVERY_PAGE)))
    return {"subscription_id": subscription_id,
            "owed": store.owed(subscription_id),
            "deliveries": [row.as_response() for row in rows]}


# --- download schedules -----------------------------------------------------

class ScheduleRegistration(BaseModel):
    """What a caller sends to register a periodic download.

    The BTF is taken field by field rather than as one string, because that is
    what it is: `ServiceName`, `MsgName` and the four optional parts are
    separate elements the bank's schema constrains separately. A single
    `"EOP/camt.053.08"` would have to be split by a parser this service would
    then own, and a wrong split is `EBICS_INVALID_ORDER_PARAMS` hours later.

    ``extra="forbid"``: a misspelled field silently dropped here is a schedule
    that asks a bank for the wrong thing on a cadence nobody chose.
    """

    model_config = ConfigDict(extra="forbid")

    connection_id: Annotated[str, Field(min_length=1, max_length=64)]
    service_name: Annotated[str, Field(min_length=1, max_length=3)]
    msg_name: Annotated[str, Field(min_length=1, max_length=10)]
    msg_version: Annotated[str, Field(max_length=3)] | None = None
    msg_variant: Annotated[str, Field(max_length=3)] | None = None
    scope: Annotated[str, Field(max_length=3)] | None = None
    service_option: Annotated[str, Field(max_length=10)] | None = None
    container: Annotated[str, Field(max_length=3)] | None = None
    cadence_seconds: Annotated[int, Field(ge=1)]
    #: Absent means no `DateRange` at all: the bank serves what it has pending
    #: and the receipt is what stops it being served twice. Present means the
    #: schedule asks for a dated window and can be re-fetched.
    window_days: Annotated[int, Field(ge=1, le=3650)] | None = None
    description: Annotated[str, Field(max_length=255)] | None = None
    enabled: bool = True


class ScheduleChange(BaseModel):
    """A partial update. Every field is optional and ``None`` means untouched.

    ``window_days`` therefore cannot be cleared through this shape, and that is
    deliberate rather than an oversight: turning a dated schedule into an
    undated one abandons a window ledger an operator may still need. Delete and
    re-register, which says what it costs.
    """

    model_config = ConfigDict(extra="forbid")

    service_name: Annotated[str, Field(min_length=1, max_length=3)] | None = None
    msg_name: Annotated[str, Field(min_length=1, max_length=10)] | None = None
    msg_version: Annotated[str, Field(max_length=3)] | None = None
    msg_variant: Annotated[str, Field(max_length=3)] | None = None
    scope: Annotated[str, Field(max_length=3)] | None = None
    service_option: Annotated[str, Field(max_length=10)] | None = None
    container: Annotated[str, Field(max_length=3)] | None = None
    cadence_seconds: Annotated[int, Field(ge=1)] | None = None
    window_days: Annotated[int, Field(ge=1, le=3650)] | None = None
    description: Annotated[str, Field(max_length=255)] | None = None
    enabled: bool | None = None


class WindowRefetch(BaseModel):
    """Which day an operator wants the bank asked about again."""

    model_config = ConfigDict(extra="forbid")

    since: _dt.date


@router.get("/schedules", tags=["schedules"], summary="Download schedules")
def list_schedules(request: Request, connection_id: str | None = None,
                   principal: Principal = Depends(requires(Scope.schedules_read)),
                   ) -> dict[str, Any]:
    """Every periodic download, what it fetches, and how far its window got.

    `health` is the word to read first, and `empty` is deliberately not one of
    its values: a run that found nothing succeeded, so it leaves the schedule
    `healthy`.

    Narrowed to the connections this caller holds.
    """
    allowed, possible = access.restrict(principal, connection_id)
    if not possible:
        return {"schedules": []}
    return {"schedules": [row.as_response() for row
                          in _schedules(request).all(
                              connection_ids=allowed)]}


@router.post("/schedules", status_code=201, tags=["schedules"],
             summary="Register a download schedule")
def register_schedule(
    registration: ScheduleRegistration, request: Request,
    principal: Principal = Depends(requires(Scope.schedules_manage)),
) -> dict[str, Any]:
    """Register one periodic download.

    **No `Idempotency-Key`, and that is not an omission.** A schedule's identity
    is its connection and its BTF, and `uq_download_schedule_btf` already
    refuses a second row for the same pair -- so a retried registration answers
    `409` naming the schedule that exists rather than creating a second one
    that would download every statement twice. A header-supplied key would add
    a second, weaker way to say the same thing.
    """
    # Checked here so a connection id that names nothing is a `404` naming it,
    # rather than a foreign-key violation surfacing as `internal_error`. The
    # access check runs first, so a connection the caller holds no grant on is
    # a `404` that says nothing about whether it exists.
    access.require(principal, registration.connection_id,
                   Scope.schedules_manage, what="bank connection")
    request.app.state.connections.get(registration.connection_id)
    schedule = _schedules(request).register(
        registration.connection_id,
        service_name=registration.service_name, msg_name=registration.msg_name,
        msg_version=registration.msg_version,
        msg_variant=registration.msg_variant, scope=registration.scope,
        service_option=registration.service_option,
        container=registration.container,
        cadence=_dt.timedelta(seconds=registration.cadence_seconds),
        window_days=registration.window_days, enabled=registration.enabled,
        description=registration.description, actor=principal.actor())
    return schedule.as_response()


@router.get("/schedules/{schedule_id}", tags=["schedules"],
            summary="One download schedule")
def read_schedule(schedule_id: str, request: Request,
                  principal: Principal = Depends(requires(Scope.schedules_read)),
                  ) -> dict[str, Any]:
    """The schedule and its window: what is covered, and what is outstanding."""
    return _held_schedule(request, principal, schedule_id,
                          Scope.schedules_read).as_response()


@router.patch("/schedules/{schedule_id}", tags=["schedules"],
              summary="Change a schedule, or pause it")
def change_schedule(
    schedule_id: str, change: ScheduleChange, request: Request,
    principal: Principal = Depends(requires(Scope.schedules_manage)),
) -> dict[str, Any]:
    """Change the BTF, the cadence, the window, the description, or pause it.

    `enabled: false` stops the schedule being claimed **without losing its
    window** -- `fetched_through` stays where it is, so re-enabling asks for the
    days that were missed rather than skipping them.
    """
    _held_schedule(request, principal, schedule_id, Scope.schedules_manage)
    changes = change.model_dump(exclude_none=True)
    return _schedules(request).update(
        schedule_id, actor=principal.actor(), **changes).as_response()


@router.delete("/schedules/{schedule_id}", tags=["schedules"],
               summary="Remove a schedule")
def delete_schedule(
    schedule_id: str, request: Request,
    principal: Principal = Depends(requires(Scope.schedules_manage)),
) -> dict[str, Any]:
    """Delete the schedule and its run ledger. **The statements are kept.**

    `runs_dropped` is what this cost: the record of what was asked for and when
    goes with it. A schedule that is coming back should be paused instead.
    """
    _held_schedule(request, principal, schedule_id, Scope.schedules_manage)
    dropped = _schedules(request).delete(schedule_id, actor=principal.actor())
    return {"schedule_id": schedule_id, "deleted": True,
            "runs_dropped": dropped}


@router.post("/schedules/{schedule_id}/run", status_code=202, tags=["schedules"],
             summary="Run this schedule now")
def run_schedule_now(
    schedule_id: str, request: Request,
    principal: Principal = Depends(requires(Scope.schedules_manage)),
) -> dict[str, Any]:
    """Make it due immediately. `202`: the **worker** downloads, not this process.

    Nothing is fetched here. This process holds no custody key and a download is
    decrypted with the connection's `E002` private half, so the route moves
    `due_at` and the download worker claims it on its next poll -- the same
    shape as a key job and as a webhook ping. Poll
    `GET /v1/schedules/{id}/runs` for the outcome.
    """
    _held_schedule(request, principal, schedule_id, Scope.schedules_manage)
    schedule = _schedules(request).run_now(schedule_id,
                                           requested_by=principal.subject,
                                           actor=principal.actor())
    return {**schedule.as_response(), "queued": True}


@router.post("/schedules/{schedule_id}/refetch", status_code=202,
             tags=["schedules"], summary="Ask the bank for a window again")
def refetch_window(
    schedule_id: str, window: WindowRefetch, request: Request,
    principal: Principal = Depends(requires(Scope.schedules_manage)),
) -> dict[str, Any]:
    """Rewind the high-water mark to ``since`` and run at once. `202`.

    **Safe to repeat.** A statement the bank serves again is keyed on the
    document, hits `uq_statement_connection_id_document_key` and is counted as a
    duplicate rather than stored twice -- the same constraint that already
    absorbs an unacknowledged download being re-served, so this adds no second
    guarantee to keep true. The run it produces reports `duplicates`, and
    `requested_by` on that run says a human asked for it.
    """
    _held_schedule(request, principal, schedule_id, Scope.schedules_manage)
    schedule = _schedules(request).refetch(schedule_id, since=window.since,
                                           requested_by=principal.subject,
                                           actor=principal.actor())
    return {**schedule.as_response(), "queued": True,
            "refetch_from": window.since.isoformat()}


@router.get("/schedules/{schedule_id}/runs", tags=["schedules"],
            summary="The window ledger for one schedule")
def read_schedule_runs(
    schedule_id: str, request: Request, limit: int = RUN_PAGE,
    principal: Principal = Depends(requires(Scope.schedules_read)),
) -> dict[str, Any]:
    """Every attempt, what window it asked for, and how it ended.

    Kept whether the run worked or not: a statement that never arrived is a row
    here rather than an absence a reader has to infer. `unfinished` is the
    subset that did not move the window -- what a gap is actually made of.
    """
    store = _schedules(request)
    schedule = _held_schedule(request, principal, schedule_id,
                              Scope.schedules_read)
    rows = store.runs(schedule_id, limit=max(1, min(limit, MAX_RUN_PAGE)))
    return {"schedule_id": schedule_id,
            "window": schedule.ledger().as_response(),
            "runs": [schedules.run_response(row) for row in rows],
            "unfinished": [schedules.run_response(row) for row
                           in store.unfinished_runs(schedule_id, limit=20)]}


def record_webhook_change(request: Request, action: str, principal: Principal,
            subscription: Subscription, **detail: Any) -> None:
    """One audit row per administrative change, with the caller named.

    Written here rather than in :mod:`painfree.webhooks` because that module is
    imported by :mod:`painfree.audit` -- the fan-out runs inside the audit
    write -- and a module cannot import its own importer. The console writes
    the same actions through the same helper.
    """
    request.app.state.audit.record(
        action, actor=principal.actor(),
        connection_id=subscription.connection_id,
        detail={"subscription_id": subscription.subscription_id, **detail})


__all__ = ["AUDIT_PAGE", "DELIVERY_PAGE", "MAX_AUDIT_PAGE",
           "IDEMPOTENCY_HEADER", "MAX_DELIVERY_PAGE", "MAX_RUN_PAGE",
           "REPLAYED_HEADER", "RUN_PAGE", "ScheduleChange",
           "ScheduleRegistration", "WebhookChange", "WebhookRegistration",
           "WindowRefetch", "record_webhook_change", "router"]
