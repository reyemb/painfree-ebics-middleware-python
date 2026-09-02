"""The console's routes. Thin: every decision is somewhere else.

Each view reads rows, or appends one, and renders a template. The rules it
would otherwise be tempted to reimplement all live in the modules that own
them -- which state a key job may be asked for from
(:mod:`painfree.keyjobs`), which states an order may be replayed from
(:mod:`painfree.orders`), whether the bank's keys match the letter
(``painfree.ebics3.verify_bank_keys``) -- so the console and the API cannot
drift into two different answers.

**Forms are parsed here rather than by a dependency.** FastAPI's ``Form``
support needs ``python-multipart``; this console posts nothing but small
``application/x-www-form-urlencoded`` bodies, and eight lines of
:func:`urllib.parse.parse_qsl` is a smaller thing to carry than a dependency and
a file-upload parser nothing here uses.

**The scope is demanded before the body is read.** ``requires(...)`` is
declared ahead of the form dependency in every write handler, so a caller
without the privilege is told which privilege it lacks rather than something
about its request body.

**Post, redirect, get.** Every write ends in a `303`, so a reload does not
repeat it and a key job cannot be enqueued twice by a refresh. What the next
page needs to know travels as a job id in the query string, not as state.

**The session cookie is ``SameSite=Lax``** (:mod:`painfree.oidc`), which is what
stops another origin's form posting to these routes: a cross-site `POST` does
not carry the cookie, so it arrives unauthenticated and the middleware refuses
it. That is the CSRF story, and it is a property of the cookie rather than of a
token this module would have to remember to check.
"""

from __future__ import annotations

import datetime as _dt
import urllib.parse
import uuid
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import PlainTextResponse, RedirectResponse

import painfree
from painfree import access, ebics3, reconcile, webhooks
from painfree.api import record_webhook_change
from painfree.authn import requires, requires_on
from painfree.errors import ConflictError, NotFoundError
from painfree.identity import Principal, Scope
from painfree.keyjobs import ALLOWED_FROM, KeyAction, KeyJobStore
from painfree.keyring import BANK, SUBSCRIBER, Keyring
from painfree.logging import bind
from painfree.orders import REPLAYABLE, OrderState, OrderStore
from painfree.schemes import DEFAULT_INSTANT, PaymentScheme
from painfree.schedule import DownloadSchedules
from painfree.ui.rendering import render
from painfree.ui.scheme_forms import scheme_rows, schemes_from
from painfree.webhooks import WebhookSubscriptions

PREFIX = "/ui"

router = APIRouter(prefix=PREFIX, tags=["console"], include_in_schema=False)

#: A console form is a few short fields. Anything larger is not one of ours.
MAX_FORM_BYTES = 64 * 1024

#: What a cadence number means. The form asks for a number and a unit because
#: "every 6 hours" is what an operator has in mind, and 21 600 is what a bank
#: sees; making the human do that multiplication is how a schedule ends up
#: running ten times too often.
CADENCE_UNITS = {"minutes": 60, "hours": 3600, "days": 86400}

#: BTFs Swiss banks commonly publish, offered as a starting point and **not**
#: as a default. Which service a bank publishes for statements is per-bank
#: configuration; the form still asks for every field, because a guess is
#: answered with `EBICS_INVALID_ORDER_PARAMS` hours later rather than with a
#: local error.
BTF_PRESETS = (
    {"label": "Daily statement (camt.053)", "service_name": "EOP",
     "msg_name": "camt.053", "msg_version": "08", "scope": "CH",
     "container": "ZIP"},
    {"label": "Intraday report (camt.052)", "service_name": "STM",
     "msg_name": "camt.052", "msg_version": "08", "scope": "CH",
     "container": "ZIP"},
    {"label": "Credit notification (camt.054)", "service_name": "REP",
     "msg_name": "camt.054", "msg_version": "08", "scope": "CH",
     "container": "ZIP"},
    {"label": "Payment status report (pain.002)", "service_name": "PSR",
     "msg_name": "pain.002", "msg_version": "10", "scope": "CH",
     "container": "ZIP"},
)


async def form_data(request: Request) -> dict[str, str]:
    """One ``application/x-www-form-urlencoded`` body as a flat mapping.

    An ``async`` dependency, so the endpoints underneath stay ``def`` and keep
    running in the thread pool: every one of them does synchronous database
    work, and doing that on the event loop would block every other request.
    """
    body = await request.body()
    if not body:
        # A form whose only control is its button. Nothing to parse, and
        # refusing it would mean every such form needed a decorative field.
        return {}
    if not request.headers.get("content-type", "").startswith(
            "application/x-www-form-urlencoded"):
        raise ConflictError("the console accepts form submissions only")
    if len(body) > MAX_FORM_BYTES:
        raise ConflictError("the submitted form is larger than this console accepts")
    return {name: value for name, value in urllib.parse.parse_qsl(
        body.decode("utf-8", "replace"), keep_blank_values=True)}


def _registry(request: Request):
    return request.app.state.connections


def _keyring(request: Request) -> Keyring:
    return request.app.state.keyring


def _orders(request: Request) -> OrderStore:
    return request.app.state.orders


def _jobs(request: Request) -> KeyJobStore:
    return request.app.state.key_jobs


def _webhooks(request: Request) -> WebhookSubscriptions:
    return request.app.state.webhooks


def _schedules(request: Request) -> DownloadSchedules:
    return request.app.state.schedules


def _see(path: str) -> RedirectResponse:
    """Post, redirect, get. `303` so the browser re-fetches with `GET`."""
    return RedirectResponse(path, status_code=303)


def _required(form: dict[str, str], name: str, label: str) -> str:
    value = (form.get(name) or "").strip()
    if not value:
        raise ConflictError(f"{label} is required")
    return value


# --- connections ------------------------------------------------------------

@router.get("")
@router.get("/")
def home(request: Request, principal: Principal = Depends(requires())):
    return _see(f"{PREFIX}/connections")


@router.get("/connections")
def connections(request: Request, principal: Principal = Depends(requires())):
    """The connections **this caller was granted**, and how far each one got.

    No scope, which makes it the console's landing page for everybody including
    a member who has been granted nothing. That person is the reason the route
    is scopeless: gating the page on `connections:read` would redirect them into
    a `403` on the first screen after signing in, and a console that refuses its
    own front page reads as broken rather than as empty. What they get instead
    is the page saying, in words, that they have no access yet and who to ask.
    An administrator's view is unchanged.
    """
    allowed, _ = access.restrict(principal)
    rows = _registry(request).all(allowed)
    return render(request, "connections.html", connections=rows,
                  outstanding={row.connection_id:
                               _jobs(request).outstanding(row.connection_id)
                               for row in rows})


@router.get("/connections/new")
def new_connection(request: Request,
                   principal: Principal = Depends(requires(Scope.connections_write))):
    return render(request, "connection_new.html", errors=None, values={})


@router.post("/connections")
def register_connection(
    request: Request,
    principal: Principal = Depends(requires(Scope.connections_write)),
    form: dict[str, str] = Depends(form_data),
):
    """Register a subscriber. No keys are minted here -- that is a key job."""
    connection_id = _required(form, "connection_id", "the connection id")
    product = None
    if (form.get("product_name") or "").strip():
        product = ebics3.Product(
            name=form["product_name"].strip(),
            language=(form.get("product_language") or "de").strip() or "de",
            institute=(form.get("product_institute") or "").strip() or None)
    with bind(connection_id=connection_id):
        _registry(request).register(
            connection_id,
            host_id=_required(form, "host_id", "the HostID"),
            partner_id=_required(form, "partner_id", "the PartnerID"),
            user_id=_required(form, "user_id", "the UserID"),
            host_url=_required(form, "host_url", "the host URL"),
            letter_digest=(form.get("letter_digest")
                           or ebics3.DEFAULT_LETTER_DIGEST.value),
            product=product, actor=principal.actor())
    return _see(f"{PREFIX}/connections/{connection_id}/keys")


@router.get("/connections/{connection_id}")
def connection(request: Request, connection_id: str, updated: int = 0,
               principal: Principal = Depends(
                   requires_on(Scope.connections_read))):
    """One connection: who we are to this bank, its keys, and its recent work."""
    with bind(connection_id=connection_id):
        row = _registry(request).get(connection_id)
        keyring = _keyring(request)
        return render(
            request, "connection.html", connection=row, updated=bool(updated),
            subscriber_keys=keyring.entries(connection_id, holder=SUBSCRIBER),
            bank_keys=keyring.entries(connection_id, holder=BANK),
            staged=keyring.staged_bank_keys(connection_id),
            jobs=_jobs(request).history(connection_id, limit=10),
            schemes=scheme_rows(row),
            orders=_orders(request).recent(connection_id=connection_id, limit=10))


@router.get("/connections/{connection_id}/edit")
def edit_connection(request: Request, connection_id: str,
                    principal: Principal = Depends(
                        requires_on(Scope.connections_write))):
    row = _registry(request).get(connection_id)
    ceiling = row.schemes.instant.max_amount if row.schemes.instant else None
    return render(request, "connection_edit.html", connection=row,
                  scheme_names=[scheme.value for scheme in PaymentScheme],
                  # The form shows the defaults for a connection with instant
                  # switched off, so turning it on does not start from blank
                  # fields the operator has to invent values for.
                  default_instant=DEFAULT_INSTANT,
                  # Never localised: it goes back into the wire format.
                  instant_ceiling=f"{ceiling:f}" if ceiling is not None else "")


@router.post("/connections/{connection_id}/edit")
def save_connection(
    request: Request, connection_id: str,
    principal: Principal = Depends(requires_on(Scope.connections_write)),
    form: dict[str, str] = Depends(form_data),
):
    """Change the host URL, the product and which digest the letter quotes.

    The three EBICS identifiers are not on this form. They are what the bank
    knows this subscriber as, and the keys on file are registered against them.
    """
    product = None
    if (form.get("product_name") or "").strip():
        product = ebics3.Product(
            name=form["product_name"].strip(),
            language=(form.get("product_language") or "de").strip() or "de",
            institute=(form.get("product_institute") or "").strip() or None)
    with bind(connection_id=connection_id):
        current = _registry(request).get(connection_id)
        wanted = form.get("letter_digest") or None
        # Changing which hash the letter quotes, once a letter has been acted
        # on, does not change a single key the bank holds -- and invalidates
        # the paper somebody already signed and posted. It stays *possible*,
        # because a bank that says "wrong convention" after INI is exactly when
        # it has to be done. It stops being silent.
        if (wanted and ebics3.LetterDigest(wanted) is not current.letter_digest
                and (current.ini_sent or current.hia_sent)):
            if (form.get("confirm_letter_digest") or "").strip() != "yes":
                raise ConflictError(
                    "INI or HIA has already been sent for this connection, so "
                    "the letter that was printed quotes the other hash. "
                    "Changing this does not change the keys the bank holds; it "
                    "changes what a reprinted letter says, and the letter has "
                    "to be reprinted, signed and posted again. Confirm to "
                    "continue.")
        _registry(request).update(
            connection_id,
            host_url=_required(form, "host_url", "the host URL"),
            letter_digest=wanted,
            schemes=schemes_from(form), product=product,
            actor=principal.actor())
    return _see(f"{PREFIX}/connections/{connection_id}?updated=1")


# --- the key lifecycle ------------------------------------------------------

@router.get("/connections/{connection_id}/keys")
def keys(request: Request, connection_id: str, job: str | None = None,
         principal: Principal = Depends(requires_on(Scope.connections_read))):
    """The walk-through: generate, INI, the letter, HIA, HPB, the comparison."""
    with bind(connection_id=connection_id):
        row = _registry(request).get(connection_id)
        keyring = _keyring(request)
        store = _jobs(request)
        return render(
            request, "keys.html", connection=row,
            subscriber_keys=keyring.entries(connection_id, holder=SUBSCRIBER),
            staged=keyring.staged_bank_keys(connection_id),
            bank_keys=keyring.entries(connection_id, holder=BANK),
            outstanding=store.outstanding(connection_id),
            watched=store.get(job) if job else None,
            jobs=store.history(connection_id, limit=10),
            # Keyed by the action's *name*, so the template asks
            # `available.send_ini` rather than importing an enum.
            available={action.value: row.key_state in states
                       for action, states in ALLOWED_FROM.items()},
            versions=[version.value for version in
                      (ebics3.KeyVersion.A006, ebics3.KeyVersion.X002,
                       ebics3.KeyVersion.E002)])


@router.get("/connections/{connection_id}/keys/bank-keys")
def bank_key_comparison(
    request: Request, connection_id: str,
    principal: Principal = Depends(requires_on(Scope.connections_read)),
):
    """The one screen where the whole trust decision for `HPB` is made.

    It is its own page, reached deliberately, because the alternative is a
    button on a busy screen next to five others. The `H005` key-management
    response carries no signature: what is on this page and the paper in the
    operator's hand is the only control there is.
    """
    with bind(connection_id=connection_id):
        row = _registry(request).get(connection_id)
        keyring = _keyring(request)
        staged = keyring.staged_bank_keys(connection_id)
        if not staged:
            raise NotFoundError(
                f"connection {connection_id!r} has no bank keys waiting to be "
                f"checked; fetch HPB first")
        return render(request, "bank_keys.html", connection=row, staged=staged,
                      received=keyring.staged_fingerprints(row),
                      outstanding=_jobs(request).outstanding(connection_id))


@router.post("/connections/{connection_id}/keys/{action}")
def request_key_job(
    request: Request, connection_id: str, action: str,
    principal: Principal = Depends(requires_on(Scope.connections_write)),
    form: dict[str, str] = Depends(form_data),
):
    """Ask the worker to perform one key operation. Nothing is decrypted here.

    This handler appends a row and redirects. The API process holds no custody
    key, so a browser session cannot cause a private key to be opened in the
    process that answered the click.
    """
    try:
        wanted = KeyAction(action)
    except ValueError:
        raise NotFoundError(f"no such key operation: {action!r}") from None

    with bind(connection_id=connection_id):
        row = _registry(request).get(connection_id)
        # The one irreversible action here whose cost is somebody else's
        # calendar: keys generated now are sealed under a secret that, if no
        # copy of it exists, takes a paper re-registration to recover from.
        # Refused rather than warned about, and only for the first generation
        # -- a connection already initialised is not made safer by stopping it.
        if wanted is KeyAction.create_keys and not _card(request).acknowledged:
            raise ConflictError(
                "this deployment has not confirmed that a copy of the custody "
                "secret exists; every key generated here is sealed under it and "
                f"nothing recovers it. See {PREFIX}/recovery.")
        params = _job_params(wanted, form)
        job = _jobs(request).request(connection_id, wanted,
                                     key_state=row.key_state, params=params,
                                     actor=principal.actor())
    return _see(f"{PREFIX}/connections/{connection_id}/keys?job={job.job_id}")


def _job_params(action: KeyAction, form: dict[str, str]) -> dict[str, Any]:
    """What the operator supplied, per action. Public values only.

    The two fingerprints are **not** defaulted and **not** pre-filled from what
    the bank sent: a confirmation whose value the console supplied confirms
    nothing. They are compared, in the worker, by the engine.
    """
    if action is KeyAction.fetch_catalogue:
        # Which of the three to ask for. Defaulted to `HTD` because that is the
        # one carrying the order catalogue -- the answer to "will this payment
        # be accepted" -- and the other two are read after it, not before.
        return {"order_type": (form.get("order_type") or "HTD").strip().upper()}
    if action is KeyAction.confirm_bank_keys:

        return {"authentication": _required(form, "authentication",
                                            "the authentication fingerprint"),
                "encryption": _required(form, "encryption",
                                        "the encryption fingerprint")}
    if action is KeyAction.decline_bank_keys:
        return {"reason": _required(form, "reason", "a reason for declining")}
    if action is KeyAction.suspend_keys:
        return {"version": (form.get("version") or "").strip() or None,
                "reason": _required(form, "reason", "a reason for suspending")}
    if action is KeyAction.renew_key:
        return {"version": _required(form, "version", "the key version"),
                "common_name": (form.get("common_name") or "").strip() or None,
                "organisation": (form.get("organisation") or "").strip() or None,
                "country": (form.get("country") or "").strip() or None}
    if action is KeyAction.create_keys:
        return {"common_name": (form.get("common_name") or "").strip() or None,
                "organisation": (form.get("organisation") or "").strip() or None,
                "country": (form.get("country") or "").strip() or None}
    return {}


def _card(request: Request):
    """The recovery card, which names a key and never carries one."""
    settings = request.app.state.settings
    return request.app.state.recovery.card(version=painfree.__version__,
                                           git_sha=settings.git_sha)


@router.get("/recovery")
def recovery(request: Request,
             principal: Principal = Depends(requires())):
    """What to hold a copy of, and which copy is the right one.

    Unprivileged, like `/ui/api`: it discloses no secret and no connection, and
    the person who most needs to read it is whoever inherited a deployment
    somebody else stood up. The key id is a hash and identifies *which* secret
    without being any part of it.
    """
    return render(request, "recovery.html", card=_card(request))


@router.get("/recovery/card.txt")
def recovery_card(request: Request,
                  principal: Principal = Depends(requires())):
    """The same card as a file, because the point is to keep it off this host.

    Plain text: it is meant to be printed, or pasted beside the archive in a
    password manager. It carries the key id, never the key.
    """
    card = _card(request)
    made = card.acknowledgement
    lines = [
        "painfree recovery card",
        "",
        f"version           {card.version}",
        f"git sha           {card.git_sha}",
        f"custody key id    {card.key_id or 'none yet -- no keys are sealed'}",
        f"acknowledged      {made.acknowledged_at.isoformat() if made else 'no'}"
        + (f" by {made.acknowledged_by}" if made else ""),
        "",
        "The custody secret seals every stored EBICS private key. It is one file",
        f"on the host, {card.secret_path}, it is in no database backup, and",
        "nothing recovers it. Losing it costs new keys, an INI letter signed on",
        "paper and posted, and days per bank before payments resume.",
        "",
        "Every path here is relative to the directory holding compose.yaml,",
        "on the host running this deployment, and the command below is a",
        "host shell command. Not inside a container: the process that served",
        "this card cannot read the custody secret and must not be able to.",
        "",
        f"Take a copy off this host:  {card.backup_command}",
        "Then encrypt the archive: it holds the secret and the data it opens.",
        "",
        "The key id above says which secret is the right one. It is a hash and",
        "is safe to keep beside the archive; it is not the secret and cannot be",
        "used to open anything.",
    ]
    return PlainTextResponse(
        "\n".join(lines) + "\n",
        headers={"Content-Disposition":
                 'attachment; filename="painfree-recovery-card.txt"'})


@router.post("/recovery/acknowledge")
def acknowledge_recovery(
    request: Request,
    principal: Principal = Depends(requires(Scope.connections_write)),
):
    """Record that a copy of the custody secret exists somewhere else.

    An `admin` act, and the same scope that registers a connection: it is a
    statement about the deployment rather than about any one bank. Nobody is
    asked to paste the secret in to prove it, because a console that could
    check would be a console that could read it.
    """
    request.app.state.recovery.acknowledge(actor=principal.actor())
    return _see(f"{PREFIX}/recovery?acknowledged=1")


@router.get("/connections/{connection_id}/letter")
def letter(request: Request, connection_id: str,
           principal: Principal = Depends(requires_on(Scope.connections_read))):
    """The INI letter, as a page built to be printed, signed and posted.

    Public material only, which is why a read-only screen can render it: the
    numbers and the hashes over them are what the bank compares against the
    keys `INI` and `HIA` delivered. The digest convention is the connection's,
    because the two are not interchangeable.
    """
    with bind(connection_id=connection_id):
        row = _registry(request).get(connection_id)
        keyring = _keyring(request)
        # Dated by the keys it attests to, not by the connection row. The row
        # is touched by an ordinary edit, so a letter already signed and posted
        # would silently re-date itself -- which is exactly the kind of thing
        # nobody notices until a bank asks why two copies disagree.
        signed_for = max(
            keyring.entry(connection_id, version).created_at
            for version in (keyring.signature_version(connection_id),
                            ebics3.KeyVersion.X002, ebics3.KeyVersion.E002))
        return render(request, "letter.html", connection=row,
                      keys_created_at=signed_for,
                      letter=keyring.letter(row))


# --- orders -----------------------------------------------------------------

@router.get("/orders")
def orders(request: Request, connection_id: str = "", state: str = "",
           principal: Principal = Depends(requires(Scope.payments_read))):
    """Order history, filterable. Never the document -- that is payment content.

    The connection filter and its dropdown both come from what this caller
    holds: a filter offering a bank whose orders the page will not show is a
    filter that teaches an operator the console is unreliable.
    """
    chosen = state if state in {member.value for member in OrderState} else ""
    allowed, possible = access.restrict(principal, connection_id or None)
    return render(
        request, "orders.html",
        orders=_orders(request).recent(connection_ids=allowed,
                                       state=chosen or None,
                                       limit=100) if possible else [],
        connections=access.held(principal, _registry(request).all()),
        states=[member.value for member in OrderState],
        selected_connection=connection_id, selected_state=chosen)


@router.get("/orders/{order_id}")
def order(request: Request, order_id: str, replayed: int = 0,
          principal: Principal = Depends(requires(Scope.payments_read))):
    """One order, and the trail of what happened to it.

    The exchange history is the audit trail for this ``order_id``: every
    transition was written through one chokepoint with the bank's return code
    and report text, so there is no second place to look and nothing to
    reconcile.
    """
    with bind(order_id=order_id):
        row = _orders(request).get(order_id)
        # An order id is opaque, which is not the same as unguessable. The
        # connection it belongs to is known only now, so this is where the
        # caller's grant on it is checked.
        access.require(principal, row.connection_id, Scope.payments_read,
                       what="order")
        return render(request, "order.html", order=row,
                      replayed=bool(replayed),
                      replayable=row.state in REPLAYABLE,
                      # Every message built for this order, so an operator can
                      # see that a payment asked to go instantly went normal,
                      # and read the BTF and the `PmtTpInf` of each attempt
                      # side by side.
                      attempts=_orders(request).attempts_for(order_id),
                      # Summaries, not payloads: a `pain.002` quotes the
                      # amounts of the payment it answers, and this page is
                      # held to the same rule as the order above it.
                      reports=request.app.state.statements.reconciler
                      .reports_for(order_id),
                      status_codes=reconcile.STATUS_CODES,
                      events=request.app.state.audit.recent(
                          50, order_id=order_id,
                          connection_ids=access.restrict(principal)[0]))


@router.get("/status-codes")
def status_codes(request: Request,
                 principal: Principal = Depends(requires(Scope.payments_read))):
    """Every ISO 20022 payment status this service reads, and what it does with it.

    Its own page because it is a *mapping*, and an operator looking at an order
    that says `ACWP` needs to know that this service called that an
    acknowledgement without reading source code to find out. The table is
    rendered from the same dictionary the reconciler decides with, so the page
    cannot describe a rule the code does not follow.
    """
    return render(request, "status_codes.html",
                  codes=sorted(reconcile.STATUS_CODES.values(),
                               key=lambda code: (code.outcome, code.code)))


@router.get("/orders/{order_id}/replay")
def confirm_replay(request: Request, order_id: str,
                   principal: Principal = Depends(requires(Scope.orders_replay))):
    """Name exactly what will be re-sent, before anything is re-sent."""
    with bind(order_id=order_id):
        order = _orders(request).get(order_id)
        access.require(principal, order.connection_id, Scope.orders_replay,
                       what="order")
        return render(request, "order_replay.html", order=order)


@router.post("/orders/{order_id}/replay")
def replay_order(
    request: Request, order_id: str,
    principal: Principal = Depends(requires(Scope.orders_replay)),
    form: dict[str, str] = Depends(form_data),
):
    """Re-queue the order. It creates nothing: same row, same document, same MsgId."""
    with bind(order_id=order_id):
        # Access first, and the confirmation second. The other order answers a
        # caller who may not touch this order with a `409` about their form,
        # which both leaks that the order is real and hides the refusal.
        access.require(principal, _orders(request).get(order_id).connection_id,
                       Scope.orders_replay, what="order")
        if (form.get("confirm") or "").strip() != "replay":
            raise ConflictError("the replay was not confirmed")
        _orders(request).replay(order_id, actor=principal.actor())
    return _see(f"{PREFIX}/orders/{order_id}?replayed=1")


# --- statements -------------------------------------------------------------

@router.get("/statements")
def statements(request: Request, connection_id: str = "", message_type: str = "",
               principal: Principal = Depends(requires(Scope.statements_read))):
    store = request.app.state.statements
    allowed, possible = access.restrict(principal, connection_id or None)
    return render(request, "statements.html",
                  statements=store.recent(connection_ids=allowed,
                                          message_type=message_type or None,
                                          limit=100) if possible else [],
                  connections=access.held(principal, _registry(request).all()),
                  message_types=store.message_types(),
                  selected_connection=connection_id,
                  selected_type=message_type)


@router.get("/statements/{statement_id}")
def statement(request: Request, statement_id: str,
              principal: Principal = Depends(requires(Scope.statements_read))):
    """One statement and its normalised JSON, exactly as it is stored."""
    row = request.app.state.statements.get(statement_id)
    if row is None:
        raise NotFoundError(f"no such statement: {statement_id!r}")
    # A statement is somebody's account activity, and the id in the URL is the
    # only thing standing between a member and another bank's balances.
    access.require(principal, row["connection_id"], Scope.statements_read,
                   what="statement")
    return render(request, "statement.html", statement=row)


# --- download schedules -----------------------------------------------------
#
# The section an operator opens because a statement did not arrive, and the
# three things that follow from that.
#
# **A failing schedule is the first thing on the page**, and a run that found
# nothing is *not* one. `EBICS_NO_DOWNLOAD_DATA_AVAILABLE` is what a scheduled
# download finds most days; a console that showed it in red would teach an
# operator to ignore red.
#
# **The console downloads nothing.** "Run now" and "re-fetch" make the schedule
# due; the worker claims it, because the download needs the connection's `E002`
# private half and this process holds no custody key.
#
# **A re-fetch is safe because ingestion is keyed on the document**, not because
# this section checks anything: the same unique constraint that absorbs a
# re-served unacknowledged download absorbs a deliberate one.

@router.get("/schedules")
def schedule_list(request: Request, connection_id: str = "",
                  principal: Principal = Depends(requires(Scope.schedules_read))):
    """Every schedule, its cadence, what it fetches, and how the last run ended."""
    store = _schedules(request)
    allowed, possible = access.restrict(principal, connection_id or None)
    rows = store.all(connection_ids=allowed) if possible else []
    return render(request, "schedules.html", schedules=rows,
                  windows={row.schedule_id: row.ledger() for row in rows},
                  last_runs={row.schedule_id: store.last_run(row.schedule_id)
                             for row in rows},
                  connections=access.held(principal, _registry(request).all()),
                  selected_connection=connection_id,
                  failing=[row for row in rows if row.health == "failing"],
                  behind=[row for row in rows if row.ledger().behind])


@router.get("/schedules/new")
def new_schedule(request: Request, connection_id: str = "",
                 principal: Principal = Depends(requires(Scope.schedules_manage))):
    """The registration form. The BTF is asked for field by field, never guessed.

    The dropdown offers only connections this caller may schedule a download
    for. Hiding an option is not the control -- the `POST` below checks -- but
    offering one that will be refused is a form that lies.
    """
    return render(request, "schedule_new.html",
                  connections=access.held(principal, _registry(request).all()),
                  selected_connection=connection_id,
                  presets=BTF_PRESETS, values={})


@router.post("/schedules")
def register_schedule(
    request: Request,
    principal: Principal = Depends(requires(Scope.schedules_manage)),
    form: dict[str, str] = Depends(form_data),
):
    """Register one periodic download and go to its page.

    This write *can* end in a `303`, unlike a webhook registration: a schedule
    has nothing to show once. A reload of the redirect is a `GET`, and a reload
    of the submitted form would hit `uq_download_schedule_btf` and be told the
    schedule already exists rather than making a second one.
    """
    connection_id = _required(form, "connection_id", "the connection")
    access.require(principal, connection_id, Scope.schedules_manage,
                   what="bank connection")
    _registry(request).get(connection_id)
    with bind(connection_id=connection_id):
        schedule = _schedules(request).register(
            connection_id, actor=principal.actor(),
            cadence=_dt.timedelta(seconds=_cadence(form)),
            description=(form.get("description") or "").strip() or None,
            window_days=_window_days(form), **_btf(form))
    return _see(f"{PREFIX}/schedules/{schedule.schedule_id}?created=1")


@router.get("/schedules/{schedule_id}")
def schedule(request: Request, schedule_id: str, created: int = 0,
             queued: str = "",
             principal: Principal = Depends(requires(Scope.schedules_read))):
    """One schedule: its window, its controls, and every run it has had."""
    store = _schedules(request)
    row = store.get(schedule_id)
    access.require(principal, row.connection_id, Scope.schedules_read,
                   what="download schedule")
    with bind(connection_id=row.connection_id):
        every, unit = cadence_parts(int(row.cadence.total_seconds()))
        return render(request, "schedule.html", schedule=row,
                      window=row.ledger(), runs=store.runs(schedule_id, limit=25),
                      unfinished=store.unfinished_runs(schedule_id, limit=10),
                      created=bool(created), queued=queued or None,
                      cadence_every=every, cadence_unit=unit,
                      cadence_units=list(CADENCE_UNITS),
                      today=_dt.date.today().isoformat())


@router.post("/schedules/{schedule_id}/edit")
def save_schedule(
    request: Request, schedule_id: str,
    principal: Principal = Depends(requires(Scope.schedules_manage)),
    form: dict[str, str] = Depends(form_data),
):
    """Change the BTF, the cadence, the window or the description.

    The window ledger is not touched by an edit. Re-asking the bank for days it
    already answered for is a deliberate act with its own control below.
    """
    access.require(principal, _schedules(request).get(schedule_id).connection_id,
                   Scope.schedules_manage, what="download schedule")
    _schedules(request).update(
        schedule_id, actor=principal.actor(), cadence_seconds=_cadence(form),
        window_days=_window_days(form),
        description=(form.get("description") or "").strip() or None,
        **_btf(form))
    return _see(f"{PREFIX}/schedules/{schedule_id}")


@router.post("/schedules/{schedule_id}/{action}")
def schedule_action(
    request: Request, schedule_id: str, action: str,
    principal: Principal = Depends(requires(Scope.schedules_manage)),
    form: dict[str, str] = Depends(form_data),
):
    """Pause, resume, run now, re-fetch a window, or delete. One scope, one style."""
    store = _schedules(request)
    access.require(principal, store.get(schedule_id).connection_id,
                   Scope.schedules_manage, what="download schedule")
    if action == "pause":
        store.set_enabled(schedule_id, False, actor=principal.actor())
    elif action == "resume":
        store.set_enabled(schedule_id, True, actor=principal.actor())
    elif action == "run":
        store.run_now(schedule_id, requested_by=principal.subject,
                      actor=principal.actor())
        return _see(f"{PREFIX}/schedules/{schedule_id}?queued=run")
    elif action == "refetch":
        since = _required(form, "since", "the first day to re-fetch")
        try:
            day = _dt.date.fromisoformat(since)
        except ValueError:
            raise ConflictError(
                f"{since!r} is not a date; use YYYY-MM-DD") from None
        store.refetch(schedule_id, since=day, requested_by=principal.subject,
                      actor=principal.actor())
        return _see(f"{PREFIX}/schedules/{schedule_id}?queued=refetch")
    elif action == "delete":
        if (form.get("confirm") or "").strip() != "delete":
            raise ConflictError("the deletion was not confirmed")
        store.delete(schedule_id, actor=principal.actor())
        return _see(f"{PREFIX}/schedules")
    else:
        raise NotFoundError(f"no such schedule operation: {action!r}")
    return _see(f"{PREFIX}/schedules/{schedule_id}")


def cadence_parts(seconds: int) -> tuple[int, str]:
    """``21600`` back into ``(6, "hours")``, for the edit form.

    The largest unit that divides exactly, so a cadence round-trips through the
    form unchanged. Rendering `21600 // 3600` and defaulting the unit would
    quietly turn 90 seconds into an hour the first time somebody saved a
    description.
    """
    for unit, size in sorted(CADENCE_UNITS.items(), key=lambda pair: -pair[1]):
        if seconds % size == 0:
            return seconds // size, unit
    return max(1, seconds // 60), "minutes"


def _btf(form: dict[str, str]) -> dict[str, str | None]:
    """The seven BTF fields off the form. Blank means absent, not empty."""
    optional = {name: (form.get(name) or "").strip() or None
                for name in ("msg_version", "msg_variant", "scope",
                             "service_option", "container")}
    return {"service_name": _required(form, "service_name",
                                      "the BTF service name"),
            "msg_name": _required(form, "msg_name", "the message name"),
            **optional}


def _cadence(form: dict[str, str]) -> int:
    """How often, in seconds, from a number and a unit.

    Two controls rather than one seconds box: an operator setting a statement
    download types "6" and picks "hours", and a console that made them compute
    21 600 is a console that will eventually be given 216 000.
    """
    raw = _required(form, "cadence", "the cadence")
    unit = (form.get("cadence_unit") or "hours").strip()
    if unit not in CADENCE_UNITS:
        raise ConflictError(f"{unit!r} is not a cadence unit")
    try:
        every = int(raw)
    except ValueError:
        raise ConflictError(f"{raw!r} is not a number of {unit}") from None
    if every < 1:
        raise ConflictError("a cadence of less than one is not a cadence")
    return every * CADENCE_UNITS[unit]


def _window_days(form: dict[str, str]) -> int | None:
    """``None`` means: send no ``DateRange`` at all, which is the EBICS default."""
    raw = (form.get("window_days") or "").strip()
    if not raw:
        return None
    try:
        days = int(raw)
    except ValueError:
        raise ConflictError(f"{raw!r} is not a number of days") from None
    if days < 1:
        raise ConflictError(
            "a window of fewer than one day asks the bank for nothing; leave "
            "it empty to send no DateRange at all")
    return days


# --- webhooks ---------------------------------------------------------------
#
# The one console section whose page has a *secret* on it, and the rules that
# follow from that are worth stating once here.
#
# **The secret is rendered, not redirected to.** Every other write in this
# console ends in a `303` so a reload cannot repeat it. Registration cannot:
# the secret exists only in the response that created it, so there is no page
# to redirect to that could still show it. What replaces the redirect is the
# idempotency key the form carries in a hidden field -- a reload re-posts the
# same key, the registration replays, and the operator is told the endpoint
# already exists instead of registering a second one.
#
# **Nothing on these pages can read a stored secret**, because the process
# rendering them cannot: `app.state.webhooks` is built with no custody key.

@router.get("/webhooks")
def webhook_list(request: Request, connection_id: str = "",
                 principal: Principal = Depends(requires(Scope.webhooks_read))):
    """Every endpoint and its health. A parked one is the reason to be here."""
    store = _webhooks(request)
    allowed, possible = access.restrict(principal, connection_id or None)
    rows = store.all(connection_ids=allowed) if possible else []
    return render(request, "webhooks.html", subscriptions=rows,
                  owed={row.subscription_id: store.owed(row.subscription_id)
                        for row in rows},
                  connections=access.held(principal, _registry(request).all()),
                  selected_connection=connection_id,
                  parked=[row for row in rows if row.parked])


@router.get("/webhooks/new")
def new_webhook(request: Request,
                principal: Principal = Depends(requires(Scope.webhooks_manage))):
    """The registration form. Its idempotency key is minted here, not on submit.

    A key generated when the form is *rendered* is the same key on a reload of
    the submitted form, which is what makes an accidental re-post a replay
    rather than a second endpoint.
    """
    return render(request, "webhook_new.html",
                  connections=_registry(request).all(),
                  event_types=sorted(webhooks.EVENT_TYPE_NAMES),
                  idempotency_key="ui-" + uuid.uuid4().hex,
                  values={})


@router.post("/webhooks")
def register_webhook(
    request: Request,
    principal: Principal = Depends(requires(Scope.webhooks_manage)),
    form: dict[str, str] = Depends(form_data),
):
    """Register an endpoint and show its secret, once, on the page that made it."""
    url = _required(form, "url", "the endpoint URL")
    types = _checked_types(form)
    connection_id = (form.get("connection_id") or "").strip() or None
    if connection_id:
        _registry(request).get(connection_id)
    store = _webhooks(request)
    try:
        subscription, secret = store.register(
            url, types, connection_id=connection_id,
            description=(form.get("description") or "").strip() or None,
            idempotency_key=_required(form, "idempotency_key",
                                      "the form's idempotency key"))
    except webhooks.Replayed as replay:
        # A reload of the submitted form. The endpoint exists; the secret does
        # not exist twice, and saying so is more honest than a second secret.
        return render(request, "webhook_secret.html",
                      subscription=replay.subscription, secret=None,
                      replayed=True, rotated=False)
    record_webhook_change(request, "webhook.subscription_registered", principal,
                          subscription, url=subscription.url,
                          event_types=list(subscription.event_types))
    return render(request, "webhook_secret.html", subscription=subscription,
                  secret=secret, replayed=False, rotated=False)


@router.get("/webhooks/{subscription_id}")
def webhook(request: Request, subscription_id: str, pinged: str = "",
            principal: Principal = Depends(requires(Scope.webhooks_read))):
    """One endpoint: what it is configured for, its health, its recent deliveries."""
    store = _webhooks(request)
    subscription = store.get(subscription_id)
    access.require(principal, subscription.connection_id, Scope.webhooks_read,
                   what="webhook subscription")
    return render(request, "webhook.html", subscription=subscription,
                  deliveries=store.deliveries(subscription_id, limit=25),
                  owed=store.owed(subscription_id),
                  connections=_registry(request).all(),
                  event_types=sorted(webhooks.EVENT_TYPE_NAMES),
                  ping_event_type=webhooks.PING_EVENT_TYPE,
                  pinged=pinged or None)


@router.post("/webhooks/{subscription_id}/edit")
def save_webhook(
    request: Request, subscription_id: str,
    principal: Principal = Depends(requires(Scope.webhooks_manage)),
    form: dict[str, str] = Depends(form_data),
):
    """Change where events go and which ones. Queued events follow the new URL."""
    access.require(principal,
                   _webhooks(request).get(subscription_id).connection_id,
                   Scope.webhooks_manage, what="webhook subscription")
    subscription = _webhooks(request).update(
        subscription_id, url=_required(form, "url", "the endpoint URL"),
        event_types=_checked_types(form),
        description=(form.get("description") or ""))
    record_webhook_change(request, "webhook.subscription_updated", principal,
                          subscription, url=subscription.url,
                          event_types=list(subscription.event_types))
    return _see(f"{PREFIX}/webhooks/{subscription_id}")


@router.post("/webhooks/{subscription_id}/{action}")
def webhook_action(
    request: Request, subscription_id: str, action: str,
    principal: Principal = Depends(requires(Scope.webhooks_manage)),
    form: dict[str, str] = Depends(form_data),
):
    """Pause, resume, ping, rotate, retire or delete -- one handler, one scope.

    They are one route because they are one privilege and one confirmation
    style: a button, a `303`, and a page that shows what changed. `rotate` is
    the exception and renders, for the same reason registration does.
    """
    store = _webhooks(request)
    access.require(principal, store.get(subscription_id).connection_id,
                   Scope.webhooks_manage, what="webhook subscription")
    if action == "pause":
        subscription = store.set_enabled(subscription_id, False)
        record_webhook_change(request, "webhook.subscription_paused",
                              principal, subscription)
    elif action == "resume":
        # One control for both states. An operator looking at an endpoint that
        # is not receiving events should not have to know whether this service
        # switched it off or a human did.
        subscription = store.get(subscription_id)
        requeued = store.resume(subscription_id)
        record_webhook_change(request, "webhook.subscription_resumed",
                              principal, subscription, requeued=requeued)
    elif action == "ping":
        delivery = store.enqueue_ping(subscription_id,
                                      actor_id=principal.subject)
        record_webhook_change(request, "webhook.ping_requested", principal,
                              store.get(subscription_id),
                              delivery_id=delivery.delivery_id)
        return _see(f"{PREFIX}/webhooks/{subscription_id}"
                    f"?pinged={delivery.delivery_id}")
    elif action == "rotate-secret":
        subscription, secret = store.rotate_secret(subscription_id)
        record_webhook_change(request, "webhook.secret_rotated", principal,
                              subscription,
                              secret_generation=subscription.secret_generation)
        return render(request, "webhook_secret.html",
                      subscription=subscription, secret=secret,
                      replayed=False, rotated=True)
    elif action == "retire-secret":
        subscription = store.retire_previous_secret(subscription_id)
        record_webhook_change(request, "webhook.previous_secret_retired",
                              principal, subscription,
                              secret_generation=subscription.secret_generation)
    elif action == "delete":
        if (form.get("confirm") or "").strip() != "delete":
            raise ConflictError("the deletion was not confirmed")
        subscription = store.get(subscription_id)
        dropped = store.delete(subscription_id)
        record_webhook_change(request, "webhook.subscription_deleted",
                              principal, subscription,
                              owed_events_dropped=dropped)
        return _see(f"{PREFIX}/webhooks")
    else:
        raise NotFoundError(f"no such webhook operation: {action!r}")
    return _see(f"{PREFIX}/webhooks/{subscription_id}")


def _checked_types(form: dict[str, str]) -> list[str]:
    """Which event-type checkboxes were ticked.

    Parsed off the flat form mapping rather than a multi-value one: an
    unchecked box sends nothing, so the field names are the contract's own
    event types and the presence of one is the answer.
    """
    chosen = [name for name in sorted(webhooks.EVENT_TYPE_NAMES)
              if form.get(f"event:{name}")]
    if not chosen:
        raise ConflictError("choose at least one event type for this endpoint")
    return chosen


__all__ = ["BTF_PRESETS", "CADENCE_UNITS", "MAX_FORM_BYTES", "PREFIX",
           "cadence_parts", "form_data", "router"]
