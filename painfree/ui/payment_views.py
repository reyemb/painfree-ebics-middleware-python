"""One payment, typed into the console, previewed, and then sent for real.

**Why this exists.** Until now a payment could only be submitted over `/v1`,
which is right for the traffic this service carries and wrong for the one
moment nobody has an integration yet: the end of an onboarding, when `INI`,
`HIA` and `HPB` are done and the only open question is whether the whole chain
-- the document, the signature, the BTF, the transport, the bank's own
acceptance -- actually works. Answering that with `curl` and a hand-built JSON
body means the first real payment is also the first exercise of the client that
builds it.

**Preview is not a dry run of its own.** The preview page is produced by
:meth:`painfree.orders.OrderStore.preview`, which runs the same steps as a
submission in the same order and stops before the row. A separate "validator"
written for the console would be a second answer to the question "would this be
accepted", and the second answer is the one that is wrong.

**What the preview cannot tell you, it does not claim.** It proves the document
is built and passes the official schema. It proves nothing about the bank: no
key has been opened, nothing has been signed, and no connection has been made.
That is stated on the page, because a green preview read as *the bank will take
this* is exactly the misreading that would make this feature worse than its
absence.

**Sending is a second, deliberate act.** The confirm form carries the fields
back and posts to a different route, so the button that moves money is never
the button that renders a page. It also carries the idempotency key minted at
preview -- not a fresh one -- so that a double-click on confirm replays the
first order instead of paying twice. A key minted at submission would have made
this console the one caller that cannot be retried safely.

**One transfer, not a batch.** This is the shape of a test payment and the
whole of what the form offers; a batch editor in HTML would be a different
feature with a different reason to exist. The API takes up to
:data:`painfree.payments.MAX_TRANSACTIONS` and is where a batch belongs.
"""

from __future__ import annotations

import datetime as _dt
import secrets
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse
from pydantic import ValidationError

from painfree import ebics3, payments, sps
from painfree.identity import Principal, Scope
from painfree.logging import bind
from painfree.authn import requires_on
from painfree.ui.rendering import render
from painfree.catalogue import Catalogue
from painfree.ui.views import PREFIX, _orders, _registry, form_data

router = APIRouter(prefix=PREFIX, tags=["console"], include_in_schema=False)

#: Prefix on the idempotency key this console mints, so that a key which turns
#: up in an audit row or a bank enquiry says where it came from. The random
#: half is what makes it a key; this half is for whoever reads it later.
KEY_PREFIX = "ui-"

#: The fields the form posts, and the only ones carried through the preview
#: into the confirmation. Named once so the two templates and the parser cannot
#: disagree about what a payment on this page consists of.
FIELDS = (
    "debtor_name", "debtor_iban", "debtor_bic",
    "creditor_name", "creditor_iban", "creditor_bic",
    "amount", "currency", "requested_execution_date",
    "reference_type", "reference", "remittance_information",
    "end_to_end_id", "scheme",
)


def _debit_accounts(request: Request,
                    connection_id: str) -> list[ebics3.AccountInfo]:
    """The accounts `HTD` says this subscriber may draw on, for the form.

    Offered as suggestions rather than as the only choices. ``AccountInfo`` is
    ``minOccurs="0"`` in the schema, so a bank may publish none at all; and a
    catalogue is only as current as the last time somebody fetched it. A
    ``select`` built from either of those would be a form that refuses a
    payment the bank would have taken, which is a worse failure than a typo --
    and the typo is caught anyway, by the IBAN check, before anything is built.

    So the form offers a select of these and a typed override beside it: pick
    when the list is right, type when it is not. Empty when no `HTD` has been
    fetched, which the form says rather than hides.
    """
    entry = Catalogue(request.app.state.engine).get(connection_id, "HTD")
    if entry is None or entry.summary is None:
        return []
    # Through the dataclass, not as the stored dict. The summary is a cache
    # written whenever `HTD` was last fetched, and a row written by an older
    # release has only the keys that release knew: 0.5.1 added `holder` and
    # `bank_code`, the template renders `account.holder`, and Jinja runs with
    # `StrictUndefined` -- so an upgrade turned the payment page into a 500 for
    # every deployment whose catalogue predated it, with nothing saying that
    # re-fetching `HTD` was the cure.
    #
    # `AccountInfo` has defaults for every field but the id, so a missing key
    # becomes `None` and the form falls back to what it always did. A stale
    # cache should read as "the bank did not tell us that", which is true, and
    # not as an exception.
    return [ebics3.AccountInfo(
                account_id=str(account.get("account_id") or ""),
                description=account.get("description"),
                iban=account.get("iban"),
                currency=account.get("currency"),
                holder=account.get("holder"),
                bank_code=account.get("bank_code"))
            for account in entry.summary.get("accounts", [])
            if account.get("iban")]


def _subscriber_name(request: Request, connection_id: str) -> str:
    """The account holder, as the bank itself names this subscriber in `HTD`.

    One value for the whole connection rather than one per account: `HTD` names
    the *subscriber*, and every account it then lists is an account that
    subscriber may draw on. So this does not need a selection to be known --
    which is why the field can be filled when the form is first drawn, with no
    script and no round trip when an account is picked.

    Still an ordinary editable input. A bank's registered name is not always
    what belongs in `Dbtr/Nm`, and a caller who needs a different one types it.
    """
    entry = Catalogue(request.app.state.engine).get(connection_id, "HTD")
    if entry is None or entry.summary is None:
        return ""
    return (entry.summary.get("name") or "").strip()


def _published_debit(request: Request, connection_id: str,
                     iban: str) -> bool | None:
    """Is this debit account one the bank published? ``None`` if unknown.

    Three-valued for the same reason the catalogue page is: a bank that was
    never asked has not said no. Shown on the preview, never enforced.
    """
    accounts = _debit_accounts(request, connection_id)
    if not accounts:
        return None
    wanted = (iban or "").replace(" ", "").upper()
    return any((account.iban or "").upper() == wanted
               for account in accounts)


def _see(path: str) -> RedirectResponse:
    return RedirectResponse(path, status_code=303)


def _clean(form: dict[str, str], name: str) -> str | None:
    """A form field, or ``None``. Empty is absent, which HTML cannot say."""
    value = (form.get(name) or "").strip()
    return value or None


def debit_account(form: dict[str, str]) -> str:
    """The debit IBAN: what was typed, or failing that what was picked.

    The form offers both because the published list can be empty, stale, or
    simply not contain the account somebody needs, and a closed list would
    refuse a payment the bank would have taken. Typing wins over picking: a
    person who filled the override meant it, and silently preferring the
    dropdown they left alone would send a payment to a different account than
    the one on screen.
    """
    typed = (form.get("debtor_iban_other") or "").strip()
    return (typed or form.get("debtor_iban") or "").replace(" ", "")


def instruction_from(form: dict[str, str]) -> payments.PaymentInstruction:
    """The form as the same model the API parses, validated by that model.

    Nothing here checks a length, a pattern or an IBAN. The model already
    states every one of those against the ISO 20022 type the builder will emit
    into, and a form handler that re-stated them would be a second set of rules
    to keep in step with the first.
    """
    reference_type = (form.get("reference_type") or "NONE").strip() or "NONE"
    transaction: dict[str, Any] = {
        "amount": (form.get("amount") or "").strip(),
        "currency": (form.get("currency") or "CHF").strip().upper() or "CHF",
        "creditor": {"name": _clean(form, "creditor_name")},
        "creditor_iban": (form.get("creditor_iban") or "").replace(" ", ""),
        "creditor_bic": _clean(form, "creditor_bic"),
        "end_to_end_id": _clean(form, "end_to_end_id"),
        "remittance_information": _clean(form, "remittance_information"),
        "reference": {"type": reference_type,
                      "reference": _clean(form, "reference")},
    }
    body: dict[str, Any] = {
        "debtor": {"name": _clean(form, "debtor_name")},
        "debtor_iban": debit_account(form),
        "debtor_bic": _clean(form, "debtor_bic"),
        "requested_execution_date": (
            form.get("requested_execution_date") or "").strip(),
        "transactions": [transaction],
    }
    if _clean(form, "scheme"):
        body["scheme"] = form["scheme"].strip()
    return payments.PaymentInstruction.model_validate(body)


def failures_from(error: ValidationError) -> list[sps.RuleFailure]:
    """A pydantic error as the same rows a Swiss rule failure renders as.

    The page has one list of things that are wrong, and an operator does not
    care which layer refused: a missing name and a malformed reference are the
    same kind of problem to the person fixing them. The location is the field
    path the model names, mapped back to the input the operator actually typed
    where the two differ -- `transactions.0.creditor.name` is not a thing on
    this page, and `creditor_name` is.
    """
    rows = []
    for detail in error.errors():
        path = ".".join(str(part) for part in detail["loc"])
        rows.append(sps.RuleFailure(FORM_FIELDS.get(path, path),
                                    f"shape.{detail['type']}",
                                    detail["msg"]))
    return rows


#: Where a model field path came from on this form. Only the paths that differ
#: from the input name are here; anything else is already the operator's word
#: for it.
FORM_FIELDS = {
    "debtor.name": "debtor_name",
    "transactions.0.creditor.name": "creditor_name",
    "transactions.0.creditor_iban": "creditor_iban",
    "transactions.0.creditor_bic": "creditor_bic",
    "transactions.0.amount": "amount",
    "transactions.0.currency": "currency",
    "transactions.0.end_to_end_id": "end_to_end_id",
    "transactions.0.reference.reference": "reference",
    "transactions.0.reference.type": "reference_type",
    "transactions.0.remittance_information": "remittance_information",
}


def _carried(form: dict[str, str]) -> dict[str, str]:
    """The fields to hand to the next page, so the form survives a refusal."""
    return {name: form.get(name, "") for name in FIELDS}


def _blank() -> dict[str, str]:
    """An empty form, dated today. Nothing else is guessed for the operator."""
    entered = {name: "" for name in FIELDS}
    entered["currency"] = "CHF"
    entered["reference_type"] = "NONE"
    entered["requested_execution_date"] = _dt.date.today().isoformat()
    return entered


@router.get("/connections/{connection_id}/payment")
def payment_form(request: Request, connection_id: str,
                 principal: Principal = Depends(
                     requires_on(Scope.payments_submit))):
    """The form. `payments:submit` **at this bank**, like the API route."""
    with bind(connection_id=connection_id):
        connection = _registry(request).get(connection_id)
        entered = _blank()
        entered["debtor_name"] = _subscriber_name(request, connection_id)
        return render(request, "payment_new.html", connection=connection,
                      entered=entered, failures=(),
                      accounts=_debit_accounts(request, connection_id))


@router.post("/connections/{connection_id}/payment/preview")
def preview_payment(
    request: Request,
    connection_id: str,
    principal: Principal = Depends(requires_on(Scope.payments_submit)),
    form: dict[str, str] = Depends(form_data),
):
    """Build it, validate it, show it. Nothing is written and nothing is sent."""
    with bind(connection_id=connection_id):
        connection = _registry(request).get(connection_id)
        entered = _carried(form)
        try:
            instruction = instruction_from(form)
        except ValidationError as error:
            return render(request, "payment_new.html", status_code=422,
                          connection=connection, entered=entered,
                          accounts=_debit_accounts(request, connection_id),
                          failures=failures_from(error))
        try:
            preview = _orders(request).preview(
                connection_id, instruction,
                software_version=request.app.state.settings.version)
        except sps.ValidationFailed as refused:
            return render(request, "payment_new.html", status_code=422,
                          connection=connection, entered=entered,
                          accounts=_debit_accounts(request, connection_id),
                          failures=refused.failures)
        return render(
            request, "payment_preview.html", connection=connection,
            entered=entered, preview=preview,
            document=preview.document.decode("utf-8"),
            debit_published=_published_debit(
                request, connection_id, debit_account(form)),
            # Minted here and carried, not minted on the way in: see the module
            # docstring. A second press of confirm has to be the same payment.
            idempotency_key=f"{KEY_PREFIX}{secrets.token_hex(16)}")


@router.post("/connections/{connection_id}/payment")
def send_payment(
    request: Request,
    connection_id: str,
    principal: Principal = Depends(requires_on(Scope.payments_submit)),
    form: dict[str, str] = Depends(form_data),
):
    """Submit it, for real, through the ordinary path.

    The same :meth:`~painfree.orders.OrderStore.submit` the API calls, with the
    actor of the person who pressed the button: an order raised here is not a
    different kind of order and must not be distinguishable from one raised by
    a client, except in who the audit trail says asked for it.
    """
    with bind(connection_id=connection_id):
        connection = _registry(request).get(connection_id)
        entered = _carried(form)
        key = (form.get("idempotency_key") or "").strip()
        try:
            instruction = instruction_from(form)
        except ValidationError as error:
            return render(request, "payment_new.html", status_code=422,
                          connection=connection, entered=entered,
                          accounts=_debit_accounts(request, connection_id),
                          failures=failures_from(error))
        submission = _orders(request).submit(
            connection_id, idempotency_key=key, instruction=instruction,
            actor=principal.actor(),
            software_version=request.app.state.settings.version)
    return _see(f"{PREFIX}/orders/{submission.order.order_id}?submitted=1")


__all__ = ["FIELDS", "instruction_from", "router"]
