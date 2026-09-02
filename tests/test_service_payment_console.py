"""Raising one payment by hand, in the console, and what the preview promises.

The console gained a payment form for one moment in a deployment's life: the
end of an onboarding, when `INI`, `HIA` and `HPB` are done and nobody yet knows
whether the rest of the chain works. Everything here is about the two claims
that page makes to somebody about to move real money.

**"This is what would be sent."** The preview has to be produced by the code
that sends, or it is a second implementation whose agreement with the first is
a matter of hope. So the central test below submits the same instruction it
previewed and compares the two documents byte for byte, allowing only the two
fields that are minted at submission.

**"Nothing has been sent."** A preview writes no order, consumes no idempotency
key and records nothing. If it ever did, the page would be lying in the
direction that costs money.

And one property that is not about the page at all: pressing confirm twice has
to be one payment. The key is minted when the preview is rendered and carried
into the form, so the second press replays the first order. A key minted on
submission would have made this console the only caller that cannot be retried
safely, which is the bug this test exists to keep out.
"""

from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from conftest import (DEBTOR_IBAN, PLAIN_IBAN, QRR_REFERENCE, QR_IBAN,
                      dev_credentials)
from painfree import ebics3
from painfree.app import create_app
from painfree.attempts import AttemptStore
from painfree.connections import ConnectionRegistry
from painfree.schema import bank_connection, payment_order
from painfree.ui.payment_views import instruction_from

CONNECTION = "acme-ubs"

#: A payment this deployment's rules accept: a QR-IBAN with the QR reference
#: that belongs to it. The pair is the thing `painfree.sps` has an opinion
#: about, so getting it right here keeps these tests about the console.
GOOD = {
    "debtor_name": "MUSTER AG",
    "debtor_iban": DEBTOR_IBAN,
    "debtor_bic": "",
    "creditor_name": "Robert Schneider AG",
    "creditor_iban": QR_IBAN,
    "creditor_bic": "",
    "amount": "1.00",
    "currency": "CHF",
    "requested_execution_date": "2026-09-30",
    "reference_type": "QRR",
    "reference": QRR_REFERENCE,
    "remittance_information": "",
    "end_to_end_id": "",
    "scheme": "",
}


def _initialise(app) -> None:
    """The state the bank puts a subscriber in, written directly.

    Re-driving `INI` and `HIA` here would buy nothing: they are
    `test_ebics3_initialisation`'s subject, and what this file needs is a
    connection that is allowed to send.
    """
    with app.state.engine.begin() as connection:
        connection.execute(
            bank_connection.update()
            .where(bank_connection.c.connection_id == CONNECTION)
            .values(key_state=ebics3.KeyState.READY.value,
                    ini_sent=True, hia_sent=True))


@pytest.fixture
def console(settings):
    app = create_app(settings)
    with TestClient(app, headers=dev_credentials()) as client:
        ConnectionRegistry(app.state.engine).register(
            CONNECTION, host_id="UBSHOST", partner_id="PARTNER1",
            user_id="USER1", host_url="https://ebics.example.test/")
        _initialise(app)
        yield client


def _orders(app) -> list:
    with app.state.engine.begin() as connection:
        return list(connection.execute(select(payment_order)).mappings())


def _hidden(page: str, name: str) -> str:
    match = re.search(rf'name="{name}" value="([^"]*)"', page)
    assert match is not None, f"no hidden {name} on the page"
    return match.group(1)


def _preview(console, **overrides):
    return console.post(f"/ui/connections/{CONNECTION}/payment/preview",
                        data={**GOOD, **overrides})


# --- what the preview is ------------------------------------------------------

def test_the_previewed_document_is_the_one_that_gets_sent(console):
    """The claim the page makes, checked rather than described.

    Only two fields may differ: the `MsgId` and the `CreDtTm`, both minted at
    submission. Anything else differing means the console is showing an
    operator a document that is not the one their money moves under.
    """
    app = console.app
    page = _preview(console)
    assert page.status_code == 200
    shown = re.search(r"<pre class=\"json\">(.*?)</pre>", page.text,
                      re.S).group(1)

    submission = app.state.orders.submit(
        CONNECTION, idempotency_key="compare-the-two-documents",
        instruction=instruction_from(GOOD),
        # The same version the page passed. Giving the two paths different
        # inputs and then comparing their output would prove nothing.
        software_version=app.state.settings.version)
    sent = AttemptStore(app.state.engine).live(
        submission.order.order_id).document

    def normalise(document: str) -> str:
        document = re.sub(r"<MsgId>[^<]+</MsgId>", "<MsgId/>", document)
        document = re.sub(r"<CreDtTm>[^<]+</CreDtTm>", "<CreDtTm/>", document)
        # `PmtInfId` defaults to the message id when the caller names none, so
        # it moves with it and for the same reason.
        return re.sub(r"<PmtInfId>[^<]+</PmtInfId>", "<PmtInfId/>", document)

    import html
    assert normalise(html.unescape(shown)) == normalise(
        sent.decode("utf-8")), "the preview is not what would be sent"


def test_a_preview_writes_nothing(console):
    """The other half of the claim. A preview that left a row would be a
    payment somebody did not know they had raised."""
    app = console.app
    assert _preview(console).status_code == 200

    assert _orders(app) == []


def test_a_preview_names_the_scheme_it_resolved(console):
    """Not an echo of the form: what was asked for and what this connection can
    actually do are different questions, and the second is the one that decides
    what the bank is told."""
    page = _preview(console)

    assert "normal" in page.text
    # The BTF triplet, which is the part an operator compares against the
    # bank's own parameter sheet when a file is refused.
    assert "pain.001" in page.text


# --- what it refuses ----------------------------------------------------------

def test_a_broken_reference_is_refused_before_anything_is_built(console):
    """A QR reference against a plain IBAN is the pairing `painfree.sps`
    exists to catch. It has to be caught here, on the page, and not by a bank
    the next morning."""
    app = console.app
    page = _preview(console, creditor_iban=PLAIN_IBAN)

    assert page.status_code == 422
    assert _orders(app) == []
    # The failure names the rule, so it can be looked up rather than guessed.
    assert "reference" in page.text.lower()


def test_a_shape_failure_names_the_field_the_operator_typed_into(console):
    """`transactions.0.creditor.name` is not a thing on this page. The person
    fixing it typed into `creditor_name`, and that is what they are shown."""
    page = _preview(console, creditor_name="")

    assert page.status_code == 422
    assert "creditor_name" in page.text
    assert "transactions.0.creditor.name" not in page.text


def test_the_form_comes_back_filled_in_after_a_refusal(console):
    """A refusal that emptied the form would be a refusal an operator answers
    by typing everything again, which is how a wrong value gets retyped."""
    page = _preview(console, creditor_iban=PLAIN_IBAN)

    assert QRR_REFERENCE in page.text
    assert "MUSTER AG" in page.text


# --- sending ------------------------------------------------------------------

def test_confirming_submits_the_payment_and_lands_on_its_order(console):
    app = console.app
    key = _hidden(_preview(console).text, "idempotency_key")

    sent = console.post(f"/ui/connections/{CONNECTION}/payment",
                        data={**GOOD, "idempotency_key": key},
                        follow_redirects=False)

    assert sent.status_code == 303
    rows = _orders(app)
    assert len(rows) == 1
    assert sent.headers["location"].endswith(
        f"{rows[0]['order_id']}?submitted=1")


def test_pressing_confirm_twice_is_one_payment(console):
    """The reason the key is minted at preview and carried. A person who does
    not see the redirect and presses again must not pay twice."""
    app = console.app
    key = _hidden(_preview(console).text, "idempotency_key")
    body = {**GOOD, "idempotency_key": key}

    first = console.post(f"/ui/connections/{CONNECTION}/payment", data=body,
                         follow_redirects=False)
    second = console.post(f"/ui/connections/{CONNECTION}/payment", data=body,
                          follow_redirects=False)

    assert len(_orders(app)) == 1, "the second press made a second payment"
    assert first.headers["location"] == second.headers["location"]


def test_the_audit_trail_names_the_person_who_pressed_the_button(console):
    """An order raised here is an ordinary order in every respect except one:
    who asked for it. That one has to be recorded."""
    app = console.app
    key = _hidden(_preview(console).text, "idempotency_key")
    console.post(f"/ui/connections/{CONNECTION}/payment",
                 data={**GOOD, "idempotency_key": key})

    accepted = app.state.audit.recent(limit=50,
                                      action_prefix="payment.accepted")
    assert accepted, "no payment.accepted row"
    assert accepted[0]["actor_id"] == "tester"


# --- the gate -----------------------------------------------------------------

def test_a_connection_the_bank_has_not_activated_offers_no_button(settings):
    """An absent button is already the explanation; a refusal is one the
    operator has to read to understand."""
    app = create_app(settings)
    with TestClient(app, headers=dev_credentials()) as client:
        ConnectionRegistry(app.state.engine).register(
            CONNECTION, host_id="UBSHOST", partner_id="PARTNER1",
            user_id="USER1", host_url="https://ebics.example.test/")

        page = client.get(f"/ui/connections/{CONNECTION}")

        assert f"/connections/{CONNECTION}/payment" not in page.text


def test_the_route_refuses_it_too_and_not_only_the_button(settings):
    """Hiding a control is a courtesy. The route is the control, and it is the
    one this asserts."""
    app = create_app(settings)
    with TestClient(app, headers=dev_credentials()) as client:
        ConnectionRegistry(app.state.engine).register(
            CONNECTION, host_id="UBSHOST", partner_id="PARTNER1",
            user_id="USER1", host_url="https://ebics.example.test/")

        refused = client.post(
            f"/ui/connections/{CONNECTION}/payment/preview", data=GOOD)

        assert refused.status_code == 409
        assert not _orders(app)


def test_a_member_without_a_grant_is_told_nothing_about_this_bank(console):
    """`requires_on`, not `requires`: the privilege that matters is
    `payments:submit` **at this bank**.

    A `404` rather than a `403`, which is the model working as designed: a
    member who was never granted this connection learns nothing from the
    refusal, not even that the connection exists. Asserting the code here
    rather than merely that it failed is the point -- a `403` would be an
    information leak that still looked like a passing test.
    """
    viewer = dev_credentials(subject="viewer-only", roles="member")

    for response in (
        console.get(f"/ui/connections/{CONNECTION}/payment", headers=viewer),
        console.post(f"/ui/connections/{CONNECTION}/payment/preview",
                     data=GOOD, headers=viewer),
        console.post(f"/ui/connections/{CONNECTION}/payment",
                     data=GOOD, headers=viewer),
    ):
        assert response.status_code == 404, response.text
    assert _orders(console.app) == []


# --- the debit account, offered rather than typed ------------------------------

def _htd(console):
    """Store an `HTD` for this connection, as the worker would have."""
    from painfree.catalogue import Catalogue

    from tests.test_service_catalogue import HTD
    Catalogue(console.app.state.engine).record(
        CONNECTION, "HTD", document=HTD)


def test_the_debit_account_is_offered_from_what_the_bank_published(console):
    """`HTD` already knows which accounts this subscriber may draw on, so the
    form stops asking somebody to retype an IBAN it has on file."""
    _htd(console)

    page = console.get(f"/ui/connections/{CONNECTION}/payment")

    assert 'list="debtor_accounts"' in page.text
    assert "<datalist" in page.text
    assert "CH5604835012345678009" in page.text
    # The label is what makes it pickable rather than a wall of digits.
    assert "Kontokorrent" in page.text


def test_without_an_htd_the_field_stays_typable_and_says_why(console):
    """A datalist, not a select, and the reason is on the page.

    `AccountInfo` is optional in the schema and a catalogue goes stale, so a
    closed list would refuse a payment the bank would have taken. An empty
    dropdown with no explanation would read as *this connection has no
    accounts*, which is not what it means.
    """
    page = console.get(f"/ui/connections/{CONNECTION}/payment")

    assert "<datalist" not in page.text
    assert 'name="debtor_iban"' in page.text
    assert "has not been asked" in page.text
    assert f"/connections/{CONNECTION}/catalogue" in page.text


def test_an_account_the_bank_did_not_publish_is_noted_and_not_refused(console):
    """Worth a second look, not a reason to stop: the published list can be
    incomplete or out of date, and the bank is the one that decides."""
    _htd(console)

    page = _preview(console, debtor_iban="CH4821966000009613388")

    assert page.status_code == 200, "a payment was refused on local evidence"
    assert "not in the bank's list" in page.text


def test_an_account_the_bank_published_is_not_flagged(console):
    _htd(console)

    page = _preview(console)

    assert page.status_code == 200
    assert "not in the bank's list" not in page.text


def test_nothing_is_flagged_when_the_bank_was_never_asked(console):
    """`None`, not `False`. Warning here would be inventing evidence."""
    page = _preview(console)

    assert page.status_code == 200
    assert "not in the bank's list" not in page.text
