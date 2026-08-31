"""`POST /v1/connections/{id}/payments`, against a running application.

Driven through the real ASGI stack, because the parts of the contract that
matter most live in the middleware and the exception handlers rather than in
the route: the `202` that does not mean the bank has seen it, the error
envelope with the request id in the body, and the rule that a validation
failure names the failing rule instead of saying "invalid".

The log stream is asserted the same way ``tests/test_service_app.py`` asserts
it -- against captured stdout -- because the log-diagnosability rule's claim is
about what an operator can reconstruct from `docker logs`, and the claim this file adds is
that a payment is logged by `order_id` and never by content.
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import update

from conftest import (DEBTOR_IBAN, PLAIN_IBAN, QRR_REFERENCE, QR_IBAN,
                      SCOR_REFERENCE, dev_credentials, payment_body,
                      scor_transfer, transfer)
from painfree import db, ebics3
from painfree.api import IDEMPOTENCY_HEADER, REPLAYED_HEADER
from painfree.app import REQUEST_ID_HEADER, create_app
from painfree.connections import ConnectionRegistry
from painfree.schema import bank_connection

CONNECTION = "acme-ubs"
PATH = f"/v1/connections/{CONNECTION}/payments"
KEY = "caller-idem-0001"


@pytest.fixture
def client(settings, capsys):
    app = create_app(settings)
    with TestClient(app, headers=dev_credentials()) as client:
        engine = app.state.engine
        ConnectionRegistry(engine).register(
            CONNECTION, host_id="UBSHOST", partner_id="PARTNER1",
            user_id="USER1", host_url="https://ebics.example.test/")
        with engine.begin() as connection:
            connection.execute(
                update(bank_connection)
                .where(bank_connection.c.connection_id == CONNECTION)
                .values(key_state=ebics3.KeyState.READY.value))
        yield client


def emitted(capsys) -> list[dict]:
    return [json.loads(line) for line
            in capsys.readouterr().out.splitlines() if line.strip()]


def post(client, body=None, key=KEY, **kwargs):
    headers = {IDEMPOTENCY_HEADER: key} if key is not None else {}
    headers.update(kwargs.pop("headers", {}))
    return client.post(PATH, json=body if body is not None else payment_body(),
                       headers=headers, **kwargs)


# --- accepting --------------------------------------------------------------

def test_a_qr_payment_is_accepted_for_processing(client):
    response = post(client)
    assert response.status_code == 202, response.text
    body = response.json()
    assert body["state"] == "accepted"
    assert body["order_id"].startswith("ord_")
    assert body["msg_id"].startswith("PF")
    assert body["message_type"] == "pain.001.001.09"
    assert body["transactions"] == 1
    assert body["control_sum"] == "3949.75"
    assert response.headers[REPLAYED_HEADER] == "false"


def test_an_iso_11649_payment_to_a_plain_iban_is_accepted(client):
    response = post(client, payment_body(transactions=[scor_transfer()]))
    assert response.status_code == 202, response.text


def test_202_does_not_claim_the_bank_has_seen_it(client):
    """Accepted is not sent. The response has no bank order id and no return
    code."""
    body = post(client).json()
    assert body["state"] == "accepted"
    assert "bank_order_id" not in body
    assert "return_code" not in body


def test_the_order_can_be_read_back(client):
    order_id = post(client).json()["order_id"]
    response = client.get(f"/v1/orders/{order_id}")
    assert response.status_code == 200
    assert response.json()["order_id"] == order_id


def test_an_unknown_order_is_the_error_envelope(client):
    response = client.get("/v1/orders/ord_nope")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "not_found"


def test_the_response_never_carries_the_document(client):
    body = post(client).json()
    rendered = json.dumps(body)
    assert "document" not in body
    for marker in ("CstmrCdtTrfInitn", "IBAN", QR_IBAN, "Robert Schneider AG"):
        assert marker not in rendered


# --- rejecting, with the rule named -----------------------------------------

def test_a_qr_reference_on_a_plain_iban_is_422_naming_the_rule(client):
    response = post(client, payment_body(transactions=[
        transfer(creditor_iban=PLAIN_IBAN,
                 reference={"type": "QRR", "reference": QRR_REFERENCE})]))
    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "validation_failed"
    assert error["detail"]["failures"] == [{
        "location": "transactions.0.creditor_iban",
        "rule": "qrr.requires_qr_iban",
        "message": error["detail"]["failures"][0]["message"]}]
    assert "QR-IBAN" in error["detail"]["failures"][0]["message"]


def test_an_iso_reference_on_a_qr_iban_is_422(client):
    response = post(client, payment_body(transactions=[
        transfer(creditor_iban=QR_IBAN,
                 reference={"type": "SCOR", "reference": SCOR_REFERENCE})]))
    assert response.status_code == 422
    assert {failure["rule"] for failure
            in response.json()["error"]["detail"]["failures"]} == {
                "scor.forbidden_with_qr_iban"}


def test_a_broken_iban_is_422_naming_the_field(client):
    response = post(client, payment_body(debtor_iban="CH5604835012345678000"))
    failure = response.json()["error"]["detail"]["failures"][0]
    assert response.status_code == 422
    assert failure["location"] == "debtor_iban"
    assert failure["rule"] == "iban.checksum"


def test_a_malformed_body_is_422_from_the_model_with_the_field_named(client):
    body = payment_body()
    body["transactions"][0].pop("amount")
    response = post(client, body)
    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "validation_failed"
    assert any("amount" in failure["location"]
               for failure in error["detail"]["failures"])


def test_an_unknown_field_is_refused_rather_than_ignored(client):
    """A caller that misspells a field must not have it silently dropped."""
    response = post(client, payment_body(reference="oops"))
    assert response.status_code == 422


def test_an_unknown_connection_is_404(client):
    response = client.post("/v1/connections/nobody/payments",
                           json=payment_body(),
                           headers={IDEMPOTENCY_HEADER: KEY})
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "not_found"


def test_every_error_body_carries_the_request_id(client):
    response = post(client, payment_body(debtor_iban="CH5604835012345678000"),
                    headers={REQUEST_ID_HEADER: "caller-abc-123"})
    assert response.json()["error"]["request_id"] == "caller-abc-123"
    assert response.headers[REQUEST_ID_HEADER] == "caller-abc-123"


# --- idempotency ------------------------------------------------------------

def test_the_header_is_required(client):
    response = post(client, key=None)
    assert response.status_code == 422
    assert response.json()["error"]["detail"]["failures"][0]["rule"] == \
        "idempotency_key.missing"


def test_a_retry_returns_the_original_order_and_says_it_replayed(client):
    first = post(client).json()
    response = post(client)
    assert response.status_code == 202
    assert response.headers[REPLAYED_HEADER] == "true"
    assert response.json() == first


def test_the_same_key_with_a_changed_payload_is_409(client):
    post(client)
    response = post(client, payment_body(transactions=[transfer(amount="1.00")]))
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "conflict"


# --- what the log stream is allowed to contain ------------------------------

def test_a_payment_is_logged_by_order_id_and_never_by_content(client, capsys):
    body = post(client, headers={REQUEST_ID_HEADER: "caller-abc-123"}).json()
    stream = capsys.readouterr().out
    lines = [json.loads(line) for line in stream.splitlines() if line.strip()]

    accepted = [line for line in lines if line["event"] == "payment.accepted"]
    assert accepted, "the acceptance was not logged"
    assert accepted[0]["order_id"] == body["order_id"]
    assert accepted[0]["request_id"] == "caller-abc-123"
    assert accepted[0]["connection_id"] == CONNECTION
    assert accepted[0]["idempotency_key"] == KEY

    # Not one account number, name, reference or amount anywhere in the stream.
    for secret in (QR_IBAN, DEBTOR_IBAN, QRR_REFERENCE, "Robert Schneider AG",
                   "3949.75", "MUSTER AG"):
        assert secret not in stream, f"{secret!r} reached the log stream"
    assert b"CstmrCdtTrfInitn".decode() not in stream


def test_the_whole_order_is_greppable_by_one_id(client, capsys):
    """The actual claim: one id reconstructs the work end to end."""
    order_id = post(client).json()["order_id"]
    lines = [json.loads(line) for line
             in capsys.readouterr().out.splitlines() if line.strip()]
    tagged = {line["event"] for line in lines if line.get("order_id") == order_id}
    assert {"payment.accepted", "audit.recorded"} <= tagged


def test_a_rejection_is_logged_with_its_code_and_no_payment_content(client, capsys):
    post(client, payment_body(debtor_iban="CH5604835012345678000"))
    lines = [json.loads(line) for line
             in capsys.readouterr().out.splitlines() if line.strip()]
    rejected = [line for line in lines if line["event"] == "request.rejected"]
    assert rejected and rejected[0]["code"] == "validation_failed"
    assert rejected[0]["status"] == 422
