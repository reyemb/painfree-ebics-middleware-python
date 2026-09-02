"""Asking a bank what it publishes, over a socket, and what the answer is for.

`HAA`, `HTD` and `HPD` are ordinary three-phase downloads carrying no BTF, so
this is driven against the same stub bank the statement downloads use: real
segments, real encryption to the subscriber's own `E002` half, a real receipt.
What is different is only the opening request and where the answer lands.

The claims:

* the round trip works and the document is stored **verbatim**, because the
  bank's own bytes are the authority for what it accepts and this service's
  reading of them is not;
* the parse is a projection kept beside the document, and a document that
  cannot be read still gets stored -- losing the evidence because the reader
  was surprised would be the worst possible response to a bank changing
  something;
* the comparison the whole feature exists for distinguishes three states, not
  two: published, not published, and *not asked*. Drawing the third as a
  refusal would tell an operator their payment will bounce on no evidence.
"""

from __future__ import annotations

import pytest

from conftest import (BANK_CONNECTION_ID, download_script, phases_in,
                      serving_bank)
from painfree import ebics3
from painfree.catalogue import Catalogue
from painfree.initialiser import KeyWorker
from painfree.keyjobs import JobState, KeyAction, KeyJobStore
from painfree.keyring import Keyring
from painfree.schema import bank_connection

HTD = b"""<?xml version="1.0" encoding="UTF-8"?>
<HTDResponseOrderData xmlns="urn:org:ebics:H005">
  <PartnerInfo>
    <AddressInfo><Name>Muster AG</Name></AddressInfo>
    <BankInfo><HostID>SGKB</HostID></BankInfo>
    <AccountInfo ID="A1" Description="Kontokorrent" Currency="CHF">
      <AccountNumber international="true">CH5604835012345678009</AccountNumber>
    </AccountInfo>
    <OrderInfo><AdminOrderType>BTU</AdminOrderType>
      <Service><ServiceName>MCT</ServiceName><Scope>CH</Scope>
        <MsgName version="09">pain.001</MsgName></Service>
      <Description>Zahlungseinlieferung (CH)</Description>
      <NumSigRequired>1</NumSigRequired></OrderInfo>
    <OrderInfo><AdminOrderType>BTD</AdminOrderType>
      <Service><ServiceName>EOP</ServiceName><Scope>CH</Scope>
        <Container containerType="ZIP"/>
        <MsgName version="08">camt.053</MsgName></Service>
      <Description>Kontoauszug</Description></OrderInfo>
  </PartnerInfo>
  <UserInfo><UserID>U1</UserID></UserInfo>
</HTDResponseOrderData>"""

HPD = b"""<?xml version="1.0" encoding="UTF-8"?>
<HPDResponseOrderData xmlns="urn:org:ebics:H005">
  <AccessParams><HostID>SGKB</HostID></AccessParams>
  <ProtocolParams>
    <Version>
      <Protocol><Version>H005</Version></Protocol>
      <Authentication><Version>X002</Version></Authentication>
      <Encryption><Version>E002</Version></Encryption>
      <Signature><Version>A006</Version></Signature>
    </Version>
    <Recovery supported="true"/>
  </ProtocolParams>
</HPDResponseOrderData>"""


@pytest.fixture
def bank(prepared_bank, custody_settings):
    engine, connection, bank_keys = prepared_bank
    worker = KeyWorker(engine, custody_settings.custody_key(),
                       worker_id="test-catalogue", timeout=10)
    subscriber = Keyring(engine).public_key(BANK_CONNECTION_ID, "E002")
    return engine, connection, bank_keys, subscriber, worker


def _point_at(engine, host_url: str) -> None:
    with engine.begin() as connection:
        connection.execute(bank_connection.update()
                           .where(bank_connection.c.connection_id
                                  == BANK_CONNECTION_ID)
                           .values(host_url=host_url))


def _fetch(engine, worker, bank_keys, subscriber, payload: bytes,
           order_type: str = "HTD", seen=None):
    """Ask for one catalogue and let the worker run it against the stub."""
    seen = [] if seen is None else seen
    script = download_script(bank_keys.authentication, subscriber, payload, seen)
    with serving_bank(script) as url:
        _point_at(engine, url)
        job = KeyJobStore(engine).request(
            BANK_CONNECTION_ID, KeyAction.fetch_catalogue,
            key_state=ebics3.KeyState.READY,
            params={"order_type": order_type})
        worker.run_once()
    return KeyJobStore(engine).get(job.job_id), seen


# --- the round trip -----------------------------------------------------------

def test_htd_is_fetched_decrypted_and_stored_verbatim(bank):
    """End to end: the worker opens the response, and the bytes are kept.

    Stored verbatim rather than only as a parse, because what the bank
    published is the authority for what it will accept and this service's
    reading of it is an opinion.
    """
    engine, _connection, bank_keys, subscriber, worker = bank

    job, seen = _fetch(engine, worker, bank_keys, subscriber, HTD)

    assert job.state is JobState.DONE, job.last_error
    assert job.result["order_type"] == "HTD"
    assert job.result["stored"] is True
    assert job.result["readable"] is True

    entry = Catalogue(engine).get(BANK_CONNECTION_ID, "HTD")
    assert entry is not None
    assert entry.document == HTD, "the bank's own bytes were not kept"
    assert entry.summary["user_id"] == "U1"


def test_the_exchange_is_a_real_download_that_ends_in_a_receipt(bank):
    """Not a single request: initialisation, transfer, then the receipt the
    bank needs before it stops offering the data."""
    engine, _connection, bank_keys, subscriber, worker = bank

    job, seen = _fetch(engine, worker, bank_keys, subscriber, HTD)

    assert job.state is JobState.DONE
    assert phases_in(seen)[0] == "Initialisation"
    assert phases_in(seen)[-1] == "Receipt"
    assert job.result["acknowledged"] is True


def test_the_opening_request_carries_the_admin_order_type_and_no_btf(bank):
    """What makes this an HTD rather than a statement download."""
    engine, _connection, bank_keys, subscriber, worker = bank

    _job, seen = _fetch(engine, worker, bank_keys, subscriber, HTD)

    opening = seen[0].decode("utf-8")
    assert "<AdminOrderType>HTD</AdminOrderType>" in opening
    assert "StandardOrderParams" in opening
    assert "BTDOrderParams" not in opening


def test_hpd_lands_under_its_own_order_type(bank):
    """Three catalogues, three rows, one connection."""
    engine, _connection, bank_keys, subscriber, worker = bank

    _fetch(engine, worker, bank_keys, subscriber, HTD, "HTD")
    _fetch(engine, worker, bank_keys, subscriber, HPD, "HPD")

    stored = Catalogue(engine).all(BANK_CONNECTION_ID)
    assert sorted(stored) == ["HPD", "HTD"]
    assert stored["HPD"].summary["authentication_versions"] == ["X002"]


def test_asking_again_replaces_rather_than_accumulates(bank):
    """A catalogue is a current fact. Two rows for one bank would mean the page
    has to choose which is true, and it has no way to."""
    engine, _connection, bank_keys, subscriber, worker = bank

    _fetch(engine, worker, bank_keys, subscriber, HTD)
    changed = HTD.replace(b"<UserID>U1</UserID>", b"<UserID>U2</UserID>")
    _fetch(engine, worker, bank_keys, subscriber, changed)

    entry = Catalogue(engine).get(BANK_CONNECTION_ID, "HTD")
    assert entry.summary["user_id"] == "U2"


# --- what it refuses, and what it keeps anyway --------------------------------

def test_an_order_type_this_service_does_not_fetch_is_refused_by_name(bank):
    engine, _connection, bank_keys, subscriber, worker = bank
    seen: list[bytes] = []
    script = download_script(bank_keys.authentication, subscriber, HTD, seen)

    with serving_bank(script) as url:
        _point_at(engine, url)
        job = KeyJobStore(engine).request(
            BANK_CONNECTION_ID, KeyAction.fetch_catalogue,
            key_state=ebics3.KeyState.READY, params={"order_type": "HKD"})
        worker.run_once()

    finished = KeyJobStore(engine).get(job.job_id)
    assert finished.state is JobState.FAILED
    assert "HTD" in (finished.last_error or ""), finished.last_error
    assert seen == [], "a refused order type still went to the bank"


def test_a_document_this_service_cannot_read_is_still_kept(bank):
    """The case where having the bytes matters most. A bank that changes
    something must not cost us the evidence of what it sent."""
    engine, _connection, bank_keys, subscriber, worker = bank

    job, _seen = _fetch(engine, worker, bank_keys, subscriber,
                        b"<Surprise xmlns='urn:org:ebics:H005'/>")

    assert job.state is JobState.DONE, job.last_error
    assert job.result["readable"] is False
    entry = Catalogue(engine).get(BANK_CONNECTION_ID, "HTD")
    assert entry.document == b"<Surprise xmlns='urn:org:ebics:H005'/>"
    assert entry.summary is None


# --- the comparison the feature exists for ------------------------------------

def test_a_configured_scheme_is_checked_against_what_the_bank_published(bank):
    """The whole point. `MCT/CH` is in this bank's catalogue and `MCT+INST/CH`
    is not, which is the St.Galler Kantonalbank case exactly -- and it is
    answered here rather than by a signed upload coming back `091112`."""
    engine, _connection, bank_keys, subscriber, worker = bank
    _fetch(engine, worker, bank_keys, subscriber, HTD)
    store = Catalogue(engine)

    normal = ebics3.Service(name="MCT", msg_name="pain.001", scope="CH")
    instant = ebics3.Service(name="MCT", msg_name="pain.001", scope="CH",
                             option="INST")

    assert store.offers(BANK_CONNECTION_ID, normal) is True
    assert store.offers(BANK_CONNECTION_ID, instant) is False


def test_a_bank_that_was_never_asked_is_not_a_bank_that_said_no(bank):
    """`None`, not `False`. A console drawing them the same way would tell
    somebody their payment will be refused on the strength of no evidence."""
    engine, _connection, _bank_keys, _subscriber, _worker = bank

    answer = Catalogue(engine).offers(
        BANK_CONNECTION_ID,
        ebics3.Service(name="MCT", msg_name="pain.001", scope="CH"))

    assert answer is None
