"""The download worker, driven against a bank over a real socket.

Every test here points a `HostURL` at a stub server and lets the worker do the
whole thing: build a `BTD`, exchange over HTTP, verify the bank's signature with
the `X002` key the keyring holds, collect the segments, unwrap the transaction
key with the sealed `E002` private half, reassemble, decrypt, unpack the ZIP,
normalise, store, and acknowledge. Nothing is mocked out; the transport is a
socket and the crypto is real.

The four things this file exists to prove:

* a **segmented** download is reassembled in order and decrypts to the bytes the
  bank encrypted -- one segment at a time is where implementations diverge;
* the **receipt** is actually sent, and after data is stored rather than before;
* `090005` is an ordinary empty result -- no exception, no alert, no retry;
* a re-served statement produces no second row.
"""

from __future__ import annotations

import datetime as _dt
import logging

import pytest

from painfree import ebics3
from painfree.config import Role, load_settings
from painfree.custody import CustodyViolation, request_path
from painfree.downloader import DownloadWorker, build_downloader
from painfree.keyring import Keyring
from painfree.schedule import COMPLETE, EMPTY, FAILED, REFUSED, DownloadSchedules
from painfree.statements import StatementStore
from conftest import (BANK_CONNECTION_ID, CUSTODY_SECRET, bank_response,
                            download_script, no_data_script, phases_in,
                            serving_bank, zipped)

STATEMENTS = {"service_name": "EOP", "scope": "CH", "container": "ZIP",
              "msg_name": "camt.053", "msg_version": "08"}


@pytest.fixture
def bank(prepared_bank, custody_settings):
    """The prepared connection, plus what a download stub needs to answer one."""
    engine, connection, bank_keys = prepared_bank
    worker = DownloadWorker(engine, custody_settings.custody_key(),
                            worker_id="test-downloader", timeout=10)
    subscriber_e002 = Keyring(engine).public_key(BANK_CONNECTION_ID, "E002")
    return engine, connection, bank_keys, subscriber_e002, worker


def schedule_for(worker, engine, host_url, **overrides):
    """Register one due schedule pointing at the stub, and re-read the connection."""
    from painfree.schema import bank_connection

    with engine.begin() as connection:
        connection.execute(bank_connection.update()
                           .where(bank_connection.c.connection_id == BANK_CONNECTION_ID)
                           .values(host_url=host_url))
    values = {**STATEMENTS, "cadence": _dt.timedelta(hours=1)}
    values.update(overrides)
    return worker.schedules.register(BANK_CONNECTION_ID, **values)


# --- the whole thing --------------------------------------------------------


def test_a_segmented_download_is_reassembled_decrypted_and_stored(bank):
    """The end-to-end case: several segments in, five statements out.

    The payload is a ZIP of the four fixtures, encrypted by the stub under a
    transaction key wrapped to the subscriber's `E002` public half, and cut
    into segments small enough that the transfer phase really runs. A worker
    that concatenated the segments in the wrong order, or decrypted them one by
    one, would fail at the first `zlib` call.
    """
    engine, _, bank_keys, subscriber_e002, worker = bank
    seen: list[bytes] = []
    payload = zipped("camt.052.001.08", "camt.053.001.08", "camt.054.001.09",
                     "pain.002.001.10")
    script = download_script(bank_keys.authentication, subscriber_e002, payload,
                             seen)
    assert len(script.segments) > 1, "the fixture must need several segments"

    with serving_bank(script) as url:
        schedule = schedule_for(worker, engine, url)
        result = worker.run_once()

    assert result is not None
    assert result.state == COMPLETE
    assert result.segments == len(script.segments)
    assert result.documents == 4            # the four members of the archive
    assert result.statements == 5           # camt.054 carries two notifications
    assert len(result.statement_ids) == 5
    assert result.acknowledged is True

    store = StatementStore(engine)
    stored = [store.get(one) for one in result.statement_ids]
    assert {one["message_type"] for one in stored} == {
        "camt.052.001.08", "camt.053.001.08", "camt.054.001.09",
        "pain.002.001.10"}
    assert all(one["run_id"] == result.run_id for one in stored)


def test_the_exchange_ends_with_a_receipt_the_bank_answered(bank):
    """Not a formality: an unacknowledged download is offered again for ever."""
    engine, _, bank_keys, subscriber_e002, worker = bank
    seen: list[bytes] = []
    script = download_script(bank_keys.authentication, subscriber_e002,
                             zipped("camt.053.001.08"), seen)

    with serving_bank(script) as url:
        schedule_for(worker, engine, url)
        result = worker.run_once()

    phases = phases_in(seen)
    assert phases[0] == "Initialisation"
    assert phases[-1] == "Receipt"
    assert phases.count("Receipt") == 1
    assert result.acknowledged is True

    # And the bank's own acknowledgement is what says so, recorded on the run.
    run, = worker.schedules.runs(result.schedule_id)
    assert run["acknowledged"] is True
    assert run["statements"] == 1
    assert run["documents"] == 1
    assert run["return_code"] == "011000"
    assert run["state"] == COMPLETE
    assert run["transaction_id"]


def test_the_receipt_carries_a_positive_receipt_code(bank):
    """`ReceiptCode` 0 -- the client telling the bank the data arrived."""
    from lxml import etree

    engine, _, bank_keys, subscriber_e002, worker = bank
    seen: list[bytes] = []
    script = download_script(bank_keys.authentication, subscriber_e002,
                             zipped("camt.053.001.08"), seen)
    with serving_bank(script) as url:
        schedule_for(worker, engine, url)
        worker.run_once()

    receipt = etree.fromstring(seen[-1])
    codes = receipt.xpath("//*[local-name()='ReceiptCode']")
    assert [node.text for node in codes] == [str(ebics3.RECEIPT_CODE_POSITIVE)]


def test_the_documents_are_stored_before_the_receipt_goes_out(bank):
    """The store-then-acknowledge ordering, asserted rather than
    asserted-about.

    The stub counts how many statements exist at the moment the receipt
    arrives. Acknowledging first and crashing loses the statement for good;
    storing first and crashing costs a re-serve the constraint absorbs.
    """
    engine, _, bank_keys, subscriber_e002, worker = bank
    seen: list[bytes] = []
    store = StatementStore(engine)
    stored_at_receipt: list[int] = []
    script = download_script(bank_keys.authentication, subscriber_e002,
                             zipped("camt.053.001.08"), seen)
    inner = script

    def counting(body: bytes) -> bytes:
        from conftest import _phase

        if _phase(body) == "Receipt":
            stored_at_receipt.append(store.count(BANK_CONNECTION_ID))
        return inner(body)

    with serving_bank(counting) as url:
        schedule_for(worker, engine, url)
        worker.run_once()

    assert stored_at_receipt == [1]


def test_re_serving_the_same_statement_produces_no_second_row(bank):
    """What happens when a receipt was lost: the bank offers it again.

    The download runs twice, the bank sends the same file twice, and the
    database has one statement -- because ingestion is idempotent and not
    because the second run was skipped.
    """
    engine, _, bank_keys, subscriber_e002, worker = bank
    seen: list[bytes] = []
    payload = zipped("camt.053.001.08")

    with serving_bank(download_script(bank_keys.authentication, subscriber_e002,
                                      payload, seen)) as url:
        schedule = schedule_for(worker, engine, url)
        first = worker.run_once()
        # Bring the schedule forward rather than waiting an hour.
        _make_due(engine, schedule.schedule_id)
        second = worker.run_once()

    assert first.statements == second.statements == 1
    assert first.duplicates == 0
    assert second.duplicates == 1
    assert StatementStore(engine).count(BANK_CONNECTION_ID) == 1
    assert [run["state"] for run in worker.schedules.runs(schedule.schedule_id)] \
        == [COMPLETE, COMPLETE]


def _make_due(engine, schedule_id: str) -> None:
    from painfree.schema import download_schedule

    with engine.begin() as connection:
        connection.execute(
            download_schedule.update()
            .where(download_schedule.c.schedule_id == schedule_id)
            .values(due_at=_dt.datetime.now(_dt.timezone.utc)
                    - _dt.timedelta(seconds=1)))


# --- nothing to download ----------------------------------------------------


def test_nothing_to_download_is_an_empty_result_and_not_an_error(bank, caplog):
    """`090005`, which is what a scheduled download finds most of the time.

    No exception, no error line, no retry: the run ends `empty`, the window
    moves on and the schedule goes back to its ordinary cadence.
    """
    engine, _, bank_keys, _, worker = bank
    seen: list[bytes] = []

    with caplog.at_level(logging.DEBUG, logger="painfree"):
        with serving_bank(no_data_script(bank_keys.authentication, seen)) as url:
            schedule = schedule_for(worker, engine, url, window_days=7)
            result = worker.run_once()

    assert result.state == EMPTY
    assert result.return_code == "090005"
    assert result.documents == 0
    assert len(seen) == 1, "an empty download has nothing to acknowledge"

    levels = {record.levelno for record in caplog.records}
    assert logging.ERROR not in levels and logging.WARNING not in levels
    assert any(record.getMessage() == "ebics.download_empty"
               for record in caplog.records)

    # The window still moved on, and the next run is a cadence away rather than
    # a retry five minutes from now.
    after = worker.schedules.get(schedule.schedule_id)
    assert after.fetched_through is not None
    assert after.last_error is None
    assert after.due_at - _dt.datetime.now(_dt.timezone.utc) > _dt.timedelta(minutes=30)


# --- refusals and failures --------------------------------------------------


def test_a_refused_download_records_the_banks_own_words(bank):
    engine, _, bank_keys, _, worker = bank

    def refusing(body: bytes) -> bytes:
        return bank_response(
            "Initialisation", signing_key=bank_keys.authentication,
            return_code="091112",
            report_text="[EBICS_INVALID_ORDER_PARAMS] the BTF EOP/camt.053 is "
                        "not in this bank's catalogue")

    with serving_bank(refusing) as url:
        schedule = schedule_for(worker, engine, url, window_days=7)
        result = worker.run_once()

    assert result.state == REFUSED
    assert result.return_code == "091112"
    assert "not in this bank's catalogue" in result.report_text
    # A refusal is not the bank answering for the window, so it stays put.
    assert worker.schedules.get(schedule.schedule_id).fetched_through is None


def test_a_bank_that_cannot_be_reached_fails_the_run_and_keeps_the_window(bank):
    engine, _, _, _, worker = bank
    with serving_bank(lambda body: b"") as url:
        pass  # the server is gone by the time the worker posts to it
    schedule = schedule_for(worker, engine, url, window_days=7)

    result = worker.run_once()

    assert result.state == FAILED
    after = worker.schedules.get(schedule.schedule_id)
    assert after.fetched_through is None
    assert after.last_error


def test_the_loop_survives_one_bad_schedule(bank):
    """A worker that exits on the first surprise stops every other download."""
    engine, _, _, _, worker = bank
    schedule_for(worker, engine, "http://127.0.0.1:1/ebics")
    assert worker.run_once().state == FAILED
    assert worker.run_once() is None       # nothing else is due


# --- the custody boundary ---------------------------------------------------


def test_a_download_cannot_be_driven_from_the_request_path(bank):
    """The same refusal the upload worker gets, for the same reason.

    A download unwraps the transaction key with our own `E002` private half, so
    it is a key operation and belongs on the worker's side of the custody
    boundary.
    """
    _, _, _, _, worker = bank
    with request_path():
        with pytest.raises(CustodyViolation):
            worker.run_once()


def test_an_api_process_cannot_build_a_download_worker(sqlite_url):
    settings = load_settings(database_url=sqlite_url, role=Role.api)
    assert settings.role.downloads is False
    with pytest.raises(ValueError):
        build_downloader(settings, engine=None)


def test_a_worker_process_can(sqlite_url):
    settings = load_settings(database_url=sqlite_url, role=Role.worker,
                             key_encryption_secret=CUSTODY_SECRET)
    assert settings.role.downloads is True
