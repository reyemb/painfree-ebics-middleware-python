"""Unit tests for the return-code table and what a response's codes mean.

The differential gate proves the half another implementation can speak to:
`ebics-client-php` names 65 codes through its own exception mapping and the two
tables are diffed code by code, and one synthesised H005 response per code asks
both implementations whether they would refuse it. Four codes where they
disagree on purpose are recorded there with the reason.

What is pinned here is what no reference exposes -- the family, the
disposition, the severity, and the exception the engine actually raises -- and
the shapes a bank sends that the corpus does not contain: a code in the H005
namespace, a code in a document with no namespace at all, an unknown code, and
a download that finishes because there was nothing to download.
"""

from __future__ import annotations

import pytest

from painfree import ebics3
from painfree.ebics3.returncodes import Disposition, Family, Severity

TRANSACTION_ID = "0F1E2D3C4B5A69788796A5B4C3D2E1F0"


def document(header="000000", body="000000", *, namespace=ebics3.EBICS_NAMESPACE,
             report="[TEST] fixture", phase="Initialisation"):
    """One ``ebicsResponse`` carrying two return codes and little else.

    ``namespace=None`` builds the same document with no namespace at all --
    banks do send that, the pooled corpus has one, and a parser that keys off
    the namespace rather than off local names stops reading it.
    """
    xmlns = f' xmlns="{namespace}"' if namespace else ""
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<ebicsResponse{xmlns} Version="H005" Revision="1">
  <header authenticate="true">
    <static><TransactionID>{TRANSACTION_ID}</TransactionID></static>
    <mutable>
      <TransactionPhase>{phase}</TransactionPhase>
      <ReturnCode>{header}</ReturnCode>
      <ReportText>{report}</ReportText>
    </mutable>
  </header>
  <body>{f"<ReturnCode>{body}</ReturnCode>" if body else ""}</body>
</ebicsResponse>
""".encode()


# --- the table -------------------------------------------------------------

def test_every_entry_is_six_digits_with_a_unique_ebics_name():
    names = [entry.name for entry in ebics3.RETURN_CODES.values()]
    assert len(names) == len(set(names))
    for code, entry in ebics3.RETURN_CODES.items():
        assert entry.code == code
        assert len(code) == 6 and code.isdigit()
        assert entry.name.startswith("EBICS_")


def test_exactly_one_code_is_success_and_it_is_the_one_everybody_knows():
    ok = [entry for entry in ebics3.RETURN_CODES.values() if entry.is_ok]
    assert [entry.code for entry in ok] == ["000000"]
    assert ok[0].name == "EBICS_OK"
    assert ok[0].family is Family.SUCCESS


@pytest.mark.parametrize("code, disposition", [
    ("000000", Disposition.SUCCESS),
    ("011000", Disposition.COMPLETED),   # the download is finished
    ("011001", Disposition.COMPLETED),   # ... and finished unacknowledged
    ("090005", Disposition.COMPLETED),   # there was nothing to download
    ("031001", Disposition.NOTICE),      # the order went ahead regardless
    ("061101", Disposition.RECOVERABLE),
    ("061099", Disposition.RETRYABLE),
    ("091116", Disposition.TERMINAL),
])
def test_the_codes_a_client_gets_wrong(code, disposition):
    assert ebics3.lookup(code).disposition is disposition


def test_only_a_transient_bank_side_condition_is_retryable():
    """Retryable is a promise: the *same* request may pass later, unchanged.

    Kept deliberately narrow. A refused order is not retryable however
    temporary its cause looks, because "retry" for an upload is a second
    payment and the decision to make one belongs upstairs.
    """
    retryable = {entry.code for entry in ebics3.RETURN_CODES.values()
                 if entry.is_retryable}
    assert retryable == {"061099", "091119"}


def test_severity_follows_from_the_disposition():
    assert ebics3.lookup("000000").severity is Severity.OK
    assert ebics3.lookup("011000").severity is Severity.INFO
    assert ebics3.lookup("061101").severity is Severity.WARNING
    assert ebics3.lookup("061001").severity is Severity.ERROR


def test_an_unknown_code_is_terminal_rather_than_a_parse_error():
    """Banks add codes. Guessing an unrecognised refusal is safe is the costly guess."""
    unknown = ebics3.lookup("099999")
    assert not unknown.known and unknown.name is None
    assert unknown.family is Family.UNKNOWN
    assert unknown.is_terminal and unknown.raises
    assert str(unknown) == "099999"


def test_an_absent_code_is_not_a_code():
    assert ebics3.lookup(None) is None
    assert ebics3.lookup("   ") is None


# --- classifying a response ------------------------------------------------

def test_the_two_codes_are_kept_apart_and_the_technical_one_decides():
    status = ebics3.parse_response(document(header="061001", body="000000")).status
    assert status.technical.name == "EBICS_AUTHENTICATION_FAILED"
    assert status.business.name == "EBICS_OK"
    assert status.decisive is status.technical


def test_a_healthy_header_leaves_the_order_to_answer_for_itself():
    """The failure this separation exists for: the protocol worked, the order did not."""
    status = ebics3.parse_response(document(header="000000", body="091116")).status
    assert status.technical.is_ok
    assert status.decisive.name == "EBICS_PROCESSING_ERROR"
    assert not status.ok


def test_a_body_refusal_is_not_described_by_the_header_s_text():
    """`report_text` belongs to the header code, and only to it.

    An upload can pass the header and fail the body -- a refused transfer phase
    is exactly that shape -- and the header then reads `[EBICS_OK] OK`, because
    the header was fine. Reporting that sentence beside the body's refusal put
    this on the order page, in the API response and in the webhook:

        {"order_state": "rejected", "return_code": "091301",
         "return_code_name": "EBICS_SIGNATURE_VERIFICATION_FAILED",
         "report_text": "[EBICS_OK] OK"}

    A rejected payment described as OK. Two structured fields right and the one
    sentence a human actually reads wrong, which is the worst of the three
    arrangements: an operator who trusts the prose concludes it went through.

    H005 gives the body a `ReturnCode` and no `ReportText` of its own, so there
    is nothing truer to substitute. `None` is the honest answer, and the code
    name is what says what happened.
    """
    status = ebics3.parse_response(
        document(header="000000", body="091301",
                 report="[EBICS_OK] OK")).status

    assert status.decisive.name == "EBICS_SIGNATURE_VERIFICATION_FAILED"
    assert status.report_text == "[EBICS_OK] OK", "the header's text is the header's"
    assert status.decisive_report_text is None

    with pytest.raises(ebics3.BankRefusedError) as refused:
        status.raise_for_status()
    assert refused.value.report_text is None
    assert "[EBICS_OK] OK" not in str(refused.value)
    assert "EBICS_SIGNATURE_VERIFICATION_FAILED" in str(refused.value)


def test_a_header_refusal_still_carries_its_own_text():
    """The other half of the rule: when the header is what failed, its sentence
    describes the failure and is the most useful thing in the refusal."""
    status = ebics3.parse_response(
        document(header="091010", body="000000",
                 report="Auftragsart nicht bekannt")).status

    assert status.decisive_report_text == "Auftragsart nicht bekannt"
    with pytest.raises(ebics3.BankRefusedError) as refused:
        status.raise_for_status()
    assert refused.value.report_text == "Auftragsart nicht bekannt"


def test_a_response_with_only_a_technical_code_still_classifies():
    status = ebics3.parse_response(document(header="061001", body="")).status
    assert status.business is None
    assert status.decisive.name == "EBICS_AUTHENTICATION_FAILED"


@pytest.mark.parametrize("namespace", [
    ebics3.EBICS_NAMESPACE,      # H005
    "urn:org:ebics:H004",        # what most of the pooled corpus is
    None,                        # and what one fixture in it is
])
def test_classification_does_not_depend_on_the_namespace(namespace):
    status = ebics3.parse_response(
        document(header="000000", body="091116", namespace=namespace)).status
    assert status.decisive.name == "EBICS_PROCESSING_ERROR"


def test_the_report_text_survives_into_the_status_and_the_exception():
    """The bank's own words are the first thing an operator reads."""
    status = ebics3.parse_response(
        document(header="091303", report="[EBICS_AMOUNT_CHECK_FAILED] limit 5000")
    ).status
    assert status.report_text == "[EBICS_AMOUNT_CHECK_FAILED] limit 5000"
    with pytest.raises(ebics3.BankRefusedError) as raised:
        status.raise_for_status()
    assert raised.value.report_text == "[EBICS_AMOUNT_CHECK_FAILED] limit 5000"
    assert "limit 5000" in str(raised.value)


def test_raising_carries_the_code_the_name_and_what_to_do_next():
    status = ebics3.parse_response(document(header="061099")).status
    with pytest.raises(ebics3.BankRefusedError) as raised:
        status.raise_for_status()
    assert raised.value.return_code == "061099"
    assert raised.value.name == "EBICS_INTERNAL_ERROR"
    assert raised.value.retryable and not raised.value.terminal
    # One class to catch for "the transaction cannot continue", whichever way.
    assert isinstance(raised.value, ebics3.TransactionError)


@pytest.mark.parametrize("code", ["000000", "011000", "011001", "031001",
                                  "011301", "061101", "090005"])
def test_the_codes_that_are_not_refusals_do_not_raise(code):
    ebics3.parse_response(document(header=code)).status.raise_for_status()


def test_recovery_is_visible_without_being_an_error():
    status = ebics3.parse_response(document(header="061101")).status
    assert status.needs_recovery and status.ok
    assert not status.ends_transaction


# --- what the transaction does with it -------------------------------------

def test_a_download_with_nothing_to_download_ends_instead_of_raising():
    """``090005`` on a scheduled statement download is a Sunday, not an incident."""
    transaction = ebics3.DownloadTransaction(
        ebics3.RequestContext(host_id="HOST0001", partner_id="P", user_id="U"),
        ebics3.EbicsKey.generate("X002"))
    transaction.feed(document(header="090005", body="000000"))
    assert transaction.phase is ebics3.Phase.DONE
    assert transaction.segments == []
    assert transaction.next_request() is None


def test_a_refused_step_names_the_phase_it_was_refused_in():
    transaction = ebics3.DownloadTransaction(
        ebics3.RequestContext(host_id="HOST0001", partner_id="P", user_id="U"),
        ebics3.EbicsKey.generate("X002"))
    with pytest.raises(ebics3.BankRefusedError) as raised:
        transaction.feed(document(header="091011"))
    assert "Initialisation" in str(raised.value)
    assert raised.value.name == "EBICS_INVALID_HOST_ID"
