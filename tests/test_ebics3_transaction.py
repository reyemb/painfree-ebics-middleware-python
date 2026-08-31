"""Unit tests for the three-phase transaction protocol.

The differential gate proves the parts another implementation can speak to: the
transfer and receipt requests are byte-identical to `ebics-client-php`, four
parsers agree on every field of every response in the pooled corpus, and the
engine is driven through a 22-segment download and upload over real HTTP with
the payload encrypted and the reassembled stream decrypted by the reference.

What is pinned here is what none of that can say: the cut points of
segmentation, the refusals that stop a malformed exchange before a bank sees
it, and the branches a well-behaved fixture server never takes -- a bank error,
a missing payload, a segment out of order, a forged signature, and the recovery
that rewinds a transfer.

Deliberately free of external key material: the module mints its own keys.
"""

from __future__ import annotations

import base64
import datetime

import pytest
from lxml import etree

from painfree import ebics3

SUBJECT = ebics3.subject_name("painfree.invalid", "painfree", "CH")

KEYS = {
    version: ebics3.EbicsKey.generate(
        version, subject=SUBJECT, serial_number=index + 1,
        not_valid_before=datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc))
    for index, version in enumerate(("A006", "E002", "X002"))
}

CONTEXT = ebics3.RequestContext(host_id="HOST0001", partner_id="PARTNER1",
                                user_id="USER0001")
SERVICE = ebics3.Service(name="EOP", scope="CH", container="ZIP",
                         msg_name="camt.053", msg_version="08")
TRANSACTION_ID = "0F1E2D3C4B5A69788796A5B4C3D2E1F0"

#: Will not compress, so it really does need several segments.
PAYLOAD = b"<Document>" + base64.b64encode(bytes(range(256)) * 4) + b"</Document>"


def secured():
    return ebics3.secure_order_data(
        PAYLOAD, signature_key=KEYS["A006"], bank_encryption_key=KEYS["E002"],
        partner_id="PARTNER1", user_id="USER0001", transaction_key=bytes(range(16)))


def response(phase="Initialisation", *, segment=None, last=False, num_segments=None,
             order_data=None, wrapped_key=None, order_id=None,
             return_code="000000", sign_with=None):
    """One ``ebicsResponse``, built here rather than taken from the corpus.

    The corpus has no H005 response at all and no complete segmented download
    in any version, which is why the differential harness builds its own too.
    """
    ns = ebics3.EBICS_NAMESPACE
    root = etree.Element(etree.QName(ns, "ebicsResponse"),
                         nsmap={None: ns, "ds": ebics3.XMLDSIG_NAMESPACE})
    root.set("Version", "H005")
    root.set("Revision", "1")

    def sub(parent, name, text=None, **attributes):
        node = etree.SubElement(parent, etree.QName(ns, name))
        node.text = text
        for key, value in attributes.items():
            node.set(key, value)
        return node

    header = sub(root, "header", authenticate="true")
    static = sub(header, "static")
    sub(static, "TransactionID", TRANSACTION_ID)
    if num_segments is not None:
        sub(static, "NumSegments", str(num_segments))
    mutable = sub(header, "mutable")
    sub(mutable, "TransactionPhase", phase)
    if segment is not None:
        sub(mutable, "SegmentNumber", str(segment),
            lastSegment="true" if last else "false")
    if order_id is not None:
        sub(mutable, "OrderID", order_id)
    sub(mutable, "ReturnCode", return_code)
    sub(mutable, "ReportText", "[TEST] fixture")

    body = sub(root, "body")
    if order_data is not None:
        transfer = sub(body, "DataTransfer")
        if wrapped_key is not None:
            encryption = sub(transfer, "DataEncryptionInfo", authenticate="true")
            sub(encryption, "TransactionKey",
                base64.b64encode(wrapped_key).decode())
        sub(transfer, "OrderData", order_data)
    sub(body, "ReturnCode", "000000", authenticate="true")

    if sign_with is not None:
        ebics3.build_auth_signature(root, sign_with.private_key, "X002")
    return root


# --- segmentation ----------------------------------------------------------

def test_segments_are_cut_from_the_encoded_stream_and_rejoin_exactly():
    encoded = secured().encrypt(PAYLOAD)
    segments = ebics3.split_segments(encoded, 64)
    assert len(segments) > 2
    assert all(len(segment) <= 64 for segment in segments)
    assert "".join(segments) == encoded


def test_a_single_segment_is_the_same_code_path():
    """Nothing branches on "does this fit": one segment is the degenerate case."""
    segments = ebics3.split_segments("QUJD")
    assert segments == ["QUJD"]
    assert ebics3.split_segments("") == [""]


def test_a_segment_size_that_would_split_a_base64_quantum_is_refused():
    with pytest.raises(ebics3.RequestError):
        ebics3.split_segments("QUJDRA==", 3)


def test_the_upload_announces_exactly_as_many_segments_as_it_will_send():
    transaction = ebics3.UploadTransaction.prepare(
        PAYLOAD, secured(), CONTEXT, authentication_key=KEYS["X002"],
        segment_size=64)
    request = transaction.initialisation_request(
        SERVICE, bank_authentication_key=KEYS["X002"],
        bank_encryption_key=KEYS["E002"], file_name="pain001.xml")
    declared = request.xpath("//*[local-name()='NumSegments']")[0].text
    assert int(declared) == transaction.num_segments == len(transaction.segments)


# --- the later phases as documents -----------------------------------------

def test_a_transfer_header_carries_the_transaction_and_nothing_else():
    """The static header is a schema choice, not a superset of the first one."""
    request = ebics3.build_transfer_request(
        CONTEXT, authentication_key=KEYS["X002"], transaction_id=TRANSACTION_ID,
        segment_number=2, last_segment=False)
    static = request.xpath("//*[local-name()='static']")[0]
    assert [etree.QName(node).localname for node in static] == [
        "HostID", "TransactionID"]
    mutable = request.xpath("//*[local-name()='mutable']")[0]
    assert [etree.QName(node).localname for node in mutable] == [
        "TransactionPhase", "SegmentNumber"]
    assert mutable[1].get("lastSegment") == "false"


def test_a_download_transfer_request_has_an_empty_body():
    request = ebics3.build_transfer_request(
        CONTEXT, authentication_key=KEYS["X002"], transaction_id=TRANSACTION_ID,
        segment_number=1, last_segment=True)
    assert len(request.xpath("//*[local-name()='body']")[0]) == 0


def test_the_receipt_body_is_part_of_what_is_signed():
    """`TransferReceipt` carries the marker, so the digest covers the code."""
    request = ebics3.build_receipt_request(
        CONTEXT, authentication_key=KEYS["X002"], transaction_id=TRANSACTION_ID)
    marked = [etree.QName(node).localname
              for node in ebics3.authenticated_nodes(request)]
    assert marked == ["header", "TransferReceipt"]
    assert request.xpath("//*[local-name()='ReceiptCode']")[0].text == "0"
    assert ebics3.verify_auth_signature(request, KEYS["X002"].public_key).ok


def test_a_negative_receipt_says_one():
    request = ebics3.build_receipt_request(
        CONTEXT, authentication_key=KEYS["X002"], transaction_id=TRANSACTION_ID,
        acknowledged=False)
    assert request.xpath("//*[local-name()='ReceiptCode']")[0].text == "1"


@pytest.mark.parametrize("transaction_id", ["", "ABCD", TRANSACTION_ID + "00", "z" * 32])
def test_a_transaction_id_that_is_not_sixteen_hex_bytes_is_refused(transaction_id):
    with pytest.raises(ebics3.RequestError):
        ebics3.build_receipt_request(CONTEXT, authentication_key=KEYS["X002"],
                                     transaction_id=transaction_id)


# --- reading a response ----------------------------------------------------

def test_the_two_return_codes_are_read_from_their_own_subtrees():
    """`//ReturnCode` would return whichever comes first, which is the header's."""
    parsed = ebics3.parse_response(etree.tostring(
        response(return_code="091101")))
    assert parsed.header_return_code == "091101"
    assert parsed.body_return_code == "000000"
    assert not parsed.ok


def test_a_finished_download_is_not_an_error():
    parsed = ebics3.parse_response(response(
        phase="Receipt", return_code=ebics3.EBICS_DOWNLOAD_POSTPROCESS_DONE))
    assert parsed.ok


def test_segment_metadata_and_payload_come_back_typed():
    parsed = ebics3.parse_response(response(
        segment=2, last=True, num_segments=2, order_data="QUJD\n  REVG",
        wrapped_key=b"wrapped"))
    assert (parsed.num_segments, parsed.segment_number) == (2, 2)
    assert parsed.last_segment is True
    assert parsed.order_data == "QUJDREVG"  # the bank's line wrapping is not data
    assert parsed.transaction_key_encrypted == b"wrapped"


def test_a_document_that_is_not_a_response_envelope_is_refused():
    with pytest.raises(ebics3.DocumentError):
        ebics3.parse_response(b"<Document><Payment>1</Payment></Document>")


# --- driving a download ----------------------------------------------------

def download(**kwargs):
    return ebics3.DownloadTransaction(CONTEXT, KEYS["X002"],
                                      encryption_key=KEYS["E002"], **kwargs)


def segments_of(size=64):
    package = secured()
    return package, ebics3.split_segments(package.encrypt(PAYLOAD), size)


def drive(transaction, segments, package, **kwargs):
    """Feed a download every segment in order, then the receipt."""
    transaction.feed(response(num_segments=len(segments), segment=1,
                              last=len(segments) == 1, order_data=segments[0],
                              wrapped_key=package.transaction_key_encrypted,
                              **kwargs))
    while (request := transaction.next_request()) is not None:
        if transaction.phase is ebics3.Phase.RECEIPT:
            transaction.feed(response(
                phase="Receipt",
                return_code=ebics3.EBICS_DOWNLOAD_POSTPROCESS_DONE, **kwargs))
            continue
        number = int(request.xpath("//*[local-name()='SegmentNumber']")[0].text)
        transaction.feed(response(phase="Transfer", segment=number,
                                  last=number == len(segments),
                                  order_data=segments[number - 1], **kwargs))
    return transaction


def test_a_segmented_download_reassembles_and_then_acknowledges():
    package, segments = segments_of()
    transaction = drive(download(), segments, package)
    assert len(segments) > 2
    assert transaction.order_data == PAYLOAD
    assert transaction.phase is ebics3.Phase.DONE


def test_the_last_request_of_a_download_is_the_receipt():
    package, segments = segments_of()
    transaction = download()
    transaction.feed(response(num_segments=1, segment=1, last=True,
                              order_data="".join(segments),
                              wrapped_key=package.transaction_key_encrypted))
    request = transaction.next_request()
    assert request.xpath("//*[local-name()='TransactionPhase']")[0].text == "Receipt"
    assert transaction.order_data == PAYLOAD


def test_a_recovery_sync_rewinds_and_the_payload_still_arrives():
    package, segments = segments_of()
    transaction = download()
    transaction.feed(response(num_segments=len(segments), segment=1,
                              order_data=segments[0],
                              wrapped_key=package.transaction_key_encrypted))
    transaction.feed(response(phase="Transfer", segment=2, order_data=segments[1]))
    assert transaction.cursor == 2

    transaction.feed(response(phase="Transfer", segment=1,
                              return_code=ebics3.EBICS_TX_RECOVERY_SYNC))
    assert transaction.cursor == 1 and transaction.segments == segments[:1]

    for number in range(2, len(segments) + 1):
        transaction.feed(response(phase="Transfer", segment=number,
                                  last=number == len(segments),
                                  order_data=segments[number - 1]))
    assert transaction.order_data == PAYLOAD


def test_a_bank_refusal_carries_the_code_it_refused_with():
    with pytest.raises(ebics3.TransactionError) as raised:
        download().feed(response(return_code="091002"))
    assert raised.value.return_code == "091002"


def test_a_download_segment_without_a_payload_is_a_protocol_error():
    with pytest.raises(ebics3.TransactionError):
        download().feed(response(num_segments=1, segment=1, last=True))


def test_a_segment_arriving_out_of_order_is_refused():
    package, segments = segments_of()
    transaction = download()
    transaction.feed(response(num_segments=len(segments), segment=1,
                              order_data=segments[0],
                              wrapped_key=package.transaction_key_encrypted))
    with pytest.raises(ebics3.TransactionError):
        transaction.feed(response(phase="Transfer", segment=3,
                                  order_data=segments[2]))


def test_a_response_the_bank_key_does_not_sign_is_refused():
    package, segments = segments_of()
    checked = download(bank_authentication_key=KEYS["X002"])
    drive(checked, segments, package, sign_with=KEYS["X002"])
    assert checked.order_data == PAYLOAD

    forged = response(num_segments=1, segment=1, last=True, order_data="QUJD",
                      wrapped_key=package.transaction_key_encrypted,
                      sign_with=KEYS["X002"])
    forged.xpath("//*[local-name()='ReturnCode']")[0].text = "091002"
    with pytest.raises(ebics3.TransactionError, match="signature"):
        download(bank_authentication_key=KEYS["X002"]).feed(forged)


# --- driving an upload -----------------------------------------------------

def test_an_upload_sends_every_segment_once_and_in_order():
    transaction = ebics3.UploadTransaction.prepare(
        PAYLOAD, secured(), CONTEXT, authentication_key=KEYS["X002"],
        segment_size=64)
    transaction.feed(response())

    sent = []
    while (request := transaction.next_request()) is not None:
        node = request.xpath("//*[local-name()='SegmentNumber']")[0]
        sent.append((int(node.text), node.get("lastSegment")))
        payload = request.xpath("//*[local-name()='OrderData']")[0].text
        assert payload == transaction.segments[sent[-1][0] - 1]
        transaction.feed(response(phase="Transfer", segment=sent[-1][0],
                                  order_id="A00A"))

    assert [number for number, _ in sent] == list(range(1, len(sent) + 1))
    assert [flag for _, flag in sent] == ["false"] * (len(sent) - 1) + ["true"]
    assert transaction.phase is ebics3.Phase.DONE
    assert transaction.order_id == "A00A"


def test_an_upload_resumes_from_the_recovery_point_the_bank_names():
    transaction = ebics3.UploadTransaction.prepare(
        PAYLOAD, secured(), CONTEXT, authentication_key=KEYS["X002"],
        segment_size=64)
    transaction.feed(response())
    transaction.feed(response(phase="Transfer", segment=1))
    transaction.feed(response(phase="Transfer", segment=2))
    assert transaction.cursor == 2

    transaction.feed(response(phase="Transfer", segment=1,
                              return_code=ebics3.EBICS_TX_RECOVERY_SYNC))
    resent = transaction.next_request()
    assert resent.xpath("//*[local-name()='SegmentNumber']")[0].text == "2"


def test_a_transfer_before_the_bank_named_a_transaction_is_refused():
    transaction = ebics3.UploadTransaction.prepare(
        PAYLOAD, secured(), CONTEXT, authentication_key=KEYS["X002"])
    transaction.phase = ebics3.Phase.TRANSFER
    with pytest.raises(ebics3.TransactionError):
        transaction.next_request()
