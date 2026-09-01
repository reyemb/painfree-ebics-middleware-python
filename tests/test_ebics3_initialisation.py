"""Unit tests for subscriber initialisation: INI, HIA, HPB and the letter.

The differential gate proves the parts another implementation can speak to: the
INI, HIA and HPB requests are byte-identical to `ebics-client-php`, the letter
fingerprint agrees with `ebics-client-php` *and* `fintech` in both of the two
conventions a letter can carry, two implementations read the same keys out of
every HPB order-data document in the corpus, and the whole flow is driven over
HTTP against a server whose HPB payload a reference encrypted.

What is pinned here is what none of that can say. Most of it is one question:
**what happens when the bank's key is not the bank's key.** Nothing signs a key
management response, so the fingerprint comparison is the only check there is,
and a test suite that only ever feeds it matching values has tested nothing.

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
    for index, version in enumerate(("A006", "X002", "E002"))
}

#: A second, unrelated pair -- the bank's, and the substitute an attacker sends.
BANK = {
    version: ebics3.EbicsKey.generate(
        version, subject=ebics3.subject_name("bank.invalid"), serial_number=9,
        not_valid_before=datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc))
    for version in ("X002", "E002")
}
IMPOSTOR = {
    version: ebics3.EbicsKey.generate(
        version, subject=ebics3.subject_name("evil.invalid"), serial_number=66,
        not_valid_before=datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc))
    for version in ("X002", "E002")
}

CONTEXT = ebics3.RequestContext(host_id="HOST0001", partner_id="PARTNER1",
                                user_id="USER0001")

H005 = "urn:org:ebics:H005"
DSIG = "http://www.w3.org/2000/09/xmldsig#"


# --- documents the tests need ----------------------------------------------

def hpb_order_data(keys=None, host_id: str = "HOST0001",
                   pub_key_value: bool = False) -> bytes:
    """`HPBResponseOrderData`, in either of the two key encodings."""
    keys = keys or BANK
    root = etree.Element(etree.QName(H005, "HPBResponseOrderData"),
                         nsmap={None: H005, "ds": DSIG})
    for element, version in (("AuthenticationPubKeyInfo", "X002"),
                             ("EncryptionPubKeyInfo", "E002")):
        info = etree.SubElement(root, etree.QName(H005, element))
        if pub_key_value:
            value = etree.SubElement(info, etree.QName(H005, "PubKeyValue"))
            rsa = etree.SubElement(value, etree.QName(DSIG, "RSAKeyValue"))
            numbers = keys[version].public_key.public_numbers()
            etree.SubElement(rsa, etree.QName(DSIG, "Modulus")).text = (
                ebics3.crypto_binary(numbers.n))
            etree.SubElement(rsa, etree.QName(DSIG, "Exponent")).text = (
                ebics3.crypto_binary(numbers.e))
        else:
            ebics3.append_x509_data(info, keys[version])
        etree.SubElement(
            info, etree.QName(H005, f"{element[:-len('PubKeyInfo')]}Version")
        ).text = version
    etree.SubElement(root, etree.QName(H005, "HostID")).text = host_id
    return ebics3.serialize_order_data(root)


def key_management_response(order_id=None, return_code="000000",
                            payload: bytes | None = None) -> bytes:
    """An `ebicsKeyManagementResponse` -- the envelope INI, HIA and HPB answer with."""
    root = etree.Element(etree.QName(H005, "ebicsKeyManagementResponse"),
                         nsmap={None: H005})
    header = etree.SubElement(root, etree.QName(H005, "header"))
    etree.SubElement(header, etree.QName(H005, "static"))
    mutable = etree.SubElement(header, etree.QName(H005, "mutable"))
    if order_id is not None:
        etree.SubElement(mutable, etree.QName(H005, "OrderID")).text = order_id
    etree.SubElement(mutable, etree.QName(H005, "ReturnCode")).text = return_code
    etree.SubElement(mutable, etree.QName(H005, "ReportText")).text = "text"

    body = etree.SubElement(root, etree.QName(H005, "body"))
    if payload is not None:
        transaction_key = ebics3.generate_transaction_key()
        transfer = etree.SubElement(body, etree.QName(H005, "DataTransfer"))
        info = etree.SubElement(transfer, etree.QName(H005, "DataEncryptionInfo"))
        etree.SubElement(info, etree.QName(H005, "TransactionKey")).text = (
            base64.b64encode(ebics3.wrap_transaction_key(
                transaction_key, KEYS["E002"])).decode())
        etree.SubElement(transfer, etree.QName(H005, "OrderData")).text = (
            ebics3.encrypt_payload(payload, transaction_key))
    etree.SubElement(body, etree.QName(H005, "ReturnCode")).text = return_code
    return etree.tostring(root, xml_declaration=True, encoding="UTF-8")


def initialisation() -> ebics3.Initialisation:
    return ebics3.Initialisation(CONTEXT, KEYS["A006"], KEYS["X002"], KEYS["E002"])


def bank_fingerprints() -> dict[str, str]:
    """The bank's fingerprints as this file's fixtures quote them.

    The **public-key** digest, which is no longer the default: H005 letters
    quote the certificate's, so every call below names the convention rather
    than inheriting one. Both values exist for one key and they never match,
    which is the whole reason the parameter exists.
    """
    return {"authentication": BANK["X002"].fingerprint_hex,
            "encryption": BANK["E002"].fingerprint_hex}


#: What the fixtures above are digests of.
FIXTURE_DIGEST = ebics3.LetterDigest.PUBLIC_KEY


# --- reading the bank's keys -----------------------------------------------

@pytest.mark.parametrize("pub_key_value", [False, True])
def test_hpb_order_data_yields_both_bank_keys(pub_key_value):
    """Both encodings read to the same two keys: H005's X509, and H004's PubKeyValue."""
    parsed = ebics3.parse_hpb_order_data(hpb_order_data(pub_key_value=pub_key_value))
    assert parsed.host_id == "HOST0001"
    assert parsed.authentication.fingerprint == BANK["X002"].fingerprint
    assert parsed.encryption.fingerprint == BANK["E002"].fingerprint
    assert parsed.authentication.version is ebics3.KeyVersion.X002
    # The certificate travels with the key where the document carried one, and
    # is genuinely absent where it did not -- rather than silently invented.
    assert (parsed.encryption.certificate is None) is pub_key_value


def test_hpb_order_data_rejects_a_document_that_is_not_one():
    with pytest.raises(ebics3.DocumentError, match="not HPBResponseOrderData"):
        ebics3.parse_hpb_order_data(key_management_response())


def test_hpb_order_data_rejects_a_version_in_the_wrong_role():
    document = hpb_order_data().replace(b"<AuthenticationVersion>X002",
                                        b"<AuthenticationVersion>E002")
    with pytest.raises(ebics3.DocumentError, match="not an authentication version"):
        ebics3.parse_hpb_order_data(document)


def test_hpb_order_data_rejects_a_key_info_with_no_key_in_it():
    document = hpb_order_data(pub_key_value=True).replace(b"Modulus", b"Modulys")
    with pytest.raises(ebics3.DocumentError, match="neither a certificate nor"):
        ebics3.parse_hpb_order_data(document)


# --- the comparison that decides whether to trust them ---------------------

def test_matching_fingerprints_are_accepted_however_they_were_typed():
    """A value copied off paper arrives in pairs, in upper case, sometimes with colons."""
    bank_keys = ebics3.parse_hpb_order_data(hpb_order_data())
    expected = bank_fingerprints()
    accepted = ebics3.verify_bank_keys(
        bank_keys,
        authentication=ebics3.format_fingerprint(expected["authentication"]).upper(),
        encryption=":".join(expected["encryption"][i:i + 2] for i in range(0, 64, 2)),
        # Named, because the default is the certificate one: these fixtures
        # quote the public-key digest.
        digest=ebics3.LetterDigest.PUBLIC_KEY,
    )
    assert accepted == expected


def test_a_substituted_encryption_key_is_refused():
    """The negative case. A bank key that does not match the letter is not the bank's.

    Substituting E002 is the attack that matters: every payment file this
    client uploads is encrypted under the bank's encryption key, so a key the
    customer never checked is a key someone else can read the payments with.
    """
    substituted = hpb_order_data({"X002": BANK["X002"], "E002": IMPOSTOR["E002"]})
    bank_keys = ebics3.parse_hpb_order_data(substituted)
    with pytest.raises(ebics3.BankKeyMismatchError) as raised:
        ebics3.verify_bank_keys(bank_keys, **bank_fingerprints(),
                                digest=FIXTURE_DIGEST)

    assert raised.value.role == "encryption"
    assert raised.value.actual == IMPOSTOR["E002"].fingerprint_hex
    assert raised.value.expected == BANK["E002"].fingerprint_hex


def test_a_substituted_authentication_key_is_refused():
    substituted = hpb_order_data({"X002": IMPOSTOR["X002"],
                                  "E002": BANK["E002"]})
    with pytest.raises(ebics3.BankKeyMismatchError) as raised:
        ebics3.verify_bank_keys(ebics3.parse_hpb_order_data(substituted),
                                **bank_fingerprints())
    assert raised.value.role == "authentication"


def test_a_fingerprint_that_is_not_one_is_refused_rather_than_mismatched():
    """A truncated or mistyped expectation is a caller bug, not a key mismatch.

    Reporting it as a mismatch would send an operator to look for an attack
    that is not there; worse, a comparison that accepted a prefix would accept
    the empty string.
    """
    bank_keys = ebics3.parse_hpb_order_data(hpb_order_data())
    expected = bank_fingerprints()
    for wrong in ("", expected["authentication"][:32], "z" * 64):
        with pytest.raises(ebics3.RequestError, match="64 hex characters"):
            ebics3.verify_bank_keys(bank_keys, authentication=wrong,
                                    encryption=expected["encryption"])


def test_the_certificate_digest_is_a_different_value_over_the_same_key():
    bank_keys = ebics3.parse_hpb_order_data(hpb_order_data())
    by_key = bank_keys.fingerprints(ebics3.LetterDigest.PUBLIC_KEY)
    by_certificate = bank_keys.fingerprints(ebics3.LetterDigest.CERTIFICATE)
    assert by_key != by_certificate
    assert by_certificate["X002"] == ebics3.certificate_fingerprint(
        BANK["X002"].certificate)
    # And the two are not interchangeable: the letter's own value, checked
    # under the other convention, is a mismatch rather than a pass.
    with pytest.raises(ebics3.BankKeyMismatchError):
        ebics3.verify_bank_keys(bank_keys, authentication=by_key["X002"],
                                encryption=by_key["E002"],
                                digest=ebics3.LetterDigest.CERTIFICATE)


def test_a_key_without_a_certificate_cannot_produce_a_certificate_digest():
    key = ebics3.EbicsKey.from_public_pem("X002", KEYS["X002"].public_pem())
    with pytest.raises(ebics3.CertificateError, match="needs a certificate"):
        ebics3.ini_letter_hash(key, ebics3.LetterDigest.CERTIFICATE)


# --- the letter ------------------------------------------------------------

def test_the_letter_carries_the_fingerprint_machinery_s_own_values():
    # The convention is named rather than defaulted: this asserts the
    # public-key digest, and the default is the certificate one.
    letter = ebics3.build_ini_letter(CONTEXT, KEYS["A006"], KEYS["X002"],
                                     KEYS["E002"],
                                     digest=ebics3.LetterDigest.PUBLIC_KEY)
    assert letter.signature.fingerprint == ebics3.public_key_digest_hex(
        KEYS["A006"].public_key)
    assert letter.authentication.version is ebics3.KeyVersion.X002
    assert letter.encryption.modulus_bits == 2048
    # 65537 is three bytes, and the modulus is exactly as many pairs as bits.
    assert letter.signature.exponent == "01 00 01"
    assert len(letter.encryption.modulus.split()) == 256
    assert letter.authentication.fingerprint_formatted == " ".join(
        letter.authentication.fingerprint[i:i + 2] for i in range(0, 64, 2))


def test_the_letter_refuses_a_key_in_the_wrong_slot():
    with pytest.raises(ebics3.RequestError, match="signature slot"):
        ebics3.build_ini_letter(CONTEXT, KEYS["X002"], KEYS["X002"], KEYS["E002"])


# --- the flow --------------------------------------------------------------

def test_the_flow_walks_ini_then_hia_then_hpb_and_stops():
    flow = initialisation()
    assert flow.state is ebics3.KeyState.CREATED
    steps = []
    for response in (key_management_response("A001"),
                     key_management_response("A002"),
                     key_management_response(payload=hpb_order_data())):
        steps.append(flow.next_step)
        request = flow.next_request()
        assert etree.QName(request).localname in (
            "ebicsUnsecuredRequest", "ebicsNoPubKeyDigestsRequest")
        flow.feed(response)

    assert steps == [ebics3.Step.INI, ebics3.Step.HIA, ebics3.Step.HPB]
    assert (flow.ini_order_id, flow.hia_order_id) == ("A001", "A002")
    assert flow.next_request() is None
    assert flow.bank_keys.authentication.fingerprint == BANK["X002"].fingerprint


def test_the_state_reaches_ready_only_after_the_letter_is_checked():
    """Holding the bank's keys is not the same as believing them."""
    flow = initialisation()
    flow.ini_sent = flow.hia_sent = True
    flow.feed(key_management_response(payload=hpb_order_data()))

    assert flow.state is ebics3.KeyState.BANK_KEYS_RECEIVED
    assert flow.next_request() is None  # nothing left to ask the bank
    flow.confirm_bank_keys(**bank_fingerprints(), digest=FIXTURE_DIGEST)
    assert flow.state is ebics3.KeyState.READY


def test_a_refused_confirmation_leaves_the_flow_where_it_was():
    flow = initialisation()
    flow.ini_sent = flow.hia_sent = True
    flow.feed(key_management_response(
        payload=hpb_order_data({"X002": BANK["X002"], "E002": IMPOSTOR["E002"]})))

    with pytest.raises(ebics3.BankKeyMismatchError):
        flow.confirm_bank_keys(**bank_fingerprints(), digest=FIXTURE_DIGEST)
    assert flow.state is ebics3.KeyState.BANK_KEYS_RECEIVED
    assert flow.bank_fingerprints is None
    # The keys that arrived are kept: they are the evidence of what happened.
    assert flow.bank_keys is not None


def test_confirming_before_hpb_is_an_error_not_a_pass():
    with pytest.raises(ebics3.DocumentError, match="not been fetched"):
        initialisation().confirm_bank_keys(**bank_fingerprints(),
                                           digest=FIXTURE_DIGEST)


def test_a_refused_registration_raises_rather_than_advancing():
    flow = initialisation()
    with pytest.raises(ebics3.BankRefusedError) as raised:
        flow.feed(key_management_response("A001", return_code="091002"))
    assert raised.value.return_code == "091002"
    assert flow.state is ebics3.KeyState.CREATED
    assert flow.next_step is ebics3.Step.INI


def test_an_hpb_response_for_another_host_is_refused():
    flow = initialisation()
    flow.ini_sent = flow.hia_sent = True
    with pytest.raises(ebics3.DocumentError, match="HostID"):
        flow.feed(key_management_response(
            payload=hpb_order_data(host_id="OTHERBNK")))


def test_an_hpb_response_with_no_payload_is_refused():
    flow = initialisation()
    flow.ini_sent = flow.hia_sent = True
    with pytest.raises(ebics3.DocumentError, match="no encrypted order data"):
        flow.feed(key_management_response())


def test_feeding_a_finished_initialisation_is_an_error():
    flow = initialisation()
    flow.ini_sent = flow.hia_sent = True
    flow.feed(key_management_response(payload=hpb_order_data()))
    with pytest.raises(ebics3.DocumentError, match="nothing outstanding"):
        flow.feed(key_management_response())


# --- which of the two fingerprints a letter quotes ---------------------------

def test_the_default_letter_digest_is_the_certificate():
    """Because this engine speaks H005 and nothing else.

    Both fingerprints exist for one key and they are different strings, so a
    match under the wrong one is not a match. `ebics-client-php` chooses by
    version: `DigestResolverV2` prints the public-key digest, `DigestResolverV3`
    -- the EBICS 3.0 rule -- always prints the certificate's. Every connection
    this engine can register is H005, so the public-key digest was a default
    that was wrong for every connection it could create.

    A bank telephoned about it: the keys were right, the letter was not.
    """
    assert ebics3.EBICS_VERSION == "H005"
    assert ebics3.DEFAULT_LETTER_DIGEST is ebics3.LetterDigest.CERTIFICATE


def test_the_two_fingerprints_are_different_strings():
    """The reason picking the wrong one is not a near miss."""
    key = KEYS["X002"]

    public = ebics3.ini_letter_hash(key, ebics3.LetterDigest.PUBLIC_KEY)
    certificate = ebics3.ini_letter_hash(key, ebics3.LetterDigest.CERTIFICATE)

    assert len(public) == len(certificate) == 64
    assert public != certificate
