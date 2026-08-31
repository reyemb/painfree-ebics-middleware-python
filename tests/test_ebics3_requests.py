"""Unit tests for the H005 request builders, the BTF and the order data.

They complement the differential gate rather than replacing it: that the engine
and ``ebics-client-php`` build the *same* INI, HIA, HPB, BTD and BTU document
down to the signature value is proved there, against the shared fixture keys and
certificates. What is pinned here is the part no other implementation checks for
us -- the H005 rules a port from H004 gets wrong, the refusals that stop a
malformed request before it is signed, and the one rule that decides whether the
authentication signature is over the right bytes.

Deliberately free of external key material: the module mints its own keys.
"""

from __future__ import annotations

import base64
import datetime
import zlib

import pytest
from lxml import etree

from painfree import ebics3

H005 = "urn:org:ebics:H005"
S002 = "http://www.ebics.org/S002"
DSIG = "http://www.w3.org/2000/09/xmldsig#"

SUBJECT = ebics3.subject_name("painfree.invalid", "painfree", "CH")

#: One key per role, generated once: RSA keygen is slow and no test here needs a
#: particular key, only a valid one carrying the right certificate.
KEYS = {
    version: ebics3.EbicsKey.generate(
        version, subject=SUBJECT, serial_number=index + 1,
        not_valid_before=datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc))
    for index, version in enumerate(("A006", "X002", "E002"))
}
BANK = {
    version: ebics3.EbicsKey.generate(
        version, subject=ebics3.subject_name("bank.invalid"), serial_number=100 + index,
        not_valid_before=datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc))
    for index, version in enumerate(("X002", "E002"))
}

CONTEXT = ebics3.RequestContext(
    host_id="TESTHOST", partner_id="PARTNER1", user_id="USER0001",
    product=ebics3.Product("painfree", "de"))

SERVICE = ebics3.Service("EOP", "camt.053", scope="CH", option="OSG",
                         container="ZIP", msg_version="08")

PINNED = dict(nonce="F88276D74C12FE082492573B6199B361",
              timestamp="2020-01-01T00:00:00Z")

#: An upload payload. The engine never parses it -- order data is opaque bytes
#: to the pipeline -- so its only job is to be something with a known digest.
ORDER_CONTENT = b"<Document><Payment>1</Payment></Document>"


def secured(**kwargs):
    """One payload through the whole pipeline, with the key pinned."""
    return ebics3.secure_order_data(
        kwargs.pop("order_content", ORDER_CONTENT),
        signature_key=kwargs.pop("signature_key", KEYS["A006"]),
        bank_encryption_key=BANK["E002"], partner_id=CONTEXT.partner_id,
        user_id=CONTEXT.user_id, transaction_key=bytes(range(16)), **kwargs)


def btu(**kwargs):
    kwargs.setdefault("secured", secured())
    kwargs.setdefault("num_segments", 1)
    return ebics3.build_btu_request(
        CONTEXT, ebics3.Service("SCT", "pain.001"),
        authentication_key=KEYS["X002"], bank_authentication_key=BANK["X002"],
        bank_encryption_key=BANK["E002"], file_name="pain001.xml",
        **PINNED, **kwargs)


def names(node, namespace=H005):
    """Local names of ``node``'s children, in document order."""
    return [etree.QName(child).localname for child in node]


def child(root, local_name):
    return root.xpath(f"//*[local-name()='{local_name}']")[0]


def order_data(root):
    """The payload inside ``<OrderData>``, inflated and parsed."""
    text = child(root, "OrderData").text
    return etree.fromstring(zlib.decompress(base64.b64decode(text)))


# --- the BTF service -------------------------------------------------------

def test_service_elements_are_in_the_order_the_schema_fixes():
    parent = etree.Element(etree.QName(H005, "BTDOrderParams"))
    ebics3.append_service(parent, SERVICE)
    assert names(parent[0]) == ["ServiceName", "Scope", "ServiceOption",
                                "Container", "MsgName"]


def test_optional_service_parts_are_absent_not_empty():
    """A bank matches order parameters exactly; an empty element is not nothing."""
    parent = etree.Element(etree.QName(H005, "BTDOrderParams"))
    ebics3.append_service(parent, ebics3.Service("SCT", "pain.001"))
    assert names(parent[0]) == ["ServiceName", "MsgName"]


def test_msg_name_attributes_ride_on_the_element():
    parent = etree.Element(etree.QName(H005, "BTDOrderParams"))
    ebics3.append_service(parent, ebics3.Service(
        "SCT", "pain.001", msg_variant="001", msg_version="09", msg_format="XML"))
    msg = parent[0][-1]
    assert msg.text == "pain.001"
    assert dict(msg.attrib) == {"variant": "001", "version": "09", "format": "XML"}


@pytest.mark.parametrize("kwargs,fragment", [
    (dict(name="CAMT", msg_name="camt.053"), "ServiceName"),
    (dict(name="eop", msg_name="camt.053"), "ServiceName"),
    (dict(name="EOP", msg_name="Camt.053"), "MsgName"),
    (dict(name="EOP", msg_name="camt.053", scope="C"), "Scope"),
    (dict(name="EOP", msg_name="camt.053", container="TAR"), "Container"),
    (dict(name="EOP", msg_name="camt.053", msg_version="8"), "version"),
])
def test_service_refuses_what_the_schema_would(kwargs, fragment):
    """``ServiceName`` 'CAMT' is the real one: epics ships a fixture with it."""
    with pytest.raises(ebics3.RequestError, match=fragment):
        ebics3.Service(**kwargs)


def test_btd_order_params_take_a_date_range_after_the_service():
    parent = etree.Element(etree.QName(H005, "OrderDetails"))
    params = ebics3.append_btd_order_params(
        parent, SERVICE, date_range=("2020-01-01", "2020-01-31"))
    assert names(params) == ["Service", "DateRange"]
    assert names(params[1]) == ["Start", "End"]


def test_btu_order_params_carry_the_file_name_and_the_signature_flag():
    parent = etree.Element(etree.QName(H005, "OrderDetails"))
    params = ebics3.append_btu_order_params(
        parent, SERVICE, file_name="pain001.xml", request_eds=True,
        parameters={"TEST": "on"})
    assert params.get("fileName") == "pain001.xml"
    assert names(params) == ["Service", "SignatureFlag", "Parameter"]
    assert params[1].get("requestEDS") == "true"
    assert names(params[2]) == ["Name", "Value"]
    assert params[2][1].get("Type") == "string"


def test_btd_order_params_never_carry_a_file_name():
    """``BTDParamsType`` marks ``fileName`` prohibited, not merely optional."""
    parent = etree.Element(etree.QName(H005, "OrderDetails"))
    params = ebics3.append_btd_order_params(parent, SERVICE)
    assert "fileName" not in params.attrib


# --- order data ------------------------------------------------------------

def test_ini_order_data_is_rooted_in_s002_and_carries_only_the_certificate():
    """H005 dropped ``PubKeyValue``: ``ds:X509Data`` is the whole key material.

    An H004 port keeps emitting ``ds:Modulus`` and ``ds:Exponent`` beside the
    certificate, which the S002 schema rejects outright.
    """
    root = ebics3.build_signature_pub_key_order_data(KEYS["A006"], "P", "U")
    assert etree.QName(root) == etree.QName(S002, "SignaturePubKeyOrderData")
    assert names(root) == ["SignaturePubKeyInfo", "PartnerID", "UserID"]
    assert names(root[0]) == ["X509Data", "SignatureVersion"]
    assert root.xpath("//*[local-name()='PubKeyValue']") == []
    assert root[0][1].text == "A006"


def test_x509_data_names_the_issuer_and_serial_before_the_certificate():
    root = ebics3.build_signature_pub_key_order_data(KEYS["A006"], "P", "U")
    data = child(root, "X509Data")
    assert names(data) == ["X509IssuerSerial", "X509Certificate"]
    assert names(data[0]) == ["X509IssuerName", "X509SerialNumber"]
    assert data[0][1].text == "1"
    assert base64.b64decode(data[1].text) == KEYS["A006"].certificate_der()


def test_hia_order_data_is_rooted_in_h005_and_carries_both_keys():
    root = ebics3.build_hia_request_order_data(KEYS["X002"], KEYS["E002"], "P", "U")
    assert etree.QName(root) == etree.QName(H005, "HIARequestOrderData")
    assert names(root) == ["AuthenticationPubKeyInfo", "EncryptionPubKeyInfo",
                            "PartnerID", "UserID"]
    assert names(root[0]) == ["X509Data", "AuthenticationVersion"]
    assert names(root[1]) == ["X509Data", "EncryptionVersion"]


def test_hia_order_data_is_not_a_signature_pub_key_order_data():
    """The defect the reference corpus is carrying, pinned so we cannot inherit it.

    ``ebics-client-php``'s ``hia_order_data.xml`` is byte-identical to its
    ``ini_order_data.xml`` and rooted at ``SignaturePubKeyOrderData``. Nothing
    upstream references either file, so nothing there notices.
    """
    root = ebics3.build_hia_request_order_data(KEYS["X002"], KEYS["E002"], "P", "U")
    assert etree.QName(root).localname != "SignaturePubKeyOrderData"


def test_hia_refuses_the_same_key_for_authentication_and_encryption():
    key = KEYS["X002"]
    twice = ebics3.EbicsKey("E002", key.public_key, key.private_key, key.certificate)
    with pytest.raises(ebics3.RequestError, match="distinct"):
        ebics3.build_hia_request_order_data(key, twice, "P", "U")


def test_order_data_refuses_a_key_in_the_wrong_role():
    with pytest.raises(ebics3.RequestError, match="signature"):
        ebics3.build_signature_pub_key_order_data(KEYS["X002"], "P", "U")


def test_order_data_refuses_a_key_without_a_certificate():
    bare = ebics3.EbicsKey("A006", KEYS["A006"].public_key, KEYS["A006"].private_key)
    with pytest.raises(ebics3.CertificateError, match="certificate"):
        ebics3.build_signature_pub_key_order_data(bare, "P", "U")


def test_order_data_is_zlib_wrapped_not_raw_deflate():
    """``gzcompress`` in PHP and ``zlib.compress`` here must agree byte for byte."""
    payload = b"<Document/>"
    compressed = ebics3.compress_order_data(payload)
    assert compressed[:1] == b"\x78"  # RFC 1950 header, not raw deflate
    assert ebics3.decompress_order_data(compressed) == payload


# --- the envelopes ---------------------------------------------------------

def test_unsecured_request_shape():
    root = ebics3.build_ini_request(CONTEXT, KEYS["A006"])
    assert etree.QName(root) == etree.QName(H005, "ebicsUnsecuredRequest")
    assert root.get("Version") == "H005" and root.get("Revision") == "1"
    assert names(root) == ["header", "body"]
    assert names(root[0]) == ["static", "mutable"]
    assert names(root[0][0]) == ["HostID", "PartnerID", "UserID", "Product",
                                  "OrderDetails", "SecurityMedium"]


def test_unsecured_request_has_no_nonce_or_timestamp():
    """The schema restricts both to ``maxOccurs="0"`` here, not merely optional."""
    root = ebics3.build_hia_request(CONTEXT, KEYS["X002"], KEYS["E002"])
    assert root.xpath("//*[local-name()='Nonce']") == []
    assert root.xpath("//*[local-name()='Timestamp']") == []


def test_order_details_use_admin_order_type_and_no_order_attribute():
    """The two renames an H004 port gets wrong, and the XSD rejects."""
    root = ebics3.build_ini_request(CONTEXT, KEYS["A006"])
    details = child(root, "OrderDetails")
    assert names(details) == ["AdminOrderType"]
    assert details[0].text == "INI"
    assert root.xpath("//*[local-name()='OrderType']") == []
    assert root.xpath("//*[local-name()='OrderAttribute']") == []


def test_ini_and_hia_carry_their_own_order_data():
    ini = order_data(ebics3.build_ini_request(CONTEXT, KEYS["A006"]))
    hia = order_data(ebics3.build_hia_request(CONTEXT, KEYS["X002"], KEYS["E002"]))
    assert etree.QName(ini).localname == "SignaturePubKeyOrderData"
    assert etree.QName(hia).localname == "HIARequestOrderData"
    assert child(ini, "PartnerID").text == CONTEXT.partner_id


def test_only_the_header_is_marked_authenticate_when_the_body_is_empty():
    """A download signs the header and nothing else -- it has no body to sign."""
    root = ebics3.build_hpb_request(CONTEXT, KEYS["X002"], **PINNED)
    marked = ebics3.authenticated_nodes(root)
    assert [etree.QName(node).localname for node in marked] == ["header"]


def test_an_upload_signs_its_body_too():
    """The rule the BTU builder exists to get right.

    ``DataEncryptionInfo`` and ``SignatureData`` carry ``authenticate="true"``,
    so a ``BTU`` whose body is missing signs a strictly smaller node-set than
    the bank will verify. Asserting the marked set is what keeps that from
    regressing silently: the digest would still be well-formed, just wrong.
    """
    root = btu()
    marked = [etree.QName(node).localname
              for node in ebics3.authenticated_nodes(root)]
    assert marked == ["header", "DataEncryptionInfo", "SignatureData"]
    assert ebics3.verify_auth_signature(root, KEYS["X002"].public_key).ok


def test_hpb_is_signed_and_verifies_against_its_own_key():
    root = ebics3.build_hpb_request(CONTEXT, KEYS["X002"], **PINNED)
    assert names(root) == ["header", "AuthSignature", "body"]
    check = ebics3.verify_auth_signature(root, KEYS["X002"].public_key, "X002")
    assert check.ok, check.as_dict()


def test_a_signed_request_is_reproducible_when_nonce_and_timestamp_are_pinned():
    """X002 is PKCS#1, so nothing else in the document is random."""
    first = ebics3.serialize_request(
        ebics3.build_hpb_request(CONTEXT, KEYS["X002"], **PINNED))
    second = ebics3.serialize_request(
        ebics3.build_hpb_request(CONTEXT, KEYS["X002"], **PINNED))
    assert first == second


def test_two_requests_differ_when_the_nonce_is_left_free():
    first = ebics3.build_hpb_request(CONTEXT, KEYS["X002"])
    second = ebics3.build_hpb_request(CONTEXT, KEYS["X002"])
    assert child(first, "Nonce").text != child(second, "Nonce").text


def test_btd_request_shape():
    root = ebics3.build_btd_request(
        CONTEXT, SERVICE, authentication_key=KEYS["X002"],
        bank_authentication_key=BANK["X002"], bank_encryption_key=BANK["E002"],
        **PINNED)
    assert etree.QName(root) == etree.QName(H005, "ebicsRequest")
    assert names(root[0][0]) == ["HostID", "Nonce", "Timestamp", "PartnerID",
                                  "UserID", "Product", "OrderDetails",
                                  "BankPubKeyDigests", "SecurityMedium"]
    assert names(child(root, "OrderDetails")) == ["AdminOrderType", "BTDOrderParams"]
    assert child(root, "TransactionPhase").text == "Initialisation"


def test_btu_request_announces_its_segment_count():
    root = btu(num_segments=3)
    assert child(root, "NumSegments").text == "3"
    assert names(root[0][0])[-1] == "NumSegments"


def test_btu_body_is_the_sequence_the_schema_fixes():
    """``DataEncryptionInfo``, ``SignatureData``, ``DataDigest`` -- and no OrderData.

    The payload itself goes up in the transfer phase; the initialisation
    request only announces it. A builder that puts ``OrderData`` here produces
    a document the H005 choice rejects, because the two branches are exclusive.
    """
    root = btu()
    transfer = child(root, "DataTransfer")
    assert names(transfer) == ["DataEncryptionInfo", "SignatureData", "DataDigest"]
    assert names(child(root, "DataEncryptionInfo")) == ["EncryptionPubKeyDigest",
                                                        "TransactionKey"]
    assert root.xpath("//*[local-name()='OrderData']") == []


def test_btu_publishes_the_digest_its_electronic_signature_covers():
    """``DataDigest`` and the ES must be over the same bytes, or the bank says no."""
    package = secured()
    root = btu(secured=package)
    digest = child(root, "DataDigest")
    assert digest.get("SignatureVersion") == "A006"
    assert base64.b64decode(digest.text) == ebics3.order_data_digest(ORDER_CONTENT)

    recovered = ebics3.parse_xml(ebics3.open_order_data(
        child(root, "SignatureData").text,
        base64.b64decode(child(root, "TransactionKey").text), BANK["E002"]))
    assert ebics3.verify_user_signature(recovered, package.digest, KEYS["A006"])


def test_encryption_pub_key_digest_names_the_bank_key_it_wrapped_to():
    root = btu()
    digest = child(root, "EncryptionPubKeyDigest")
    assert digest.get("Version") == "E002"
    assert digest.text == ebics3.certificate_digest_b64(BANK["E002"])


def test_bank_pub_key_digests_hash_the_certificate_not_the_public_key():
    """H005 moved these digests to the certificate; H004 hashed the RSA numbers.

    Both values exist for the same key, and only one of them is accepted -- so
    the test asserts which, and that the other really is different.
    """
    root = ebics3.build_btd_request(
        CONTEXT, SERVICE, authentication_key=KEYS["X002"],
        bank_authentication_key=BANK["X002"], bank_encryption_key=BANK["E002"],
        **PINNED)
    authentication = child(root, "Authentication")
    assert authentication.text == ebics3.certificate_digest_b64(BANK["X002"])
    assert authentication.get("Version") == "X002"
    assert base64.b64decode(authentication.text) != BANK["X002"].fingerprint


def test_schema_location_changes_the_digest_over_the_same_header():
    """The hint is optional, and it is not cosmetic.

    Putting ``xsi:schemaLocation`` on the root declares ``xmlns:xsi``, which
    inclusive canonicalisation re-emits on the ``header`` apex -- so the same
    header signs to a different value. That is why the engine does not add one
    unless a caller asks.
    """
    plain = ebics3.build_hpb_request(CONTEXT, KEYS["X002"], **PINNED)
    hinted = ebics3.build_hpb_request(
        CONTEXT, KEYS["X002"], schema_location="urn:org:ebics:H005 ebics.xsd",
        **PINNED)
    assert ebics3.auth_digest(plain) != ebics3.auth_digest(hinted)
    assert ebics3.verify_auth_signature(hinted, KEYS["X002"].public_key).ok


def test_signed_envelopes_declare_the_dsig_prefix_on_the_root():
    """It must be in scope before the header is digested, not added with the signature."""
    for root in (ebics3.build_hpb_request(CONTEXT, KEYS["X002"], **PINNED),
                 ebics3.build_btd_request(
                     CONTEXT, SERVICE, authentication_key=KEYS["X002"],
                     bank_authentication_key=BANK["X002"],
                     bank_encryption_key=BANK["E002"], **PINNED)):
        assert root.nsmap["ds"] == DSIG
        assert ebics3.in_scope_namespaces(child(root, "header"))["ds"] == DSIG


def test_unsecured_envelope_does_not_declare_a_prefix_it_never_uses():
    root = ebics3.build_ini_request(CONTEXT, KEYS["A006"])
    assert "ds" not in root.nsmap


# --- refusals --------------------------------------------------------------

@pytest.mark.parametrize("kwargs,fragment", [
    (dict(host_id=""), "HostID"),
    (dict(partner_id="P" * 36), "PartnerID"),
    (dict(security_medium="000"), "SecurityMedium"),
    (dict(security_medium="00X0"), "SecurityMedium"),
])
def test_request_context_refuses_what_the_schema_would(kwargs, fragment):
    fields = dict(host_id="H", partner_id="P", user_id="U") | kwargs
    with pytest.raises(ebics3.RequestError, match=fragment):
        ebics3.RequestContext(**fields)


def test_product_language_must_be_a_two_letter_code():
    with pytest.raises(ebics3.RequestError, match="ISO 639"):
        ebics3.Product("painfree", "deu")


def test_signing_refuses_a_version_that_is_not_x002():
    with pytest.raises(ebics3.RequestError, match="X002"):
        ebics3.build_hpb_request(CONTEXT, KEYS["A006"], **PINNED)


def test_signing_refuses_a_key_without_its_private_half():
    public_only = ebics3.EbicsKey("X002", KEYS["X002"].public_key,
                                  certificate=KEYS["X002"].certificate)
    with pytest.raises(ebics3.RequestError, match="private"):
        ebics3.build_hpb_request(CONTEXT, public_only, **PINNED)


def test_bank_digests_refuse_the_roles_the_other_way_round():
    with pytest.raises(ebics3.RequestError, match="authentication"):
        ebics3.build_btd_request(
            CONTEXT, SERVICE, authentication_key=KEYS["X002"],
            bank_authentication_key=BANK["E002"],
            bank_encryption_key=BANK["E002"], **PINNED)


def test_an_upload_has_at_least_one_segment():
    with pytest.raises(ebics3.RequestError, match="segment"):
        btu(num_segments=0)


# --- primitives ------------------------------------------------------------

def test_nonce_is_sixteen_bytes_of_upper_case_hex():
    nonce = ebics3.generate_nonce()
    assert len(nonce) == 32 and nonce == nonce.upper()
    assert bytes.fromhex(nonce)


def test_timestamp_is_utc_to_the_second():
    moment = datetime.datetime(2020, 6, 1, 12, 30, 45,
                               tzinfo=datetime.timezone(datetime.timedelta(hours=2)))
    assert ebics3.utc_timestamp(moment) == "2020-06-01T10:30:45Z"
