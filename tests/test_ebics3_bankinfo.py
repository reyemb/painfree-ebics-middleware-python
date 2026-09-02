"""Asking the bank what it accepts, instead of reading its PDF.

``HAA``, ``HTD`` and ``HPD`` are the three administrative downloads that turn a
bank's published parameter sheet into something a program can check. The sheet
is what an operator otherwise transcribes into a connection's scheme
configuration by hand, and a transcription is wrong the day the bank changes
something and tells nobody.

Two claims are made here and both are checked against the **official H005
schemas**, which ship in the reference checkout beside this project rather than
being reproduced from memory:

* the requests are documents the schema accepts, and the mandatory
  ``StandardOrderParams`` is present -- its absence is checked too, because a
  builder that quietly omitted it would produce a bank refusal rather than a
  local error, and that is an afternoon;
* the responses parse into the fields that decide something, and a document
  that is not what it claims to be is refused rather than read as empty.

The order data here is written to the schema and validated against it, which is
what makes it evidence rather than a fixture agreeing with the parser it was
written for.
"""

from __future__ import annotations

import pathlib

import pytest
from lxml import etree

from painfree import ebics3
from painfree.ebics3.bankinfo import (parse_haa_order_data,
                                      parse_hpd_order_data,
                                      parse_htd_order_data)
from painfree.ebics3.errors import DocumentError
from painfree.ebics3.requests import RequestContext

NS = "urn:org:ebics:H005"

#: The reference checkout carries the official schemas. Without it these tests
#: are checking documents against nothing, so they skip rather than pass.
SCHEMA = (pathlib.Path.home() / "dev/reyemb/ebics-client-php"
          / "doc/schema/H005/ebics_H005.xsd")


@pytest.fixture(scope="module")
def h005():
    if not SCHEMA.is_file():
        pytest.skip(f"official H005 schema not at {SCHEMA}; "
                    "clone ebics-client-php beside this project")
    return etree.XMLSchema(etree.parse(str(SCHEMA)))


@pytest.fixture(scope="module")
def keys():
    subject = ebics3.subject_name("tester", "Acme AG", "CH")
    bank = ebics3.subject_name("bank", "Bank AG", "CH")
    return (
        ebics3.EbicsKey.generate(ebics3.KeyVersion.X002, subject=subject),
        ebics3.EbicsKey.generate(ebics3.KeyVersion.X002, subject=bank),
        ebics3.EbicsKey.generate(ebics3.KeyVersion.E002, subject=bank),
    )


def _request(order: str, keys):
    ours, bank_auth, bank_enc = keys
    return ebics3.build_admin_download_request(
        RequestContext(host_id="SGKB", partner_id="P1", user_id="U1"),
        order, authentication_key=ours,
        bank_authentication_key=bank_auth, bank_encryption_key=bank_enc)


# --- the requests -------------------------------------------------------------

@pytest.mark.parametrize("order", ["HAA", "HTD", "HPD"])
def test_each_administrative_download_is_a_document_the_schema_accepts(
        order, keys, h005):
    root = _request(order, keys)

    assert h005.validate(root), h005.error_log
    details = root.find(f".//{{{NS}}}OrderDetails")
    assert [etree.QName(node).localname for node in details] == [
        "AdminOrderType", "StandardOrderParams"]
    assert details.find(f"{{{NS}}}AdminOrderType").text == order


def test_the_empty_order_params_is_mandatory_and_not_decoration(keys, h005):
    """``StaticHeaderOrderDetailsType`` declares ``OrderParams`` with no
    ``minOccurs``, so it is required, and ``StandardOrderParams`` is what
    substitutes into it for an administrative order. Leaving it out builds a
    document the bank's schema rejects -- which arrives as a refusal rather
    than as an error here, so it is worth one test."""
    root = _request("HTD", keys)
    details = root.find(f".//{{{NS}}}OrderDetails")
    details.remove(details.find(f"{{{NS}}}StandardOrderParams"))

    assert not h005.validate(root)


def test_an_order_this_engine_does_not_build_is_refused_by_name(keys):
    """`HKD` and `HAC` are real EBICS orders and are deliberately not here.
    Being told which three are known beats a request the bank rejects."""
    with pytest.raises(ebics3.RequestError) as refused:
        _request("HKD", keys)

    assert "HAA" in str(refused.value) and "HTD" in str(refused.value)


# --- the responses ------------------------------------------------------------

def _order_data(name: str, body: str) -> bytes:
    return (f'<?xml version="1.0" encoding="UTF-8"?>'
            f'<{name} xmlns="{NS}">{body}</{name}>').encode()


HTD = _order_data("HTDResponseOrderData", """
  <PartnerInfo>
    <AddressInfo><Name>Muster AG</Name></AddressInfo>
    <BankInfo><HostID>SGKB</HostID></BankInfo>
    <AccountInfo ID="A1" Description="Kontokorrent" Currency="CHF">
      <AccountNumber international="true">CH5604835012345678009</AccountNumber>
    </AccountInfo>
    <OrderInfo>
      <AdminOrderType>BTU</AdminOrderType>
      <Service>
        <ServiceName>MCT</ServiceName>
        <Scope>CH</Scope>
        <MsgName version="09">pain.001</MsgName>
      </Service>
      <Description>Zahlungseinlieferung</Description>
      <NumSigRequired>1</NumSigRequired>
    </OrderInfo>
    <OrderInfo>
      <AdminOrderType>BTD</AdminOrderType>
      <Service>
        <ServiceName>EOP</ServiceName>
        <Scope>CH</Scope>
        <Container containerType="ZIP"/>
        <MsgName version="08">camt.053</MsgName>
      </Service>
      <Description>Kontoauszug</Description>
    </OrderInfo>
    <OrderInfo>
      <AdminOrderType>HAC</AdminOrderType>
      <Description>Kundenprotokoll</Description>
    </OrderInfo>
  </PartnerInfo>
  <UserInfo>
    <UserID>U1</UserID>
    <Name>Tester</Name>
  </UserInfo>
""")


def test_htd_reads_the_catalogue_the_pdf_would_have_carried():
    info = parse_htd_order_data(HTD)

    assert info.user_id == "U1"
    assert info.name == "Muster AG"
    assert [a.account_id for a in info.accounts] == ["A1"]
    assert info.accounts[0].iban == "CH5604835012345678009"
    assert info.accounts[0].currency == "CHF"
    # Three rows, and the administrative one carries no BTF -- which is the
    # schema's shape, not a gap in the parse.
    assert [row.admin_order_type for row in info.orders] == ["BTU", "BTD", "HAC"]
    assert info.orders[2].service is None
    assert info.orders[0].num_sig_required == 1


def test_htd_separates_what_may_be_sent_from_what_may_be_fetched():
    """The upload list is the one a payment is judged against."""
    info = parse_htd_order_data(HTD)

    assert [row.service.name for row in info.uploads()] == ["MCT"]
    assert [row.service.name for row in info.downloads()] == ["EOP"]


def test_a_configured_scheme_can_be_checked_against_what_the_bank_publishes():
    """The point of fetching any of this: answering "will this be accepted"
    without sending a payment to find out.

    The normal profile matches the row the bank publishes. The instant profile
    -- `MCT` with service option `INST` -- does not, because this bank's
    catalogue has one upload row and it carries no option. That is exactly the
    St.Galler Kantonalbank case, and it is the difference between reading it
    here and learning it from `091112` after a signed upload.
    """
    from painfree import schemes

    info = parse_htd_order_data(HTD)
    normal = schemes.DEFAULT_NORMAL
    instant = schemes.DEFAULT_INSTANT

    assert info.offers(ebics3.Service(
        name=normal.service_name, msg_name="pain.001",
        scope=normal.scope, option=normal.service_option))
    assert not info.offers(ebics3.Service(
        name=instant.service_name, msg_name="pain.001",
        scope=instant.scope, option=instant.service_option))


def test_haa_reads_the_services_with_data_waiting():
    services = parse_haa_order_data(_order_data("HAAResponseOrderData", """
      <Service><ServiceName>EOP</ServiceName><Scope>CH</Scope>
        <Container containerType="ZIP"/>
        <MsgName version="08">camt.053</MsgName></Service>
      <Service><ServiceName>PSR</ServiceName><Scope>CH</Scope>
        <MsgName version="10">pain.002</MsgName></Service>
    """))

    assert [s.name for s in services] == ["EOP", "PSR"]
    assert services[0].container == "ZIP"
    assert services[1].msg_version == "10"


def test_an_empty_haa_means_nothing_waiting_rather_than_an_error():
    """A bank with no files ready answers with no services. Raising here would
    turn an ordinary quiet morning into an incident."""
    assert parse_haa_order_data(
        _order_data("HAAResponseOrderData", "")) == ()


def test_hpd_reads_the_versions_the_bank_still_accepts():
    parameters = parse_hpd_order_data(_order_data("HPDResponseOrderData", """
      <AccessParams>
        <URL>https://ebics.sgkb.ch/</URL>
        <Institute>St.Galler Kantonalbank</Institute>
        <HostID>SGKB</HostID>
      </AccessParams>
      <ProtocolParams>
        <Version>
          <Protocol><Version>H005</Version></Protocol>
          <Authentication><Version>X002</Version></Authentication>
          <Encryption><Version>E002</Version></Encryption>
          <Signature><Version>A006</Version></Signature>
        </Version>
        <Recovery supported="true"/>
        <ClientDataDownload supported="false"/>
      </ProtocolParams>
    """))

    assert parameters.host_id == "SGKB"
    assert parameters.protocol_versions == ("H005",)
    assert parameters.authentication_versions == ("X002",)
    assert parameters.signature_versions == ("A006",)
    assert parameters.recovery_supported is True
    assert parameters.client_data_download is False
    # Absent is not false: the bank said nothing about pre-validation.
    assert parameters.pre_validation_supported is None


# --- what the parsers refuse --------------------------------------------------

def test_order_data_that_is_not_what_it_claims_is_refused():
    """Handed the wrong document, an empty structure would read as *this bank
    offers nothing*, which is a conclusion nobody should reach by accident."""
    with pytest.raises(DocumentError) as refused:
        parse_htd_order_data(_order_data("HPDResponseOrderData", ""))

    assert "HTDResponseOrderData" in str(refused.value)

    with pytest.raises(DocumentError):
        parse_haa_order_data(b"<not-even-close/>")

    with pytest.raises(DocumentError):
        parse_hpd_order_data(b"<<<broken")


def test_a_service_missing_what_the_schema_requires_is_refused():
    """``ServiceName`` and ``MsgName`` are both mandatory. A half-service read
    as a service is a BTF comparison that silently never matches."""
    with pytest.raises(DocumentError):
        parse_haa_order_data(_order_data(
            "HAAResponseOrderData", "<Service><Scope>CH</Scope></Service>"))
