"""Fixtures shared by the service-layer tests.

Every test gets its own SQLite file, so migrations really do run from empty and
one test cannot see another's audit rows.

The second half of this file is a **bank**: a connection that is fully
initialised the way the worker needs to find it -- subscriber keys sealed in
the keyring, the bank's `X002` and `E002` accepted after a fingerprint
comparison -- and a small HTTP server that answers `BTU` exchanges the way a
bank does. That server is what the worker's tests point a `HostURL` at, so the
upload path runs over a real socket rather than against a mocked transport.

The bank keys are **generated per test**, not borrowed, and the stub signs its
responses with the same `X002` key the keyring holds, so the worker's signature
verification is genuinely exercised rather than switched off.

The same stub serves downloads. There the bank is the one doing the encrypting:
it mints a transaction key, wraps it to the *subscriber's* `E002` public half
and cuts the encoded stream into segments, which is the direction
``open_order_data`` has to read back. The crypto underneath that is proved
elsewhere, against other implementations; what these tests are about is the
worker driving the exchange, storing what came out and acknowledging it.
"""

from __future__ import annotations

import base64
import contextlib
import datetime as _dt
import io
import pathlib
import threading
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from lxml import etree

from painfree import authn, db, ebics3
from painfree.audit import Actor, AuditLog
from painfree.config import Settings, load_settings
from painfree.connections import ConnectionRegistry
from painfree.identity import Level
from painfree.keyring import KeyCustodian
from painfree.schema import bank_connection


@pytest.fixture
def sqlite_url(tmp_path: pathlib.Path) -> str:
    return f"sqlite+pysqlite:///{tmp_path / 'painfree.db'}"


@pytest.fixture
def settings(sqlite_url: str) -> Settings:
    return load_settings(database_url=sqlite_url)


#: Generated once for the suite rather than per test, because deriving a custody
#: key is HKDF over a secret and the tests care about what it protects, not
#: about how fast it derives.
CUSTODY_SECRET = "test-only-custody-secret-Sk9pQ2x1-do-not-reuse"


@pytest.fixture
def custody_secret() -> str:
    return CUSTODY_SECRET


@pytest.fixture
def custody_settings(sqlite_url: str, custody_secret: str) -> Settings:
    """Settings that can seal and open a keyring, as the worker's would."""
    return load_settings(database_url=sqlite_url,
                         key_encryption_secret=custody_secret)


# --- credentials ------------------------------------------------------------
#
# Nothing but the probes and the login flow is reachable without one, so a test
# that drives an endpoint has to present something. In the development
# authentication mode -- which production refuses to start in -- that something
# is a header.

#: What a production process needs before it has an identity provider at all.
#: Every production case here supplies it for the same reason it supplies a
#: custody secret: the process refuses to start without it.
PRODUCTION_OIDC = {
    "auth_mode": "oidc",
    "oidc_issuer": "https://id.example.test/realms/painfree",
    "oidc_client_id": "painfree",
    "oidc_redirect_uri": "https://painfree.example.test/auth/callback",
}


def dev_credentials(subject: str = "tester",
                    roles: str = "admin") -> dict[str, str]:
    """Headers that authenticate as ``subject`` with ``roles``.

    The roles claim decides one thing only: whether the caller is an `admin`.
    What a member may touch is a **grant**, which is a database row -- see
    :func:`grant`. Nothing here fabricates one, deliberately: a header that
    could confer access to a bank connection would leave the per-connection
    half of the model untested by every test in this suite.
    """
    return {authn.DEV_PRINCIPAL_HEADER: subject, authn.DEV_ROLES_HEADER: roles}


def grant(app, subject: str, connection_id: str, level: str = "operator"):
    """Give ``subject`` a real grant on ``connection_id``, the way an admin would.

    Through :class:`painfree.access.Grants`, not through an `INSERT`: a test
    that wrote the row itself would pass while the store that writes it in
    production was broken.
    """
    return app.state.grants.grant(
        subject, connection_id, Level(level),
        actor=Actor("user", "test-administrator"))


def revoke(app, subject: str, connection_id: str) -> bool:
    return app.state.grants.revoke(
        subject, connection_id, actor=Actor("user", "test-administrator"))


def grant_oversight(app, subject: str):
    """Give ``subject`` deployment-wide read-only oversight.

    Through the store, like :func:`grant`, and for the same reason: a test that
    inserted the row itself would keep passing while the only code path that
    writes one in production was broken.
    """
    return app.state.grants.grant_oversight(
        subject, actor=Actor("user", "test-administrator"))


def revoke_oversight(app, subject: str) -> bool:
    return app.state.grants.revoke_oversight(
        subject, actor=Actor("user", "test-administrator"))


# --- payment instructions ---------------------------------------------------
#
# The account numbers and references below are not invented. They are the
# values another EBICS implementation ships in its own Swiss `pain.001`
# templates -- `ebics-java/ebics-web-client`, `ebics-dbmodel/.../
# upload-templates/pain.001.001.09_PaymentType_Domestic_{QRR,SCOR}.xml` --
# which is what makes them useful: the QR-IBAN really is in the QR-IID range,
# the QR reference really does carry a correct recursive check digit, and the
# RF reference really does satisfy ISO 11649. A rule that accepts a value we
# made up has proved nothing.

#: IID 31999, inside the 30000..31999 QR range.
QR_IBAN = "CH4431999123000889012"
QRR_REFERENCE = "210000000003139471430009017"

#: IID 21966: an ordinary account, which may not carry a QR reference.
PLAIN_IBAN = "CH4821966000009613388"
SCOR_REFERENCE = "RF18539007547034"

DEBTOR_IBAN = "CH5604835012345678009"
DEBTOR_BIC = "CRESCHZZ80A"


def payment_body(**overrides) -> dict:
    """The JSON a caller posts: one debtor, one transfer to a QR-IBAN."""
    body = {
        "debtor": {"name": "MUSTER AG",
                   "postal_address": {"town": "SELDWYLA", "country": "CH"}},
        "debtor_iban": DEBTOR_IBAN,
        "debtor_bic": DEBTOR_BIC,
        "requested_execution_date": "2026-09-01",
        "transactions": [transfer()],
    }
    body.update(overrides)
    return body


def transfer(**overrides) -> dict:
    """One credit transfer, QR-IBAN and QR reference by default."""
    entry = {
        "amount": "3949.75",
        "currency": "CHF",
        "creditor": {
            "name": "Robert Schneider AG",
            "postal_address": {"street": "Rue du Lac", "building_number": "1268",
                               "postal_code": "2501", "town": "Biel",
                               "country": "CH"},
        },
        "creditor_iban": QR_IBAN,
        "reference": {"type": "QRR", "reference": QRR_REFERENCE},
    }
    entry.update(overrides)
    return entry


def scor_transfer(**overrides) -> dict:
    """One credit transfer to an ordinary IBAN with an ISO 11649 reference."""
    entry = {"creditor_iban": PLAIN_IBAN,
             "reference": {"type": "SCOR", "reference": SCOR_REFERENCE}}
    entry.update(overrides)
    return transfer(**entry)


# --- a bank ----------------------------------------------------------------

EBICS_NS = ebics3.EBICS_NAMESPACE
DSIG_NS = ebics3.XMLDSIG_NAMESPACE

#: Hex, sixteen bytes, as `TransactionIDType` requires.
TRANSACTION_ID = "A1B2C3D4E5F60718293A4B5C6D7E8F90"

BANK_ORDER_ID = "N01A"

BANK_CONNECTION_ID = "test-bank"


def bank_subject(name: str = "acme"):
    return ebics3.subject_name(name, "Acme AG", "CH")


@pytest.fixture
def prepared_bank(custody_settings):
    """A connection the worker can upload for: keys sealed, bank keys accepted.

    Returns ``(engine, connection, bank_keys)`` where ``bank_keys`` still has
    its private halves -- the stub server needs the `X002` private key to sign
    its responses, which a real bank has and this service never does.
    """
    engine = db.build_engine(custody_settings)
    db.migrate(engine)
    audit = AuditLog(engine)
    registry = ConnectionRegistry(engine, audit)
    custodian = KeyCustodian(engine, audit, custody_settings.custody_key())

    registry.register(
        BANK_CONNECTION_ID, host_id="TESTHOST", partner_id="PARTNER1",
        user_id="USER1", host_url="http://127.0.0.1:1/ebics")
    custodian.create_subscriber_keys(BANK_CONNECTION_ID, subject=bank_subject())

    bank = {
        version: ebics3.EbicsKey.generate(version, subject=bank_subject("bank"))
        for version in (ebics3.KeyVersion.X002, ebics3.KeyVersion.E002)
    }
    keys = ebics3.BankKeys(authentication=bank[ebics3.KeyVersion.X002],
                           encryption=bank[ebics3.KeyVersion.E002])
    custodian.accept_bank_keys(
        BANK_CONNECTION_ID, keys,
        {"authentication": keys.authentication.fingerprint_hex,
         "encryption": keys.encryption.fingerprint_hex})
    # `INI`, `HIA` and the letter comparison are not re-driven here -- they are
    # `test_ebics3_initialisation`'s subject, and three more RSA generations
    # per test would buy nothing. The state they end at is written directly.
    with engine.begin() as connection:
        connection.execute(
            bank_connection.update()
            .where(bank_connection.c.connection_id == BANK_CONNECTION_ID)
            .values(key_state=ebics3.KeyState.READY.value,
                    ini_sent=True, hia_sent=True))
    yield engine, registry.get(BANK_CONNECTION_ID), keys
    engine.dispose()


def bank_response(phase: str, *, signing_key: ebics3.EbicsKey,
                  transaction_id: str | None = TRANSACTION_ID,
                  segment_number: int | None = None, last: bool = False,
                  order_id: str | None = None, return_code: str = "000000",
                  report_text: str = "[EBICS_OK] OK",
                  body_return_code: str = "000000") -> bytes:
    """One `ebicsResponse`, signed with the bank's `X002` key.

    Built here rather than captured because what varies between the cases the
    worker has to handle -- a refusal, a retryable code, a missing segment
    number -- is exactly the part a fixture would freeze.
    """
    root = etree.Element(etree.QName(EBICS_NS, "ebicsResponse"),
                         nsmap={None: EBICS_NS, "ds": DSIG_NS})
    root.set("Version", "H005")
    root.set("Revision", "1")

    header = _sub(root, "header", authenticate="true")
    static = _sub(header, "static")
    if transaction_id is not None:
        _sub(static, "TransactionID", transaction_id)

    mutable = _sub(header, "mutable")
    _sub(mutable, "TransactionPhase", phase)
    if segment_number is not None:
        _sub(mutable, "SegmentNumber", str(segment_number),
             lastSegment="true" if last else "false")
    if order_id is not None:
        _sub(mutable, "OrderID", order_id)
    _sub(mutable, "ReturnCode", return_code)
    _sub(mutable, "ReportText", report_text)

    body = _sub(root, "body")
    _sub(body, "ReturnCode", body_return_code, authenticate="true")

    ebics3.build_auth_signature(root, signing_key.private_key, "X002")
    return etree.tostring(root, xml_declaration=True, encoding="UTF-8")


def upload_script(signing_key: ebics3.EbicsKey, seen: list[bytes]):
    """The ordinary bank: acknowledge the announcement, then every segment."""
    def script(body: bytes) -> bytes:
        seen.append(body)
        number = _segment_number(body)
        if number is None:
            return bank_response("Initialisation", signing_key=signing_key)
        return bank_response("Transfer", signing_key=signing_key,
                             segment_number=number, last=True,
                             order_id=BANK_ORDER_ID)
    return script


def btf_in(body: bytes) -> tuple[str, str | None, str | None] | None:
    """The BTF triplet the request announces, read out of the cleartext header.

    `BTUOrderParams/Service` travels unencrypted -- it is what the bank matches
    against its own catalogue before it can decrypt anything -- so a stub bank
    can answer differently per scheme exactly as a real one does. Returns
    ``(ServiceName, ServiceOption, Scope)``, or ``None`` for a request that
    carries no ``Service`` (a transfer segment, or a receipt).
    """
    root = etree.fromstring(body)
    found = root.xpath("//*[local-name()='BTUOrderParams']"
                       "/*[local-name()='Service']")
    if not found:
        return None
    def text(name: str) -> str | None:
        node = found[0].xpath(f"./*[local-name()='{name}']")
        return node[0].text if node else None
    return text("ServiceName"), text("ServiceOption"), text("Scope")


def payment_type_in(document: bytes) -> list[str]:
    """Every ``PmtTpInf`` in a `pain.001`, as ``parent: Tag/Choice=value``.

    Reads the element the schema fixes rather than the summary this service
    stores beside it, so the two can be compared instead of one being trusted.
    """
    root = etree.fromstring(document)
    summaries = []
    for node in root.xpath("//*[local-name()='PmtTpInf']"):
        parent = etree.QName(node.getparent()).localname
        parts = []
        for child in node:
            tag = etree.QName(child).localname
            if len(child):
                inner = child[0]
                parts.append(f"{tag}/{etree.QName(inner).localname}"
                             f"={inner.text}")
            else:
                parts.append(f"{tag}={child.text}")
        summaries.append(f"{parent}: " + " ".join(parts))
    return summaries


def _segment_number(body: bytes) -> int | None:
    root = etree.fromstring(body)
    found = root.xpath("//*[local-name()='SegmentNumber']")
    return int(found[0].text) if found else None


def msg_ids_in(seen: list[bytes]) -> set[str]:
    """Every `MsgId` the bank was shown, read out of the ES.

    An upload's payload is encrypted, but the `MsgId` is what the *file name*
    carries, and the file name is in the clear in `BTUOrderParams`. That is
    enough to answer the only question that matters: did this service put two
    different messages on the wire for one order?
    """
    names: set[str] = set()
    for body in seen:
        root = etree.fromstring(body)
        for params in root.xpath("//*[local-name()='BTUOrderParams']"):
            name = params.get("fileName")
            if name:
                names.add(name)
    return names


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self) -> None:  # noqa: N802 -- BaseHTTPRequestHandler API
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        try:
            payload = self.server.script(body)
        except _HangUp:
            # The bank drops the connection mid-exchange. The client sees a
            # transport failure with the request already sent, which is the
            # case the retry path has to get right.
            self.close_connection = True
            self.wfile.close()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/xml; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args) -> None:
        pass


class _HangUp(Exception):
    """Raised by a script to make the bank drop the connection."""


hang_up = _HangUp


@contextlib.contextmanager
def serving_bank(script):
    """Run the stub bank for the duration of the block; yields its `HostURL`."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server.script = script
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://{server.server_address[0]}:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _sub(parent, name: str, text: str | None = None, **attributes):
    element = etree.SubElement(parent, etree.QName(EBICS_NS, name))
    if text is not None:
        element.text = text
    for key, value in attributes.items():
        element.set(key, value)
    return element


def utcnow() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def reset_database(engine) -> None:
    """Drop every table this service owns. The PostgreSQL database is shared.

    Driven off the metadata rather than off a list written out per test file:
    the per-file lists drifted the moment anything added a table, and the
    symptom was a migration failing with "relation already exists" in an
    unrelated test.
    """
    from painfree.schema import metadata

    metadata.drop_all(engine)
    with engine.begin() as connection:
        connection.exec_driver_sql("DROP TABLE IF EXISTS alembic_version")


# --- downloaded documents ---------------------------------------------------

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
SCHEMAS = pathlib.Path(__file__).parent / "schemas"

#: The four message types this service normalises, each with the schema it is
#: held to. `camt.054` is at `.09` because no `.08` schema could be found; see
#: `tests/schemas/README.md`.
MESSAGE_TYPES = ("camt.052.001.08", "camt.053.001.08", "camt.054.001.09",
                 "pain.002.001.10")


def fixture_bytes(message_type: str) -> bytes:
    return (FIXTURES / f"{message_type}.xml").read_bytes()


def schema_for(message_type: str):
    """The official XSD for one message type, compiled."""
    return etree.XMLSchema(etree.parse(str(SCHEMAS / f"{message_type}.xsd")))


def zipped(*message_types: str) -> bytes:
    """The fixtures as a ZIP container, which is how a bank sends `camt`."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for message_type in message_types:
            archive.writestr(f"{message_type}.xml", fixture_bytes(message_type))
    return buffer.getvalue()


#: A `pain.002` the way a bank answers one of *our* `pain.001` files: the
#: `OrgnlMsgId` is the `MsgId` this service generated, which a committed fixture
#: cannot know. So the status reports the reconciliation tests need are built
#: here rather than read from a file, and every one of them is held to the
#: official `pain.002.001.10` XSD by :func:`valid_payment_status` before a
#: single assertion is made about what was parsed out of it.
#:
#: They are **derived from the schema**, not captured: the pooled reference
#: corpus (`ebics-client-php`, `epics`) contains no `pain.002` document at all
#: -- neither project ships one, and neither ships the schema either. See
#: `tests/schemas/README.md` for where the XSD itself came from.
PAIN002_NAMESPACE = "urn:iso:std:iso:20022:tech:xsd:pain.002.001.10"
PAIN002_TYPE = "pain.002.001.10"


def status_transaction(status: str, *, end_to_end: str = "E2E-0001",
                       instruction: str = "INSTR-0001",
                       amount: str = "3949.75", currency: str = "CHF",
                       reason_code: str | None = None,
                       reason_text: str | None = None,
                       originator: str = "CREDIT SUISSE (SCHWEIZ) AG") -> dict:
    """One `TxInfAndSts`, as the builder below wants it."""
    return {"status": status, "end_to_end": end_to_end,
            "instruction": instruction, "amount": amount, "currency": currency,
            "reason_code": reason_code, "reason_text": reason_text,
            "originator": originator}


def payment_status(original_msg_id: str, *, report_id: str = "STSRPT-0001",
                   group_status: str | None = "ACSP",
                   payment_status: str | None = None,
                   transactions: tuple = (),
                   reason_code: str | None = None,
                   reason_text: str | None = None,
                   number_of_transactions: str = "1",
                   control_sum: str = "3949.75",
                   created_at: str = "2026-08-29T08:00:00Z") -> bytes:
    """One `pain.002.001.10` answering ``original_msg_id``.

    ``report_id`` is the report's *own* `MsgId`. Two reports about one order
    differ in it, which is what stops the second being filed as a re-serve of
    the first.
    """
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<Document xmlns="{PAIN002_NAMESPACE}">', "  <CstmrPmtStsRpt>",
        "    <GrpHdr>", f"      <MsgId>{report_id}</MsgId>",
        f"      <CreDtTm>{created_at}</CreDtTm>", "    </GrpHdr>",
        "    <OrgnlGrpInfAndSts>",
        f"      <OrgnlMsgId>{original_msg_id}</OrgnlMsgId>",
        "      <OrgnlMsgNmId>pain.001.001.09</OrgnlMsgNmId>",
        "      <OrgnlCreDtTm>2026-08-28T17:42:11Z</OrgnlCreDtTm>",
        f"      <OrgnlNbOfTxs>{number_of_transactions}</OrgnlNbOfTxs>",
        f"      <OrgnlCtrlSum>{control_sum}</OrgnlCtrlSum>",
    ]
    if group_status is not None:
        lines.append(f"      <GrpSts>{group_status}</GrpSts>")
    lines += _status_reason(reason_code, reason_text, indent=6)
    lines.append("    </OrgnlGrpInfAndSts>")
    if transactions or payment_status is not None:
        lines += ["    <OrgnlPmtInfAndSts>",
                  "      <OrgnlPmtInfId>PMTINF-0001</OrgnlPmtInfId>",
                  f"      <OrgnlNbOfTxs>{number_of_transactions}</OrgnlNbOfTxs>",
                  f"      <OrgnlCtrlSum>{control_sum}</OrgnlCtrlSum>"]
        if payment_status is not None:
            lines.append(f"      <PmtInfSts>{payment_status}</PmtInfSts>")
        for index, one in enumerate(transactions, start=1):
            lines += [
                "      <TxInfAndSts>",
                f"        <StsId>STS-{index:04d}</StsId>",
                f"        <OrgnlInstrId>{one['instruction']}</OrgnlInstrId>",
                f"        <OrgnlEndToEndId>{one['end_to_end']}</OrgnlEndToEndId>",
                f"        <TxSts>{one['status']}</TxSts>",
            ]
            lines += _status_reason(one["reason_code"], one["reason_text"],
                                    indent=8, originator=one["originator"])
            lines += [
                "        <OrgnlTxRef>", "          <Amt>",
                f'            <InstdAmt Ccy="{one["currency"]}">'
                f'{one["amount"]}</InstdAmt>',
                "          </Amt>", "          <ReqdExctnDt>",
                "            <Dt>2026-09-01</Dt>", "          </ReqdExctnDt>",
                "        </OrgnlTxRef>", "      </TxInfAndSts>",
            ]
        lines.append("    </OrgnlPmtInfAndSts>")
    lines += ["  </CstmrPmtStsRpt>", "</Document>", ""]
    return "\n".join(lines).encode("utf-8")


def _status_reason(code: str | None, text: str | None, *, indent: int,
                   originator: str = "CREDIT SUISSE (SCHWEIZ) AG") -> list[str]:
    if code is None and text is None:
        return []
    pad = " " * indent
    lines = [f"{pad}<StsRsnInf>",
             f"{pad}  <Orgtr><Nm>{originator}</Nm></Orgtr>"]
    if code is not None:
        lines.append(f"{pad}  <Rsn><Cd>{code}</Cd></Rsn>")
    if text is not None:
        lines.append(f"{pad}  <AddtlInf>{text}</AddtlInf>")
    lines.append(f"{pad}</StsRsnInf>")
    return lines


def valid_payment_status(document: bytes) -> bytes:
    """The document, once the official XSD has agreed it is one.

    Called by every test that builds one. A parser proved right against a
    document only this repository believes in has proved nothing -- the schema
    is the independent oracle, and it is applied before the assertions.
    """
    schema = schema_for(PAIN002_TYPE)
    parsed = etree.fromstring(document)
    if not schema.validate(parsed):
        raise AssertionError(
            f"the built pain.002 is not valid against {PAIN002_TYPE}.xsd: "
            f"{schema.error_log}")
    return document


#: Small enough that the fixtures need several segments, and a multiple of four
#: so every cut stays base64-aligned.
DOWNLOAD_SEGMENT_SIZE = 512


def download_script(signing_key: ebics3.EbicsKey,
                    encryption_key: ebics3.EbicsKey, payload: bytes,
                    seen: list[bytes], *,
                    segment_size: int = DOWNLOAD_SEGMENT_SIZE,
                    receipt_code: str = "011000"):
    """A bank that serves one `BTD`: the key, the segments, then the receipt.

    ``encryption_key`` is the *subscriber's* `E002` public half -- the bank
    encrypts to the client, which is the direction that makes a download
    readable at all.
    """
    transaction_key = ebics3.generate_transaction_key()
    encoded = ebics3.encrypt_payload(payload, transaction_key)
    segments = ebics3.split_segments(encoded, segment_size)
    wrapped = ebics3.wrap_transaction_key(transaction_key, encryption_key)

    def script(body: bytes) -> bytes:
        seen.append(body)
        phase = _phase(body)
        if phase == "Receipt":
            return bank_response("Receipt", signing_key=signing_key,
                                 return_code=receipt_code,
                                 report_text="[EBICS_DOWNLOAD_POSTPROCESS_DONE] "
                                             "positive receipt received")
        number = _segment_number(body) or 1
        return download_response(
            phase, signing_key=signing_key, segment=segments[number - 1],
            number=number, last=number == len(segments),
            num_segments=len(segments) if phase == "Initialisation" else None,
            wrapped_key=wrapped if phase == "Initialisation" else None)

    script.segments = segments
    return script


def no_data_script(signing_key: ebics3.EbicsKey, seen: list[bytes]):
    """A bank with nothing to send: `090005`, and the transaction is over.

    Not an error. `EBICS_NO_DOWNLOAD_DATA_AVAILABLE` is what a scheduled
    download finds most of the time.
    """
    def script(body: bytes) -> bytes:
        seen.append(body)
        return bank_response(
            "Initialisation", signing_key=signing_key, return_code="090005",
            report_text="[EBICS_NO_DOWNLOAD_DATA_AVAILABLE] no download data "
                        "available")
    return script


def download_response(phase: str, *, signing_key: ebics3.EbicsKey,
                      segment: str, number: int, last: bool,
                      num_segments: int | None = None,
                      wrapped_key: bytes | None = None) -> bytes:
    """One `ebicsResponse` carrying a download segment, signed with `X002`.

    ``DataEncryptionInfo`` travels once, with the initialisation response, which
    is the part a client that decrypts segment by segment gets wrong.
    """
    root = etree.Element(etree.QName(EBICS_NS, "ebicsResponse"),
                         nsmap={None: EBICS_NS, "ds": DSIG_NS})
    root.set("Version", "H005")
    root.set("Revision", "1")

    header = _sub(root, "header", authenticate="true")
    static = _sub(header, "static")
    _sub(static, "TransactionID", TRANSACTION_ID)
    if num_segments is not None:
        _sub(static, "NumSegments", str(num_segments))

    mutable = _sub(header, "mutable")
    _sub(mutable, "TransactionPhase", phase)
    _sub(mutable, "SegmentNumber", str(number),
         lastSegment="true" if last else "false")
    _sub(mutable, "ReturnCode", "000000")
    _sub(mutable, "ReportText", "[EBICS_OK] OK")

    body = _sub(root, "body")
    transfer = _sub(body, "DataTransfer")
    if wrapped_key is not None:
        encryption = _sub(transfer, "DataEncryptionInfo", authenticate="true")
        _sub(encryption, "EncryptionPubKeyDigest", "AAAA", Version="E002",
             Algorithm="http://www.w3.org/2001/04/xmlenc#sha256")
        _sub(encryption, "TransactionKey",
             base64.b64encode(wrapped_key).decode())
    _sub(transfer, "OrderData", segment)
    _sub(body, "ReturnCode", "000000", authenticate="true")

    ebics3.build_auth_signature(root, signing_key.private_key, "X002")
    return etree.tostring(root, xml_declaration=True, encoding="UTF-8")


def _phase(body: bytes) -> str:
    found = etree.fromstring(body).xpath("//*[local-name()='TransactionPhase']")
    return found[0].text if found else "Initialisation"


def phases_in(seen: list[bytes]) -> list[str]:
    """Which phases the bank was taken through, in order."""
    return [_phase(body) for body in seen]


# --- a bank that answers the key lifecycle ---------------------------------
#
# `INI`, `HIA` and `HPB` are a different envelope from a transaction:
# `ebicsKeyManagementResponse`, with an `OrderID` for the two registrations and
# a `DataTransfer` for the one download. The bank's own keys are generated per
# test like every other key here, so the fingerprints the console ends up
# comparing are values the test computed rather than values it asserted.

KEY_MANAGEMENT_ORDER_IDS = {"INI": "A001", "HIA": "A002"}


def key_management_response(*, order_id: str | None = None,
                            return_code: str = "000000",
                            report_text: str = "[EBICS_OK] OK",
                            order_data: str | None = None,
                            wrapped_key: bytes | None = None) -> bytes:
    """One `ebicsKeyManagementResponse`. Unsigned -- H005 has no signature here."""
    root = etree.Element(etree.QName(EBICS_NS, "ebicsKeyManagementResponse"),
                         nsmap={None: EBICS_NS, "ds": DSIG_NS})
    root.set("Version", "H005")
    root.set("Revision", "1")
    header = _sub(root, "header", authenticate="true")
    _sub(header, "static")
    mutable = _sub(header, "mutable")
    if order_id is not None:
        _sub(mutable, "OrderID", order_id)
    _sub(mutable, "ReturnCode", return_code)
    _sub(mutable, "ReportText", report_text)

    body = _sub(root, "body")
    if order_data is not None:
        transfer = _sub(body, "DataTransfer")
        encryption = _sub(transfer, "DataEncryptionInfo", authenticate="true")
        _sub(encryption, "EncryptionPubKeyDigest", "AAAA", Version="E002",
             Algorithm="http://www.w3.org/2001/04/xmlenc#sha256")
        _sub(encryption, "TransactionKey",
             base64.b64encode(wrapped_key or b"").decode())
        _sub(transfer, "OrderData", order_data)
    _sub(body, "ReturnCode", return_code, authenticate="true")
    return etree.tostring(root, xml_declaration=True, encoding="UTF-8")


def hpb_order_data(bank_keys: ebics3.BankKeys, host_id: str) -> bytes:
    """`HPBResponseOrderData`: the bank's two keys, each inside a certificate."""
    root = etree.Element(etree.QName(EBICS_NS, "HPBResponseOrderData"),
                         nsmap={None: EBICS_NS, "ds": DSIG_NS})
    for element, key in (("AuthenticationPubKeyInfo", bank_keys.authentication),
                         ("EncryptionPubKeyInfo", bank_keys.encryption)):
        info = _sub(root, element)
        data = etree.SubElement(info, etree.QName(DSIG_NS, "X509Data"))
        certificate = etree.SubElement(data, etree.QName(DSIG_NS, "X509Certificate"))
        certificate.text = base64.b64encode(
            ebics3.certificate_der(key.certificate)).decode()
        _sub(info, f"{element[:-len('PubKeyInfo')]}Version", key.version.value)
    _sub(root, "HostID", host_id)
    return etree.tostring(root, xml_declaration=True, encoding="UTF-8")


def initialisation_script(bank_keys: ebics3.BankKeys, subscriber_encryption,
                          seen: list[bytes], *, host_id: str = "TESTHOST",
                          return_code: str = "000000"):
    """A bank that answers INI, HIA and HPB.

    ``subscriber_encryption`` is *our* `E002` public half -- an ``EbicsKey``, or
    a callable returning one, because the keys are minted by the first job this
    server is asked about and do not exist when it starts. The bank encrypts the
    HPB payload to the client, which is the direction that makes it readable at
    all and the reason this exchange needs the worker's custody key.
    """
    def script(body: bytes) -> bytes:
        seen.append(body)
        order_type = _order_type(body)
        if order_type in KEY_MANAGEMENT_ORDER_IDS:
            return key_management_response(
                order_id=KEY_MANAGEMENT_ORDER_IDS[order_type],
                return_code=return_code,
                report_text="[EBICS_OK] OK" if return_code == "000000"
                            else "[EBICS_INVALID_USER_STATE] invalid user state")
        transaction_key = ebics3.generate_transaction_key()
        encoded = ebics3.encrypt_payload(hpb_order_data(bank_keys, host_id),
                                         transaction_key)
        return key_management_response(
            order_data=encoded,
            wrapped_key=ebics3.wrap_transaction_key(
                transaction_key,
                subscriber_encryption() if callable(subscriber_encryption)
                else subscriber_encryption))
    return script


def _order_type(body: bytes) -> str:
    root = etree.fromstring(body)
    for name in ("OrderType", "AdminOrderType"):
        found = root.xpath(f"//*[local-name()='{name}']")
        if found:
            return (found[0].text or "").strip()
    return ""
