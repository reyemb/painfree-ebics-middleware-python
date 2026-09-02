"""Build a `pain.001.001.09` message, and hold it to the official schema.

The XSD in ``painfree/schemas/`` is the ISO 20022 one -- Standards Editor
output, `targetNamespace urn:iso:std:iso:20022:tech:xsd:pain.001.001.09`,
vendored from `ebics-api/ebics-client-php` (MIT) so that validation does not
depend on a checkout sitting next to this one. It is the oracle for this
module: the document is validated against the published schema rather than
against what this file believes it emitted, and the builder's tests assert the
element order the schema's own sequences require rather than the order that
happened to work.

The schema is not the whole answer, which is the point of
:mod:`painfree.sps`. ``ActiveOrHistoricCurrencyAndAmount`` permits five decimal
places in any currency, so a three-decimal CHF amount is schema-valid and
bank-rejected; ``Max35Text`` accepts any 27 characters where a QR reference is
27 *digits* with a recursive check digit. The two layers answer different
questions and both run before anything is signed.

The document carries no ``xsi:schemaLocation``: a hint pointing at a file the
bank does not have is noise, and the namespace already says which message this
is.
"""

from __future__ import annotations

import datetime as _dt
import decimal
import functools
import pathlib
import re
import uuid
from typing import Iterable

from lxml import etree

from painfree import payments, sps
from painfree.schemes import SchemeProfile

#: The ISO 20022 namespace this message lives in. It doubles as the version
#: statement -- `pain.001.001.09` is what Swiss banks take under EBICS 3.0.
NAMESPACE = "urn:iso:std:iso:20022:tech:xsd:pain.001.001.09"
MESSAGE_TYPE = "pain.001.001.09"

SCHEMA_PATH = pathlib.Path(__file__).parent / "schemas" / "pain.001.001.09.xsd"

#: `TRF` -- a credit transfer. The other two `PaymentMethod3Code` values are a
#: cheque and a transfer advice, and neither is something this service sends.
PAYMENT_METHOD = "TRF"

#: What ISO 20022 wants when the caller has no end-to-end reference of its own.
NOT_PROVIDED = "NOTPROVIDED"

#: The `SvcLvl` external code that says a payment follows the SEPA schemes.
#: Not a Swiss value: SPS uses `SvcLvl/Prtry` or nothing at all.
SEPA_SERVICE_LEVEL = "SEPA"


#: `Max35Text`, and 34 characters of it: `PF` plus a UUID's hex. Unique per
#: message because the bank's duplicate detection keys on it, and opaque
#: because a `MsgId` that encodes something is a `MsgId` someone parses.
MESSAGE_ID_PREFIX = "PF"


def new_message_id() -> str:
    """A fresh `MsgId`. Unique, 34 characters, no meaning to read into it."""
    return f"{MESSAGE_ID_PREFIX}{uuid.uuid4().hex.upper()}"


def _text(parent: etree._Element, tag: str, value: str) -> etree._Element:
    element = etree.SubElement(parent, f"{{{NAMESPACE}}}{tag}")
    element.text = value
    return element


def _element(parent: etree._Element, tag: str) -> etree._Element:
    return etree.SubElement(parent, f"{{{NAMESPACE}}}{tag}")


def format_amount(amount: decimal.Decimal, currency: str) -> str:
    """The amount as the currency's minor units, never in exponent notation."""
    quantum = decimal.Decimal(1).scaleb(-sps.minor_units(currency))
    return f"{amount.quantize(quantum):f}"


def _postal_address(parent: etree._Element,
                    address: payments.PostalAddress) -> None:
    # The `PostalAddress24` sequence, in the schema's order: an out-of-order
    # `PstCd` is not a warning, it is an invalid document.
    node = _element(parent, "PstlAdr")
    if address.street:
        _text(node, "StrtNm", address.street)
    if address.building_number:
        _text(node, "BldgNb", address.building_number)
    if address.postal_code:
        _text(node, "PstCd", address.postal_code)
    _text(node, "TwnNm", address.town)
    _text(node, "Ctry", address.country)


def _party(parent: etree._Element, tag: str, party: payments.Party) -> etree._Element:
    node = _element(parent, tag)
    _text(node, "Nm", party.name)
    if party.postal_address:
        _postal_address(node, party.postal_address)
    return node


def declares_sepa(profile) -> bool:
    """Does this profile announce the payment as SEPA?

    ``SvcLvl/Cd`` of ``SEPA`` is the declaration itself, so it is what decides
    whether the rest of the document follows SEPA conventions. A proprietary
    service level is by definition not the SEPA external code, and a profile
    with none is not claiming SEPA either -- both answer ``False``.

    ``None`` for a message built with no profile at all: that is the shape a
    connection with no scheme configuration produces, and it is Swiss by
    default in this service.
    """
    level = getattr(profile, "service_level", None)
    if level is None:
        return False
    return not level.proprietary and level.value == SEPA_SERVICE_LEVEL


def _agent(parent: etree._Element, tag: str, bic: str) -> None:
    node = _element(parent, tag)
    _text(_element(node, "FinInstnId"), "BICFI", bic)


def _account(parent: etree._Element, tag: str, iban: str) -> None:
    node = _element(parent, tag)
    _text(_element(node, "Id"), "IBAN", sps.normalise_iban(iban))


def _remittance(parent: etree._Element, transaction: payments.Transaction) -> None:
    """`RmtInf`, structured or unstructured -- the Swiss rules make it one.

    `Ustrd` precedes `Strd` in `RemittanceInformation16`, and the encoding of
    the reference type is the detail worth pinning: `QRR` is *proprietary*
    (`Prtry`), because the Swiss QR reference is not an ISO document type,
    while `SCOR` is an ISO `DocumentType3Code` and goes in `Cd`. Emitting QRR
    as a code produces a document the schema refuses.
    """
    reference = transaction.reference
    structured = reference.type != sps.NONE and reference.reference
    if not structured and not transaction.remittance_information:
        return

    node = _element(parent, "RmtInf")
    if transaction.remittance_information:
        _text(node, "Ustrd", transaction.remittance_information)
    if structured:
        strd = _element(node, "Strd")
        info = _element(strd, "CdtrRefInf")
        choice = _element(_element(info, "Tp"), "CdOrPrtry")
        if reference.type == sps.QRR:
            _text(choice, "Prtry", sps.QRR)
        else:
            _text(choice, "Cd", sps.SCOR)
        _text(info, "Ref", sps.normalise_reference(reference.reference or ""))
        if transaction.additional_remittance_information:
            _text(strd, "AddtlRmtInf",
                  transaction.additional_remittance_information)


def _payment_type(parent: etree._Element, profile: SchemeProfile) -> None:
    """``PmtTpInf``, in the order ``PaymentTypeInformation26`` fixes.

    ``InstrPrty``, ``SvcLvl``, ``LclInstrm``, ``CtgyPurp`` -- and each of the
    three code slots is a *choice* between ``Cd`` and ``Prtry``, so which
    element is written comes from the profile rather than from a guess about
    the value. A profile with no codes writes nothing at all: an empty
    ``PmtTpInf`` is schema-valid and is a bank's order matcher being told
    something it did not ask for.
    """
    if not profile.emits_payment_type:
        return
    node = _element(parent, "PmtTpInf")
    if profile.instruction_priority:
        _text(node, "InstrPrty", profile.instruction_priority)
    for tag, code in (("SvcLvl", profile.service_level),
                      ("LclInstrm", profile.local_instrument),
                      ("CtgyPurp", profile.category_purpose)):
        if code is not None:
            _text(_element(node, tag), code.tag, code.value)


def build(
    instruction: payments.PaymentInstruction,
    *,
    message_id: str,
    created_at: _dt.datetime,
    payment_information_id: str | None = None,
    software_version: str | None = None,
    payment_type: SchemeProfile | None = None,
    per_transaction: bool = False,
) -> bytes:
    """Render the instruction as a `pain.001.001.09` document.

    The derived fields are derived here and nowhere else: the transaction
    count, the control sum, and the `EndToEndId` of a transfer that did not
    bring one. A caller that supplied its own `NbOfTxs` would eventually supply
    a wrong one, and `NbOfTxs` disagreeing with the transfers present is a
    rejection at the bank rather than a discrepancy anyone notices here.

    ``payment_type`` is the resolved :class:`~painfree.schemes.SchemeProfile`
    for the scheme this document is being sent under. ``per_transaction`` puts
    its ``PmtTpInf`` on every ``CdtTrfTxInf`` instead of on ``PmtInf`` -- ISO
    20022 allows either -- and which one is written follows where the caller
    named the scheme, so a document reads back the way its request was written.
    The profile is the same either way: one upload carries one BTF and the
    scheme is unanimous across a message (:func:`painfree.schemes.resolve`).
    """
    if created_at.tzinfo is None:
        raise ValueError("created_at must be timezone-aware")

    currency = next(iter(instruction.currencies))
    count = str(len(instruction.transactions))
    control_sum = format_amount(instruction.control_sum, currency)

    root = etree.Element(f"{{{NAMESPACE}}}Document", nsmap={None: NAMESPACE})
    initiation = _element(root, "CstmrCdtTrfInitn")

    header = _element(initiation, "GrpHdr")
    _text(header, "MsgId", message_id)
    _text(header, "CreDtTm",
          created_at.astimezone(_dt.timezone.utc).isoformat(timespec="seconds"))
    _text(header, "NbOfTxs", count)
    _text(header, "CtrlSum", control_sum)
    # `InitgPty` is who submitted the file, not who is paying -- the debtor
    # below is that, with its address. A postal address here would be the same
    # address twice, so only the name and the software identification go in.
    initiating = _element(header, "InitgPty")
    _text(initiating, "Nm", instruction.debtor.name)
    if software_version:
        # Which software produced the file. Swiss banks ask for it in support
        # cases, and answering "some middleware" is how a support case stalls.
        contact = _element(initiating, "CtctDtls")
        for channel, value in (("NAME", "painfree"), ("VRSN", software_version)):
            other = _element(contact, "Othr")
            _text(other, "ChanlTp", channel)
            _text(other, "Id", value)

    payment = _element(initiation, "PmtInf")
    _text(payment, "PmtInfId", payment_information_id or message_id)
    _text(payment, "PmtMtd", PAYMENT_METHOD)
    _text(payment, "BtchBookg", "true" if instruction.batch_booking else "false")
    _text(payment, "NbOfTxs", count)
    _text(payment, "CtrlSum", control_sum)
    if payment_type is not None and not per_transaction:
        _payment_type(payment, payment_type)
    _text(_element(payment, "ReqdExctnDt"), "Dt",
          instruction.requested_execution_date.isoformat())
    _party(payment, "Dbtr", instruction.debtor)
    _account(payment, "DbtrAcct", instruction.debtor_iban)
    # `DbtrAgt` is mandatory in `PmtInf` and every child of `FinInstnId` is
    # optional, so with no BIC there are two defensible documents and the
    # scheme decides which.
    #
    # **Under SEPA**, `Othr/Id` of `NOTPROVIDED` is the EPC convention for
    # "IBAN only, no BIC", and receiving banks expect it. **Under the Swiss
    # standards it is refused** -- *"Das Element 'Othr' soll in diesem Kontext
    # nicht verwendet werden"* -- and refused after the file is signed and
    # uploaded, which is the expensive place to find out.
    #
    # So the same field that tells the bank which scheme this is decides which
    # convention to follow: `SvcLvl/Cd` of `SEPA`. Reading the declaration
    # rather than guessing from a currency or an IBAN country means the
    # document cannot claim one scheme and be built for the other -- and a
    # deployment sending real SEPA keeps the element it needs.
    debtor_agent = _element(payment, "DbtrAgt")
    financial = _element(debtor_agent, "FinInstnId")
    if instruction.debtor_bic:
        _text(financial, "BICFI", instruction.debtor_bic)
    elif declares_sepa(payment_type):
        _text(_element(financial, "Othr"), "Id", NOT_PROVIDED)

    for transaction in instruction.transactions:
        _transaction(payment, transaction,
                     payment_type if per_transaction else None)

    return etree.tostring(root, xml_declaration=True, encoding="UTF-8",
                          pretty_print=True)


def _transaction(parent: etree._Element,
                 transaction: payments.Transaction,
                 payment_type: SchemeProfile | None = None) -> None:
    node = _element(parent, "CdtTrfTxInf")
    identification = _element(node, "PmtId")
    if transaction.instruction_id:
        _text(identification, "InstrId", transaction.instruction_id)
    _text(identification, "EndToEndId", transaction.end_to_end_id or NOT_PROVIDED)

    if payment_type is not None:
        # `PmtTpInf` sits between `PmtId` and `Amt` in
        # `CreditTransferTransaction34`. Out of order is not a warning here
        # either; it is an invalid document.
        _payment_type(node, payment_type)

    amount = _text(_element(node, "Amt"), "InstdAmt",
                   format_amount(transaction.amount, transaction.currency))
    amount.set("Ccy", transaction.currency)

    if transaction.creditor_bic:
        _agent(node, "CdtrAgt", transaction.creditor_bic)
    _party(node, "Cdtr", transaction.creditor)
    _account(node, "CdtrAcct", transaction.creditor_iban)
    _remittance(node, transaction)


# --- the schema oracle ------------------------------------------------------


@functools.lru_cache(maxsize=1)
def schema() -> etree.XMLSchema:
    """The compiled XSD, parsed once. Compiling it per request is not free."""
    return etree.XMLSchema(etree.parse(str(SCHEMA_PATH)))


def schema_failures(document: bytes) -> list[sps.RuleFailure]:
    """Every way the document fails the official schema.

    Reaching this with failures means the builder is wrong, not the caller --
    the shape and Swiss layers already ran. It is checked anyway, because
    "the builder is wrong" is exactly the thing that must not be discovered by
    a bank two hours later, and because the schema is the only oracle this
    module has.
    """
    validator = schema()
    parsed = etree.fromstring(document)
    if validator.validate(parsed):
        return []
    return [
        sps.RuleFailure(
            location=_location_of(error),
            rule="xsd.invalid",
            message=error.message or "does not validate against the schema",
        )
        for error in validator.error_log
    ]


#: libxml2 writes the offending element into its own message, and that is the
#: only place it is named: `error.path` is positional (`/*/*/*[1]/*[3]`), which
#: nobody can act on. The name is read back out rather than reported as a path.
_ELEMENT_IN_MESSAGE = re.compile(r"Element '(?:\{[^}]*\})?([^']+)'")


def _location_of(error: object) -> str:
    matched = _ELEMENT_IN_MESSAGE.search(getattr(error, "message", "") or "")
    if matched:
        return matched.group(1)
    path = (getattr(error, "path", None) or "").replace(f"{{{NAMESPACE}}}", "")
    return path or "Document"


def validate_document(document: bytes) -> None:
    """Raise :class:`~painfree.sps.ValidationFailed` if the schema refuses it."""
    failures = schema_failures(document)
    if failures:
        raise sps.ValidationFailed(failures)


def element_paths(document: bytes) -> Iterable[str]:
    """Every element as a slash-separated path. What a structural diff compares."""
    tree = etree.fromstring(document)
    for element in tree.iter():
        if not isinstance(element.tag, str):  # pragma: no cover - comments
            continue
        steps = [step.tag.split("}")[-1]
                 for step in reversed(list(element.iterancestors()))]
        yield "/".join([*steps, element.tag.split("}")[-1]])


__all__ = ["MESSAGE_TYPE", "MESSAGE_ID_PREFIX", "NAMESPACE", "NOT_PROVIDED",
           "SEPA_SERVICE_LEVEL", "declares_sepa",
           "PAYMENT_METHOD", "SCHEMA_PATH", "build", "element_paths",
           "format_amount", "new_message_id", "schema", "schema_failures",
           "validate_document"]
