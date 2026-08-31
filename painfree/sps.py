"""Swiss Payment Standards rules, checked before anything is signed.

The XSD says whether a `pain.001` is a well-formed ISO 20022 message. It does
not say whether a Swiss bank will accept it, and the gap between those two
questions is where the rejections actually come from: a QR-IBAN carrying an
ISO Creditor Reference, a QR reference whose recursive check digit is wrong, an
amount with three decimals in a two-decimal currency. Every one of those is
schema-valid and every one of them is refused -- hours later, by the bank, when
the order is already in the audit trail. That is why this module runs first.

**What it is checked against.** These are the rules published by SIX Interbank
Clearing as the Swiss Payment Standards -- the *Swiss Implementation Guidelines
for Credit Transfers* (`pain.001`) and the *Swiss Implementation Guidelines
QR-bill* -- resting in turn on three ISO standards that are self-contained
enough to implement exactly:

* **ISO 13616** -- the IBAN, whose check digits are ISO 7064 MOD 97-10.
* **ISO 11649** -- the RF Creditor Reference, `SCOR`, also MOD 97-10.
* the **Modulo 10 recursive** check digit, the Swiss ESR/QR convention, whose
  ten-by-ten carry table is reproduced in :data:`MOD10R`.

The three algorithms are pinned in the tests against reference values taken
from another EBICS implementation's own Swiss templates rather than from our
expectations of them: the QR-IBAN `CH44 3199 9123 0008 8901 2` with the QR
reference `21 00000 00003 13947 14300 09017`, and the regular IBAN
`CH48 2196 6000 0096 1338 8` with `RF18 5390 0754 7034`.

**What is deliberately not checked**, so that its absence is a decision rather
than an oversight: membership of the ISO 4217 currency register. There is no
authoritative copy of that list in this repository, and a hand-typed one would
reject a legitimate payment the first time it was wrong. The XSD's own
``ActiveOrHistoricCurrencyCode`` pattern is the shape check; the bank stays the
authority on which codes exist. What *is* checked is the part that depends on
the currency rather than on the register: the number of minor units it may
carry, and the two currencies a QR-bill is allowed to be denominated in.

Every failure is a :class:`RuleFailure` carrying a stable ``rule`` id, the
dotted ``location`` of the offending field in the submitted instruction, and a
message that **names the field and never quotes its value** -- these messages
travel into the audit log, and a QR reference identifies a bill as surely as an
account number identifies an account.
"""

from __future__ import annotations

import decimal
import re
from dataclasses import dataclass
from typing import Iterable

from painfree.errors import ServiceError

# --- failures ---------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RuleFailure:
    """One broken rule, named precisely enough to fix without guessing."""

    location: str
    rule: str
    message: str

    def as_dict(self) -> dict[str, str]:
        return {"location": self.location, "rule": self.rule,
                "message": self.message}


class ValidationFailed(ServiceError):
    """The instruction is not acceptable. `422`, with every rule that broke.

    All of them, not the first: a caller fixing a batch one rejection per round
    trip is a caller that gives up and mails the file to the bank instead.
    """

    status_code = 422
    code = "validation_failed"

    def __init__(self, failures: Iterable[RuleFailure]) -> None:
        self.failures = tuple(failures)
        if not self.failures:  # pragma: no cover - a guard against an empty raise
            raise ValueError("ValidationFailed needs at least one failure")
        super().__init__(
            "the payment instruction is not valid",
            detail={"failures": [failure.as_dict() for failure in self.failures]},
        )


# --- ISO 7064 MOD 97-10, shared by the IBAN and the RF reference ------------

_ALNUM = re.compile(r"^[0-9A-Z]+$")


def _mod97(value: str) -> int:
    """MOD 97-10 over a string whose letters count as 10..35."""
    digits = "".join(
        str(ord(char) - 55) if char.isalpha() else char for char in value
    )
    return int(digits) % 97


# --- IBAN (ISO 13616) -------------------------------------------------------

#: Length per country. Only the ones a Swiss corporate actually pays to are
#: enumerated; an unlisted country is length-checked loosely (15..34) rather
#: than rejected, because a wrong entry here refuses a valid payment and the
#: check digit catches a typo either way.
IBAN_LENGTHS = {
    "AT": 20, "BE": 16, "CH": 21, "CZ": 24, "DE": 22, "DK": 18, "ES": 24,
    "FI": 18, "FR": 27, "GB": 22, "GR": 27, "HU": 28, "IE": 22, "IT": 27,
    "LI": 21, "LU": 20, "NL": 18, "NO": 15, "PL": 28, "PT": 25, "SE": 24,
    "SI": 19, "SK": 24,
}

#: Swiss QR-IBANs are ordinary IBANs whose IID -- the five characters after the
#: country code and check digits -- falls in this range. SIX reserved it so that
#: a QR-bill account is recognisable from the account number alone.
QR_IID_RANGE = (30000, 31999)


def normalise_iban(value: str) -> str:
    """Upper case with spaces removed. Presentation format is what people paste."""
    return re.sub(r"\s+", "", (value or "")).upper()


def iban_failure(value: str) -> str | None:
    """The rule id an IBAN breaks, or ``None`` if it is well-formed."""
    iban = normalise_iban(value)
    if not (4 <= len(iban) <= 34) or not _ALNUM.match(iban):
        return "iban.format"
    if not iban[:2].isalpha() or not iban[2:4].isdigit():
        return "iban.format"
    expected = IBAN_LENGTHS.get(iban[:2])
    if expected is not None and len(iban) != expected:
        return "iban.length"
    if _mod97(iban[4:] + iban[:4]) != 1:
        return "iban.checksum"
    return None


def swiss_iid(value: str) -> int | None:
    """The five-digit institution id of a Swiss or Liechtenstein IBAN."""
    iban = normalise_iban(value)
    if iban[:2] not in ("CH", "LI") or len(iban) != 21 or not iban[4:9].isdigit():
        return None
    return int(iban[4:9])


def is_qr_iban(value: str) -> bool:
    """Whether this account may -- and therefore must -- carry a QR reference."""
    iid = swiss_iid(value)
    return iid is not None and QR_IID_RANGE[0] <= iid <= QR_IID_RANGE[1]


# --- the QR reference, QRR --------------------------------------------------

#: The Modulo 10 recursive carry table. `MOD10R[carry][digit]` is the next
#: carry; the check digit is `(10 - carry) % 10` once every digit is consumed.
MOD10R = (
    (0, 9, 4, 6, 8, 2, 7, 1, 3, 5),
    (9, 4, 6, 8, 2, 7, 1, 3, 5, 0),
    (4, 6, 8, 2, 7, 1, 3, 5, 0, 9),
    (6, 8, 2, 7, 1, 3, 5, 0, 9, 4),
    (8, 2, 7, 1, 3, 5, 0, 9, 4, 6),
    (2, 7, 1, 3, 5, 0, 9, 4, 6, 8),
    (7, 1, 3, 5, 0, 9, 4, 6, 8, 2),
    (1, 3, 5, 0, 9, 4, 6, 8, 2, 7),
    (3, 5, 0, 9, 4, 6, 8, 2, 7, 1),
    (5, 0, 9, 4, 6, 8, 2, 7, 1, 3),
)

QRR_LENGTH = 27

#: A QR-bill exists in these two currencies and no others.
QR_BILL_CURRENCIES = frozenset({"CHF", "EUR"})


def mod10_recursive(digits: str) -> int:
    """The Swiss recursive check digit over a run of decimal digits."""
    carry = 0
    for char in digits:
        carry = MOD10R[carry][int(char)]
    return (10 - carry) % 10


def normalise_reference(value: str) -> str:
    """References are printed in groups; the groups are not part of the value."""
    return re.sub(r"\s+", "", (value or "")).upper()


def qrr_failure(value: str) -> str | None:
    reference = normalise_reference(value)
    if len(reference) != QRR_LENGTH or not reference.isdigit():
        return "qrr.format"
    if mod10_recursive(reference[:-1]) != int(reference[-1]):
        return "qrr.check_digit"
    return None


def scor_failure(value: str) -> str | None:
    reference = normalise_reference(value)
    # RF + two check digits + 1..21 alphanumeric characters.
    if not re.match(r"^RF[0-9]{2}[0-9A-Z]{1,21}$", reference):
        return "scor.format"
    if _mod97(reference[4:] + reference[:4]) != 1:
        return "scor.check_digit"
    return None


# --- amounts ----------------------------------------------------------------

#: ISO 4217 minor units, as exceptions to the two-decimal default. Rule data,
#: not logic: an entry is added when a currency is added, and nothing else in
#: this module changes.
CURRENCY_MINOR_UNITS = {
    **{code: 0 for code in (
        "BIF", "CLP", "DJF", "GNF", "ISK", "JPY", "KMF", "KRW", "PYG", "RWF",
        "UGX", "UYI", "VND", "VUV", "XAF", "XOF", "XPF")},
    **{code: 3 for code in (
        "BHD", "IQD", "JOD", "KWD", "LYD", "OMR", "TND")},
    **{code: 4 for code in ("CLF", "UYW")},
}

DEFAULT_MINOR_UNITS = 2

CURRENCY_CODE = re.compile(r"^[A-Z]{3}$")


def minor_units(currency: str) -> int:
    return CURRENCY_MINOR_UNITS.get(currency, DEFAULT_MINOR_UNITS)


def amount_failures(amount: decimal.Decimal, currency: str,
                    location: str) -> list[RuleFailure]:
    """Positive, and no more precision than the currency has."""
    failures: list[RuleFailure] = []
    if not CURRENCY_CODE.match(currency or ""):
        failures.append(RuleFailure(
            f"{location}.currency", "currency.format",
            "the currency must be a three-letter ISO 4217 code"))
        return failures
    if amount <= 0:
        failures.append(RuleFailure(
            f"{location}.amount", "amount.positive",
            "the instructed amount must be greater than zero"))
    exponent = -amount.as_tuple().exponent
    allowed = minor_units(currency)
    if exponent > allowed:
        failures.append(RuleFailure(
            f"{location}.amount", "amount.minor_units",
            f"the instructed amount carries more decimal places than this "
            f"currency has minor units ({allowed})"))
    return failures


# --- the rule that ties an account to its reference -------------------------

QRR = "QRR"
SCOR = "SCOR"
NONE = "NONE"

REFERENCE_TYPES = frozenset({QRR, SCOR, NONE})


def reference_failures(
    *,
    creditor_iban: str,
    reference_type: str,
    reference: str | None,
    unstructured: str | None,
    currency: str,
    location: str,
) -> list[RuleFailure]:
    """The Swiss rules that are about the *combination*, not the parts.

    The QR-IBAN and the QR reference are two halves of one decision: SIX
    reserved an IID range so that the account number itself says which reference
    scheme applies, and a bank rejects either half without the other. Everything
    here follows from that, plus the ISO rule that a structured and an
    unstructured remittance are alternatives rather than both.
    """
    failures: list[RuleFailure] = []
    qr_account = is_qr_iban(creditor_iban)

    if reference_type not in REFERENCE_TYPES:
        return [RuleFailure(
            f"{location}.reference.type", "reference.type",
            "the reference type must be QRR, SCOR or NONE")]

    if reference_type == NONE:
        if reference:
            failures.append(RuleFailure(
                f"{location}.reference.reference", "reference.unexpected",
                "a reference value was given but the reference type is NONE"))
    elif not reference:
        failures.append(RuleFailure(
            f"{location}.reference.reference", "reference.missing",
            f"the reference type is {reference_type} but no reference was given"))

    # A structured creditor reference and free-text remittance information are
    # alternatives in the Swiss guidelines, and a message carrying both is
    # rejected rather than truncated.
    if reference_type != NONE and reference and unstructured:
        failures.append(RuleFailure(
            f"{location}.remittance_information", "reference.exclusive",
            "a structured creditor reference and unstructured remittance "
            "information are mutually exclusive"))

    if reference_type == QRR and reference:
        broken = qrr_failure(reference)
        if broken == "qrr.format":
            failures.append(RuleFailure(
                f"{location}.reference.reference", broken,
                f"a QR reference is exactly {QRR_LENGTH} digits"))
        elif broken == "qrr.check_digit":
            failures.append(RuleFailure(
                f"{location}.reference.reference", broken,
                "the QR reference's recursive modulo-10 check digit is wrong"))
        if not qr_account:
            failures.append(RuleFailure(
                f"{location}.creditor_iban", "qrr.requires_qr_iban",
                "a QR reference may only be paid to a QR-IBAN, and the "
                "creditor account is not one"))
        if currency not in QR_BILL_CURRENCIES:
            failures.append(RuleFailure(
                f"{location}.currency", "currency.qr_bill",
                "a QR-bill is denominated in CHF or EUR only"))

    if reference_type == SCOR and reference:
        broken = scor_failure(reference)
        if broken == "scor.format":
            failures.append(RuleFailure(
                f"{location}.reference.reference", broken,
                "an ISO 11649 creditor reference is RF, two check digits and "
                "up to 21 alphanumeric characters"))
        elif broken == "scor.check_digit":
            failures.append(RuleFailure(
                f"{location}.reference.reference", broken,
                "the creditor reference's modulo-97 check digits are wrong"))
        if qr_account:
            failures.append(RuleFailure(
                f"{location}.reference.type", "scor.forbidden_with_qr_iban",
                "the creditor account is a QR-IBAN, which requires a QR "
                "reference rather than an ISO 11649 creditor reference"))

    if reference_type == NONE and qr_account:
        failures.append(RuleFailure(
            f"{location}.reference.type", "qr_iban.requires_qrr",
            "the creditor account is a QR-IBAN, which may only be paid with a "
            "QR reference"))

    return failures


def iban_failures(value: str, location: str, *, what: str) -> list[RuleFailure]:
    """The IBAN rules, phrased for whichever side of the payment this is."""
    broken = iban_failure(value)
    if broken is None:
        return []
    reason = {
        "iban.format": "is not shaped like an IBAN",
        "iban.length": "has the wrong length for its country",
        "iban.checksum": "fails its ISO 7064 check digits",
    }[broken]
    return [RuleFailure(location, broken, f"the {what} IBAN {reason}")]


__all__ = [
    "CURRENCY_MINOR_UNITS", "IBAN_LENGTHS", "MOD10R", "NONE", "QRR",
    "QRR_LENGTH", "QR_BILL_CURRENCIES", "QR_IID_RANGE", "REFERENCE_TYPES",
    "RuleFailure", "SCOR", "ValidationFailed", "amount_failures",
    "iban_failure", "iban_failures", "is_qr_iban", "minor_units",
    "mod10_recursive", "normalise_iban", "normalise_reference",
    "qrr_failure", "reference_failures", "scor_failure", "swiss_iid",
]
