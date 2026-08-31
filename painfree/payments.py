"""The payment instruction as a caller sends it, and the rules it has to pass.

This is the JSON half of "JSON in, EBICS out". A caller describes one debit
account, an execution date and a list of credit transfers; everything ISO 20022
needs and this service can derive -- the message id, the timestamp, the
transaction count, the control sum -- is derived rather than demanded, because
a field the caller has to compute is a field the caller computes wrongly.

Two layers of validation, in this order and for a reason:

1. **Shape**, by the model below. Lengths and patterns come from the ISO 20022
   types the builder will emit into (``Max35Text``, ``Max140Text``,
   ``CountryCode``, ``BICFIDec2014Identifier``), so a value that would fail the
   XSD fails here first, against a field name the caller recognises rather than
   an XPath.
2. **Meaning**, by :func:`swiss_failures`, which is :mod:`painfree.sps` applied
   to a whole instruction: the IBANs, the references, the amounts, and the
   Swiss rules about the combination of an account and its reference.

Both run before a document is built and long before anything is signed. Neither
needs a key, and the module imports nothing that could open one.
"""

from __future__ import annotations

import datetime as _dt
import decimal
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from painfree import sps
from painfree.schemes import PaymentScheme

# ISO 20022 text types, expressed once so the model and the builder cannot
# disagree about what fits.
Max16Text = Annotated[str, Field(min_length=1, max_length=16)]
Max35Text = Annotated[str, Field(min_length=1, max_length=35)]
Max70Text = Annotated[str, Field(min_length=1, max_length=70)]
Max140Text = Annotated[str, Field(min_length=1, max_length=140)]
CountryCode = Annotated[str, Field(pattern=r"^[A-Z]{2}$")]
Bic = Annotated[str, Field(pattern=r"^[A-Z0-9]{4}[A-Z]{2}[A-Z0-9]{2}([A-Z0-9]{3})?$")]

#: How many transfers one message may carry. Not a protocol limit -- a limit on
#: how much a single validation failure can cost a caller to re-send, and on how
#: large a document the worker has to segment.
MAX_TRANSACTIONS = 1000


class PostalAddress(BaseModel):
    """Structured, never a free-text block.

    Swiss banks are on structured addresses; `AdrLine` is the legacy form and
    is deliberately not offered, so nothing has to be migrated off it later.
    """

    model_config = ConfigDict(extra="forbid")

    street: Max70Text | None = None
    building_number: Max16Text | None = None
    postal_code: Max16Text | None = None
    town: Max35Text
    country: CountryCode


class Party(BaseModel):
    """A debtor or a creditor: a name, and where they are."""

    model_config = ConfigDict(extra="forbid")

    name: Max140Text
    postal_address: PostalAddress | None = None


class CreditorReference(BaseModel):
    """Which reference scheme this transfer carries, and the reference itself.

    `QRR` is the Swiss QR reference and `SCOR` the ISO 11649 creditor
    reference; `NONE` is a transfer with no structured reference at all. The
    rules about which is allowed with which account live in
    :mod:`painfree.sps`, because they are rules about the pair.
    """

    model_config = ConfigDict(extra="forbid")

    type: Literal["QRR", "SCOR", "NONE"] = "NONE"
    reference: Annotated[str, Field(max_length=35)] | None = None


class Transaction(BaseModel):
    """One credit transfer."""

    model_config = ConfigDict(extra="forbid")

    amount: decimal.Decimal
    currency: Annotated[str, Field(pattern=r"^[A-Z]{3}$")]
    creditor: Party
    creditor_iban: Annotated[str, Field(min_length=5, max_length=42)]
    creditor_bic: Bic | None = None
    end_to_end_id: Max35Text | None = None
    instruction_id: Max35Text | None = None
    reference: CreditorReference = Field(default_factory=CreditorReference)
    remittance_information: Max140Text | None = None
    additional_remittance_information: Max140Text | None = None
    #: Override the message's payment scheme for this transfer alone. Left
    #: unset, the message's scheme applies. Every transfer in one message has
    #: to end up on the same scheme -- one upload carries one BTF -- so this
    #: is a way of being explicit rather than a way of mixing
    #: (:func:`painfree.schemes.resolve`).
    scheme: PaymentScheme | None = None

    @field_validator("amount", mode="before")
    @classmethod
    def _decimal_from_text(cls, value: Any) -> Any:
        """Accept money as a string, and keep the digits the caller wrote.

        `Decimal(3949.75)` is not `3949.75`, so a JSON number is routed through
        its own decimal representation rather than through the binary float.
        The precision rule in :mod:`painfree.sps` then judges what came out.
        """
        if isinstance(value, float):
            return decimal.Decimal(repr(value))
        return value


class PaymentInstruction(BaseModel):
    """One `pain.001` message: one debit account, one execution date, N transfers."""

    model_config = ConfigDict(extra="forbid")

    debtor: Party
    debtor_iban: Annotated[str, Field(min_length=5, max_length=42)]
    debtor_bic: Bic | None = None
    requested_execution_date: _dt.date
    transactions: Annotated[list[Transaction],
                            Field(min_length=1, max_length=MAX_TRANSACTIONS)]
    batch_booking: bool = True
    payment_information_id: Max35Text | None = None
    #: Which payment scheme this message is sent under. Left unset, the
    #: connection's default applies. ``instant`` fails if the bank cannot do
    #: it; ``instant_or_normal`` falls back to an ordinary transfer, but only
    #: on a definitive refusal.
    scheme: PaymentScheme | None = None

    @property
    def currencies(self) -> set[str]:
        return {transaction.currency for transaction in self.transactions}

    @property
    def control_sum(self) -> decimal.Decimal:
        return sum((transaction.amount for transaction in self.transactions),
                   decimal.Decimal(0))


def swiss_failures(instruction: PaymentInstruction) -> list[sps.RuleFailure]:
    """Every Swiss Payment Standards rule this instruction breaks.

    Every one, not the first -- see :class:`painfree.sps.ValidationFailed`.
    """
    failures: list[sps.RuleFailure] = []
    failures += sps.iban_failures(instruction.debtor_iban, "debtor_iban",
                                  what="debtor")
    if len(instruction.currencies) > 1:
        # `CtrlSum` is a bare decimal with no currency attached, so the control
        # sum of a mixed-currency batch is a number that means nothing -- and
        # the control sum is one of the few things a bank checks for itself.
        failures.append(sps.RuleFailure(
            "transactions", "currency.mixed",
            "every transfer in one message must be in the same currency"))

    for index, transaction in enumerate(instruction.transactions):
        location = f"transactions.{index}"
        failures += sps.iban_failures(
            transaction.creditor_iban, f"{location}.creditor_iban",
            what="creditor")
        failures += sps.amount_failures(
            transaction.amount, transaction.currency, location)
        # The account/reference rules only mean anything once the account is a
        # real IBAN; running them on a typo produces a second failure that
        # disappears when the first is fixed.
        if sps.iban_failure(transaction.creditor_iban) is None:
            failures += sps.reference_failures(
                creditor_iban=transaction.creditor_iban,
                reference_type=transaction.reference.type,
                reference=transaction.reference.reference,
                unstructured=transaction.remittance_information,
                currency=transaction.currency,
                location=location,
            )
    return failures


def validate(instruction: PaymentInstruction) -> None:
    """Raise :class:`~painfree.sps.ValidationFailed` if any rule is broken."""
    failures = swiss_failures(instruction)
    if failures:
        raise sps.ValidationFailed(failures)


__all__ = ["CreditorReference", "MAX_TRANSACTIONS", "PaymentInstruction",
           "Party", "PaymentScheme", "PostalAddress", "Transaction",
           "swiss_failures", "validate"]
