"""Payment schemes: normal, instant, and the one decision both halves read.

A caller can ask for an ordinary credit transfer, an **instant** one, or
*instant if the bank will take it, normal if it definitively will not*. That
choice shows up in two places on the wire and they must not disagree:

1. **The BTF** in the EBICS upload, which is what the bank matches against its
   own catalogue. Instant is normally a different ``ServiceName``, or a
   ``ServiceOption`` beside the same one.
2. **``PmtTpInf``** inside the ``pain.001`` -- ``SvcLvl``, and for instant
   ``LclInstrm``.

A BTF claiming instant over a document that does not claim it is refused by the
bank with a code that will not explain itself. So the decision is made **once**,
by :func:`resolve`, and both halves are then persisted together on a
:class:`painfree.attempts.Attempt` row: the BTF triplet sits in the same row as
the document it announces. There is no code path that computes one without the
other.

**Nothing here is hard-coded per bank.** Which triplet and which ISO 20022 code
values mean "instant" differ by bank and by scheme version, so they are
per-connection configuration with the defaults below, editable in the console.
The elements themselves are not configurable -- ``PaymentTypeInformation26`` in
the vendored ``pain.001.001.09`` XSD settles where ``SvcLvl``, ``LclInstrm`` and
``CtgyPurp`` sit and what may go in them.

**The ceiling is configuration and has no default.** The SEPA instant ceiling
has moved more than once and was removed entirely in 2025; a constant here
would refuse a legitimate payment on the day a bank raised its limit. So
:attr:`SchemeProfile.max_amount` defaults to ``None`` -- no ceiling -- and a
deployment sets its bank's.

**The fallback rule lives in :mod:`painfree.queue`, not here.** This module
decides what to *send*; the decision to fall back is a decision about an order
that has already been refused, and it belongs beside the claim that makes it
single-flight. What this module contributes to it is
:meth:`SchemeProfiles.refuses_instant`, the **whitelist** of return codes that
mean *instant could not be used*. A whitelist rather than a blocklist, because
an unrecognised refusal must not become a second payment.
"""

from __future__ import annotations

import decimal
import enum
from dataclasses import dataclass, replace
from typing import Any, Iterable, Mapping

from painfree import sps

__all__ = [
    "DEFAULT_INSTANT", "DEFAULT_NORMAL", "DEFAULT_REFUSAL_CODES",
    "Code", "PaymentScheme", "SchemeDecision", "SchemeProfile",
    "SchemeProfiles", "SchemeUnavailable", "resolve",
]


class PaymentScheme(str, enum.Enum):
    """What a caller may ask for, and what one attempt may actually be.

    ``INSTANT_OR_NORMAL`` is a *request*, never an attempt: an attempt is
    either instant or it is not. :func:`resolve` turns the request into the
    attempt that goes first and the one held in reserve.
    """

    NORMAL = "normal"
    INSTANT = "instant"
    INSTANT_OR_NORMAL = "instant_or_normal"

    @property
    def sendable(self) -> bool:
        """Can an attempt be this scheme? ``instant_or_normal`` cannot."""
        return self is not PaymentScheme.INSTANT_OR_NORMAL

    @property
    def wants_instant(self) -> bool:
        return self is not PaymentScheme.NORMAL


#: The two schemes an attempt may be. Ordered so the console lists them the
#: way the wire does: what is ordinary first.
SENDABLE = (PaymentScheme.NORMAL, PaymentScheme.INSTANT)


class SchemeUnavailable(sps.ValidationFailed):
    """The connection cannot send what was asked for, and said so locally.

    A `422` like any other rule failure, and deliberately not a bank round
    trip: an amount above the scheme's ceiling and a connection with no instant
    profile are both knowable before anything is signed.
    """


@dataclass(frozen=True, slots=True)
class Code:
    """One ISO 20022 code slot: an external code, or a proprietary value.

    ``SvcLvl``, ``LclInstrm`` and ``CtgyPurp`` are all a choice between ``Cd``
    and ``Prtry`` in the schema, and banks use both -- ``LclInstrm/Cd`` is
    ``INST`` under the EPC rulebook, while Swiss domestic instruments are
    ``LclInstrm/Prtry``. One field with a flag rather than two fields, so that
    "which of the two is set" is not a state that can be wrong.
    """

    value: str
    proprietary: bool = False

    def __post_init__(self) -> None:
        text = (self.value or "").strip()
        if not text:
            raise ValueError("a code slot cannot be empty")
        limit = 35 if self.proprietary else 4
        if len(text) > limit:
            raise ValueError(
                f"{text!r} is longer than the {limit} characters the schema "
                f"allows here")
        object.__setattr__(self, "value", text)

    @property
    def tag(self) -> str:
        """``Cd`` or ``Prtry`` -- the element name this value is written into."""
        return "Prtry" if self.proprietary else "Cd"

    def as_json(self) -> dict[str, str]:
        return {self.tag.lower(): self.value}

    @classmethod
    def parse(cls, value: Any) -> "Code | None":
        """A stored slot back into a :class:`Code`. ``None`` stays ``None``."""
        if value is None:
            return None
        if isinstance(value, Code):
            return value
        if isinstance(value, str):
            return cls(value)
        if isinstance(value, Mapping):
            if value.get("prtry"):
                return cls(str(value["prtry"]), proprietary=True)
            if value.get("cd"):
                return cls(str(value["cd"]))
            return None
        raise ValueError(f"{value!r} is not a code slot")


#: ``Priority2Code`` -- the only two values ``InstrPrty`` takes.
PRIORITIES = ("HIGH", "NORM")


@dataclass(frozen=True, slots=True)
class SchemeProfile:
    """Everything one scheme needs, for one connection: the BTF and the codes.

    The BTF fields are validated by the engine's own :class:`Service` when the
    upload is built, not re-validated here -- if the bank would refuse the
    value, storing it is not useful, and one validator is one answer.
    """

    #: ``ServiceName``: three characters. ``MCT`` is the Swiss Payment
    #: Standards multi-currency credit transfer.
    service_name: str = "MCT"
    #: ``ServiceOption``, if this bank distinguishes the scheme with one.
    service_option: str | None = None
    #: ``Scope``: two or three characters, or ``BIL`` / ``INT``.
    scope: str | None = "CH"
    #: ``PmtTpInf/SvcLvl``.
    service_level: Code | None = None
    #: ``PmtTpInf/LclInstrm``.
    local_instrument: Code | None = None
    #: ``PmtTpInf/CtgyPurp``.
    category_purpose: Code | None = None
    #: ``PmtTpInf/InstrPrty`` -- ``HIGH`` or ``NORM``.
    instruction_priority: str | None = None
    #: The largest single transfer this scheme accepts, or ``None`` for no
    #: ceiling. Checked before anything is sent; see :func:`resolve`.
    max_amount: decimal.Decimal | None = None

    def __post_init__(self) -> None:
        if self.instruction_priority is not None \
                and self.instruction_priority not in PRIORITIES:
            raise ValueError(
                f"InstrPrty {self.instruction_priority!r} must be one of "
                f"{', '.join(PRIORITIES)}")
        if self.max_amount is not None and self.max_amount <= 0:
            raise ValueError("a scheme ceiling must be a positive amount")

    # --- what the document carries ----------------------------------------

    @property
    def emits_payment_type(self) -> bool:
        """Does this profile put a ``PmtTpInf`` in the document at all?

        An empty ``PmtTpInf`` is not the same as an absent one to a bank's
        matcher, and a scheme code nobody asked us to emit is a document
        refused for saying too much. So a profile with no codes emits nothing.
        """
        return any((self.instruction_priority, self.service_level,
                    self.local_instrument, self.category_purpose))

    def payment_type_summary(self) -> str | None:
        """The ``PmtTpInf`` in one short line, for a log, a column and a page.

        ``InstrPrty=HIGH SvcLvl/Cd=SEPA LclInstrm/Cd=INST``. Not XML: it is
        read by an operator comparing a document against a BTF, and an XML
        fragment in a table cell is not read at all.
        """
        if not self.emits_payment_type:
            return None
        parts = []
        if self.instruction_priority:
            parts.append(f"InstrPrty={self.instruction_priority}")
        for label, code in (("SvcLvl", self.service_level),
                            ("LclInstrm", self.local_instrument),
                            ("CtgyPurp", self.category_purpose)):
            if code is not None:
                parts.append(f"{label}/{code.tag}={code.value}")
        return " ".join(parts)

    def btf_summary(self) -> str:
        """The BTF triplet in one short line, beside the summary above."""
        parts = [self.service_name]
        if self.service_option:
            parts.append(self.service_option)
        if self.scope:
            parts.append(self.scope)
        return "/".join(parts)

    # --- storage -----------------------------------------------------------

    def as_json(self) -> dict[str, Any]:
        return {
            "service_name": self.service_name,
            "service_option": self.service_option,
            "scope": self.scope,
            "service_level": self.service_level.as_json()
            if self.service_level else None,
            "local_instrument": self.local_instrument.as_json()
            if self.local_instrument else None,
            "category_purpose": self.category_purpose.as_json()
            if self.category_purpose else None,
            "instruction_priority": self.instruction_priority,
            "max_amount": f"{self.max_amount:f}" if self.max_amount is not None
            else None,
        }

    @classmethod
    def parse(cls, value: Mapping[str, Any], *,
              default: "SchemeProfile") -> "SchemeProfile":
        """A stored profile, with anything absent taken from ``default``.

        Absent rather than null: a deployment that only wants to correct the
        ``ServiceOption`` should not have to restate the whole profile, and a
        key that is present and ``null`` genuinely means *no value*.
        """
        def slot(name: str, fallback: Code | None) -> Code | None:
            return Code.parse(value[name]) if name in value else fallback

        amount = value.get("max_amount", _KEEP)
        if amount is _KEEP:
            ceiling = default.max_amount
        elif amount in (None, ""):
            ceiling = None
        else:
            ceiling = decimal.Decimal(str(amount))
        return cls(
            service_name=str(value.get("service_name")
                             or default.service_name),
            service_option=_optional(value, "service_option",
                                     default.service_option),
            scope=_optional(value, "scope", default.scope),
            service_level=slot("service_level", default.service_level),
            local_instrument=slot("local_instrument", default.local_instrument),
            category_purpose=slot("category_purpose", default.category_purpose),
            instruction_priority=_optional(value, "instruction_priority",
                                           default.instruction_priority),
            max_amount=ceiling,
        )


_KEEP = object()


def _optional(value: Mapping[str, Any], name: str,
              fallback: str | None) -> str | None:
    if name not in value:
        return fallback
    text = value[name]
    return str(text).strip() or None if text else None


#: The ordinary credit transfer. ``MCT`` in scope ``CH``, and **no
#: ``PmtTpInf``** -- which is exactly what this service emitted before schemes
#: existed. A ``SvcLvl`` for an ordinary transfer is per-bank (``SEPA`` in the
#: euro area, nothing at all domestically in Switzerland), and emitting one we
#: were not told to emit is a document refused for saying too much.
DEFAULT_NORMAL = SchemeProfile()

#: Instant. The BTF option and the two codes below are the **EPC SCT Inst**
#: convention -- ``LclInstrm/Cd`` is ``INST`` in that rulebook, under
#: ``SvcLvl/Cd`` ``SEPA`` -- and they are a default, not a discovery. A Swiss
#: bank on SIC instant publishes its own triplet and may use
#: ``LclInstrm/Prtry``; that is what the per-connection configuration is for.
#: A wrong value here produces `EBICS_INVALID_ORDER_PARAMS` from the bank, not
#: a schema error, which is why it is configuration rather than a constant.
DEFAULT_INSTANT = SchemeProfile(
    service_name="MCT", service_option="INST", scope="CH",
    service_level=Code("SEPA"), local_instrument=Code("INST"),
)

#: The return codes that mean *instant could not be used*, and the only ones a
#: fallback may be taken on. A **whitelist**: `091112`
#: (`EBICS_INVALID_ORDER_PARAMS`) is what a bank answers when the BTF is not in
#: its catalogue, which is what an instant upload to a bank that cannot do
#: instant looks like. Every other refusal, definitive or not, ends the order
#: rather than sending a second file.
DEFAULT_REFUSAL_CODES: tuple[str, ...] = ("091112",)


@dataclass(frozen=True, slots=True)
class SchemeProfiles:
    """One connection's scheme configuration: a default, and a profile each."""

    default: PaymentScheme = PaymentScheme.NORMAL
    normal: SchemeProfile = DEFAULT_NORMAL
    #: ``None`` until somebody configures it, which means this connection
    #: cannot send an instant credit transfer and says so locally.
    #:
    #: It used to default to :data:`DEFAULT_INSTANT`, and that was wrong for
    #: every connection this engine can create. An instant upload is announced
    #: with a BTF the bank has to have in its catalogue, and the shipped one is
    #: the EPC SEPA convention -- the *euro* scheme. A Swiss bank on SIC
    #: publishes its own triplet, and plenty publish no instant row at all: at
    #: least one cantonal bank's whole upload catalogue is a single
    #: ``MCT / CH / pain.001.09``. Against those, a populated default made
    #: ``instant`` fail at the bank with ``091112`` and made
    #: ``instant_or_normal`` spend a signed upload and a round trip on every
    #: payment before falling back.
    #:
    #: Unset, both are decided here instead: ``instant`` is refused before
    #: anything is signed, naming the reason, and ``instant_or_normal`` goes
    #: out as an ordinary transfer first time. A deployment whose bank really
    #: does instant sets the triplet the bank publishes, which is the only way
    #: it was ever going to work.
    instant: SchemeProfile | None = None
    #: The whitelist above, per connection.
    instant_refusal_codes: tuple[str, ...] = DEFAULT_REFUSAL_CODES

    def __post_init__(self) -> None:
        if self.default is PaymentScheme.INSTANT and self.instant is None:
            raise ValueError(
                "a connection whose default is instant needs an instant "
                "profile")

    @property
    def instant_configured(self) -> bool:
        return self.instant is not None

    def profile(self, scheme: PaymentScheme | str) -> SchemeProfile:
        """The profile one *attempt* sends under. Never ``instant_or_normal``."""
        scheme = PaymentScheme(scheme)
        if scheme is PaymentScheme.NORMAL:
            return self.normal
        if scheme is PaymentScheme.INSTANT:
            if self.instant is None:
                raise ValueError(
                    "this connection has no instant profile configured")
            return self.instant
        raise ValueError(f"{scheme.value!r} is a request, not an attempt")

    def refuses_instant(self, return_code: str | None) -> bool:
        """Does this return code mean *instant could not be used*?

        The whole safety of ``instant_or_normal`` narrows to this predicate, so
        it is deliberately dull: exact membership of a configured set, and
        ``False`` for ``None``. An outcome with no parsed return code is not a
        refusal.
        """
        return bool(return_code) and return_code in self.instant_refusal_codes

    # --- storage -----------------------------------------------------------

    def as_json(self) -> dict[str, Any]:
        return {
            "default": self.default.value,
            "normal": self.normal.as_json(),
            "instant": self.instant.as_json() if self.instant else None,
            "instant_refusal_codes": list(self.instant_refusal_codes),
        }

    @classmethod
    def parse(cls, value: Mapping[str, Any] | None) -> "SchemeProfiles":
        """Stored configuration back into profiles, defaults filling the gaps.

        ``None`` -- a connection registered before schemes existed, or one
        nobody has configured -- is the default set, which sends exactly what
        this service sent before this existed.
        """
        if not value:
            return cls()
        instant: SchemeProfile | None
        if "instant" not in value:
            # A stored connection that never named one has none. On an
            # upgrade this takes the instant profile away from any
            # connection that was only ever relying on the old
            # default -- deliberately, because that default was the
            # euro convention and was not going to be accepted. A
            # deployment sending instant successfully configured the
            # triplet its bank publishes, so it has the key and keeps
            # it.
            instant = None
        elif value["instant"] is None:
            instant = None
        else:
            instant = SchemeProfile.parse(value["instant"],
                                          default=DEFAULT_INSTANT)
        codes = value.get("instant_refusal_codes")
        return cls(
            default=PaymentScheme(value.get("default", "normal")),
            normal=SchemeProfile.parse(value.get("normal") or {},
                                       default=DEFAULT_NORMAL),
            instant=instant,
            instant_refusal_codes=tuple(str(code) for code in codes)
            if codes is not None else DEFAULT_REFUSAL_CODES,
        )

    def with_instant(self, profile: SchemeProfile | None) -> "SchemeProfiles":
        return replace(self, instant=profile)


#: Why an order is being sent under the scheme it is being sent under. Machine
#: readable and English, like every other `code` this service emits: a consumer
#: matches on it and the console glosses it.
REQUESTED = "requested"
CONNECTION_DEFAULT = "connection_default"
PREFLIGHT_NO_INSTANT = "preflight.instant_not_configured"
PREFLIGHT_CEILING = "preflight.amount_above_instant_ceiling"
BANK_REFUSED_INSTANT = "bank_refused_instant"

#: The rule ids a submission is refused with. Named, so a caller can branch on
#: which of the three things went wrong rather than reading a sentence.
RULE_UNSUPPORTED = "scheme.unsupported"
RULE_CEILING = "scheme.amount_above_instant_ceiling"
RULE_MIXED = "scheme.mixed"


@dataclass(frozen=True, slots=True)
class SchemeDecision:
    """The one decision. Both the BTF and the ``PmtTpInf`` are read off this.

    ``effective`` is what the first attempt sends. ``fallback`` is the scheme
    of the attempt built at the same time and held dormant -- it is only ever
    ``NORMAL``, and only when the caller asked for ``instant_or_normal`` and
    instant was actually reachable.
    """

    requested: PaymentScheme
    effective: PaymentScheme
    fallback: PaymentScheme | None
    reason: str
    #: Was the scheme named on the transactions rather than on the message? It
    #: decides whether ``PmtTpInf`` is written at B level or at C level.
    per_transaction: bool = False
    #: Set when the decision downgraded something the caller asked for.
    downgraded: bool = False

    def as_json(self) -> dict[str, Any]:
        return {"requested": self.requested.value,
                "effective": self.effective.value,
                "downgraded": self.downgraded,
                "reason": self.reason}


def resolve(profiles: SchemeProfiles, *, instruction,
            ) -> SchemeDecision:
    """Decide, once, what this instruction is sent as. Raises rather than guesses.

    In order:

    1. the scheme the caller named on the message, or the connection's default;
    2. any per-transaction override, which must be **unanimous** -- one upload
       carries one BTF, and a file whose BTF claims instant over a transaction
       that does not is the disagreement this module exists to prevent;
    3. the pre-flight checks, which are the whole reason this happens here and
       not after a round trip: a connection with no instant profile and an
       amount above the ceiling are both knowable now. ``instant_or_normal``
       downgrades; ``instant`` is refused, because *fails if it cannot be done*
       is what it means, and failing locally is strictly better than failing at
       the bank.
    """
    requested, per_transaction = _requested(profiles, instruction)
    origin = (REQUESTED if per_transaction or _named(instruction)
              else CONNECTION_DEFAULT)

    if not requested.wants_instant:
        return SchemeDecision(
            requested=requested, effective=PaymentScheme.NORMAL, fallback=None,
            reason=origin, per_transaction=per_transaction)

    optional = requested is PaymentScheme.INSTANT_OR_NORMAL

    if not profiles.instant_configured:
        if not optional:
            raise SchemeUnavailable([sps.RuleFailure(
                "scheme", RULE_UNSUPPORTED,
                "this connection has no instant payment profile configured, "
                "so it cannot send an instant credit transfer")])
        return _downgraded(requested, PREFLIGHT_NO_INSTANT, per_transaction)

    ceiling = profiles.instant.max_amount
    if ceiling is not None:
        over = [index for index, transaction
                in enumerate(instruction.transactions)
                if transaction.amount > ceiling]
        if over:
            if not optional:
                raise SchemeUnavailable([
                    sps.RuleFailure(
                        f"transactions.{index}.amount", RULE_CEILING,
                        f"an instant credit transfer on this connection is "
                        f"limited to {ceiling:f}")
                    for index in over])
            return _downgraded(requested, PREFLIGHT_CEILING, per_transaction)

    return SchemeDecision(
        requested=requested, effective=PaymentScheme.INSTANT,
        fallback=PaymentScheme.NORMAL if optional else None,
        reason=origin, per_transaction=per_transaction)


def _named(instruction) -> bool:
    return getattr(instruction, "scheme", None) is not None


def _downgraded(requested: PaymentScheme, reason: str,
                per_transaction: bool) -> SchemeDecision:
    return SchemeDecision(
        requested=requested, effective=PaymentScheme.NORMAL, fallback=None,
        reason=reason, per_transaction=per_transaction, downgraded=True)


def _requested(profiles: SchemeProfiles,
               instruction) -> tuple[PaymentScheme, bool]:
    """The scheme this whole message is, and whether a transaction named it."""
    message = getattr(instruction, "scheme", None) or profiles.default
    wanted = {
        PaymentScheme(transaction.scheme) if transaction.scheme else message
        for transaction in instruction.transactions
    }
    if len(wanted) > 1:
        raise SchemeUnavailable([sps.RuleFailure(
            "transactions", RULE_MIXED,
            "one upload carries one BTF, so every transfer in a message must "
            "use the same payment scheme; this message asks for "
            + ", ".join(sorted(scheme.value for scheme in wanted)))])
    per_transaction = any(transaction.scheme is not None
                          for transaction in instruction.transactions)
    return (wanted.pop() if wanted else message), per_transaction


def scheme_names() -> Iterable[str]:
    return (scheme.value for scheme in PaymentScheme)
