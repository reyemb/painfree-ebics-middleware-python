"""What a bank's return code means, and what a caller is supposed to do about it.

`responses.py` reports the code the bank sent. This module says what it *is*: a
symbolic name, which part of the protocol produced it, and -- the field the
service layer actually branches on -- what happens next.

Three facts drive everything here and each of them is a bug a client ships
without noticing:

* **"not 000000" is not "failed".** ``011000`` is the positive acknowledgement
  that ends a download, ``011001`` its negative twin, ``090005`` means the bank
  simply had nothing to send, ``031001`` says some order parameters were
  ignored and the order went ahead anyway. A client that raises on all of them
  reports every completed statement download as an incident.
* **``061101`` is a resumption offer, not a refusal.** It carries the bank's own
  view of where the transfer got to, and the transaction continues from there.
  Raising it to the caller throws away a transfer that was being handed back.
* **The two return codes are not interchangeable.** The technical code in
  ``header/mutable`` is the status of the *transaction step*; the
  bank-technical code in ``body`` is the status of the *order*. A ``000000``
  header over a non-zero body means the protocol worked and the order did not,
  which is a completely different call to make.

What is deliberately *not* here: no retry schedule, no log level, no HTTP
status. :class:`Disposition` says whether trying again could possibly help; how
long to wait, how often, and whether to page anybody is the service layer's.

The table is data. It carries no prose gloss per code: the bank sends its own
``ReportText`` and that is the field worth surfacing -- a second, static
English sentence per code would duplicate the specification and drift from it.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

__all__ = [
    "RETURN_CODES",
    "Disposition",
    "Family",
    "ReturnCode",
    "Severity",
    "lookup",
]


class Family(Enum):
    """Which part of the protocol produced the code.

    An operator grouping, not a field of the specification -- EBICS numbers its
    return codes and groups them in prose, and the numbering is not a clean
    prefix scheme (``090005`` is a transaction outcome, ``091009`` a
    segmentation one). Naming the families is what lets a dashboard say "this
    connection's keys are wrong" rather than "code 091205".
    """

    SUCCESS = "success"
    TECHNICAL = "technical"          # the message itself: schema, host, transport
    AUTHENTICATION = "authentication"  # who is asking, and whether they may
    TRANSACTION = "transaction"      # the three phases, segmentation, recovery
    KEY_MANAGEMENT = "key_management"  # INI/HIA/HPB and X.509
    BUSINESS = "business"            # the order and the signatures over it
    UNKNOWN = "unknown"              # a code this table does not name


class Disposition(Enum):
    """What happens next. The only field a caller has to branch on."""

    SUCCESS = "success"          # 000000 -- carry on
    NOTICE = "notice"            # non-zero, the step still succeeded
    COMPLETED = "completed"      # non-zero, and the transaction is over, normally
    RECOVERABLE = "recoverable"  # the bank is offering to resume
    RETRYABLE = "retryable"      # transient at the bank; the same request may pass later
    TERMINAL = "terminal"        # sending this again changes nothing


class Severity(Enum):
    """A logging view of :class:`Disposition`, so log levels are not re-derived."""

    OK = "ok"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


_SEVERITY = {
    Disposition.SUCCESS: Severity.OK,
    Disposition.NOTICE: Severity.INFO,
    Disposition.COMPLETED: Severity.INFO,
    Disposition.RECOVERABLE: Severity.WARNING,
    Disposition.RETRYABLE: Severity.WARNING,
    Disposition.TERMINAL: Severity.ERROR,
}


@dataclass(frozen=True)
class ReturnCode:
    """One six-digit code, and what the engine knows about it."""

    code: str
    name: str | None
    family: Family
    disposition: Disposition

    @property
    def known(self) -> bool:
        """Is this a code the engine has a name for?

        An unknown code is not a parse failure: banks add codes and the engine
        must still say something useful. It is treated as terminal, because
        guessing that an unrecognised refusal is safe to retry is the one wrong
        guess with a cost attached.
        """
        return self.name is not None

    @property
    def severity(self) -> Severity:
        return _SEVERITY[self.disposition]

    @property
    def is_ok(self) -> bool:
        return self.disposition is Disposition.SUCCESS

    @property
    def is_benign(self) -> bool:
        """Did the protocol do what it was supposed to, whatever the digits say?"""
        return self.disposition in (Disposition.SUCCESS, Disposition.NOTICE,
                                    Disposition.COMPLETED)

    @property
    def ends_transaction(self) -> bool:
        """Is the transaction over -- normally, with nothing left to send?"""
        return self.disposition is Disposition.COMPLETED

    @property
    def needs_recovery(self) -> bool:
        return self.disposition is Disposition.RECOVERABLE

    @property
    def is_retryable(self) -> bool:
        return self.disposition is Disposition.RETRYABLE

    @property
    def is_terminal(self) -> bool:
        return self.disposition is Disposition.TERMINAL

    @property
    def raises(self) -> bool:
        """Does a caller hear about this as an exception?

        Everything benign is normal control flow, and so is recovery -- the
        transaction handles it and the caller never learns it happened.
        """
        return not (self.is_benign or self.needs_recovery)

    def __str__(self) -> str:
        return f"{self.code} {self.name}" if self.name else self.code


_S, _T, _A, _X, _K, _B = (Family.SUCCESS, Family.TECHNICAL, Family.AUTHENTICATION,
                          Family.TRANSACTION, Family.KEY_MANAGEMENT, Family.BUSINESS)
_OK, _NOTE, _DONE = Disposition.SUCCESS, Disposition.NOTICE, Disposition.COMPLETED
_SYNC, _RETRY, _STOP = (Disposition.RECOVERABLE, Disposition.RETRYABLE,
                        Disposition.TERMINAL)

#: Every code the engine names, as ``(code, name, family, disposition)``.
_TABLE = (
    ("000000", "EBICS_OK", _S, _OK),

    ("011000", "EBICS_DOWNLOAD_POSTPROCESS_DONE", _X, _DONE),
    ("011001", "EBICS_DOWNLOAD_POSTPROCESS_SKIPPED", _X, _DONE),
    ("011101", "EBICS_TX_SEGMENT_NUMBER_UNDERRUN", _X, _STOP),
    ("011301", "EBICS_NO_ONLINE_CHECKS", _T, _NOTE),
    ("031001", "EBICS_ORDER_PARAMS_IGNORED", _T, _NOTE),

    ("061001", "EBICS_AUTHENTICATION_FAILED", _A, _STOP),
    ("061002", "EBICS_INVALID_REQUEST", _T, _STOP),
    ("061099", "EBICS_INTERNAL_ERROR", _T, _RETRY),
    ("061101", "EBICS_TX_RECOVERY_SYNC", _X, _SYNC),

    ("090003", "EBICS_AUTHORISATION_ORDER_TYPE_FAILED", _B, _STOP),
    ("090004", "EBICS_INVALID_ORDER_DATA_FORMAT", _B, _STOP),
    ("090005", "EBICS_NO_DOWNLOAD_DATA_AVAILABLE", _X, _DONE),
    ("090006", "EBICS_UNSUPPORTED_REQUEST_FOR_ORDER_INSTANCE", _B, _STOP),

    ("091001", "EBICS_DOWNLOAD_SIGNED_ONLY", _B, _STOP),
    ("091002", "EBICS_INVALID_USER_OR_USER_STATE", _A, _STOP),
    ("091003", "EBICS_USER_UNKNOWN", _A, _STOP),
    ("091004", "EBICS_INVALID_USER_STATE", _A, _STOP),
    ("091005", "EBICS_INVALID_ORDER_TYPE", _B, _STOP),
    ("091006", "EBICS_UNSUPPORTED_ORDER_TYPE", _B, _STOP),
    ("091007", "EBICS_DISTRIBUTED_SIGNATURE_AUTHORISATION_FAILED", _B, _STOP),
    ("091008", "EBICS_BANK_PUBKEY_UPDATE_REQUIRED", _K, _STOP),
    ("091009", "EBICS_SEGMENT_SIZE_EXCEEDED", _X, _STOP),
    ("091010", "EBICS_INVALID_XML", _T, _STOP),
    ("091011", "EBICS_INVALID_HOST_ID", _T, _STOP),

    ("091101", "EBICS_TX_UNKNOWN_TXID", _X, _STOP),
    ("091102", "EBICS_TX_ABORT", _X, _STOP),
    ("091103", "EBICS_TX_MESSAGE_REPLAY", _X, _STOP),
    ("091104", "EBICS_TX_SEGMENT_NUMBER_EXCEEDED", _X, _STOP),
    ("091105", "EBICS_RECOVERY_NOT_SUPPORTED", _X, _STOP),
    ("091111", "EBICS_INVALID_SIGNATURE_FILE_FORMAT", _B, _STOP),
    ("091112", "EBICS_INVALID_ORDER_PARAMS", _B, _STOP),
    ("091113", "EBICS_INVALID_REQUEST_CONTENT", _T, _STOP),
    ("091114", "EBICS_ORDERID_UNKNOWN", _B, _STOP),
    ("091115", "EBICS_ORDERID_ALREADY_EXISTS", _B, _STOP),
    ("091116", "EBICS_PROCESSING_ERROR", _B, _STOP),
    ("091117", "EBICS_MAX_ORDER_DATA_SIZE_EXCEEDED", _X, _STOP),
    ("091118", "EBICS_MAX_SEGMENTS_EXCEEDED", _X, _STOP),
    ("091119", "EBICS_MAX_TRANSACTIONS_EXCEEDED", _X, _RETRY),
    ("091120", "EBICS_PARTNER_ID_MISMATCH", _B, _STOP),
    ("091121", "EBICS_INCOMPATIBLE_ORDER_ATTRIBUTE", _B, _STOP),

    ("091201", "EBICS_KEYMGMT_UNSUPPORTED_VERSION_SIGNATURE", _K, _STOP),
    ("091202", "EBICS_KEYMGMT_UNSUPPORTED_VERSION_AUTHENTICATION", _K, _STOP),
    ("091203", "EBICS_KEYMGMT_UNSUPPORTED_VERSION_ENCRYPTION", _K, _STOP),
    ("091204", "EBICS_KEYMGMT_KEYLENGTH_ERROR_SIGNATURE", _K, _STOP),
    ("091205", "EBICS_KEYMGMT_KEYLENGTH_ERROR_AUTHENTICATION", _K, _STOP),
    ("091206", "EBICS_KEYMGMT_KEYLENGTH_ERROR_ENCRYPTION", _K, _STOP),
    ("091207", "EBICS_KEYMGMT_NO_X509_SUPPORT", _K, _STOP),
    ("091208", "EBICS_X509_CERTIFICATE_EXPIRED", _K, _STOP),
    ("091209", "EBICS_X509_CERTIFICATE_NOT_VALID_YET", _K, _STOP),
    ("091210", "EBICS_X509_WRONG_KEY_USAGE", _K, _STOP),
    ("091211", "EBICS_X509_WRONG_ALGORITHM", _K, _STOP),
    ("091212", "EBICS_X509_INVALID_THUMBPRINT", _K, _STOP),
    ("091213", "EBICS_X509_CTL_INVALID", _K, _STOP),
    ("091214", "EBICS_X509_UNKNOWN_CERTIFICATE_AUTHORITY", _K, _STOP),
    ("091215", "EBICS_X509_INVALID_POLICY", _K, _STOP),
    ("091216", "EBICS_X509_INVALID_BASIC_CONSTRAINTS", _K, _STOP),
    ("091217", "EBICS_ONLY_X509_SUPPORT", _K, _STOP),
    ("091218", "EBICS_KEYMGMT_DUPLICATE_KEY", _K, _STOP),
    ("091219", "EBICS_CERTIFICATES_VALIDATION_ERROR", _K, _STOP),

    ("091301", "EBICS_SIGNATURE_VERIFICATION_FAILED", _B, _STOP),
    ("091302", "EBICS_ACCOUNT_AUTHORISATION_FAILED", _B, _STOP),
    ("091303", "EBICS_AMOUNT_CHECK_FAILED", _B, _STOP),
    ("091304", "EBICS_SIGNER_UNKNOWN", _B, _STOP),
    ("091305", "EBICS_INVALID_SIGNER_STATE", _B, _STOP),
    ("091306", "EBICS_DUPLICATE_SIGNATURE", _B, _STOP),
)

#: Code -> :class:`ReturnCode`, keyed by the six digits as they arrive.
RETURN_CODES: dict[str, ReturnCode] = {
    code: ReturnCode(code, name, family, disposition)
    for code, name, family, disposition in _TABLE
}


def lookup(code: str | None) -> ReturnCode | None:
    """The table entry for ``code``, or an unnamed terminal one if it is new.

    ``None`` in, ``None`` out: an absent element is not a code, and a response
    legitimately carries only one of the two.
    """
    if code is None:
        return None
    code = code.strip()
    if not code:
        return None
    known = RETURN_CODES.get(code)
    if known is not None:
        return known
    return ReturnCode(code, None, Family.UNKNOWN, Disposition.TERMINAL)
