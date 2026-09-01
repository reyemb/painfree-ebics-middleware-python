"""Subscriber initialisation: ``INI``, ``HIA``, ``HPB`` -- and the letter.

Three exchanges register a subscriber, and a fourth step happens on paper::

    INI   the A005/A006 signature key            ebicsUnsecuredRequest
    HIA   the X002 and E002 keys                 ebicsUnsecuredRequest
    ----  the INI letter, printed, signed, posted -- the bank compares hashes
    HPB   the bank's X002 and E002 keys          ebicsNoPubKeyDigestsRequest

The order of the first two is free and both are unsecured: nothing signs them,
because the keys they carry are what a signature would have to be checked
against. That is not a weakness in the protocol, it is where the protocol stops
and the paper starts. **The letter is the trust anchor**, in both directions:
the bank checks the fingerprints on it against the keys that arrived over
``INI``/``HIA``, and the customer checks the fingerprints on the bank's own
letter against the keys that arrive over ``HPB``.

**The HPB response is not signed.** ``ebicsKeyManagementResponse`` in
``ebics_keymgmt_response_H005.xsd`` is a sequence of ``header`` and ``body``
and nothing else -- there is no ``AuthSignature`` in it, and there could not
usefully be one: the response delivers the keys a signature would be verified
with. ``ebics-client-php`` reaches the same conclusion from the other side and
passes ``'HPB' !== $orderType`` to skip verification for exactly this order.
So there is no cryptographic check available here at all, and
:func:`verify_bank_keys` -- a human-supplied fingerprint, compared -- is the
whole of the trust decision. An engine that parses the bank's keys and calls
itself initialised has silently accepted whatever key it was sent, which is why
:class:`Initialisation` reaches :attr:`KeyState.READY` only after the
comparison has been made.

Two fingerprints exist over the same key and they are not interchangeable:

``public_key``
    ``sha256(hex(e) + " " + hex(n))``, zero-stripped -- the classic EBICS
    key digest, and what most bank letters print.
``certificate``
    ``sha256`` over the certificate's DER. What ``ebics-client-php``'s
    ``DigestResolverV3`` uses for an EBICS 3.0 letter, because H005 carries the
    key only inside a certificate.

The caller says which one the letter in front of it is quoting; the engine does
not guess, because guessing wrong here means comparing a value against a digest
it can never equal and concluding "mismatch" for a key that is fine -- or, with
a looser rule, accepting a match that was never checked.

Provenance: the flow and the two digest conventions follow
``ebics-api/ebics-client-php`` (MIT) -- ``EbicsClient::executeInitializationOrder``,
``Orders/HPB::afterExecute``, ``Handlers/OrderDataHandlerV30`` and
``Services/DigestResolverV3``. See ADR D-005 and D-016.
"""

from __future__ import annotations

import base64
import hmac
from dataclasses import dataclass, field
from enum import Enum

from cryptography.hazmat.primitives.asymmetric import rsa
from lxml import etree

from .canon import parse_xml
from .certificates import certificate_fingerprint
from .crypto import public_key_digest_hex
from .errors import BankKeyMismatchError, CertificateError, DocumentError, RequestError
from .keys import EbicsKey
from .pipeline import open_order_data
from .requests import (RequestContext, build_hia_request, build_hpb_request,
                       build_ini_request)
from .responses import BankResponse, parse_response
from .versions import KeyRole, KeyVersion

__all__ = [
    "BankKeys",
    "Initialisation",
    "IniLetter",
    "KeyState",
    "LetterDigest",
    "LetterKey",
    "Step",
    "build_ini_letter",
    "format_fingerprint",
    "ini_letter_hash",
    "parse_hpb_order_data",
    "verify_bank_keys",
]


class Step(str, Enum):
    """One exchange of the initialisation, in the order the engine drives them."""

    INI = "INI"
    HIA = "HIA"
    HPB = "HPB"


class KeyState(str, Enum):
    """Where an initialisation has got to.

    The engine models these; it stores none of them. Which is the point: a
    service that persists three booleans and the bank's two keys can rebuild an
    :class:`Initialisation` and carry on, and a half-finished registration
    survives a restart instead of starting again with fresh keys the bank has
    never seen.
    """

    CREATED = "created"
    INI_SENT = "ini_sent"
    HIA_SENT = "hia_sent"
    KEYS_SENT = "keys_sent"
    BANK_KEYS_RECEIVED = "bank_keys_received"
    READY = "ready"


class LetterDigest(str, Enum):
    """Which of the two fingerprints over a key a letter is quoting.

    Both exist for the same key and they are different 64-character strings, so
    a match under the wrong one is not a match. `ebics-client-php` picks between
    them by protocol version: ``DigestResolverV2`` prints the public-key digest
    unless a certificate is present, and ``DigestResolverV3`` -- the EBICS 3.0
    rule -- always prints the certificate's.

    **This engine speaks H005 only**, so :data:`DEFAULT` is the certificate. It
    was the public-key digest until a bank telephoned about an INI letter whose
    hashes did not match the keys it had just been sent: the keys were right,
    the letter quoted the H004 fingerprint, and every connection this engine can
    register is H005. A default that is wrong for every connection it can create
    is not a default, it is a trap.
    """

    PUBLIC_KEY = "public_key"
    CERTIFICATE = "certificate"


#: What a letter quotes unless a connection says otherwise. See above: H005.
DEFAULT_LETTER_DIGEST = LetterDigest.CERTIFICATE


# --- the bank's keys -------------------------------------------------------

@dataclass(frozen=True)
class BankKeys:
    """What ``HPB`` delivers: the bank's authentication and encryption keys.

    Parsed is not trusted. Holding this object means the bank sent these two
    keys, not that they are the bank's -- :func:`verify_bank_keys` is what turns
    the first statement into the second.
    """

    authentication: EbicsKey
    encryption: EbicsKey
    host_id: str | None = None

    def fingerprints(self, digest: LetterDigest = DEFAULT_LETTER_DIGEST
                     ) -> dict[str, str]:
        """The two values to read off the bank's letter, keyed by version."""
        return {self.authentication.version.value: ini_letter_hash(
                    self.authentication, digest),
                self.encryption.version.value: ini_letter_hash(
                    self.encryption, digest)}


def parse_hpb_order_data(document: bytes | str | etree._Element) -> BankKeys:
    """Read ``HPBResponseOrderData`` into the bank's two keys.

    Addressed by local name, like every other parser in the engine: the H004
    and H005 shapes are the same tree under different namespaces, and a captured
    bank document is as likely to arrive with no namespace at all.

    Both key encodings are read. H005 carries the key inside
    ``ds:X509Certificate`` and nothing else; H004 carried it as a
    ``PubKeyValue`` with ``ds:Modulus`` and ``ds:Exponent``, and the certificate
    was optional beside it. The engine speaks H005, but refusing the older
    encoding would mean refusing every captured HPB response in existence,
    including the one this is proved against.
    """
    root = document if isinstance(document, etree._Element) else parse_xml(document)
    if etree.QName(root).localname != "HPBResponseOrderData":
        raise DocumentError(
            f"<{etree.QName(root).localname}> is not HPBResponseOrderData")

    host = root.xpath("/*/*[local-name()='HostID']")
    return BankKeys(
        authentication=_pub_key_info(root, "Authentication"),
        encryption=_pub_key_info(root, "Encryption"),
        host_id=((host[0].text or "").strip() or None) if host else None,
    )


def _pub_key_info(root: etree._Element, role: str) -> EbicsKey:
    """One ``*PubKeyInfo`` element, as an :class:`EbicsKey` with no private half."""
    nodes = root.xpath(f"/*/*[local-name()='{role}PubKeyInfo']")
    if not nodes:
        raise DocumentError(f"HPB order data carries no {role}PubKeyInfo")
    info = nodes[0]

    declared = info.xpath(f"./*[local-name()='{role}Version']")
    if not declared or not (declared[0].text or "").strip():
        raise DocumentError(f"{role}PubKeyInfo declares no {role}Version")
    version = KeyVersion.parse(declared[0].text.strip())

    certificates = info.xpath(".//*[local-name()='X509Certificate']")
    if certificates:
        key = EbicsKey.from_certificate(
            version, _der(certificates[0].text or "", role))
    else:
        key = EbicsKey(version, _rsa_key_value(info, role))

    expected = (KeyRole.AUTHENTICATION if role == "Authentication"
                else KeyRole.ENCRYPTION)
    if key.version.role is not expected:
        raise DocumentError(
            f"{role}PubKeyInfo declares {key.version.value}, "
            f"which is not an {expected.value} version")
    return key


def _der(text: str, role: str) -> bytes:
    try:
        return base64.b64decode("".join(text.split()), validate=True)
    except ValueError as exc:
        raise CertificateError(
            f"{role}PubKeyInfo carries an unreadable certificate: {exc}") from exc


def _rsa_key_value(info: etree._Element, role: str) -> rsa.RSAPublicKey:
    """The H004 fallback: a modulus and an exponent as ``ds:CryptoBinary``."""
    numbers = {}
    for name in ("Modulus", "Exponent"):
        found = info.xpath(f".//*[local-name()='{name}']")
        if not found or not (found[0].text or "").strip():
            raise DocumentError(
                f"{role}PubKeyInfo carries neither a certificate nor a {name}")
        numbers[name] = int.from_bytes(
            base64.b64decode("".join((found[0].text or "").split())), "big")
    return rsa.RSAPublicNumbers(numbers["Exponent"],
                               numbers["Modulus"]).public_key()


# --- the fingerprint, and the comparison that matters ----------------------

def ini_letter_hash(key: EbicsKey,
                    digest: LetterDigest = DEFAULT_LETTER_DIGEST) -> str:
    """The fingerprint a letter carries for one key, lower-case hex."""
    if LetterDigest(digest) is LetterDigest.CERTIFICATE:
        if key.certificate is None:
            raise CertificateError(
                f"a certificate fingerprint needs a certificate; the "
                f"{key.version.value} key has none")
        return certificate_fingerprint(key.certificate)
    return public_key_digest_hex(key.public_key)


def format_fingerprint(value: str) -> str:
    """Hex in pairs, as a letter prints it: ``d9 5b 40 …``.

    ``ebics-client-php``'s ``BankLetterService::formatKeyHashForBankLetter``
    splits the hex string every two characters and joins with a space, and the
    lower case comes from ``bin2hex``. A human reading a value off paper is the
    only consumer, so matching the reference's grouping matters more than any
    argument about which grouping is nicer.
    """
    normalised = _normalise(value, "fingerprint")
    return " ".join(normalised[i:i + 2] for i in range(0, len(normalised), 2))


def verify_bank_keys(
    bank_keys: BankKeys,
    *,
    authentication: str,
    encryption: str,
    digest: LetterDigest = DEFAULT_LETTER_DIGEST,
) -> dict[str, str]:
    """Compare the bank's keys against the fingerprints on the bank's letter.

    Both values are required and neither has a default. A signature that let a
    caller check one key, or none, would make the dangerous call the easy one
    to write -- and the encryption key is the one that matters most, because a
    substituted E002 key means every payment file this client uploads is
    readable by whoever substituted it.

    Whitespace and case are ignored, because the value is copied off paper in
    groups of two. Nothing else is: the comparison is over the full 64 hex
    characters, in constant time, and a prefix does not match.

    Raises :class:`BankKeyMismatchError` naming the key that failed. Returns
    the computed fingerprints, so a caller can record what it accepted.
    """
    digest = LetterDigest(digest)
    computed = {"authentication": ini_letter_hash(bank_keys.authentication, digest),
                "encryption": ini_letter_hash(bank_keys.encryption, digest)}
    expected = {"authentication": authentication, "encryption": encryption}

    for role, actual in computed.items():
        wanted = _normalise(expected[role], f"the {role} fingerprint")
        if not hmac.compare_digest(wanted, actual):
            raise BankKeyMismatchError(
                f"the bank's {role} key does not match the letter",
                role=role, expected=wanted, actual=actual, digest=digest.value)
    return computed


def _normalise(value: str, what: str) -> str:
    """A fingerprint as typed, reduced to the 64 hex characters it should be."""
    cleaned = "".join(str(value).split()).replace(":", "").lower()
    if len(cleaned) != 64 or any(c not in "0123456789abcdef" for c in cleaned):
        raise RequestError(
            f"{what} must be 64 hex characters (SHA-256); got {len(cleaned)}")
    return cleaned


# --- the letter ------------------------------------------------------------

@dataclass(frozen=True)
class LetterKey:
    """One key as the letter prints it: the numbers, and the hash over them."""

    version: KeyVersion
    exponent: str
    modulus: str
    modulus_bits: int
    fingerprint: str
    fingerprint_formatted: str


@dataclass(frozen=True)
class IniLetter:
    """The document a human signs and posts, reduced to its content.

    Content only. Rendering it as text, HTML or a PDF is a presentation
    decision and belongs where the fonts do -- the engine's job is that the
    numbers on the page are the numbers in the request, and that the hash is
    the one the fingerprint machinery produces.
    """

    host_id: str
    partner_id: str
    user_id: str
    digest: LetterDigest
    signature: LetterKey
    authentication: LetterKey
    encryption: LetterKey

    @property
    def keys(self) -> tuple[LetterKey, LetterKey, LetterKey]:
        return (self.signature, self.authentication, self.encryption)


def build_ini_letter(
    context: RequestContext,
    signature_key: EbicsKey,
    authentication_key: EbicsKey,
    encryption_key: EbicsKey,
    *,
    digest: LetterDigest = DEFAULT_LETTER_DIGEST,
) -> IniLetter:
    """The three keys of a subscriber, formatted for the printed letter."""
    digest = LetterDigest(digest)
    return IniLetter(
        host_id=context.host_id, partner_id=context.partner_id,
        user_id=context.user_id, digest=digest,
        signature=_letter_key(signature_key, KeyRole.SIGNATURE, digest),
        authentication=_letter_key(authentication_key,
                                   KeyRole.AUTHENTICATION, digest),
        encryption=_letter_key(encryption_key, KeyRole.ENCRYPTION, digest),
    )


def _letter_key(key: EbicsKey, role: KeyRole, digest: LetterDigest) -> LetterKey:
    if key.version.role is not role:
        raise RequestError(
            f"the letter's {role.value} slot needs a {role.value} key; "
            f"got {key.version.value}")
    fingerprint = ini_letter_hash(key, digest)
    numbers = key.public_key.public_numbers()
    return LetterKey(
        version=key.version,
        exponent=format_bytes(numbers.e),
        modulus=format_bytes(numbers.n),
        modulus_bits=key.public_key.key_size,
        fingerprint=fingerprint,
        fingerprint_formatted=format_fingerprint(fingerprint),
    )


def format_bytes(value: int) -> str:
    """An RSA number in lower-case hex byte pairs, as the letter prints it.

    From the *minimal* big-endian bytes, which is what ``decomposePublicKey``
    hands the reference's formatter -- so a 2048-bit modulus is 256 pairs and
    never 257, and the exponent is ``01 00 01``.
    """
    width = max(1, (value.bit_length() + 7) // 8)
    raw = value.to_bytes(width, "big").hex()
    return " ".join(raw[i:i + 2] for i in range(0, len(raw), 2))


# --- the flow --------------------------------------------------------------

@dataclass
class Initialisation:
    """The three exchanges, as a state machine the caller drives.

    Transport-agnostic like the rest of the engine: it hands out request
    documents and consumes response documents. The caller posts them::

        init = Initialisation(context, a_key, x_key, e_key)
        while (request := init.next_request()) is not None:
            init.feed(post(serialize_request(request)))
        init.confirm_bank_keys(authentication=..., encryption=...)

    Every field below is state a service layer persists, which is what makes a
    half-finished initialisation resumable: reconstruct with ``ini_sent`` and
    ``hia_sent`` as they were and the loop picks up at the right exchange.
    ``HPB`` is the exception that needs nothing remembered -- it can be repeated
    freely, and a bank whose keys have rolled expects exactly that.
    """

    context: RequestContext
    signature_key: EbicsKey
    authentication_key: EbicsKey
    encryption_key: EbicsKey
    schema_location: str | None = None

    ini_sent: bool = False
    hia_sent: bool = False
    ini_order_id: str | None = None
    hia_order_id: str | None = None
    bank_keys: BankKeys | None = field(default=None, repr=False)
    bank_fingerprints: dict[str, str] | None = None

    @property
    def state(self) -> KeyState:
        if self.bank_keys is None:
            if self.ini_sent and self.hia_sent:
                return KeyState.KEYS_SENT
            if self.ini_sent:
                return KeyState.INI_SENT
            if self.hia_sent:
                return KeyState.HIA_SENT
            return KeyState.CREATED
        return (KeyState.READY if self.bank_fingerprints is not None
                else KeyState.BANK_KEYS_RECEIVED)

    @property
    def next_step(self) -> Step | None:
        if not self.ini_sent:
            return Step.INI
        if not self.hia_sent:
            return Step.HIA
        if self.bank_keys is None:
            return Step.HPB
        return None

    def letter(self, digest: LetterDigest = DEFAULT_LETTER_DIGEST) -> IniLetter:
        """The letter for *our* keys -- what the bank checks INI and HIA against."""
        return build_ini_letter(self.context, self.signature_key,
                                self.authentication_key, self.encryption_key,
                                digest=digest)

    def next_request(self, **kwargs) -> etree._Element | None:
        """The next document to send, or ``None`` when the bank's keys are in."""
        step = self.next_step
        if step is None:
            return None
        if step is Step.INI:
            return build_ini_request(self.context, self.signature_key,
                                     schema_location=self.schema_location)
        if step is Step.HIA:
            return build_hia_request(self.context, self.authentication_key,
                                     self.encryption_key,
                                     schema_location=self.schema_location)
        return build_hpb_request(self.context, self.authentication_key,
                                 schema_location=self.schema_location, **kwargs)

    def feed(self, document: bytes | str | etree._Element) -> BankResponse:
        """Consume the answer to the step that was pending, and advance.

        Refusals raise, through the same classification the transaction
        protocol uses: an ``INI`` the bank rejects because the subscriber is
        already initialised comes back as ``EBICS_INVALID_USER_STATE``, and
        pretending that succeeded would leave the caller waiting for a letter
        the bank will never process.
        """
        step = self.next_step
        if step is None:
            raise DocumentError("the initialisation has nothing outstanding")

        response = parse_response(document)
        response.status.raise_for_status(f"the bank refused {step.value}")

        if step is Step.INI:
            self.ini_sent, self.ini_order_id = True, response.order_id
        elif step is Step.HIA:
            self.hia_sent, self.hia_order_id = True, response.order_id
        else:
            self.bank_keys = self._open_hpb(response)
        return response

    def _open_hpb(self, response: BankResponse) -> BankKeys:
        """Decrypt the HPB payload and read the bank's keys out of it.

        The order data is encrypted to *our* E002 key, exactly like a download
        segment, but it arrives in one piece with the transaction key beside
        it: ``HPB`` has no transfer phase and no receipt.
        """
        if response.order_data is None or response.transaction_key_encrypted is None:
            raise DocumentError(
                "the HPB response carries no encrypted order data")
        bank_keys = parse_hpb_order_data(open_order_data(
            response.order_data, response.transaction_key_encrypted,
            self.encryption_key))

        if bank_keys.host_id and bank_keys.host_id != self.context.host_id:
            raise DocumentError(
                f"the HPB order data is for HostID {bank_keys.host_id!r}, "
                f"not {self.context.host_id!r}")
        return bank_keys

    def confirm_bank_keys(self, *, authentication: str, encryption: str,
                          digest: LetterDigest = DEFAULT_LETTER_DIGEST
                          ) -> dict[str, str]:
        """Check the bank's keys against its letter. Until this, nothing is trusted.

        The state stays at :attr:`KeyState.BANK_KEYS_RECEIVED` while it has not
        been called, and a failed comparison leaves it there rather than
        reverting anything: the keys that arrived are still the evidence of
        what happened, and discarding them would make the incident harder to
        investigate than it already is.
        """
        if self.bank_keys is None:
            raise DocumentError("the bank's keys have not been fetched yet")
        fingerprints = verify_bank_keys(
            self.bank_keys, authentication=authentication,
            encryption=encryption, digest=digest)
        self.bank_fingerprints = fingerprints
        return fingerprints
