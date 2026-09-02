"""What the bank says about itself: ``HAA``, ``HTD`` and ``HPD`` order data.

These three replace a PDF. Until now the only way to know which BTFs a bank
accepts was its published parameter sheet -- a document that goes out of date
without telling anybody, and that has to be transcribed by hand into a
connection's scheme configuration. The bank knows the answer and EBICS has
always had a way to ask it.

===========  ==========================================================
``HAA``      the services the bank currently has data ready for
``HTD``      this subscriber's customer and user data, and **the order
             catalogue**: one ``OrderInfo`` per thing this subscriber may
             send or fetch, each with its BTF
``HPD``      the bank's own parameters: protocol versions, algorithms,
             recovery and segment limits
===========  ==========================================================

**``HTD`` is the one that matters most**, because its ``PartnerInfo/OrderInfo``
list is precisely the table an operator otherwise reads off a PDF: an admin
order type, the BTF that goes with it, a human description, and how many
signatures the bank wants. Comparing it against a connection's configured
schemes answers "will this payment be accepted" without sending one.

**What is modelled and what is not.** The schema types here are large -- an
address, a bank's name and postcode, per-account usage lists -- and most of it
is of no interest to a payment engine. What is read is what decides something:
the order catalogue, the accounts, and the bank's declared limits. Everything
else is left in the document rather than half-modelled, because a dataclass
with a field nobody fills is a field somebody later trusts. The raw document is
kept alongside the parse for exactly that reason.

Provenance: element names, ordering and cardinality from the official H005
schemas (``ebics_orders_H005.xsd``), which is also what the request builders
are checked against. See ADR D-005.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from lxml import etree

from .btf import Service
from .errors import DocumentError

__all__ = [
    "AccountInfo",
    "BankParameters",
    "OrderInfo",
    "SubscriberInfo",
    "parse_haa_order_data",
    "parse_hpd_order_data",
    "parse_htd_order_data",
]

NAMESPACE = "urn:org:ebics:H005"


def _q(name: str) -> str:
    return f"{{{NAMESPACE}}}{name}"


def _root(document: bytes | str | etree._Element, expected: str) -> etree._Element:
    """The document element, having checked it is the one asked for.

    A parser handed the wrong order data would otherwise return an empty
    structure rather than an error, and an empty catalogue reads as *this bank
    offers nothing* -- which is a conclusion nobody should reach by accident.
    """
    if isinstance(document, etree._Element):
        root = document
    else:
        raw = document.encode("utf-8") if isinstance(document, str) else document
        try:
            root = etree.fromstring(raw)
        except etree.XMLSyntaxError as exc:
            raise DocumentError(f"{expected} is not well-formed XML: {exc}") from None
    found = etree.QName(root).localname
    if found != expected:
        raise DocumentError(f"<{found}> is not {expected}")
    return root


def _text(parent: etree._Element, name: str) -> str | None:
    node = parent.find(_q(name))
    if node is None or node.text is None:
        return None
    value = node.text.strip()
    return value or None


def _service(node: etree._Element | None) -> Service | None:
    """``RestrictedServiceType`` back into the same :class:`Service` a request
    is built from, so a published BTF and a configured one are comparable
    without either side being translated first."""
    if node is None:
        return None
    name = _text(node, "ServiceName")
    message = node.find(_q("MsgName"))
    if name is None or message is None or not (message.text or "").strip():
        # Both are required by the schema. A bank that omits one has sent
        # something this engine should not quietly treat as a service.
        raise DocumentError(
            "a Service in the bank's order data has no ServiceName or MsgName")
    container = node.find(_q("Container"))
    return Service(
        name=name,
        msg_name=message.text.strip(),
        scope=_text(node, "Scope"),
        option=_text(node, "ServiceOption"),
        container=(container.get("containerType") if container is not None
                   else None),
        msg_variant=message.get("variant"),
        msg_version=message.get("version"),
        msg_format=message.get("format"),
    )


@dataclass(frozen=True)
class OrderInfo:
    """One row of the bank's catalogue for this subscriber.

    ``service`` is ``None`` for the administrative orders -- ``HAC``, ``HPB``
    and the rest carry no BTF because they are not business traffic.
    """

    admin_order_type: str
    service: Service | None
    description: str | None = None
    num_sig_required: int | None = None

    @property
    def is_upload(self) -> bool:
        return self.admin_order_type == "BTU"

    @property
    def is_download(self) -> bool:
        return self.admin_order_type == "BTD"


@dataclass(frozen=True)
class AccountInfo:
    """One account this subscriber may act on, as the bank names it."""

    account_id: str
    description: str | None = None
    iban: str | None = None
    currency: str | None = None


@dataclass(frozen=True)
class SubscriberInfo:
    """``HTD``: who this subscriber is to the bank, and what they may send."""

    partner_id: str | None
    user_id: str | None
    name: str | None
    accounts: tuple[AccountInfo, ...] = ()
    orders: tuple[OrderInfo, ...] = ()
    document: bytes | None = field(default=None, repr=False)

    def uploads(self) -> tuple[OrderInfo, ...]:
        """Every ``BTU`` row: what this subscriber may *send*.

        The list a payment is checked against. A connection configured to send
        under a BTF that is not in here is a connection whose next upload the
        bank refuses.
        """
        return tuple(row for row in self.orders if row.is_upload)

    def downloads(self) -> tuple[OrderInfo, ...]:
        return tuple(row for row in self.orders if row.is_download)

    def offers(self, service: Service) -> bool:
        """Does the bank publish an upload matching this configured service?

        Compared on the fields that decide a match at the bank -- the name, the
        scope, the option and the message -- and not on the container, which a
        bank may leave off an upload row it still accepts.
        """
        for row in self.uploads():
            published = row.service
            if published is None:
                continue
            if (published.name == service.name
                    and published.scope == service.scope
                    and published.option == service.option
                    and published.msg_name == service.msg_name):
                return True
        return False


@dataclass(frozen=True)
class BankParameters:
    """``HPD``: what the bank says it can do, rather than what it holds."""

    host_id: str | None = None
    protocol_versions: tuple[str, ...] = ()
    authentication_versions: tuple[str, ...] = ()
    encryption_versions: tuple[str, ...] = ()
    signature_versions: tuple[str, ...] = ()
    recovery_supported: bool | None = None
    pre_validation_supported: bool | None = None
    client_data_download: bool | None = None
    document: bytes | None = field(default=None, repr=False)


def parse_haa_order_data(
    document: bytes | str | etree._Element,
) -> tuple[Service, ...]:
    """``HAAResponseOrderData``: the services the bank has data ready for.

    A list of what is *available now*, which is not the same question as what
    this subscriber is permitted to send -- that is ``HTD``. An empty list is a
    legitimate answer meaning nothing is waiting, and is returned as one rather
    than raised.
    """
    root = _root(document, "HAAResponseOrderData")
    return tuple(service for service in
                 (_service(node) for node in root.findall(_q("Service")))
                 if service is not None)


def parse_htd_order_data(
    document: bytes | str | etree._Element,
) -> SubscriberInfo:
    """``HTDResponseOrderData``: this subscriber, and the bank's catalogue."""
    root = _root(document, "HTDResponseOrderData")
    partner = root.find(_q("PartnerInfo"))
    user = root.find(_q("UserInfo"))
    if partner is None or user is None:
        raise DocumentError(
            "HTDResponseOrderData needs both PartnerInfo and UserInfo")

    address = partner.find(_q("AddressInfo"))
    accounts = []
    for node in partner.findall(_q("AccountInfo")):
        identifier = node.get("ID")
        if identifier is None:
            # Required by the schema, and the key the permissions reference.
            raise DocumentError("an AccountInfo in HTD carries no ID")
        number = node.find(_q("AccountNumber"))
        accounts.append(AccountInfo(
            account_id=identifier,
            description=node.get("Description"),
            iban=(number.text.strip()
                  if number is not None and number.text else None),
            currency=node.get("Currency"),
        ))

    orders = []
    for node in partner.findall(_q("OrderInfo")):
        admin = _text(node, "AdminOrderType")
        if admin is None:
            raise DocumentError("an OrderInfo in HTD carries no AdminOrderType")
        signatures = _text(node, "NumSigRequired")
        orders.append(OrderInfo(
            admin_order_type=admin,
            service=_service(node.find(_q("Service"))),
            description=_text(node, "Description"),
            num_sig_required=int(signatures) if signatures is not None else None,
        ))

    user_identity = user.find(_q("UserID"))
    return SubscriberInfo(
        partner_id=(partner.find(_q("PartnerID")).text.strip()
                    if partner.find(_q("PartnerID")) is not None
                    and partner.find(_q("PartnerID")).text else None),
        user_id=(user_identity.text.strip()
                 if user_identity is not None and user_identity.text else None),
        name=_text(address, "Name") if address is not None else None,
        accounts=tuple(accounts),
        orders=tuple(orders),
        document=(etree.tostring(root) if not isinstance(document, bytes)
                  else document),
    )


def parse_hpd_order_data(
    document: bytes | str | etree._Element,
) -> BankParameters:
    """``HPDResponseOrderData``: the bank's declared capabilities.

    ``ProtocolParams/Version`` carries one element per key role -- ``Protocol``,
    ``Authentication``, ``Encryption``, ``Signature`` -- each holding one or
    more ``<Version>`` values. That is where "does this bank still take X002"
    is answered, and it is answered by the bank rather than by a support email.

    ``Recovery``, ``PreValidation`` and ``ClientDataDownload`` are optional and
    carry ``OptSupportFlag``, whose ``supported`` attribute is the whole
    content. Absent means the bank said nothing, which is not the same as
    ``false``, so all three are ``None`` when missing rather than defaulted.
    """
    root = _root(document, "HPDResponseOrderData")
    access = root.find(_q("AccessParams"))
    protocol = root.find(_q("ProtocolParams"))
    version = protocol.find(_q("Version")) if protocol is not None else None

    def versions(role: str) -> tuple[str, ...]:
        if version is None:
            return ()
        node = version.find(_q(role))
        if node is None:
            return ()
        return tuple(value.text.strip()
                     for value in node.findall(_q("Version"))
                     if value.text and value.text.strip())

    def supported(tag: str) -> bool | None:
        if protocol is None:
            return None
        node = protocol.find(_q(tag))
        if node is None:
            return None
        raw = node.get("supported")
        return None if raw is None else raw in ("true", "1")

    host = None
    if access is not None:
        node = access.find(_q("HostID"))
        if node is not None and node.text:
            host = node.text.strip()

    return BankParameters(
        host_id=host,
        protocol_versions=versions("Protocol"),
        authentication_versions=versions("Authentication"),
        encryption_versions=versions("Encryption"),
        signature_versions=versions("Signature"),
        recovery_supported=supported("Recovery"),
        pre_validation_supported=supported("PreValidation"),
        client_data_download=supported("ClientDataDownload"),
        document=(document if isinstance(document, bytes)
                  else etree.tostring(root)),
    )
