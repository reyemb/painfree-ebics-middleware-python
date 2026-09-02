"""Business Transaction Formats -- what EBICS 3.0 uses instead of order types.

Under H004 an order was named by a three-letter order type (``STA``, ``CDD``,
``FUL``) and the file format travelled out of band, in a ``FileFormat`` element
or in nothing at all. H005 replaces that with a **BTF**: the admin order type is
always ``BTD`` (download) or ``BTU`` (upload), and what is actually being moved
is described by a ``Service`` structure the bank matches against its own
catalogue.

::

    <OrderDetails>
      <AdminOrderType>BTD</AdminOrderType>
      <BTDOrderParams>
        <Service>
          <ServiceName>EOP</ServiceName>          three characters, exactly
          <Scope>CH</Scope>                       two or three, or "BIL"/"INT"
          <ServiceOption>OSG</ServiceOption>
          <Container containerType="ZIP"/>
          <MsgName version="08">camt.053</MsgName>
        </Service>
        <DateRange><Start/><End/></DateRange>
      </BTDOrderParams>
    </OrderDetails>

The element order inside ``Service`` is fixed by ``RestrictedServiceType`` and
is not negotiable: ``ServiceName``, ``Scope``, ``ServiceOption``, ``Container``,
``MsgName``. ``ServiceName`` and ``MsgName`` are required, the rest optional.
``BTDOrderParams`` then takes an optional ``DateRange`` and ``BTUOrderParams``
an optional ``SignatureFlag``; both may carry ``Parameter`` elements, and only
``BTUOrderParams`` may carry the ``fileName`` attribute -- the schema
*prohibits* it on the download side.

Getting a field wrong here does not produce an XML error. It produces
``EBICS_INVALID_ORDER_PARAMS`` from the bank, or silence, so the field lengths
are validated locally before anything is signed -- the repo's
validate-before-the-bank rule, applied one layer down.

Provenance: element names and ordering from the official H005 schemas; the
build order follows ``ebics-api/ebics-client-php``'s ``Orders/BTU`` and
``Orders/BTD`` (MIT). See ADR D-005.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from lxml import etree

from .errors import RequestError

__all__ = [
    "CONTAINER_TYPES",
    "Service",
    "append_btd_order_params",
    "append_btu_order_params",
    "append_standard_order_params",
    "append_service",
]

#: ``ContainerStringType``: how the bank wraps what it sends back.
CONTAINER_TYPES = ("SVC", "XML", "ZIP")

_CODE = re.compile(r"^[A-Z0-9]+$")
_MSG_NAME = re.compile(r"^[a-z.0-9]{1,10}$")
_NUM = re.compile(r"^[0-9]{2,3}$")


@dataclass(frozen=True)
class Service:
    """One BTF service: what is being moved, in whose scope, in what format.

    ``name`` and ``msg_name`` are required by ``RestrictedServiceType``; the
    rest are omitted from the XML when left unset, because an empty element is
    not the same as an absent one to a bank's order-parameter matcher.
    """

    name: str
    msg_name: str
    scope: str | None = None
    option: str | None = None
    container: str | None = None
    msg_variant: str | None = None
    msg_version: str | None = None
    msg_format: str | None = None

    def __post_init__(self) -> None:
        _check_code("ServiceName", self.name, 3, 3)
        if not _MSG_NAME.match(self.msg_name):
            raise RequestError(
                f"MsgName {self.msg_name!r} must be 1-10 characters of [a-z.0-9]"
            )
        if self.scope is not None:
            _check_code("Scope", self.scope, 2, 3)
        if self.option is not None:
            _check_code("ServiceOption", self.option, 3, 10)
        if self.container is not None and self.container not in CONTAINER_TYPES:
            raise RequestError(
                f"Container type {self.container!r} is not one of "
                f"{', '.join(CONTAINER_TYPES)}"
            )
        for label, value in (("variant", self.msg_variant),
                             ("version", self.msg_version)):
            if value is not None and not _NUM.match(value):
                raise RequestError(
                    f"MsgName {label} {value!r} must be two or three digits")
        if self.msg_format is not None:
            _check_code("MsgName format", self.msg_format, 1, 4)


def _check_code(field: str, value: str, minimum: int, maximum: int) -> None:
    """``CodeStringType`` plus the per-field length the schema narrows it to."""
    if not _CODE.match(value):
        raise RequestError(f"{field} {value!r} must be upper-case A-Z0-9")
    if not minimum <= len(value) <= maximum:
        raise RequestError(
            f"{field} {value!r} must be {minimum}-{maximum} characters, is {len(value)}"
        )


def append_service(parent: etree._Element, service: Service) -> etree._Element:
    """Append ``<Service>`` in the order ``RestrictedServiceType`` fixes."""
    namespace = etree.QName(parent).namespace
    element = _sub(parent, namespace, "Service")

    _sub(element, namespace, "ServiceName", service.name)
    if service.scope is not None:
        _sub(element, namespace, "Scope", service.scope)
    if service.option is not None:
        _sub(element, namespace, "ServiceOption", service.option)
    if service.container is not None:
        _sub(element, namespace, "Container", containerType=service.container)

    attributes = {}
    if service.msg_variant is not None:
        attributes["variant"] = service.msg_variant
    if service.msg_version is not None:
        attributes["version"] = service.msg_version
    if service.msg_format is not None:
        attributes["format"] = service.msg_format
    _sub(element, namespace, "MsgName", service.msg_name, **attributes)
    return element


def append_btd_order_params(
    parent: etree._Element,
    service: Service,
    *,
    date_range: tuple[str, str] | None = None,
    parameters: dict[str, str] | None = None,
) -> etree._Element:
    """``<BTDOrderParams>`` -- the download side. No ``fileName``, by schema.

    ``date_range`` is ``(start, end)`` as ISO dates. A bank that supports it
    uses it to bound a statement download; one that does not rejects the
    request rather than ignoring the range, which is why it stays optional.
    """
    namespace = etree.QName(parent).namespace
    element = _sub(parent, namespace, "BTDOrderParams")
    append_service(element, service)
    if date_range is not None:
        start, end = date_range
        node = _sub(element, namespace, "DateRange")
        _sub(node, namespace, "Start", start)
        _sub(node, namespace, "End", end)
    _append_parameters(element, namespace, parameters)
    return element


def append_btu_order_params(
    parent: etree._Element,
    service: Service,
    *,
    file_name: str | None = None,
    request_eds: bool | None = None,
    parameters: dict[str, str] | None = None,
) -> etree._Element:
    """``<BTUOrderParams>`` -- the upload side.

    ``request_eds`` sets ``SignatureFlag/@requestEDS``: the order is uploaded
    for a *distributed* signature, to be released by a human in the bank portal.
    That is the mode the repo's key-custody rule prefers, so it is a
    first-class parameter rather than something the service layer has to
    assemble itself.
    """
    namespace = etree.QName(parent).namespace
    attributes = {"fileName": file_name} if file_name is not None else {}
    element = _sub(parent, namespace, "BTUOrderParams", **attributes)
    append_service(element, service)
    if request_eds is not None:
        _sub(element, namespace, "SignatureFlag",
             requestEDS="true" if request_eds else "false")
    _append_parameters(element, namespace, parameters)
    return element


def append_standard_order_params(
    parent: etree._Element,
    *,
    date_range: tuple[str, str] | None = None,
) -> etree._Element:
    """``<StandardOrderParams>`` -- what an *administrative* order carries.

    ``HTD``, ``HPD``, ``HAA`` and the rest of the administrative downloads take
    no BTF: they are not business traffic and have no service to describe. What
    H005 requires of them is still an ``OrderParams``, because
    ``StaticHeaderOrderDetailsType`` declares that element without a
    ``minOccurs`` -- it is mandatory, and ``StandardOrderParams`` is what
    substitutes into it for these orders (``ebics_orders_H005.xsd``, the
    ``substitutionGroup="ebics:OrderParams"`` on line 194).

    So the element is empty and is still not optional. Leaving it out builds a
    document the H005 schema rejects, which is a bank refusal rather than a
    local error, and is the kind of thing that costs an afternoon to find.

    ``date_range`` exists because ``StandardOrderParamsType`` allows one -- some
    banks bound ``HAC`` by it. None of the three orders this was added for uses
    it, and it stays optional rather than being left out, because adding it back
    later would mean changing a signature that other things call.
    """
    namespace = etree.QName(parent).namespace
    element = _sub(parent, namespace, "StandardOrderParams")
    if date_range is not None:
        start, end = date_range
        node = _sub(element, namespace, "DateRange")
        _sub(node, namespace, "Start", start)
        _sub(node, namespace, "End", end)
    return element


def _append_parameters(
    parent: etree._Element, namespace: str | None, parameters: dict[str, str] | None
) -> None:
    for name, value in (parameters or {}).items():
        parameter = _sub(parent, namespace, "Parameter")
        _sub(parameter, namespace, "Name", name)
        _sub(parameter, namespace, "Value", value, Type="string")


def _sub(parent: etree._Element, namespace: str | None, name: str,
         text: str | None = None, **attributes: str) -> etree._Element:
    element = etree.SubElement(parent, etree.QName(namespace, name))
    if text is not None:
        element.text = text
    for key, value in attributes.items():
        element.set(key, value)
    return element
