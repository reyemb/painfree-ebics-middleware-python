"""Inclusive XML canonicalisation, implemented rather than delegated.

The EBICS authentication signature covers the canonical form of a node-set, so
this module decides whether a bank accepts the request at all. It implements
**inclusive C14N 1.0** (``REC-xml-c14n-20010315``) directly over the lxml tree
instead of calling into lxml's own canonicaliser, because both of lxml's
obvious entry points get an EBICS subtree wrong:

* ``etree.tostring(node, method="c14n")`` emits ``xmlns=""`` on every child when
  an ancestor declares a default namespace, pushing the children out of the
  EBICS namespace.
* ``etree.canonicalize(etree.tostring(node))`` renders the children correctly
  but drops in-scope declarations the subtree does not itself use -- typically
  ``xmlns:ds`` -- which inclusive C14N requires on the apex element.

Patching around either one means editing canonical text after the fact. Walking
the tree is less code than that, and it is the only version that also gets the
converse right: a declaration already rendered on an output ancestor is *not*
repeated further down.

Provenance: written from the W3C Recommendation. ``ebics-client-php`` (MIT)
delegates this to ``DOMNode::C14N``, so there was nothing to port.
"""

from __future__ import annotations

from typing import Iterator

from lxml import etree

from .errors import DocumentError

__all__ = [
    "AUTHENTICATED_XPATH",
    "C14N_INCLUSIVE",
    "XMLDSIG_NAMESPACE",
    "authenticated_nodes",
    "canonicalize_element",
    "canonicalize_nodeset",
    "in_scope_namespaces",
    "parse_xml",
]

#: The canonicalisation algorithm EBICS names in ``CanonicalizationMethod`` and
#: in the reference's ``Transform``. Inclusive, not exclusive -- see ADR D-011.
C14N_INCLUSIVE = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"

XMLDSIG_NAMESPACE = "http://www.w3.org/2000/09/xmldsig#"
XML_NAMESPACE = "http://www.w3.org/XML/1998/namespace"

#: The node-set the EBICS reference URI ``#xpointer(//*[@authenticate='true'])``
#: selects.
AUTHENTICATED_XPATH = "//*[@authenticate='true']"


def parse_xml(data: bytes | str) -> etree._Element:
    """Parse without touching whitespace -- canonicalisation is byte sensitive.

    ``remove_blank_text`` would silently change the digest of every
    pretty-printed document, and entity resolution is off because the engine
    parses bytes that arrived from a bank.
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    parser = etree.XMLParser(remove_blank_text=False, resolve_entities=False)
    try:
        return etree.fromstring(data, parser=parser)
    except etree.XMLSyntaxError as exc:
        raise DocumentError(f"not well-formed XML: {exc}") from exc


def in_scope_namespaces(node: etree._Element) -> dict[str | None, str]:
    """Every namespace declaration visible at ``node``, nearest one winning.

    lxml's ``nsmap`` already resolves the ancestor axis for us; this wrapper
    exists so the rule is named where the C14N code reads it, and so a caller
    can inspect it when a digest disagrees.
    """
    return dict(node.nsmap)


def authenticated_nodes(root: etree._Element) -> list[etree._Element]:
    return list(root.xpath(AUTHENTICATED_XPATH))


def canonicalize_element(node: etree._Element) -> bytes:
    """Canonical form of one element as if it were still in its document.

    The apex therefore carries every in-scope namespace declaration, including
    inherited ones the subtree never uses.
    """
    out: list[str] = []
    _render(node, {}, out)
    return "".join(out).encode("utf-8")


def canonicalize_nodeset(
    root: etree._Element, xpath: str = AUTHENTICATED_XPATH
) -> bytes:
    """Canonical form of an XML-DSig node-set: document order, each node once.

    A selected node that lies inside another selected node is already part of
    its ancestor's canonical subtree. Serialising it again double-counts it and
    yields a digest no bank accepts, so descendants are skipped -- the case is
    rare in practice, which is exactly why it is easy to get wrong.
    """
    try:
        selected = list(root.xpath(xpath))
    except etree.XPathError as exc:
        raise DocumentError(f"bad node-set expression {xpath!r}: {exc}") from exc

    return b"".join(canonicalize_element(node) for node in _outermost(selected))


def _outermost(nodes: list[etree._Element]) -> Iterator[etree._Element]:
    identities = {id(node) for node in nodes}
    for node in nodes:
        if not any(id(a) in identities for a in node.iterancestors()):
            yield node


# --- the serialiser --------------------------------------------------------
#
# Canonical XML 1.0, minus what an EBICS document cannot contain: no DTD, no
# document-level prolog, and comments are excluded (the signature never covers
# them).

def _render(node: etree._Element, rendered: dict[str, str], out: list[str]) -> None:
    nsmap = node.nsmap
    name = _element_name(node.tag, nsmap)

    declarations = _declarations(nsmap, rendered)
    out.append(f"<{name}")
    for declaration, uri in declarations:
        out.append(f' {declaration}="{_escape_attribute(uri)}"')
    for qualified in _attributes(node, nsmap):
        out.append(qualified)
    out.append(">")

    inherited = {**rendered, **dict(declarations)}
    if node.text:
        out.append(_escape_text(node.text))
    for child in node:
        if isinstance(child, etree._Comment):
            pass  # excluded: the signature is taken with_comments=false
        elif isinstance(child, etree._ProcessingInstruction):
            out.append(_processing_instruction(child))
        else:
            _render(child, inherited, out)
        if child.tail:
            out.append(_escape_text(child.tail))
    out.append(f"</{name}>")


def _declarations(
    nsmap: dict[str | None, str], rendered: dict[str, str]
) -> list[tuple[str, str]]:
    """Namespace declarations this element must emit, in canonical order.

    A declaration is emitted unless an output ancestor already emitted the same
    prefix with the same URI. ``xmlns=""`` appears only where it is needed to
    undeclare a default namespace an ancestor did emit. Order is the default
    declaration first, then by prefix.
    """
    declarations: list[tuple[str, str]] = []
    for prefix, uri in nsmap.items():
        if uri == XML_NAMESPACE:
            continue  # the xml prefix is implicitly declared everywhere
        declaration = "xmlns" if prefix is None else f"xmlns:{prefix}"
        if rendered.get(declaration) != uri:
            declarations.append((declaration, uri))
    if None not in nsmap and rendered.get("xmlns", ""):
        declarations.append(("xmlns", ""))
    declarations.sort(key=lambda item: (item[0] != "xmlns", item[0]))
    return declarations


def _attributes(node: etree._Element, nsmap: dict[str | None, str]) -> list[str]:
    """Attributes sorted by namespace URI then local name, already escaped.

    Unprefixed attributes carry no namespace, so they sort ahead of every
    qualified one.
    """
    ordered = []
    for tag, value in node.attrib.items():
        uri, local, qualified = _attribute_name(tag, nsmap)
        ordered.append((uri, local, f' {qualified}="{_escape_attribute(value)}"'))
    ordered.sort(key=lambda item: (item[0], item[1]))
    return [rendered for _, _, rendered in ordered]


def _element_name(tag: object, nsmap: dict[str | None, str]) -> str:
    if not isinstance(tag, str):
        raise DocumentError(f"cannot canonicalise node of type {type(tag)}")
    if not tag.startswith("{"):
        return tag
    uri, local = tag[1:].split("}", 1)
    if nsmap.get(None) == uri:
        return local
    return f"{_prefix_for(uri, nsmap)}:{local}"


def _attribute_name(
    tag: str, nsmap: dict[str | None, str]
) -> tuple[str, str, str]:
    """``(namespace uri, local name, qualified name)`` for one attribute.

    An attribute is never in the default namespace, so a namespaced attribute
    always needs an explicit prefix.
    """
    if not tag.startswith("{"):
        return "", tag, tag
    uri, local = tag[1:].split("}", 1)
    return uri, local, f"{_prefix_for(uri, nsmap)}:{local}"


def _prefix_for(uri: str, nsmap: dict[str | None, str]) -> str:
    if uri == XML_NAMESPACE:
        return "xml"
    for prefix, declared in nsmap.items():
        if prefix is not None and declared == uri:
            return prefix
    raise DocumentError(f"no in-scope prefix declares {uri}")


def _escape_text(text: str) -> str:
    return (text.replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace("\r", "&#xD;"))


def _escape_attribute(value: str) -> str:
    return (value.replace("&", "&amp;").replace("<", "&lt;")
                 .replace('"', "&quot;").replace("\t", "&#x9;")
                 .replace("\n", "&#xA;").replace("\r", "&#xD;"))


def _processing_instruction(node: etree._ProcessingInstruction) -> str:
    body = node.text or ""
    return f"<?{node.target} {body}?>" if body else f"<?{node.target}?>"
