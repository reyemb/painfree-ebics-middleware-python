"""Unit tests for the engine's canonicalisation and authentication signature.

These complement the differential gate, they do not replace it: that four
implementations produce the same canonical bytes over the corpus is proved in
`conformance` L2. What is pinned here is what no other implementation proves
for us -- the C14N rules that no EBICS fixture happens to exercise, the two
lxml behaviours that made a hand-written serialiser necessary, and the failure
reporting a bank rejection is diagnosed with.

Self-contained on purpose: the documents are built inline and the key is minted
here, so the engine's own suite runs without the reference checkouts.
"""

from __future__ import annotations

import base64

import pytest
from lxml import etree

from painfree import ebics3

H004 = "urn:org:ebics:H004"
DS = "http://www.w3.org/2000/09/xmldsig#"

#: A minimal but schema-shaped H004 request: the ds prefix is declared on the
#: root and used nowhere, which is exactly the case inclusive C14N gets wrong
#: if the apex does not re-emit its in-scope declarations.
REQUEST = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    f'<ebicsNoPubKeyDigestsRequest xmlns="{H004}" xmlns:ds="{DS}"'
    ' Version="H004" Revision="1">\n'
    '  <header authenticate="true">\n'
    '    <static><HostID>HOST</HostID></static>\n'
    '    <mutable/>\n'
    '  </header>\n'
    '  <body/>\n'
    '</ebicsNoPubKeyDigestsRequest>\n'
).encode("utf-8")

KEY = ebics3.generate_private_key()


def parsed():
    return ebics3.parse_xml(REQUEST)


# --- canonicalisation ------------------------------------------------------

def test_apex_carries_declarations_inherited_from_ancestors():
    canonical = ebics3.canonicalize_nodeset(parsed()).decode()
    assert canonical.startswith(
        f'<header xmlns="{H004}" xmlns:ds="{DS}" authenticate="true">')
    assert 'xmlns=""' not in canonical


def test_both_lxml_shortcuts_produce_a_digest_no_bank_accepts():
    """Why this engine canonicalises by hand rather than delegating.

    Pinned as a test because the two calls look obviously correct, and a later
    reader will otherwise try one of them again.
    """
    header = ebics3.authenticated_nodes(parsed())[0]
    assert b'xmlns=""' in etree.tostring(header, method="c14n")
    assert f'xmlns:ds="{DS}"' not in etree.canonicalize(
        etree.tostring(header, encoding="unicode"))


def test_a_selected_node_inside_another_is_rendered_once():
    """Serialising a nested selection twice double-counts it in the digest."""
    xml = (f'<r xmlns="{H004}"><header authenticate="true">'
           '<inner authenticate="true">x</inner></header></r>').encode()
    root = ebics3.parse_xml(xml)
    assert len(ebics3.authenticated_nodes(root)) == 2
    assert ebics3.canonicalize_nodeset(root).count(b"<inner") == 1


def test_a_declaration_already_rendered_is_not_repeated_on_a_child():
    """The converse of the apex rule, and the one lxml text-patching misses.

    No corpus fixture nests a prefixed element under an authenticated one, so
    this value is not covered by the differential gate. It was captured from
    the two independent oracles instead: `ebics-client-php` 8.5.9 and the
    `epics` gem both canonicalise this document exactly as asserted here.
    """
    xml = (f'<r xmlns="{H004}" xmlns:ds="{DS}"><header authenticate="true">'
           '<ds:KeyName>k</ds:KeyName></header></r>').encode()
    assert ebics3.canonicalize_nodeset(ebics3.parse_xml(xml)) == (
        f'<header xmlns="{H004}" xmlns:ds="{DS}" authenticate="true">'
        '<ds:KeyName>k</ds:KeyName></header>').encode()


def test_leaving_the_default_namespace_is_undeclared_explicitly():
    xml = (f'<r xmlns="{H004}"><header authenticate="true">'
           '<plain xmlns="">x</plain></header></r>').encode()
    assert b'<plain xmlns="">x</plain>' in ebics3.canonicalize_nodeset(
        ebics3.parse_xml(xml))


def test_attributes_sort_after_declarations_and_by_name():
    xml = (f'<r xmlns="{H004}" xmlns:ds="{DS}">'
           '<header b="2" authenticate="true" a="1" ds:z="3"/></r>').encode()
    assert ebics3.canonicalize_nodeset(ebics3.parse_xml(xml)) == (
        f'<header xmlns="{H004}" xmlns:ds="{DS}"'
        ' a="1" authenticate="true" b="2" ds:z="3"></header>').encode()


def test_markup_in_text_and_attributes_is_escaped_canonically():
    xml = (f'<r xmlns="{H004}"><header authenticate="true" a="&lt;&amp;&#9;">'
           '1 &lt; 2 &amp; 3 &gt; 0</header></r>').encode()
    canonical = ebics3.canonicalize_nodeset(ebics3.parse_xml(xml)).decode()
    assert 'a="&lt;&amp;&#x9;"' in canonical
    assert "1 &lt; 2 &amp; 3 &gt; 0" in canonical


def test_comments_are_not_part_of_the_signature():
    xml = (f'<r xmlns="{H004}"><header authenticate="true">'
           '<!-- ignored --><a>1</a></header></r>').encode()
    assert b"ignored" not in ebics3.canonicalize_nodeset(ebics3.parse_xml(xml))


def test_whitespace_between_elements_is_preserved():
    """`remove_blank_text` on the parser would silently change every digest."""
    assert b"\n    <mutable></mutable>\n" in ebics3.canonicalize_nodeset(parsed())


def test_a_malformed_document_is_refused_as_a_document_error():
    with pytest.raises(ebics3.DocumentError):
        ebics3.parse_xml(b"<broken>")


# --- the authentication signature ------------------------------------------

@pytest.mark.parametrize("version", ["X002", "A005", "A006"])
def test_a_signed_request_verifies_under_every_signature_version(version):
    root = ebics3.build_auth_signature(parsed(), KEY, version)
    assert ebics3.verify_auth_signature(root, KEY.public_key(), version).ok


def test_the_signature_sits_between_the_header_and_the_body():
    """Element order the H00X schema insists on, and a signer can get wrong."""
    root = ebics3.build_auth_signature(parsed(), KEY)
    assert [etree.QName(child).localname for child in root] == [
        "header", "AuthSignature", "body"]


def test_signing_twice_replaces_the_previous_signature():
    root = ebics3.build_auth_signature(parsed(), KEY)
    first = ebics3.declared_signature(root)
    ebics3.build_auth_signature(root, KEY)
    assert len(root.xpath("//*[local-name()='AuthSignature']")) == 1
    assert ebics3.declared_digest(root) == ebics3.auth_digest_b64(root)
    assert first is not None


def test_a006_is_not_byte_reproducible_but_still_verifies():
    """RSA-PSS salts randomly, so two A006 signatures over one document differ.

    Recorded as behaviour rather than treated as a defect: A006 output can only
    ever be round-trip verified, never diffed against another implementation.
    """
    first = ebics3.build_auth_signature(parsed(), KEY, "A006")
    second = ebics3.build_auth_signature(parsed(), KEY, "A006")
    assert ebics3.declared_digest(first) == ebics3.declared_digest(second)
    assert ebics3.declared_signature(first) != ebics3.declared_signature(second)
    assert ebics3.verify_auth_signature(first, KEY.public_key(), "A006").ok


def test_a_tampered_header_fails_the_digest_but_not_the_signature():
    """The two halves are reported apart because they mean different things."""
    root = ebics3.build_auth_signature(parsed(), KEY)
    root.xpath("//*[local-name()='HostID']")[0].text = "OTHER"
    check = ebics3.verify_auth_signature(root, KEY.public_key())
    assert not check.ok and not check.digest_ok and check.signature_ok


def test_the_wrong_key_fails_the_signature_but_not_the_digest():
    root = ebics3.build_auth_signature(parsed(), KEY)
    check = ebics3.verify_auth_signature(
        root, ebics3.generate_private_key().public_key())
    assert not check.ok and check.digest_ok and not check.signature_ok
    assert check.signature_present


def test_signed_info_is_addressed_by_name_not_as_the_signature_subtree():
    """`//AuthSignature/*` also selects SignatureValue once a document is
    signed, which is how a verifier ends up disagreeing with its own signer."""
    root = ebics3.build_auth_signature(parsed(), KEY)
    assert b"SignatureValue" not in ebics3.signed_info_c14n(root)
    assert ebics3.C14N_INCLUSIVE.encode() in ebics3.signed_info_c14n(root)


def test_an_unsigned_document_reports_what_is_missing():
    root = parsed()
    check = ebics3.verify_auth_signature(root, KEY.public_key())
    assert not check.signature_present and check.digest_expected is None
    assert check.digest_actual == ebics3.auth_digest_b64(root)
    with pytest.raises(ebics3.DocumentError):
        ebics3.signed_info_c14n(root)


def test_an_empty_digest_element_is_not_the_same_as_an_absent_one():
    """Corpus fixtures ship `<DigestValue/>` as an unfilled slot; reporting it
    as absent would hide a document that claims a digest and gives none."""
    empty = ebics3.parse_xml(
        f'<r xmlns="{H004}"><ds:DigestValue xmlns:ds="{DS}"/></r>'.encode())
    assert ebics3.declared_digest(empty) == ""
    assert ebics3.declared_digest(parsed()) is None


def test_a_document_without_a_header_cannot_be_signed():
    with pytest.raises(ebics3.DocumentError):
        ebics3.build_auth_signature(
            ebics3.parse_xml(f'<r xmlns="{H004}"><body/></r>'.encode()), KEY)


def test_the_declared_digest_survives_serialisation():
    """A signature is only worth anything after the document has been written
    out and read back by somebody else."""
    root = ebics3.build_auth_signature(parsed(), KEY)
    again = ebics3.parse_xml(etree.tostring(root, encoding="UTF-8"))
    assert ebics3.verify_auth_signature(again, KEY.public_key()).ok
    assert base64.b64decode(ebics3.declared_digest(again)) == ebics3.auth_digest(again)
