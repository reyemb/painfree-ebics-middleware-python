"""painfree.ebics3 -- an EBICS 3.0 (H005) protocol engine.

Bytes and keys in, bytes out. The engine implements the protocol and nothing
else: no HTTP client, no database, no logging policy, and no opinion about where
private keys are stored. It ships inside the `painfree` distribution but must
never import from the rest of it -- that one-way dependency is what keeps the
engine separable, and releasable on its own under a permissive licence.

Ported from ``ebics-api/ebics-client-php`` (MIT). No LGPL or GPL implementation
is read while writing it; the Ruby `epics` gem takes part only as a black-box
oracle behind the differential adapter contract.

Implemented so far: the crypto layer -- key versions, RSA primitives, E002
hybrid encryption, the X.509 handling EBICS 3.0 requires, and the public-key
fingerprint a human compares against the INI letter -- inclusive XML
canonicalisation and the authentication signature over ``authenticate="true"``
elements, the H005 request builders (the three envelopes, the BTF order details
and the INI/HIA order-data payloads) and the order-data pipeline: sign the
payload with A005/A006, compress, encrypt under a per-transaction key, encode,
and the exact inverse, and the three-phase transaction protocol: an explicit
state machine the caller drives through initialisation, transfer and receipt,
segmenting an upload and reassembling a download, the return-code table
that turns the bank's six digits into a symbolic name, a severity and a
decision about what happens next, and subscriber initialisation: INI, HIA and
HPB as a resumable state machine, the bank's keys read out of the HPB order
data, the INI letter's content, and the fingerprint comparison against the
bank's letter -- which is the only check an unsigned HPB response has.

    >>> from painfree.ebics3 import EbicsKey, subject_name
    >>> key = EbicsKey.generate("A006", subject=subject_name("acme", "Acme AG", "CH"))
    >>> key.fingerprint_hex[:8] != ""
    True
"""

from __future__ import annotations

from .bankinfo import (AccountInfo, BankParameters, OrderInfo,
                       SubscriberInfo, parse_haa_order_data,
                       parse_hpd_order_data, parse_htd_order_data)
from .btf import (CONTAINER_TYPES, Service, append_btd_order_params,
                  append_btu_order_params, append_service)
from .canon import (AUTHENTICATED_XPATH, C14N_INCLUSIVE, XMLDSIG_NAMESPACE,
                    authenticated_nodes, canonicalize_element,
                    canonicalize_nodeset, in_scope_namespaces, parse_xml)
from .certificates import (certificate_der, certificate_fingerprint, issuer_name,
                           load_certificate, self_signed_certificate, subject_name)
from .crypto import (AES_BLOCK_SIZE, TRANSACTION_KEY_SIZE, aes_decrypt,
                     aes_encrypt, crypto_binary, generate_private_key,
                     generate_transaction_key, load_private_key,
                     load_public_key, private_pem, public_key_digest,
                     public_key_digest_hex, public_key_hex, public_pem,
                     rsa_decrypt, rsa_encrypt, sign, sign_digest, verify,
                     verify_digest)
from .errors import (BankKeyMismatchError, BankRefusedError, CertificateError,
                     DocumentError, Ebics3Error, KeyMaterialError,
                     RequestError, TransactionError, UnsupportedVersionError)
from .initialisation import (BankKeys, IniLetter, Initialisation, KeyState,
                             DEFAULT_LETTER_DIGEST, LetterDigest, LetterKey,
                             Step, build_ini_letter,
                             format_bytes, format_fingerprint, ini_letter_hash,
                             parse_hpb_order_data, verify_bank_keys)
from .keys import EbicsKey
from .orderdata import (S002_NAMESPACE, append_x509_data,
                        build_hia_request_order_data,
                        build_signature_pub_key_order_data,
                        compress_order_data, decompress_order_data,
                        encode_order_data, serialize_order_data)
from .pipeline import (USER_SIGNATURE_SCHEMA_LOCATION, SecuredOrderData,
                       build_user_signature, decrypt_payload, encrypt_payload,
                       open_order_data, order_data_digest, secure_order_data,
                       unwrap_transaction_key, user_signature_value,
                       verify_user_signature, wrap_transaction_key)
from .requests import (DIGEST_ALGORITHM, EBICS_REVISION, RECEIPT_CODE_NEGATIVE,
                       RECEIPT_CODE_POSITIVE, Product, RequestContext,
                       ADMIN_DOWNLOADS, append_data_transfer,
                       build_admin_download_request, build_btd_request,
                       build_btu_request, build_hia_request, build_hpb_request,
                       build_ini_request, build_receipt_request,
                       build_transfer_request, certificate_digest_b64,
                       generate_nonce, serialize_request, utc_timestamp)
from .responses import (EBICS_DOWNLOAD_POSTPROCESS_DONE,
                        EBICS_DOWNLOAD_POSTPROCESS_SKIPPED, EBICS_OK,
                        EBICS_TX_RECOVERY_SYNC, BankResponse, ResponseStatus,
                        classify, parse_response)
from .returncodes import (RETURN_CODES, Disposition, Family, ReturnCode,
                          Severity, lookup)
from .signature import (AuthSignatureCheck, auth_digest, auth_digest_b64,
                        build_auth_signature, declared_digest,
                        declared_signature, signed_info_c14n,
                        verify_auth_signature)
from .transaction import (SEGMENT_SIZE, DownloadTransaction, Phase,
                          UploadTransaction, split_segments)
from .versions import KeyRole, KeyVersion

__version__ = "0.1.0"

#: The EBICS protocol version this engine speaks. The engine targets 3.0 only
#: -- Swiss banks require it, and supporting both would double the request
#: builders for no user.
EBICS_VERSION = "H005"
EBICS_NAMESPACE = "urn:org:ebics:H005"

__all__ = [
    "AES_BLOCK_SIZE",
    "AUTHENTICATED_XPATH",
    "AuthSignatureCheck",
    "BankKeyMismatchError",
    "BankKeys",
    "BankRefusedError",
    "BankResponse",
    "C14N_INCLUSIVE",
    "CONTAINER_TYPES",
    "CertificateError",
    "DIGEST_ALGORITHM",
    "Disposition",
    "DocumentError",
    "DownloadTransaction",
    "EBICS_DOWNLOAD_POSTPROCESS_DONE",
    "EBICS_DOWNLOAD_POSTPROCESS_SKIPPED",
    "EBICS_NAMESPACE",
    "EBICS_OK",
    "EBICS_REVISION",
    "EBICS_TX_RECOVERY_SYNC",
    "EBICS_VERSION",
    "Ebics3Error",
    "EbicsKey",
    "Family",
    "IniLetter",
    "Initialisation",
    "KeyMaterialError",
    "KeyRole",
    "KeyState",
    "KeyVersion",
    "DEFAULT_LETTER_DIGEST",
    "LetterDigest",
    "LetterKey",
    "Phase",
    "Product",
    "RECEIPT_CODE_NEGATIVE",
    "RECEIPT_CODE_POSITIVE",
    "RETURN_CODES",
    "RequestContext",
    "RequestError",
    "ResponseStatus",
    "ReturnCode",
    "S002_NAMESPACE",
    "SEGMENT_SIZE",
    "SecuredOrderData",
    "Service",
    "Severity",
    "Step",
    "TRANSACTION_KEY_SIZE",
    "TransactionError",
    "USER_SIGNATURE_SCHEMA_LOCATION",
    "UnsupportedVersionError",
    "UploadTransaction",
    "XMLDSIG_NAMESPACE",
    "__version__",
    "aes_decrypt",
    "aes_encrypt",
    "append_btd_order_params",
    "append_btu_order_params",
    "append_data_transfer",
    "append_service",
    "append_x509_data",
    "auth_digest",
    "auth_digest_b64",
    "authenticated_nodes",
    "build_auth_signature",
    "ADMIN_DOWNLOADS",
    "AccountInfo",
    "BankParameters",
    "OrderInfo",
    "SubscriberInfo",
    "parse_haa_order_data",
    "parse_hpd_order_data",
    "parse_htd_order_data",
    "build_admin_download_request",
    "build_btd_request",
    "build_btu_request",
    "build_hia_request",
    "build_hia_request_order_data",
    "build_hpb_request",
    "build_ini_letter",
    "build_ini_request",
    "build_receipt_request",
    "build_signature_pub_key_order_data",
    "build_transfer_request",
    "build_user_signature",
    "canonicalize_element",
    "canonicalize_nodeset",
    "certificate_der",
    "certificate_digest_b64",
    "certificate_fingerprint",
    "classify",
    "compress_order_data",
    "crypto_binary",
    "declared_digest",
    "declared_signature",
    "decompress_order_data",
    "decrypt_payload",
    "encode_order_data",
    "encrypt_payload",
    "format_bytes",
    "format_fingerprint",
    "generate_nonce",
    "generate_private_key",
    "generate_transaction_key",
    "in_scope_namespaces",
    "ini_letter_hash",
    "issuer_name",
    "load_certificate",
    "load_private_key",
    "load_public_key",
    "lookup",
    "open_order_data",
    "order_data_digest",
    "parse_hpb_order_data",
    "parse_response",
    "parse_xml",
    "private_pem",
    "public_key_digest",
    "public_key_digest_hex",
    "public_key_hex",
    "public_pem",
    "rsa_decrypt",
    "rsa_encrypt",
    "secure_order_data",
    "self_signed_certificate",
    "serialize_order_data",
    "serialize_request",
    "sign",
    "sign_digest",
    "signed_info_c14n",
    "split_segments",
    "subject_name",
    "unwrap_transaction_key",
    "user_signature_value",
    "utc_timestamp",
    "verify",
    "verify_auth_signature",
    "verify_bank_keys",
    "verify_digest",
    "verify_user_signature",
    "wrap_transaction_key",
]
