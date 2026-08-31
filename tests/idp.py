"""A stub identity provider: real keys, a real JWKS, a real socket.

There is no reference implementation to diff an authentication layer against, so
the evidence here is not a match with an oracle -- it is that a deliberately
hostile token is refused. That needs a provider whose keys this test suite
controls: one that can rotate, revoke, sign with the wrong key, and answer a
token request with whatever the attack requires.

Everything is generated per test: no borrowed key material, and no fixture
token whose signature nobody can re-derive.

The HTTP half exists because the discovery document, the JWKS and the token
endpoint are three places this service goes out to the network, and mocking them
away would mock away the code being tested.
"""

from __future__ import annotations

import base64
import contextlib
import datetime as _dt
import hashlib
import hmac
import json
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from jwt.algorithms import ECAlgorithm, RSAAlgorithm

CLIENT_ID = "painfree-test"
SUBJECT = "8f14e45f-ea4c-4b12-9f2e-000000000001"


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def now() -> int:
    return int(_dt.datetime.now(_dt.timezone.utc).timestamp())


class StubProvider:
    """Keys, tokens and the three documents a relying party fetches."""

    def __init__(self) -> None:
        self.issuer = "http://127.0.0.1:0"        # rewritten when it starts serving
        self.keys: dict[str, Any] = {}
        self.published: list[str] = []
        self.add_key("k1")
        #: What the token endpoint answers with next, and what it was asked.
        self.next_token_response: dict[str, Any] = {}
        self.token_requests: list[dict[str, str]] = []
        self.token_status = 200
        self.authorizations: dict[str, dict[str, str]] = {}
        self.jwks_requests = 0
        self.discovery_requests = 0
        #: When true the token endpoint refuses a request whose `code_verifier`
        #: does not hash to the challenge it saw -- a provider doing its job.
        self.enforce_pkce = True

    # --- keys ---------------------------------------------------------------

    def add_key(self, kid: str, *, kind: str = "RSA", publish: bool = True) -> None:
        if kind == "RSA":
            private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            jwk = RSAAlgorithm.to_jwk(private.public_key(), as_dict=True)
            algorithm = "RS256"
        else:
            private = ec.generate_private_key(ec.SECP256R1())
            jwk = ECAlgorithm.to_jwk(private.public_key(), as_dict=True)
            algorithm = "ES256"
        jwk = {k: v for k, v in jwk.items() if k != "key_ops"}
        jwk.update(kid=kid, use="sig", alg=algorithm)
        self.keys[kid] = {"private": private, "jwk": jwk, "alg": algorithm}
        if publish and kid not in self.published:
            self.published.append(kid)

    def withdraw(self, kid: str) -> None:
        """Stop publishing a key without forgetting how to sign with it."""
        if kid in self.published:
            self.published.remove(kid)

    def public_pem(self, kid: str) -> bytes:
        return self.keys[kid]["private"].public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo)

    def jwks(self) -> dict[str, Any]:
        return {"keys": [self.keys[kid]["jwk"] for kid in self.published]}

    # --- tokens -------------------------------------------------------------

    def claims(self, **overrides: Any) -> dict[str, Any]:
        issued = now()
        claims: dict[str, Any] = {
            "iss": self.issuer, "sub": SUBJECT, "aud": CLIENT_ID,
            "iat": issued, "exp": issued + 300, "jti": b64url(b"jti-token-0001"),
            "roles": ["operator"], "name": "Test Operator",
        }
        claims.update(overrides)
        return {name: value for name, value in claims.items() if value is not None}

    def token(self, *, kid: str = "k1", **overrides: Any) -> str:
        """A properly signed token, with whatever claims the attack needs."""
        key = self.keys[kid]
        return jwt.encode(self.claims(**overrides),
                          key["private"], algorithm=key["alg"],
                          headers={"kid": kid})

    def unsigned_token(self, **overrides: Any) -> str:
        """``alg: none``. Built by hand, because no library will produce one."""
        header = b64url(json.dumps({"alg": "none", "typ": "JWT",
                                    "kid": "k1"}).encode())
        payload = b64url(json.dumps(self.claims(**overrides)).encode())
        return f"{header}.{payload}."

    def confused_token(self, *, kid: str = "k1", **overrides: Any) -> str:
        """HS256, signed with the RSA **public** key as the HMAC secret.

        The classic algorithm-confusion forgery: everything a verifier needs to
        check it is public, so if the verifier lets the token pick ``HS256`` the
        signature verifies and the token is accepted. Built by hand because
        PyJWT itself refuses to HMAC with a PEM.
        """
        header = b64url(json.dumps({"alg": "HS256", "typ": "JWT",
                                    "kid": kid}).encode())
        payload = b64url(json.dumps(self.claims(**overrides)).encode())
        signing_input = f"{header}.{payload}".encode("ascii")
        signature = hmac.new(self.public_pem(kid), signing_input,
                             hashlib.sha256).digest()
        return f"{header}.{payload}.{b64url(signature)}"

    # --- documents ----------------------------------------------------------

    def discovery(self) -> dict[str, Any]:
        return {
            "issuer": self.issuer,
            "authorization_endpoint": f"{self.issuer}/authorize",
            "token_endpoint": f"{self.issuer}/token",
            "jwks_uri": f"{self.issuer}/jwks",
            "end_session_endpoint": f"{self.issuer}/logout",
            "response_types_supported": ["code"],
            "code_challenge_methods_supported": ["S256"],
        }


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    @property
    def provider(self) -> StubProvider:
        return self.server.provider

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        path = urllib.parse.urlparse(self.path).path
        if path == "/.well-known/openid-configuration":
            self.provider.discovery_requests += 1
            return self._json(self.provider.discovery())
        if path == "/jwks":
            self.provider.jwks_requests += 1
            return self._json(self.provider.jwks())
        if path == "/authorize":
            query = dict(urllib.parse.parse_qsl(
                urllib.parse.urlparse(self.path).query))
            self.provider.authorizations[query.get("state", "")] = query
            return self._json({"ok": True})
        self._json({"error": "not_found"}, status=404)

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        form = dict(urllib.parse.parse_qsl(body.decode("ascii")))
        provider = self.provider
        provider.token_requests.append(form)
        if provider.enforce_pkce:
            verifier = form.get("code_verifier")
            expected = form.get("_challenge") or _challenge_for(provider, form)
            if verifier is None or (expected is not None
                                    and _s256(verifier) != expected):
                # A provider doing its job. Without the verifier the flow stops
                # here, which is the property the PKCE test asserts.
                return self._json({"error": "invalid_grant"}, status=400)
        self._json(provider.next_token_response, status=provider.token_status)

    def _json(self, document: dict, status: int = 200) -> None:
        payload = json.dumps(document).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args) -> None:
        pass


def _s256(verifier: str) -> str:
    return b64url(hashlib.sha256(verifier.encode("ascii")).digest())


def _challenge_for(provider: StubProvider, form: dict[str, str]) -> str | None:
    """The challenge this code's authorization request carried, if it was seen."""
    for query in provider.authorizations.values():
        if query.get("code_challenge"):
            return query["code_challenge"]
    return None


@contextlib.contextmanager
def serving_provider(provider: StubProvider):
    """Run the provider on a real socket; yields its issuer URL."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server.provider = provider
    provider.issuer = f"http://{server.server_address[0]}:{server.server_address[1]}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield provider.issuer
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
