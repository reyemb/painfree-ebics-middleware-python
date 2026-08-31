"""Typed configuration, read from the environment and validated at startup.

Three properties matter more than the settings themselves:

**No silent fallbacks.** A misspelled variable is a configuration error, not a
default quietly winning. ``pydantic-settings`` ignores environment variables it
does not recognise, so :func:`load_settings` scans the ``PAINFREE_`` namespace
itself and refuses to start on an unknown name. Production additionally refuses
a SQLite URL, because inheriting the development default in production is the
exact failure this repo was told to design out.

**Validated once, at startup.** Settings are frozen. Nothing re-reads the
environment per request, and a bad value fails the process rather than the
hundredth request.

**Redacted when logged.** :meth:`Settings.redacted` is the only rendering used
for logs. The one secret in play at this level is the database password inside
``PAINFREE_DATABASE_URL``, and SQLAlchemy's own URL renderer removes it, rather
than a regular expression guessing where it was.

**The authentication mode decides where an identity comes from, and there is
exactly one of them.** ``PAINFREE_AUTH_MODE`` is ``oidc``, ``basic`` or
``development``. Left unset it is **derived**, and the rule is a table rather
than a cascade of ifs:

===========================  ==============  ===================================
``PAINFREE_AUTH_MODE``       environment     resolved mode
===========================  ==============  ===================================
set                          any             exactly what was set
unset                        development     ``development``
unset, an OIDC issuer set    production      ``oidc``
unset, no OIDC issuer        production      ``basic``
===========================  ==============  ===================================

**Nothing is inferred outside production.** A checkout with nothing configured
has always run in the development header mode and still does, whatever else is
in its environment; inferring a mode from a stray variable would change what an
existing checkout does the day this shipped. Production is where the inference
lives because production is where the wrong answer -- refusing to start, or
inheriting a mode it is not allowed to run in -- had no good outcome.

A deployment with no identity provider is a supported production configuration,
not a broken one: it authenticates with HTTP Basic against accounts this
deployment owns. What it is *not* is two modes at once -- a service that
accepted both a provider's tokens and its own passwords would be a service
whose security is the weaker of the two, so configuring a provider and
selecting ``basic`` anyway logs a warning naming the provider that is being
ignored.

``development`` accepts a header instead of a token so a checkout is testable
with no provider to run, and it is **refused in production** by the same kind of
validator that refuses the custody secret to an API process: a deployment that
ships with it does not start. ``oidc`` in turn requires an issuer, a client id
and a redirect URI, so the other failure -- a production process that starts and
then cannot authenticate anyone -- is a startup error rather than a support call.

**Basic authentication refuses to run over plaintext.** Basic sends a reversible
credential on *every* request, so a production process in that mode does not
start unless ``PAINFREE_TLS_TERMINATED_UPSTREAM`` states that something in front
of it terminates TLS -- which is what the proxy in ``compose.yaml`` does. That is
a statement of fact about the deployment, not a switch that turns a defence off:
its default is the safe one, and setting it wrongly is the operator asserting
something untrue about their own network.

**The role decides who may hold the custody secret.** ``PAINFREE_ROLE`` says
whether this process serves HTTP, uploads orders, or both, and the validators
below turn that into a refusal rather than a convention: an ``api`` process
that carries ``PAINFREE_KEY_ENCRYPTION_SECRET`` does not start, a ``worker``
without it does not start, and ``combined`` is refused in production
altogether. That is the fourth custody mechanism -- the one that makes the
custody boundary a property of two processes rather than of one process's
discipline.
"""

from __future__ import annotations

import os
import pathlib
from enum import Enum
from typing import Any

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError

from painfree import __version__

ENV_PREFIX = "PAINFREE_"

#: Any setting may be read from a file instead: ``PAINFREE_X_FILE`` names a path
#: whose contents are the value of ``PAINFREE_X``. That is how a secret reaches
#: this process without passing through its environment -- see
#: :func:`settings_from_files`.
FILE_SUFFIX = "_FILE"

#: Development default: a file next to the working directory, no service to run.
DEFAULT_DATABASE_URL = "sqlite+pysqlite:///painfree.db"

LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")

#: Query parameters of a database URL that carry a credential. SQLAlchemy's
#: `hide_password` only removes the userinfo password, and libpq happily takes
#: `?password=` or `?sslpassword=` in the query instead -- a URL redacted the
#: obvious way still prints those.
SECRET_URL_PARAMETERS = frozenset({"password", "sslpassword", "sslkey", "sslcert"})

REDACTED = "***"


class ConfigurationError(Exception):
    """The process cannot start with the environment it was given."""


class Environment(str, Enum):
    development = "development"
    production = "production"


class AuthMode(str, Enum):
    """Where an identity comes from. One of these, never two.

    ``oidc`` verifies a bearer token against the provider's published keys and
    establishes browser sessions through the authorization-code flow.

    ``basic`` verifies an HTTP Basic credential against accounts stored in this
    deployment's own database, their passwords hashed with Argon2id. It is what
    a deployment with no identity provider runs, and it is a supported
    production configuration rather than a fallback that should be replaced. It
    is **authentication only**: a Basic caller becomes the same
    :class:`~painfree.identity.Principal` an OIDC caller becomes, with the same
    roles and the same per-connection grants.

    ``development`` accepts ``X-Painfree-Dev-Principal`` instead, so the service
    is runnable and testable with no provider and no accounts -- and is refused
    in production outright.
    """

    oidc = "oidc"
    basic = "basic"
    development = "development"


class Role(str, Enum):
    """What this process is for -- and therefore what it may hold.

    ``api`` serves HTTP and must not carry the custody secret; ``worker``
    claims orders and must; ``combined`` is both, which is convenient in
    development and refused in production because it puts the secret back into
    the request-handling process.
    """

    api = "api"
    worker = "worker"
    combined = "combined"

    @property
    def serves_http(self) -> bool:
        return self is not Role.worker

    @property
    def uploads(self) -> bool:
        return self is not Role.api

    @property
    def downloads(self) -> bool:
        """Downloads sit on the same side of the boundary as uploads.

        A download is decrypted with our own `E002` private half, so it needs
        the custody key exactly as an upload does. Two properties rather than
        one so a reader of either worker sees the question being asked, not a
        name that happens to fit.
        """
        return self is not Role.api


class Settings(BaseSettings):
    """The resolved configuration of one painfree process."""

    model_config = SettingsConfigDict(
        env_prefix=ENV_PREFIX,
        frozen=True,
        extra="forbid",
        validate_default=True,
    )

    environment: Environment = Environment.development

    role: Role = Role.combined
    """Which half of the service this process is.

    ``combined`` by default so a checkout runs with nothing configured. A
    production deployment runs one ``api`` and one or more ``worker``
    processes from the same image, and only the workers' environment carries
    ``PAINFREE_KEY_ENCRYPTION_SECRET``.
    """

    database_url: str = DEFAULT_DATABASE_URL
    """SQLAlchemy URL. SQLite in development, PostgreSQL in production."""

    migrate_on_startup: bool = True
    """Bring the schema to head during lifespan startup.

    True by default: a single self-hosted process should not need a separate
    deploy step. The migration runner takes a PostgreSQL advisory lock, so
    several replicas starting at once is safe; see :mod:`painfree.db`.
    """

    key_encryption_secret: SecretStr | None = None
    """The secret every stored EBICS private key is sealed under.

    Generated, not chosen -- ``python -m painfree new-secret`` prints one. It is
    optional in development so a checkout still starts with nothing configured,
    and **required of a production worker**, because a worker that cannot open
    its keyring is one that discovers it at the first payment. An ``api``
    process must not have it at all -- see ``role``.

    Losing it means losing every private key in the database, and no restore of
    the database brings them back. Changing it is a re-seal, run with
    ``previous_key_encryption_secret`` also set (``python -m painfree rekey``),
    not an edit to this variable alone.
    """

    previous_key_encryption_secret: SecretStr | None = None
    """The secret the stored material is sealed under *today*, during a rotation.

    Set alongside the new ``key_encryption_secret`` for exactly as long as
    ``python -m painfree rekey`` takes to re-seal every row, then removed. It is
    a second door to every private key in the database, so it is subject to the
    same refusal as the first: an ``api`` process that carries it does not
    start.
    """

    auth_mode: AuthMode = AuthMode.development
    """``oidc``, ``basic``, or ``development`` -- which production refuses.

    Left unset it is derived by :meth:`_derive_auth_mode` from whether an OIDC
    issuer is configured and which environment this is; see the module
    docstring for the table. Once resolved it is a single mode: nothing here
    ever accepts two kinds of credential at once.
    """

    tls_terminated_upstream: bool = False
    """Something in front of this process terminates TLS and it is not reachable
    except through it.

    A statement about the deployment, which is why it is off by default: the
    operator asserts it, and a production process in ``basic`` mode refuses to
    start until they do. HTTP Basic puts a reversible credential in every single
    request, so plaintext is not a degraded configuration for it, it is a
    published password. The proxy in ``compose.yaml`` is what makes it true
    there.
    """

    basic_lockout_threshold: int = Field(default=5, ge=1, le=100)
    """Failed sign-ins against **one account name** before it is locked.

    Counted per attempted name whether or not an account by that name exists, so
    a locked-out unknown name and a locked-out real one behave alike and the
    lockout itself does not become the oracle the password check refuses to be.
    """

    basic_source_lockout_threshold: int = Field(default=20, ge=1, le=1000)
    """Failed sign-ins from **one source address** before it is locked.

    Higher than the per-account threshold on purpose: a shared office address is
    many people, and locking all of them out because one of them mistyped a
    password four times is an outage this service caused.
    """

    basic_lockout_window_minutes: int = Field(default=15, ge=1, le=1440)
    """How far back failures are counted. Older ones do not accumulate."""

    basic_lockout_minutes: int = Field(default=15, ge=1, le=1440)
    """How long a lockout lasts before it expires by itself.

    It also ends when an administrator clears it, which is the lever that
    matters: a person locked out at the wrong moment should not have to wait.
    """

    oidc_issuer: str | None = None
    """The provider's issuer identifier: the `iss` every token must carry, and
    the base the discovery document is fetched from. Compared exactly, never
    prefix-matched."""

    oidc_client_id: str | None = None
    """This service's client registration. Also the default audience."""

    oidc_client_secret: SecretStr | None = None
    """Optional. A public client using PKCE has none, and PKCE is used either
    way -- the secret authenticates the token request, it does not replace the
    proof that the browser that started the flow is the one finishing it."""

    oidc_audience: str | None = None
    """What a bearer token's `aud` must contain. Defaults to the client id."""

    oidc_redirect_uri: str | None = None
    """Where the provider sends the browser back. Registered with the provider,
    so it is configuration rather than something derived from the request --
    deriving it from `Host` is how an attacker chooses it."""

    oidc_roles_claim: str = "roles"
    """Which claim carries granted roles. A dotted path, so Keycloak's
    ``realm_access.roles`` needs no code."""

    oidc_scope_claim: str = "scope"
    """Which claim carries requested scopes. They narrow, never grant."""

    oidc_clock_skew_seconds: int = Field(default=60, ge=0, le=300)
    """Leeway on `exp`, `nbf` and `iat`. Bounded: a large skew allowance is an
    expired token that still works."""

    session_ttl_minutes: int = Field(default=480, ge=1, le=10080)
    """How long a browser session lives before the provider is consulted again."""

    login_ttl_seconds: int = Field(default=600, ge=30, le=3600)
    """How long an authorization-code flow may take between login and callback."""

    dev_subject: str = "developer"
    """Who ``development`` mode authenticates as when no header names someone."""

    oidc_admin_role: str = "admin,administrator"
    """Claim values this deployment's directory uses for an administrator.

    Comma-separated, because a group is named by the directory and the directory
    is not reshaped to suit one service: `painfree-admins`, `CN=Treasury Ops`,
    whatever is already there. The default is the pair this service has always
    accepted, so a deployment that sets nothing keeps every administrator it had
    across an upgrade.

    What it decides is exactly one thing -- whether a caller is an `admin` --
    and everything else a member may touch is a grant, one connection at a time.
    The resolved value is in the `service.starting` line, so an operator reads
    back what this deployment calls an administrator rather than inferring it.
    """

    oidc_member_role: str = "member,operator,viewer,auditor"
    """Claim values that are recognised and grant nothing on their own.

    Comma-separated, and the four-role model's names are the default for the
    reason they were kept in the first place: so they are not logged as unmapped
    noise on every request. `auditor` is here and not in the administrator list
    deliberately -- deployment-wide read is an oversight grant issued per person,
    never a word a directory happens to still send.

    A name in neither list still authenticates and still holds nothing. The
    warning it produces is the point: an empty console becomes "the group is not
    the one this deployment calls admin" rather than a mystery.
    """

    dev_roles: str = "admin"
    """The roles ``development`` mode grants by default, comma-separated.

    ``admin`` rather than ``administrator``, since the roles collapsed to two.
    Both names still mean the same thing to :func:`painfree.identity.role_for`,
    so a development environment pinned to the old word keeps working; the
    default is the new one because it is what a reader of this file should
    copy."""

    @property
    def admin_role_names(self) -> frozenset[str]:
        """`oidc_admin_role`, parsed. Empty entries dropped, order irrelevant."""
        return frozenset(name.strip() for name in self.oidc_admin_role.split(",")
                         if name.strip())

    @property
    def member_role_names(self) -> frozenset[str]:
        """`oidc_member_role`, parsed."""
        return frozenset(name.strip() for name in self.oidc_member_role.split(",")
                         if name.strip())

    @property
    def known_role_names(self) -> frozenset[str]:
        """Every name this deployment recognises, mapped or merely expected."""
        return self.admin_role_names | self.member_role_names


    log_level: str = "INFO"

    http_host: str = "127.0.0.1"
    http_port: int = Field(default=8000, ge=1, le=65535)

    git_sha: str = "unknown"
    """Set by the image build, and emitted in the startup line."""

    @model_validator(mode="before")
    @classmethod
    def _derive_auth_mode(cls, data: Any) -> Any:
        """Fill ``auth_mode`` from what is configured, when it was not chosen.

        The rule is the table in the module docstring and it is one line of
        logic per row, deliberately: an operator diagnosing *why am I being asked
        for a password* should be able to read the answer rather than trace it.

        Only an **absent** value is derived. An explicit ``PAINFREE_AUTH_MODE``
        is never second-guessed -- including the case where it names ``basic``
        on a deployment that also configured a provider, which is a decision
        somebody took and which :attr:`auth_mode_reason` reports back to them.
        """
        if not isinstance(data, dict):  # pragma: no cover - pydantic passes a dict
            return data
        chosen = data.get("auth_mode", data.get("AUTH_MODE"))
        if chosen is not None and chosen != "":
            return data
        environment = data.get("environment", data.get("ENVIRONMENT"))
        if isinstance(environment, Environment):
            environment = environment.value
        if environment != Environment.production.value:
            # Unchanged, deliberately: a checkout has always run in the
            # development header mode with nothing configured.
            data["auth_mode"] = AuthMode.development.value
            return data
        issuer = data.get("oidc_issuer", data.get("OIDC_ISSUER"))
        # The mode this whole rule exists for. A production deployment with no
        # identity provider is not misconfigured -- it authenticates against
        # accounts it owns -- and the alternative, inheriting the development
        # header mode, is refused two validators below anyway, so the process
        # would simply have failed to start.
        data["auth_mode"] = (AuthMode.oidc if issuer else AuthMode.basic).value
        return data

    @field_validator("log_level", mode="before")
    @classmethod
    def _upper_case_level(cls, value: Any) -> Any:
        return value.upper() if isinstance(value, str) else value

    @field_validator("log_level")
    @classmethod
    def _known_level(cls, value: str) -> str:
        if value not in LOG_LEVELS:
            raise ValueError(f"must be one of {', '.join(LOG_LEVELS)}")
        return value

    @field_validator("auth_mode", "oidc_issuer", "oidc_client_id",
                     "oidc_audience", "oidc_redirect_uri", mode="before")
    @classmethod
    def _blank_is_unset(cls, value: Any) -> Any:
        """An empty value is not a configured one.

        ``compose.yaml`` interpolates ``${PAINFREE_OIDC_ISSUER:-}`` into an
        *empty* variable rather than an absent one when the ``.env`` file does
        not name a provider, and an empty issuer that satisfied "is it set" is a
        process that starts in ``oidc`` mode and authenticates nobody.
        """
        return None if isinstance(value, str) and not value.strip() else value

    @field_validator("database_url")
    @classmethod
    def _parseable_url(cls, value: str) -> str:
        try:
            make_url(value)
        except ArgumentError as exc:  # pragma: no cover - message varies by version
            raise ValueError(f"not a SQLAlchemy URL: {exc}") from exc
        return value

    @field_validator("key_encryption_secret", "previous_key_encryption_secret")
    @classmethod
    def _long_enough_to_be_generated(cls, value: SecretStr | None) -> SecretStr | None:
        # Checked here so a too-short secret fails at startup rather than at the
        # first key operation. The message never quotes the value.
        if value is not None:
            from painfree.sealing import MINIMUM_SECRET_LENGTH

            if len(value.get_secret_value()) < MINIMUM_SECRET_LENGTH:
                raise ValueError(
                    f"must be at least {MINIMUM_SECRET_LENGTH} characters; "
                    f"generate one with `python -m painfree new-secret`"
                )
        return value

    @model_validator(mode="after")
    def _production_is_not_sqlite(self) -> "Settings":
        if self.environment is Environment.production and self.dialect == "sqlite":
            raise ValueError(
                "PAINFREE_DATABASE_URL is SQLite but PAINFREE_ENVIRONMENT is "
                "production; production runs on PostgreSQL"
            )
        return self

    @model_validator(mode="after")
    def _production_has_a_real_identity_provider(self) -> "Settings":
        """The development authentication mode cannot reach production.

        The same shape as the custody split above, for the same reason: a
        property that depends on an operator remembering to set a variable is
        not a property. ``development`` accepts a header in place of a signed
        token, so a production process that started with it would be a service
        whose authorisation model is "whatever the caller claims".
        """
        if (self.environment is Environment.production
                and self.auth_mode is AuthMode.development):
            raise ValueError(
                "PAINFREE_AUTH_MODE is development but PAINFREE_ENVIRONMENT is "
                "production; the development authentication mode accepts an "
                "unsigned header in place of a token and must never serve real "
                "traffic"
            )
        return self

    @model_validator(mode="after")
    def _basic_is_not_served_over_plaintext(self) -> "Settings":
        """Basic authentication in production needs TLS in front of it, stated.

        Every other credential this service accepts is either a signed token
        that a listener cannot replay usefully for long, or a random session id
        that can be revoked. A Basic credential is the password itself, sent
        again on every single request, reversible by base64. One plaintext hop
        is not a weakened deployment, it is a disclosed password and every
        request repeats the disclosure.

        So the deployment has to say that something terminates TLS in front of
        it. That is not a switch that disables a check -- there is nothing this
        process can observe about its own network -- it is the operator making a
        statement, and the refusal is here so that the statement is *made*
        rather than assumed.

        A ``worker`` is exempt because it serves no HTTP and therefore receives
        no credential. That is the one exception and it is the difference
        between a rule and a ritual: a worker declaring a proxy in front of it
        would be declaring something untrue.
        """
        if (self.environment is Environment.production
                and self.auth_mode is AuthMode.basic
                and self.role.serves_http
                and not self.tls_terminated_upstream):
            raise ValueError(
                "PAINFREE_AUTH_MODE is basic and PAINFREE_ENVIRONMENT is "
                "production, but PAINFREE_TLS_TERMINATED_UPSTREAM is not set; "
                "HTTP Basic sends a reversible credential on every request, so "
                "this process must sit behind a proxy that terminates TLS (the "
                "`proxy` service in compose.yaml does). Set "
                "PAINFREE_TLS_TERMINATED_UPSTREAM=true once that is true"
            )
        return self

    @model_validator(mode="after")
    def _oidc_is_configured_when_it_is_selected(self) -> "Settings":
        if self.auth_mode is not AuthMode.oidc:
            return self
        missing = [name for name in ("oidc_issuer", "oidc_client_id",
                                     "oidc_redirect_uri")
                   if getattr(self, name) is None]
        if missing:
            raise ValueError(
                "PAINFREE_AUTH_MODE is oidc but "
                + ", ".join(f"PAINFREE_{name.upper()}" for name in missing)
                + " is not set; the process would start and authenticate nobody"
            )
        if (self.environment is Environment.production
                and not str(self.oidc_issuer).startswith("https://")):
            raise ValueError(
                "PAINFREE_OIDC_ISSUER must be https in production; the "
                "discovery document and the signing keys are fetched from it"
            )
        return self

    @model_validator(mode="after")
    def _the_api_process_holds_no_custody_secret(self) -> "Settings":
        """The process split, enforced at startup rather than in a runbook.

        A request-handling process that carries the secret can derive the
        custody key from its own environment whatever the in-process checks
        say -- which is precisely the gap those checks leave open. Refusing to
        start closes it: the API process cannot hold what it is not given, and
        a deployment that hands it the secret anyway fails loudly at boot
        instead of quietly widening the boundary.
        """
        if self.role is Role.api and self.key_encryption_secret is not None:
            raise ValueError(
                "PAINFREE_ROLE is api but PAINFREE_KEY_ENCRYPTION_SECRET is "
                "set; the request-handling process must not be able to open a "
                "private key"
            )
        if self.role is Role.api and self.previous_key_encryption_secret is not None:
            # The rotation variable is a custody secret like any other -- it
            # opens every row that has not been re-sealed yet. A rotation is no
            # reason for the request path to hold one for an afternoon.
            raise ValueError(
                "PAINFREE_ROLE is api but PAINFREE_PREVIOUS_KEY_ENCRYPTION_SECRET "
                "is set; it opens every key that has not been re-sealed yet, so "
                "the request-handling process must not have it either"
            )
        return self

    @model_validator(mode="after")
    def _a_rotation_has_two_different_secrets(self) -> "Settings":
        """``rekey`` needs both halves, and they have to be two.

        Both failures are silent otherwise: the previous secret alone re-seals
        nothing, and two equal secrets produce a run that reports every row
        migrated while changing none of them.
        """
        if self.previous_key_encryption_secret is None:
            return self
        if self.key_encryption_secret is None:
            raise ValueError(
                "PAINFREE_PREVIOUS_KEY_ENCRYPTION_SECRET is set but "
                "PAINFREE_KEY_ENCRYPTION_SECRET is not; a rotation re-seals "
                "from the previous secret to the new one and needs both"
            )
        if (self.previous_key_encryption_secret.get_secret_value()
                == self.key_encryption_secret.get_secret_value()):
            raise ValueError(
                "PAINFREE_PREVIOUS_KEY_ENCRYPTION_SECRET and "
                "PAINFREE_KEY_ENCRYPTION_SECRET are the same value; there is "
                "nothing to rotate"
            )
        return self

    @model_validator(mode="after")
    def _a_worker_can_open_its_keyring(self) -> "Settings":
        if self.role is Role.worker and self.key_encryption_secret is None:
            raise ValueError(
                "PAINFREE_ROLE is worker but PAINFREE_KEY_ENCRYPTION_SECRET is "
                "not set; a worker that cannot open a key cannot upload anything"
            )
        return self

    @model_validator(mode="after")
    def _production_splits_the_two_processes(self) -> "Settings":
        if (self.environment is Environment.production
                and self.role is Role.combined):
            raise ValueError(
                "PAINFREE_ROLE is combined but PAINFREE_ENVIRONMENT is "
                "production; production runs the API and the upload worker as "
                "separate processes, so that only the worker's environment "
                "carries the custody secret"
            )
        if (self.environment is Environment.production
                and self.role is not Role.api
                and self.key_encryption_secret is None):
            raise ValueError(
                "PAINFREE_KEY_ENCRYPTION_SECRET is required in production; "
                "without it no EBICS private key can be stored or opened"
            )
        return self

    def without_custody_secret(self) -> "Settings":
        """The same configuration with the encryption secret removed.

        What :func:`painfree.app.create_app` puts on ``app.state``: the object
        graph a request handler can reach then does not contain the secret at
        all, which is one of the three mechanisms in :mod:`painfree.custody`.
        """
        return self.model_copy(update={"key_encryption_secret": None,
                                       "previous_key_encryption_secret": None})

    def custody_key(self):
        """Derive the custody key. The only door to it, and the worker's door.

        Returns a :class:`painfree.sealing.CustodyKey`. Called on a settings
        object that went through :meth:`without_custody_secret` -- which is the
        one the request path can reach -- it raises, which is the point.
        """
        from painfree.sealing import derive_custody_key

        if self.key_encryption_secret is None:
            raise ConfigurationError(
                "PAINFREE_KEY_ENCRYPTION_SECRET is not configured, so no EBICS "
                "private key can be sealed or opened"
            )
        return derive_custody_key(self.key_encryption_secret.get_secret_value())

    @property
    def custody_key_id(self) -> str | None:
        """The id of the custody key this configuration derives, or ``None``.

        A hash, not the key. Emitted in the startup line so a rotated secret is
        visible at boot rather than at the first key operation.
        """
        if self.key_encryption_secret is None:
            return None
        return self.custody_key().key_id

    def previous_custody_key(self):
        """The custody key a rotation is migrating *away* from.

        Only ``python -m painfree rekey`` asks for it. Nothing else does, and
        nothing else should: a process that opens material under two keys has
        two keys to lose.
        """
        from painfree.sealing import derive_custody_key

        if self.previous_key_encryption_secret is None:
            raise ConfigurationError(
                "PAINFREE_PREVIOUS_KEY_ENCRYPTION_SECRET is not configured, so "
                "there is no key to re-seal from"
            )
        return derive_custody_key(
            self.previous_key_encryption_secret.get_secret_value())

    @property
    def previous_custody_key_id(self) -> str | None:
        """The id of the key a rotation is migrating away from, or ``None``."""
        if self.previous_key_encryption_secret is None:
            return None
        return self.previous_custody_key().key_id

    @property
    def audience(self) -> str:
        """What a bearer token's `aud` must contain: the configured one, or the
        client id. Never the token's own."""
        return self.oidc_audience or self.oidc_client_id or ""

    @property
    def auth_mode_reason(self) -> str:
        """Why this process is in the mode it is in, in one sentence.

        Emitted at startup and shown on the developer page. The mode is derived
        when it is not set, and a derived value nobody can see the reasoning for
        is the kind of thing an operator ends up reading source code to
        understand.
        """
        if self.auth_mode is AuthMode.oidc:
            return "an OIDC issuer is configured"
        if self.auth_mode is AuthMode.basic:
            if self.oidc_issuer:
                return ("basic was selected explicitly; the configured OIDC "
                        "issuer is not used, because this service accepts one "
                        "kind of credential and not two")
            return "no identity provider is configured"
        return ("this is not production and no mode was chosen; the "
                "development mode accepts a header in place of a credential "
                "and production refuses to start in it")

    @property
    def cookies_are_secure(self) -> bool:
        """Whether session cookies carry `Secure`.

        Derived rather than configured: the one deployment that needs it off is
        a developer on plain `http`, and that is exactly what
        ``PAINFREE_ENVIRONMENT`` already says. A knob here would be a knob
        someone turns off in production.
        """
        return self.environment is Environment.production

    @property
    def dialect(self) -> str:
        """``sqlite`` or ``postgresql`` -- the name the driver differences key off."""
        return make_url(self.database_url).get_backend_name()

    @property
    def version(self) -> str:
        return __version__

    def redacted(self) -> dict[str, Any]:
        """The whole configuration, safe to log.

        Every field appears -- an operator reading the startup line should see
        what the process resolved, including the things that were left at their
        default -- with the database password removed by SQLAlchemy itself.
        """
        rendered = {
            name: getattr(self, name).value
            if isinstance(getattr(self, name), Enum)
            else getattr(self, name)
            for name in type(self).model_fields
        }
        rendered["database_url"] = redact_database_url(self.database_url)
        # The secret is replaced by the *id* of the key it derives: an operator
        # needs to know which key the process is holding, and never the key.
        rendered["key_encryption_secret"] = (
            REDACTED if self.key_encryption_secret is not None else None
        )
        rendered["previous_key_encryption_secret"] = (
            REDACTED if self.previous_key_encryption_secret is not None else None
        )
        rendered["oidc_client_secret"] = (
            REDACTED if self.oidc_client_secret is not None else None
        )
        rendered["auth_mode_reason"] = self.auth_mode_reason
        rendered["custody_key_id"] = self.custody_key_id
        rendered["previous_custody_key_id"] = self.previous_custody_key_id
        rendered["dialect"] = self.dialect
        rendered["version"] = self.version
        return rendered


def redact_database_url(url: str) -> str:
    """The URL with every credential removed, in userinfo *and* in the query."""
    parsed = make_url(url)
    query = {
        name: (REDACTED if name in SECRET_URL_PARAMETERS else value)
        for name, value in parsed.query.items()
    }
    return parsed.set(query=query).render_as_string(hide_password=True)


def unknown_environment_names(environ: dict[str, str] | None = None) -> list[str]:
    """``PAINFREE_*`` names that no field claims.

    Kept separate from :class:`Settings` so a test can ask the question without
    mutating the process environment.
    """
    environ = os.environ if environ is None else environ
    known = {f"{ENV_PREFIX}{name}".upper() for name in Settings.model_fields}
    known |= {f"{name}{FILE_SUFFIX}" for name in known}
    return sorted(
        name for name in environ
        if name.upper().startswith(ENV_PREFIX) and name.upper() not in known
    )


def settings_from_files(environ: dict[str, str] | None = None) -> dict[str, Any]:
    """Values taken from ``PAINFREE_<NAME>_FILE`` rather than from the variable.

    An orchestrator's secret is a file, not an environment variable — a
    container's environment is readable by anything that can inspect it, ends
    up in `podman inspect` output, and is inherited by every child process.
    Docker Compose `secrets:` and podman's `--secret` both mount a file, so the
    configuration has to be able to read one.

    Every field takes the suffix, not just the secrets: a rule with exceptions
    is a rule an operator has to look up. Setting both forms of the same
    setting is refused rather than resolved by precedence, because which one
    won is exactly the question nobody wants to be asking during an incident.

    Surrounding whitespace is stripped. `printf` writes a file without a
    trailing newline and every editor writes one with; neither is part of a
    generated secret.
    """
    environ = os.environ if environ is None else environ
    values: dict[str, Any] = {}
    for field in Settings.model_fields:
        variable = f"{ENV_PREFIX}{field}".upper()
        path = environ.get(f"{variable}{FILE_SUFFIX}")
        if path is None:
            continue
        if variable in environ:
            raise ConfigurationError(
                f"{variable} and {variable}{FILE_SUFFIX} are both set; "
                f"set one of them"
            )
        try:
            content = pathlib.Path(path).read_text(encoding="utf-8")
        except OSError as exc:
            # The path, never the content: this message reaches the log stream.
            raise ConfigurationError(
                f"{variable}{FILE_SUFFIX} is {path!r}, which could not be "
                f"read: {exc.strerror}"
            ) from exc
        content = content.strip()
        if not content:
            raise ConfigurationError(
                f"{variable}{FILE_SUFFIX} is {path!r}, which is empty; a "
                f"secret mounted from an unpopulated volume looks exactly "
                f"like this"
            )
        values[field] = content
    return values


def load_settings(**overrides: Any) -> Settings:
    """Read, validate and freeze the configuration, or refuse to start.

    Raises :class:`ConfigurationError` with every problem named, because an
    operator fixing a container's environment should need one restart, not one
    per typo.
    """
    if not overrides:
        unknown = unknown_environment_names()
        if unknown:
            raise ConfigurationError(
                "unknown configuration variables: " + ", ".join(unknown)
            )
        overrides = settings_from_files()
    try:
        return Settings(**overrides)
    except Exception as exc:  # pydantic raises ValidationError; keep one type at the edge
        raise ConfigurationError(str(exc)) from exc
