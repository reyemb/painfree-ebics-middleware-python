"""Configuration: validated at startup, redacted when logged, no silent fallbacks.

The property under test is not "the defaults are these values". It is that a
process either starts with a configuration an operator can read off one log
line, or refuses to start and says why.
"""

from __future__ import annotations

import pytest

from conftest import PRODUCTION_OIDC

from painfree.config import (DEFAULT_DATABASE_URL, ConfigurationError, Environment,
                             Settings, load_settings, settings_from_files,
                             unknown_environment_names)

#: A production worker refuses to start without one, so every production case
#: here has to supply it -- together with `role="worker"`, because production
#: has no single-process role and an `api` process is refused the secret
#: outright.
CUSTODY_SECRET = "test-only-custody-secret-Sk9pQ2x1-do-not-reuse"
PRODUCTION_WORKER = {"environment": "production", "role": "worker",
                     **PRODUCTION_OIDC}


def test_development_needs_no_environment_at_all():
    """SQLite in a file, no service to install -- the user's stated default."""
    settings = load_settings()
    assert settings.environment is Environment.development
    assert settings.database_url == DEFAULT_DATABASE_URL
    assert settings.dialect == "sqlite"


def test_environment_variables_are_read_with_the_painfree_prefix(monkeypatch):
    monkeypatch.setenv("PAINFREE_LOG_LEVEL", "debug")
    monkeypatch.setenv("PAINFREE_HTTP_PORT", "9000")
    settings = Settings()
    assert settings.log_level == "DEBUG"   # normalised, so "debug" is not a typo
    assert settings.http_port == 9000


def test_an_unknown_painfree_variable_refuses_to_start(monkeypatch):
    """A misspelling is a configuration error, not a default quietly winning.

    `pydantic-settings` ignores names it does not recognise, which is exactly
    how `PAINFREE_DATABSE_URL` ends up running production on the development
    default. The scan is the whole point of `load_settings`.
    """
    monkeypatch.setenv("PAINFREE_DATABSE_URL", "postgresql://x/y")
    assert unknown_environment_names() == ["PAINFREE_DATABSE_URL"]
    with pytest.raises(ConfigurationError, match="PAINFREE_DATABSE_URL"):
        load_settings()


def test_production_refuses_a_sqlite_url():
    """Production inheriting the development database is the failure to design out."""
    with pytest.raises(ConfigurationError, match="production runs on PostgreSQL"):
        load_settings(**PRODUCTION_WORKER, database_url=DEFAULT_DATABASE_URL,
                      key_encryption_secret=CUSTODY_SECRET)


def test_production_accepts_postgres():
    settings = load_settings(
        **PRODUCTION_WORKER,
        database_url="postgresql+psycopg://painfree:pw@db:5432/painfree",
        key_encryption_secret=CUSTODY_SECRET,
    )
    assert settings.dialect == "postgresql"


@pytest.mark.parametrize(
    "overrides",
    [
        {"log_level": "LOUD"},
        {"http_port": 0},
        {"http_port": 70000},
        {"database_url": "not a url at all"},
    ],
)
def test_a_bad_value_fails_the_process_not_the_hundredth_request(overrides):
    with pytest.raises(ConfigurationError):
        load_settings(**overrides)


def test_settings_are_frozen():
    settings = load_settings()
    with pytest.raises(Exception):
        settings.log_level = "DEBUG"


def test_the_redacted_rendering_drops_the_database_password():
    settings = load_settings(
        **PRODUCTION_WORKER,
        database_url="postgresql+psycopg://painfree:s3cr3t@db:5432/painfree",
        key_encryption_secret=CUSTODY_SECRET,
    )
    rendered = settings.redacted()
    assert "s3cr3t" not in repr(rendered)
    assert rendered["database_url"] == "postgresql+psycopg://painfree:***@db:5432/painfree"


def test_the_redacted_rendering_shows_every_field():
    """An operator reading the startup line sees defaults too, not just overrides."""
    rendered = load_settings().redacted()
    assert set(Settings.model_fields) <= set(rendered)
    assert rendered["version"] and rendered["dialect"]


def test_a_credential_in_the_url_query_is_redacted_too():
    """libpq takes `?password=`; SQLAlchemy's `hide_password` does not touch it.

    A URL redacted the obvious way still prints that one, which is the kind of
    thing found once and then never again.
    """
    settings = load_settings(
        **PRODUCTION_WORKER,
        database_url="postgresql+psycopg://painfree@db/painfree?password=s3cr3t&sslmode=require",
        key_encryption_secret=CUSTODY_SECRET,
    )
    rendered = settings.redacted()["database_url"]
    assert "s3cr3t" not in rendered
    assert "sslmode=require" in rendered


# --- the custody secret ------------------------------------------------------

def test_production_refuses_to_start_without_a_custody_secret():
    """A production worker that cannot open its keyring should not serve."""
    with pytest.raises(ConfigurationError, match="KEY_ENCRYPTION_SECRET"):
        load_settings(**PRODUCTION_WORKER,
                      database_url="postgresql+psycopg://p:x@db/painfree")


def test_a_custody_secret_short_enough_to_guess_is_refused():
    with pytest.raises(ConfigurationError, match="new-secret"):
        load_settings(key_encryption_secret="hunter2")


def test_the_custody_secret_never_appears_in_the_redacted_rendering():
    """It is replaced by the *id* of the key it derives, which is a hash."""
    rendered = load_settings(key_encryption_secret=CUSTODY_SECRET).redacted()
    assert CUSTODY_SECRET not in repr(rendered)
    assert rendered["key_encryption_secret"] == "***"
    assert rendered["custody_key_id"]


def test_the_settings_the_request_path_gets_cannot_derive_the_key():
    settings = load_settings(key_encryption_secret=CUSTODY_SECRET)
    stripped = settings.without_custody_secret()
    assert stripped.key_encryption_secret is None
    assert stripped.custody_key_id is None
    with pytest.raises(ConfigurationError):
        stripped.custody_key()
    # Everything else survives, so the app is configured the same way.
    assert stripped.database_url == settings.database_url


# --- reading a setting from a file ------------------------------------------
#
# A container's environment is readable by anything that can inspect it and is
# inherited by every child process. Compose and podman both hand a secret over
# as a *file*, so the configuration has to be able to read one.

def test_a_setting_can_come_from_a_file(tmp_path):
    secret = tmp_path / "custody_secret"
    secret.write_text(CUSTODY_SECRET + "\n")   # the newline an editor adds
    values = settings_from_files(
        {"PAINFREE_KEY_ENCRYPTION_SECRET_FILE": str(secret)})
    assert values == {"key_encryption_secret": CUSTODY_SECRET}


def test_the_file_suffix_is_accepted_for_every_setting(tmp_path):
    """Not just for the secrets: a rule with exceptions is one to look up."""
    url = tmp_path / "database_url"
    url.write_text("postgresql+psycopg://painfree@db:5432/painfree")
    assert settings_from_files({"PAINFREE_DATABASE_URL_FILE": str(url)}) == {
        "database_url": "postgresql+psycopg://painfree@db:5432/painfree"}
    assert unknown_environment_names(
        {"PAINFREE_DATABASE_URL_FILE": str(url)}) == []


def test_setting_both_forms_is_refused_rather_than_resolved(tmp_path):
    """Which one won is the question nobody wants during an incident."""
    secret = tmp_path / "custody_secret"
    secret.write_text(CUSTODY_SECRET)
    with pytest.raises(ConfigurationError, match="are both set"):
        settings_from_files({
            "PAINFREE_KEY_ENCRYPTION_SECRET": "something else entirely",
            "PAINFREE_KEY_ENCRYPTION_SECRET_FILE": str(secret)})


def test_an_unreadable_file_names_the_path_and_not_its_contents(tmp_path):
    with pytest.raises(ConfigurationError) as raised:
        settings_from_files({
            "PAINFREE_KEY_ENCRYPTION_SECRET_FILE": str(tmp_path / "absent")})
    assert "absent" in str(raised.value)
    assert "No such file" in str(raised.value)


def test_an_empty_file_is_refused(tmp_path):
    """An unpopulated secret volume looks exactly like this."""
    empty = tmp_path / "custody_secret"
    empty.write_text("   \n")
    with pytest.raises(ConfigurationError, match="which is empty"):
        settings_from_files({
            "PAINFREE_KEY_ENCRYPTION_SECRET_FILE": str(empty)})


def test_an_unknown_name_is_still_unknown_with_the_file_suffix():
    assert unknown_environment_names({"PAINFREE_DATABSE_URL_FILE": "/x"}) == \
        ["PAINFREE_DATABSE_URL_FILE"]
