"""Six languages in the console, and the line the wire is on the other side of.

One rule, and one only: **localisation is display only, and nothing localised
reaches the wire.** Everything here is an attempt to break that rule or to show
that it holds.

**The differential gate is the first test in this file.** The same payment is
submitted six times, once under each locale, with the console *demonstrably*
rendering in that locale in the same session -- and the six stored `pain.001`
documents are compared byte for byte. The message id and the timestamp are
frozen so that the only thing left that could differ is the locale, which is
the whole point: an amount, a date, a reference or a decimal separator that
moved would show up as a diff, and there is nowhere for it to hide.

**A catalogue is data, and data is checked like data.** Every catalogue carries
English's key set exactly -- no hole, no stray -- every plural entry carries the
CLDR categories its own language uses, every translation carries the same HTML
tags and the same `{placeholders}` as the English it replaces, and every
`t('...')` a template names exists. A missing string is a test failure here
rather than a raw key on a page an operator is reading.

**The bank's words are not ours.** A `ReportText` arrives in the bank's
language, and under all six locales it is rendered verbatim, unescaped-into
nothing and untranslated, and it is marked on the page as the bank's.

**Selection.** Negotiated from `Accept-Language`, overridden by an explicit
choice, and the choice persists -- with no route, no form and no script, so it
works with scripting off.
"""

from __future__ import annotations

import datetime as _dt
import decimal
import json
import pathlib
import re

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from conftest import (BANK_CONNECTION_ID, CUSTODY_SECRET, bank_subject,
                      dev_credentials, grant, payment_body, transfer)
from painfree import db, ebics3, pain001, wrapping
from painfree.api import IDEMPOTENCY_HEADER
from painfree.app import create_app
from painfree.audit import AuditLog
from painfree.config import load_settings
from painfree.connections import ConnectionRegistry
from painfree.keyring import KeyCustodian
from painfree.schema import bank_connection, payment_order
from painfree.ui import i18n, rendering

BROWSER = {"accept": "text/html,application/xhtml+xml"}

#: One string per locale that appears on the connections page and nowhere in
#: another language's catalogue. Used to prove a page really is in the language
#: the test believes it asked for, rather than trusting the header.
MARKERS = {
    "en": "Bank connections",
    "de": "Bankverbindungen",
    "fr": "Connexions bancaires",
    "it": "Connessioni bancarie",
    "es": "Conexiones bancarias",
    "pl": "Połączenia bankowe",
}

#: The CLDR plural categories each of the six actually uses. Polish is the
#: reason this is a table rather than a constant.
CATEGORIES = {"en": {"one", "other"}, "de": {"one", "other"},
              "fr": {"one", "other"}, "it": {"one", "other"},
              "es": {"one", "other"}, "pl": {"one", "few", "many"}}

TAG = re.compile(r"<[^>]+>")
PLACEHOLDER = re.compile(r"\{([a-z_]+)\}")

#: Keys built by concatenation in a template -- `t('state.' ~ row.state.value)`.
#: A prefix here is exempt from the "every key is referenced" check, and the
#: members are checked against the model instead, below.
DYNAMIC_PREFIXES = ("state.", "key_state.", "status_code.", "bank_keys.role_",
                    "schedule_new.", "alerts.", "audit.target.", "cadence.",
                    "unit.", "scheme.", "scheme_state.", "scheme_reason.")

LOCALES = pathlib.Path(rendering.TEMPLATES).parent / "locales"


def catalogue(locale: str) -> dict:
    return json.loads((LOCALES / f"{locale}.json").read_text(encoding="utf-8"))


def _flat(value) -> list[str]:
    return [value] if isinstance(value, str) else list(value.values())


# --- the gate: the wire does not move -------------------------------------

@pytest.fixture
def console(prepared_bank, custody_settings):
    engine, _connection, _bank_keys = prepared_bank
    wrapping.publish(engine, custody_settings.custody_key())
    app = create_app(custody_settings)
    with TestClient(app) as client:
        grant(app, "olive", BANK_CONNECTION_ID, "operator")
        yield client, app, engine


@pytest.fixture
def frozen(monkeypatch):
    """One `MsgId` and one `CreDtTm` for every submission in a test.

    Both are unique per message in production -- the `MsgId` is the bank's
    duplicate control -- so six real submissions differ in two fields whatever
    the locale did. Freezing them is what leaves the locale as the only
    remaining variable, which is the only way the byte comparison below means
    anything.
    """
    moment = _dt.datetime(2026, 9, 15, 8, 30, 0, tzinfo=_dt.timezone.utc)

    class _Clock(_dt.datetime):
        @classmethod
        def now(cls, tz=None):
            return moment if tz is None else moment.astimezone(tz)

    class _FakeDatetimeModule:
        datetime = _Clock
        date = _dt.date
        timedelta = _dt.timedelta
        timezone = _dt.timezone

    from painfree import orders
    monkeypatch.setattr(orders, "_dt", _FakeDatetimeModule)
    monkeypatch.setattr(orders.pain001, "new_message_id",
                        lambda: "PF00000000000000000000000000000001")
    return moment


def _deployment(tmp_path: pathlib.Path, name: str):
    """A whole deployment of its own: database, connection, keys, app.

    One per locale, because the gate below freezes the `MsgId` and a `MsgId` is
    unique by construction -- it is the bank's duplicate control. Six
    submissions of the same frozen message into one database would collide with
    each other rather than prove anything, so each locale gets a deployment
    that has never seen it, which is what the six documents are then compared
    as: six first submissions, differing only in the reader's language.
    """
    settings = load_settings(
        database_url=f"sqlite+pysqlite:///{tmp_path / (name + '.db')}",
        key_encryption_secret=CUSTODY_SECRET)
    engine = db.build_engine(settings)
    db.migrate(engine)
    audit = AuditLog(engine)
    registry = ConnectionRegistry(engine, audit)
    custodian = KeyCustodian(engine, audit, settings.custody_key())
    registry.register(BANK_CONNECTION_ID, host_id="TESTHOST",
                      partner_id="PARTNER1", user_id="USER1",
                      host_url="http://127.0.0.1:1/ebics")
    custodian.create_subscriber_keys(BANK_CONNECTION_ID, subject=bank_subject())
    bank = {version: ebics3.EbicsKey.generate(version,
                                              subject=bank_subject("bank"))
            for version in (ebics3.KeyVersion.X002, ebics3.KeyVersion.E002)}
    keys = ebics3.BankKeys(authentication=bank[ebics3.KeyVersion.X002],
                           encryption=bank[ebics3.KeyVersion.E002])
    custodian.accept_bank_keys(
        BANK_CONNECTION_ID, keys,
        {"authentication": keys.authentication.fingerprint_hex,
         "encryption": keys.encryption.fingerprint_hex})
    with engine.begin() as connection:
        connection.execute(
            bank_connection.update()
            .where(bank_connection.c.connection_id == BANK_CONNECTION_ID)
            .values(key_state=ebics3.KeyState.READY.value,
                    ini_sent=True, hia_sent=True))
    wrapping.publish(engine, settings.custody_key())
    return settings, engine


def _submit(client, locale: str, key: str):
    """Submit the same payment as a browser reading the console in `locale`."""
    return client.post(
        f"/v1/connections/{BANK_CONNECTION_ID}/payments",
        headers={**dev_credentials("olive", "member"),
                 "accept-language": locale,
                 IDEMPOTENCY_HEADER: key},
        cookies={i18n.COOKIE: locale},
        json=payment_body(transactions=[transfer(),
                                        transfer(amount="1234567.89")]))


def test_the_same_payment_under_six_locales_is_one_pain001(tmp_path, frozen):
    """The gate. Six locales, one payment, six identical documents.

    The amounts are chosen to be the ones a locale would rewrite if it could:
    `1234567.89` groups differently in all six, and `3949.75` has a decimal
    separator four of them do not use. The `pain.001` carries `1234567.89` and
    `3949.75` in every one of them, because the builder has never heard of a
    locale and this test is what says so.
    """
    documents, digests = {}, set()

    for locale in i18n.SUPPORTED:
        settings, engine = _deployment(tmp_path, locale)
        app = create_app(settings)
        with TestClient(app) as client:
            grant(app, "olive", BANK_CONNECTION_ID, "operator")
            # The console is genuinely in this language for this caller --
            # asserted rather than assumed, so a locale that silently fell back
            # to English cannot make the byte comparison below trivially true.
            page = client.get("/ui/connections",
                              headers={**dev_credentials("olive", "member"),
                                       **BROWSER, "accept-language": locale},
                              cookies={i18n.COOKIE: locale})
            assert page.status_code == 200
            assert MARKERS[locale] in page.text, locale

            response = _submit(client, locale, f"i18n-wire-{locale}")
            assert response.status_code == 202, (locale, response.text)
            order_id = response.json()["order_id"]
        with engine.begin() as connection:
            row = connection.execute(
                select(payment_order.c.document, payment_order.c.control_sum,
                       payment_order.c.msg_id,
                       payment_order.c.requested_execution_date)
                .where(payment_order.c.order_id == order_id)).mappings().one()
        documents[locale] = bytes(row["document"])
        digests.add(bytes(row["document"]))
        engine.dispose()

        # The stored derivations are canonical too, not just the document.
        # Stored as the digits, not as a float and not as a rendered
        # string: `pain001.format_amount` wrote it and no locale saw it.
        assert str(row["control_sum"]) == "1238517.64"
        assert row["requested_execution_date"] == "2026-09-01"
        assert row["msg_id"] == "PF00000000000000000000000000000001"

    assert len(digests) == 1, (
        "the pain.001 differs between locales: "
        + ", ".join(f"{name}={len(body)}b" for name, body in documents.items()))

    english = documents["en"].decode("utf-8")
    assert "<InstdAmt Ccy=\"CHF\">1234567.89</InstdAmt>" in english
    assert "<InstdAmt Ccy=\"CHF\">3949.75</InstdAmt>" in english
    assert "<CtrlSum>1238517.64</CtrlSum>" in english
    # `ReqdExctnDt` wraps a `Dt`; the ISO 8601 date is the point.
    assert "<Dt>2026-09-01</Dt>" in english
    for separator in ("1 234 567", "1.234.567", "1,234,567", "1234567,89"):
        assert separator not in english, separator


def test_the_console_shows_the_same_amount_six_different_ways(console, frozen):
    """The other half of the gate: the display really is locale-dependent.

    A test that only proved the document was identical would also pass if
    nothing had been localised at all. So the same order is read back through
    the console in each locale and the amount on the page is asserted to be the
    one that locale writes -- while the document behind it does not move.
    """
    client, _app, _engine = console
    order_id = _submit(client, "en", "i18n-display-0001").json()["order_id"]
    expected = {
        "en": "1,238,517.64", "de": "1.238.517,64", "it": "1.238.517,64",
        "es": "1.238.517,64", "fr": "1 238 517,64",
        "pl": "1 238 517,64",
    }
    for locale, shown in expected.items():
        page = client.get(f"/ui/orders/{order_id}",
                          headers={**dev_credentials("olive", "member"),
                                   **BROWSER},
                          cookies={i18n.COOKIE: locale})
        assert page.status_code == 200
        assert shown in page.text, (locale, shown)


def test_a_locale_cannot_reach_the_builder_at_all(frozen):
    """The unit-level statement of the same rule.

    `pain001.build` takes no locale and reads none. Called directly under each
    of the six with everything else held equal, it returns one document.
    """
    from painfree import payments
    built = set()
    for locale in i18n.SUPPORTED:
        translator, formats = i18n.for_locale(locale)
        # The formatter is exercised on the very values the document carries,
        # so the test is not passing merely because nothing was formatted.
        assert formats.amount(decimal.Decimal("1234567.89"), "CHF")
        assert translator("orders.title")
        instruction = payments.PaymentInstruction.model_validate(
            payment_body(transactions=[transfer(amount="1234567.89")]))
        built.add(pain001.build(
            instruction, message_id="PF00000000000000000000000000000001",
            created_at=frozen, payment_information_id="PMT-1",
            software_version="test"))
    assert len(built) == 1


def test_the_formatter_refuses_a_float():
    """`Money` refuses a float; so does the thing that draws money on a page.

    A float has already lost the digits by the time it arrives, and formatting
    it prettily would hide that rather than fix it.
    """
    _translator, formats = i18n.for_locale("de")
    with pytest.raises(TypeError):
        formats.amount(3949.75, "CHF")
    assert formats.amount(decimal.Decimal("3949.75"), "CHF") == "3.949,75 CHF"


# --- the catalogues are data, and are checked like data --------------------

def test_every_catalogue_has_exactly_english_s_keys():
    """A missing string or a stray one is a test failure, not a discovery."""
    english = set(catalogue("en"))
    for locale in i18n.SUPPORTED:
        if locale == "en":
            continue
        theirs = set(catalogue(locale))
        assert not english - theirs, f"{locale} is missing {sorted(english - theirs)[:10]}"
        assert not theirs - english, f"{locale} has stray {sorted(theirs - english)[:10]}"


def test_every_plural_entry_carries_its_own_language_s_categories():
    """Polish has three forms. A two-form rule gets two thirds of them wrong."""
    english = catalogue("en")
    for locale in i18n.SUPPORTED:
        theirs = catalogue(locale)
        for key, value in english.items():
            mine = theirs[key]
            assert isinstance(mine, dict) == isinstance(value, dict), \
                f"{locale}:{key} is not the same shape as English"
            if isinstance(value, dict):
                assert set(mine) == CATEGORIES[locale], \
                    f"{locale}:{key} has {sorted(mine)}, wanted {sorted(CATEGORIES[locale])}"


def test_a_translation_carries_the_same_markup_and_the_same_placeholders():
    """A catalogue is trusted markup, so a catalogue cannot introduce markup.

    ``Translator.t`` returns :class:`markupsafe.Markup` -- half this console's
    prose names a `<code>` value inside a sentence -- and the values substituted
    into it are escaped. That makes the catalogues themselves the trust
    boundary, so a translation may carry exactly the tags its English carried
    and no others, and exactly the same `{placeholders}`.
    """
    english = catalogue("en")
    for locale in i18n.SUPPORTED:
        theirs = catalogue(locale)
        for key, value in english.items():
            want_tags = sorted(set(TAG.findall(" ".join(_flat(value)))))
            got_tags = sorted(set(TAG.findall(" ".join(_flat(theirs[key])))))
            assert got_tags == want_tags, f"{locale}:{key} tags {got_tags}"
            want = set(PLACEHOLDER.findall(" ".join(_flat(value))))
            got = set(PLACEHOLDER.findall(" ".join(_flat(theirs[key]))))
            assert got == want, f"{locale}:{key} placeholders {sorted(got)}"
            for text in _flat(theirs[key]):
                lowered = text.lower()
                assert "<script" not in lowered and "javascript:" not in lowered
                assert "onerror=" not in lowered and "onclick=" not in lowered


def test_every_key_a_template_names_exists_and_every_key_is_named():
    """No raw key can reach a page, and no string is carried for nothing."""
    english = set(catalogue("en"))
    used: set[str] = set()
    for path in sorted(pathlib.Path(rendering.TEMPLATES).glob("*.html")):
        used |= set(re.findall(
            r"(?<![A-Za-z0-9_.])t(?:\.maybe)?\('([a-zA-Z0-9_.]+)'",
            path.read_text(encoding="utf-8")))
    missing = sorted(used - english - {"", })
    missing = [key for key in missing
               if not any(key == prefix.rstrip(".") for prefix in DYNAMIC_PREFIXES)
               and key not in {p[:-1] for p in DYNAMIC_PREFIXES}]
    # A concatenated key shows up as its literal prefix; those are checked
    # against the model in the tests below rather than here.
    missing = [key for key in missing if key not in DYNAMIC_PREFIXES]
    assert not missing, f"templates name keys no catalogue has: {missing}"

    unused = sorted(key for key in english - used
                    if not key.startswith(DYNAMIC_PREFIXES))
    assert not unused, f"catalogue keys nothing renders: {unused}"


def test_the_keys_built_by_concatenation_cover_the_model():
    """The dynamic families, against the enums they are indexed by.

    `t('state.' ~ row.state.value)` cannot be found by reading a template, so
    it is checked against the model instead: a state added to the service
    without a word for it fails here rather than rendering `state.whatever` on
    an operator's screen.
    """
    from painfree.ebics3 import KeyState
    from painfree.orders import OrderState
    from painfree.reconcile import STATUS_CODES
    english = catalogue("en")
    for state in OrderState:
        assert f"state.{state.value}" in english, state
    for state in KeyState:
        assert f"key_state.{state.value}" in english, state
    for code in STATUS_CODES:
        assert f"status_code.{code}" in english, code
    for role in ("authentication", "encryption"):
        assert f"bank_keys.role_{role}" in english
    for unit in ("minutes", "hours", "days"):
        assert f"schedule_new.{unit}" in english
    # The payment schemes, the attempt states and every reason the scheme
    # decision can give. A scheme added without a word for it fails here rather
    # than rendering `scheme.whatever` on an operator's screen.
    from painfree.attempts import LIVE, PLANNED, SUPERSEDED
    from painfree.schemes import (BANK_REFUSED_INSTANT, CONNECTION_DEFAULT,
                                  PREFLIGHT_CEILING, PREFLIGHT_NO_INSTANT,
                                  REQUESTED, PaymentScheme)
    for scheme in PaymentScheme:
        assert f"scheme.{scheme.value}" in english, scheme
    for state in (PLANNED, LIVE, SUPERSEDED):
        assert f"scheme_state.{state}" in english, state
    for reason in (REQUESTED, CONNECTION_DEFAULT, PREFLIGHT_NO_INSTANT,
                   PREFLIGHT_CEILING, BANK_REFUSED_INSTANT):
        assert f"scheme_reason.{reason}" in english, reason


def test_every_alert_names_keys_the_catalogue_has():
    """The bell's five conditions carry keys, not sentences."""
    from painfree.ui import notifications  # noqa: F401 - for the module's Alert
    english = catalogue("en")
    for key in ("webhooks_parked", "schedules_failing", "orders_failed",
                "connections_uninitialised", "key_jobs_unfinished"):
        assert f"alerts.{key}.title" in english, key
    assert "alerts.key_jobs_unfinished.why_one" in english
    assert "alerts.key_jobs_unfinished.why_many" in english


def test_the_review_file_names_strings_that_exist():
    """The honest limit is recorded, and cannot outlive the strings it names."""
    review = json.loads((LOCALES / "review.json").read_text(encoding="utf-8"))
    assert set(review) - {"_about"} == set(i18n.SUPPORTED) - {"en"}
    for locale, entries in review.items():
        if locale == "_about":
            continue
        assert "_register" in entries, locale
        for key in entries:
            if key.startswith("_"):
                continue
            assert key in catalogue(locale), f"{locale}:{key} was reviewed away"


# --- falling back, rather than showing a key -------------------------------

def test_a_missing_translation_falls_back_to_english(monkeypatch):
    """A hole in a catalogue degrades to a sentence, never to a raw key."""
    monkeypatch.setitem(i18n.CATALOGUES, "de",
                        {k: v for k, v in catalogue("de").items()
                         if k != "connections.heading"})
    translator, _formats = i18n.for_locale("de")
    assert translator("connections.heading") == "Bank connections"
    assert translator("connections.title") == "Verbindungen"


def test_no_raw_key_reaches_a_page_when_a_catalogue_has_a_hole(console,
                                                               monkeypatch):
    """The same thing, asserted on the rendered page rather than the function."""
    client, _app, _engine = console
    monkeypatch.setitem(i18n.CATALOGUES, "pl",
                        {k: v for k, v in catalogue("pl").items()
                         if not k.startswith("connections.")})
    page = client.get("/ui/connections",
                      headers={**dev_credentials("olive", "member"), **BROWSER},
                      cookies={i18n.COOKIE: "pl"})
    assert page.status_code == 200
    assert "connections.heading" not in page.text
    assert "connections.lede" not in page.text
    assert "Bank connections" in page.text
    # The chrome around it is still Polish: the fallback is per string.
    assert "Wyloguj się" in page.text
    assert not re.search(r">\s*[a-z_]+\.[a-z_]+\s*<", page.text), \
        "something that looks like a raw catalogue key reached the page"


def test_an_unknown_status_code_shows_the_reconcilers_own_words():
    """`painfree.reconcile` stays locale-free; the console falls back to it."""
    translator, _formats = i18n.for_locale("de")
    assert translator.maybe("status_code.RJCT", "fallback") \
        == "abgelehnt; sie wird nicht ausgeführt"
    assert translator.maybe("status_code.NEWCODE", "a code nobody translated") \
        == "a code nobody translated"


# --- choosing a language ---------------------------------------------------

@pytest.mark.parametrize("header,expected", [
    ("de", "de"),
    ("de-CH,de;q=0.9,en;q=0.5", "de"),
    ("fr-CH", "fr"),
    ("en-GB,en;q=0.9", "en"),
    ("pl,de;q=0.8", "pl"),
    ("de;q=0.4,pl;q=0.9", "pl"),
    ("de;q=0", "en"),
    ("kl-KL", "en"),
    ("", "en"),
    (None, "en"),
    ("it_IT", "it"),
])
def test_accept_language_is_negotiated_against_the_six(header, expected):
    assert i18n.negotiate(header) == expected


def test_the_console_answers_in_the_negotiated_language(console):
    client, _app, _engine = console
    for locale, marker in MARKERS.items():
        page = client.get("/ui/connections",
                          headers={**dev_credentials("olive", "member"),
                                   **BROWSER, "accept-language": locale})
        assert page.status_code == 200
        assert marker in page.text, locale
        assert f'<html lang="{locale}"' in page.text


def test_an_explicit_choice_overrides_the_browser_and_persists(console):
    """A link, a cookie, and no route -- so it works with scripting off."""
    client, _app, _engine = console
    headers = {**dev_credentials("olive", "member"), **BROWSER,
               "accept-language": "de"}

    chosen = client.get("/ui/connections?lang=pl", headers=headers)
    assert chosen.status_code == 200
    assert MARKERS["pl"] in chosen.text
    assert chosen.cookies[i18n.COOKIE] == "pl"

    # The next request carries no `?lang=` and the browser still says German.
    remembered = client.get("/ui/orders", headers=headers)
    assert remembered.status_code == 200
    assert "Zlecenia" in remembered.text

    # And the choice survives a page that is not the one it was made on.
    again = client.get("/ui/connections", headers=headers)
    assert MARKERS["pl"] in again.text
    assert MARKERS["de"] not in again.text


def test_the_chooser_is_six_links_that_keep_the_page_and_its_filter(console):
    """No form, no `<select>`, no script -- and no filter lost to a language."""
    client, _app, _engine = console
    page = client.get("/ui/orders?state=failed",
                      headers={**dev_credentials("olive", "member"), **BROWSER})
    assert page.status_code == 200
    for locale in i18n.SUPPORTED:
        assert f'href="/ui/orders?state=failed&amp;lang={locale}"' in page.text
    assert 'name="lang"' not in page.text, "the chooser must not need a form"


def test_choosing_a_language_is_not_a_route(console):
    """There is nothing to POST to, which is why nothing had to be authorised.

    A display preference is not deployment state, so it does not belong in the
    write surface `tests/test_service_oversight.py` enumerates. The way it is
    kept out is structural: there is no route.
    """
    _client, app, _engine = console
    paths = {getattr(route, "path", "") for route in app.routes}
    assert not any("lang" in path or "language" in path for path in paths)


def test_an_unknown_language_is_ignored_rather_than_obeyed(console):
    client, _app, _engine = console
    page = client.get("/ui/connections?lang=klingon",
                      headers={**dev_credentials("olive", "member"), **BROWSER,
                               "accept-language": "fr"})
    assert page.status_code == 200
    assert MARKERS["fr"] in page.text
    assert i18n.COOKIE not in page.cookies


def test_a_page_says_what_it_varies_on(console):
    client, _app, _engine = console
    page = client.get("/ui/connections",
                      headers={**dev_credentials("olive", "member"), **BROWSER})
    assert "accept-language" in page.headers["vary"].lower()


# --- the bank's words ------------------------------------------------------

def test_a_banks_report_text_is_verbatim_and_attributed_in_every_locale(
        console, frozen):
    """What the bank said, in the bank's language, marked as the bank's.

    The text below is what a Swiss bank sends: German, on a page an operator
    may be reading in Polish. Translating it would be this console telling an
    operator the bank said something it did not.
    """
    client, _app, engine = console
    from sqlalchemy import update
    from painfree.orders import OrderState
    said = "Auftrag wegen fehlerhafter Referenz zurückgewiesen"
    order_id = _submit(client, "en", "i18n-bank-words").json()["order_id"]
    with engine.begin() as connection:
        connection.execute(update(payment_order)
                           .where(payment_order.c.order_id == order_id)
                           .values(state=OrderState.REJECTED.value,
                                   return_code="091302", report_text=said))

    for locale in i18n.SUPPORTED:
        page = client.get(f"/ui/orders/{order_id}",
                          headers={**dev_credentials("olive", "member"),
                                   **BROWSER},
                          cookies={i18n.COOKIE: locale})
        assert page.status_code == 200
        assert said in page.text, f"{locale} did not show the bank's own words"
        # Attributed, so a German sentence on a Polish page does not read as a
        # translation somebody got wrong.
        translator, _ = i18n.for_locale(locale)
        assert str(translator("bank.verbatim")) in page.text, locale
        assert 'class="pf-bank-text" translate="no"' in page.text, locale
        assert "091302" in page.text


def test_identifiers_are_never_reformatted_in_any_locale(console, frozen):
    """An IBAN, a `MsgId` and an order id are values, not prose.

    A grouped `MsgId` is not a `MsgId`, and this is the test that says a
    locale's number formatting cannot wander into one.
    """
    client, _app, _engine = console
    order = _submit(client, "en", "i18n-identifiers").json()
    for locale in i18n.SUPPORTED:
        page = client.get(f"/ui/orders/{order['order_id']}",
                          headers={**dev_credentials("olive", "member"),
                                   **BROWSER},
                          cookies={i18n.COOKIE: locale})
        assert order["msg_id"] in page.text, locale
        assert order["order_id"] in page.text, locale
        assert BANK_CONNECTION_ID in page.text, locale
        assert "pain.001.001.09" in page.text, locale
        # The ISO date is on the wire; the page shows the locale's own form and
        # never a half-localised hybrid.
        assert "2026-09-01" in page.text or "01.09.2026" in page.text \
            or "01/09/2026" in page.text


# --- formatting, in isolation ----------------------------------------------

@pytest.mark.parametrize("locale,expected", [
    ("en", "1,234,567.89 CHF"),
    ("de", "1.234.567,89 CHF"),
    ("fr", "1 234 567,89 CHF"),
    ("it", "1.234.567,89 CHF"),
    ("es", "1.234.567,89 CHF"),
    ("pl", "1 234 567,89 CHF"),
])
def test_an_amount_is_written_the_way_the_locale_writes_it(locale, expected):
    _translator, formats = i18n.for_locale(locale)
    assert formats.amount(decimal.Decimal("1234567.89"), "CHF") == expected


@pytest.mark.parametrize("locale,expected", [
    ("en", "2026-09-15"), ("de", "15.09.2026"), ("fr", "15/09/2026"),
    ("it", "15/09/2026"), ("es", "15/09/2026"), ("pl", "15.09.2026"),
])
def test_a_date_is_written_the_way_the_locale_writes_it(locale, expected):
    _translator, formats = i18n.for_locale(locale)
    assert formats.date("2026-09-15") == expected
    assert formats.date(_dt.date(2026, 9, 15)) == expected


@pytest.mark.parametrize("count,category", [
    (1, "one"), (2, "few"), (3, "few"), (4, "few"), (5, "many"),
    (12, "many"), (13, "many"), (14, "many"), (22, "few"), (25, "many"),
    (0, "many"), (101, "many"), (102, "few"),
])
def test_polish_has_three_plural_forms(count, category):
    assert i18n.plural_category("pl", count) == category


def test_the_plural_a_locale_uses_is_the_locale_s_own():
    translator, _formats = i18n.for_locale("pl")
    assert "1 wyciąg" in translator("schedules.statement_count", count=1)
    assert "2 wyciągi" in translator("schedules.statement_count", count=2)
    assert "5 wyciągów" in translator("schedules.statement_count", count=5)
    english, _ = i18n.for_locale("en")
    assert english("schedules.statement_count", count=1) == "1 statement"
    assert english("schedules.statement_count", count=5) == "5 statements"


def test_a_value_substituted_into_a_catalogue_string_is_escaped():
    """The catalogues are trusted markup. What goes into them is not."""
    translator, _formats = i18n.for_locale("en")
    rendered = translator("keys.requested_by", who="<script>x</script>",
                          when="now")
    assert "<script>" not in rendered
    assert "&lt;script&gt;" in rendered
