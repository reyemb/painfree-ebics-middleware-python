"""Six languages in the console, and the line the wire is on the other side of.

The console speaks `en`, `de`, `fr`, `it`, `es` and `pl`. Nothing else in this
service does, and that is the whole design: **localisation is display only, and
nothing localised reaches the wire**.

**What is not translated, ever.** The REST API, the webhook envelope, the log
stream, an audit ``action`` and an error ``code`` are machine-facing contracts
whose consumers match on the string; a localised `code` would break every one
of them. Amounts in a `pain.001` are canonical ISO 20022 decimal -- a full
stop, no group separator -- and dates on the wire are ISO 8601, whatever this
module shows an operator. `MsgId`s, IBANs, BICs, references, connection ids and
order ids are **identifiers rather than prose**: they are never translated and
never reformatted, because a grouped IBAN is a different string and a
translated `MsgId` is not a `MsgId`.

**And the bank's own words are not ours.** A `ReportText`, an EBICS return-code
report or a `pain.002` status reason arrives in whatever language the bank
chose. It is shown verbatim and attributed to the bank
(``t('bank.verbatim')`` beside it), because rewriting it would be this console
telling an operator that the bank said something it did not. A gloss of our own
may sit beside a *code*; the text stays untouched.

**How a locale is chosen.** In order: an explicit ``?lang=`` on the request, the
``pf_lang`` cookie the previous explicit choice left, the ``Accept-Language``
header negotiated against :data:`SUPPORTED`, and English. The explicit choice is
a link rather than a form, so it needs no route of its own -- and therefore
nothing for the write-route enumeration of ``tests/test_service_oversight.py``
to classify, which is right, because a display preference is not deployment
state. It also means the chooser works with scripting off, like everything in
this console except the theme toggle.

**A missing string falls back to English rather than to its key.** Translating
6 000 words of banking prose into 5 languages is not something that ever ends;
a catalogue with a hole in it must degrade to a sentence an operator can read.
``tests/test_service_i18n.py`` holds every catalogue to English's key set, so a
hole is a test failure rather than a discovery.

**A catalogue may carry markup, and a value substituted into one may not.**
Half of this console's prose names an identifier or a state value inside a
sentence -- `a connection can accept payments once its key state reads
``ready``` -- and a catalogue that could not say `<code>` would have lost that
everywhere. So a string is returned as :class:`markupsafe.Markup` and formatted
with :meth:`markupsafe.Markup.format`, which **escapes every value it
substitutes**: the catalogues are repository files reviewed like code, and the
connection ids and counts that go into them are not.
``tests/test_service_i18n.py`` holds every translation to English's own tag
multiset, so a catalogue cannot introduce a tag -- or a `<script>` -- that the
English string did not have.

**Plurals are the locale's own.** Polish has three forms and English has two, so
a catalogue entry may be an object keyed by CLDR category and
:func:`plural_category` picks. A two-form rule applied to Polish reads as
broken to a Polish operator, which is exactly the class of error this module is
honest about elsewhere.
"""

from __future__ import annotations

import datetime as _dt
import decimal
import json
import pathlib
import urllib.parse
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from markupsafe import Markup

HERE = pathlib.Path(__file__).parent
LOCALES = HERE / "locales"

#: The six. Order is the order the chooser lists them in: English first because
#: it is the fallback and the source, then the rest alphabetically by code.
SUPPORTED: tuple[str, ...] = ("en", "de", "fr", "it", "es", "pl")

#: What a language is called *in that language*. A chooser that says "German"
#: to somebody who does not read English is a chooser they cannot use.
NATIVE_NAMES: Mapping[str, str] = {
    "en": "English", "de": "Deutsch", "fr": "Français",
    "it": "Italiano", "es": "Español", "pl": "Polski",
}

DEFAULT = "en"

#: The explicit choice, remembered in the operator's browser. Not a row in a
#: table: what language somebody reads a page in is display state, and the
#: alternative was a write route the oversight enumeration would have needed an
#: exception for.
COOKIE = "pf_lang"
QUERY = "lang"
COOKIE_MAX_AGE = 365 * 24 * 3600


def _load() -> dict[str, dict[str, Any]]:
    """Every catalogue, read once at import.

    A catalogue is JSON because it is data: a translator changing a sentence
    should not be editing Python, and a diff of a string change should be one
    line.
    """
    found: dict[str, dict[str, Any]] = {}
    for code in SUPPORTED:
        path = LOCALES / f"{code}.json"
        found[code] = json.loads(path.read_text(encoding="utf-8"))
    return found


CATALOGUES = _load()


# --- choosing a locale -----------------------------------------------------

def supported(code: str | None) -> str | None:
    """``de-CH`` is German. ``de_CH`` is German. ``klingon`` is nothing."""
    if not code:
        return None
    base = code.strip().replace("_", "-").split("-")[0].lower()
    return base if base in SUPPORTED else None


def negotiate(header: str | None) -> str:
    """The best of what a browser asked for, by q-value, or English.

    ``Accept-Language`` is a preference list and not a demand: a browser that
    asks for `fr-CH, fr;q=0.9, en;q=0.5` is asking for French and will accept
    English. Answering it with English because `fr-CH` is not one of the six
    would be answering a question nobody asked.
    """
    if not header:
        return DEFAULT
    ranked: list[tuple[float, int, str]] = []
    for position, part in enumerate(header.split(",")):
        piece, _, parameters = part.strip().partition(";")
        code = supported(piece)
        if code is None:
            continue
        quality = 1.0
        for parameter in parameters.split(";"):
            name, _, value = parameter.strip().partition("=")
            if name.strip() == "q":
                try:
                    quality = float(value)
                except ValueError:
                    quality = 0.0
        if quality <= 0:
            continue
        # Position breaks a tie the way the header wrote it: `de, fr` with no
        # q-values is a preference even though both weigh 1.0.
        ranked.append((-quality, position, code))
    if not ranked:
        return DEFAULT
    return sorted(ranked)[0][2]


def resolve(request: Any) -> tuple[str, bool]:
    """The locale for this request, and whether it was explicitly chosen now.

    The second half is what tells :func:`painfree.ui.rendering.render` to write
    the cookie: a link carrying ``?lang=`` is the choice being made, and every
    later request is the choice being remembered.
    """
    chosen = supported(request.query_params.get(QUERY))
    if chosen:
        return chosen, True
    remembered = supported(request.cookies.get(COOKIE))
    if remembered:
        return remembered, False
    return negotiate(request.headers.get("accept-language")), False


def switch_links(request: Any) -> list[dict[str, str]]:
    """One link per language, back to the page the operator is on.

    The current query string is carried through, so switching language on a
    filtered list does not silently clear the filter -- an operator who loses
    their filter learns not to touch the chooser.
    """
    current, _ = resolve(request)
    links = []
    for code in SUPPORTED:
        parameters = [(name, value) for name, value
                      in request.query_params.multi_items() if name != QUERY]
        parameters.append((QUERY, code))
        query = "&".join(f"{_quote(name)}={_quote(value)}"
                         for name, value in parameters)
        links.append({
            "code": code,
            "name": NATIVE_NAMES[code],
            "href": f"{request.url.path}?{query}",
            "current": code == current,
        })
    return links


def _quote(value: str) -> str:
    return urllib.parse.quote(str(value), safe="")


# --- plurals ---------------------------------------------------------------

def plural_category(locale: str, count: int) -> str:
    """The CLDR category for a count, in this locale.

    Only the four categories these six languages use. Polish is the reason the
    function exists: `1 zlecenie`, `2 zlecenia`, `5 zleceń` are three different
    words, and a two-form rule gets two thirds of the numbers wrong.
    """
    number = abs(int(count))
    if locale == "pl":
        if number == 1:
            return "one"
        if number % 10 in (2, 3, 4) and number % 100 not in (12, 13, 14):
            return "few"
        return "many"
    if locale == "fr":
        return "one" if number in (0, 1) else "other"
    return "one" if number == 1 else "other"


# --- saying something ------------------------------------------------------

@dataclass(frozen=True, slots=True)
class Translator:
    """One locale's strings, with English underneath it.

    Callable as ``t('orders.title')`` and as ``t('alerts.failed', count=3)``:
    a value carrying ``{placeholders}`` is formatted with the keywords, and a
    value that is an object is a plural set indexed by ``count``.
    """

    locale: str

    def __call__(self, key: str, **values: Any) -> str:
        return self.t(key, **values)

    def t(self, key: str, **values: Any) -> str:
        for code in (self.locale, DEFAULT):
            pattern = _pattern(CATALOGUES[code], key, code, values)
            if pattern is None:
                continue
            if not values:
                return Markup(pattern)
            try:
                return Markup(pattern).format(**values)
            except (KeyError, IndexError):  # pragma: no cover - the tests catch it
                return Markup(pattern)
        # Nowhere, not even in English. The key is returned so that a page still
        # renders, and `tests/test_service_i18n.py` fails the build over it so
        # that this never happens on a page an operator is looking at.
        return key

    def has(self, key: str) -> bool:
        return key in CATALOGUES[self.locale]

    def maybe(self, key: str, fallback: Any) -> str:
        """The translation if any catalogue has one, else what the model said.

        For the sentences that are written in a module the console must not
        make locale-dependent -- ``painfree.reconcile``'s reading of each
        `pain.002` status code is the case that exists. The gloss belongs to
        the reconciler, and translating it here would have meant a locale
        reaching into the module that decides payment state. So the catalogue
        may carry a translation of it, and where it does not, the reconciler's
        own English sentence is shown rather than a hole.
        """
        if key in CATALOGUES[self.locale] or key in CATALOGUES[DEFAULT]:
            return self.t(key)
        return fallback


def _pattern(catalogue: Mapping[str, Any], key: str, locale: str,
             values: Mapping[str, Any]) -> str | None:
    """One catalogue's answer for a key, plural set resolved."""
    entry = catalogue.get(key)
    if entry is None:
        return None
    if isinstance(entry, str):
        return entry
    if isinstance(entry, Mapping):
        category = (plural_category(locale, values["count"])
                    if "count" in values else "other")
        return entry.get(category) or entry.get("other") or entry.get("one")
    return None


# --- how a number, a date and a duration look ------------------------------

@dataclass(frozen=True, slots=True)
class NumberStyle:
    group: str
    decimal: str


#: Display only. The wire is `pain001.format_amount`, which is ISO 20022
#: canonical decimal and does not know this table exists.
NUMBERS: Mapping[str, NumberStyle] = {
    "en": NumberStyle(",", "."),
    "de": NumberStyle(".", ","),
    "fr": NumberStyle(" ", ","),
    "it": NumberStyle(".", ","),
    "es": NumberStyle(".", ","),
    "pl": NumberStyle(" ", ","),
}

#: ``Y`` `` M`` ``D`` in the order this locale writes them, and the separator.
#: English keeps ISO order on purpose: an English-reading operator of this
#: console is reading `2026-09-15` everywhere else in it, including in the
#: documents, and two orders on one screen is how a date is misread.
DATES: Mapping[str, tuple[str, str]] = {
    "en": ("ymd", "-"),
    "de": ("dmy", "."),
    "fr": ("dmy", "/"),
    "it": ("dmy", "/"),
    "es": ("dmy", "/"),
    "pl": ("dmy", "."),
}


@dataclass(frozen=True, slots=True)
class Formats:
    """Every number, date and duration an operator reads, in their locale.

    Nothing here is ever asked for a value that goes anywhere but a page. It
    takes :class:`decimal.Decimal` and refuses :class:`float` for the same
    reason :class:`painfree.schema.Money` does: by the time a float arrives the
    digits are already wrong, and formatting it prettily would hide that.
    """

    locale: str
    translator: Translator

    # -- numbers

    def amount(self, value: Any, currency: str | None = None) -> str:
        """``1234.56`` as ``1 234,56 CHF``. Never as a float, never on the wire."""
        if value is None or value == "":
            return "—"
        if isinstance(value, float):
            raise TypeError(
                "money is never a float; pass a Decimal or its digits as a string")
        if not isinstance(value, decimal.Decimal):
            value = decimal.Decimal(str(value))
        digits = format(value, "f")
        sign = ""
        if digits.startswith("-"):
            sign, digits = "-", digits[1:]
        whole, _, fraction = digits.partition(".")
        style = NUMBERS[self.locale]
        grouped = _group(whole, style.group)
        shown = grouped if not fraction else grouped + style.decimal + fraction
        return f"{sign}{shown} {currency}" if currency else f"{sign}{shown}"

    def number(self, value: int | None) -> str:
        if value is None:
            return "—"
        return _group(str(abs(int(value))), NUMBERS[self.locale].group) \
            if value >= 0 else "-" + _group(str(abs(int(value))),
                                            NUMBERS[self.locale].group)

    # -- dates

    def date(self, value: Any) -> str:
        """A date, or an ISO date string, as this locale writes it."""
        if value is None or value == "":
            return "—"
        if isinstance(value, str):
            try:
                value = _dt.date.fromisoformat(value)
            except ValueError:
                # ISO 20022 lets a bank choose per field, so a booking date
                # arrives as a date from one bank and as a date-time from the
                # next. Both are the same day to a reader, and printing the raw
                # string for one of them would put an ISO timestamp in a column
                # of dates.
                try:
                    value = _dt.datetime.fromisoformat(value)
                except ValueError:
                    return value
        if isinstance(value, _dt.datetime):
            value = value.astimezone(_dt.timezone.utc).date()
        order, separator = DATES[self.locale]
        parts = {"y": f"{value.year:04d}", "m": f"{value.month:02d}",
                 "d": f"{value.day:02d}"}
        return separator.join(parts[letter] for letter in order)

    def moment(self, value: _dt.datetime | None) -> str:
        """A timestamp. The clock is 24-hour everywhere and the zone is UTC.

        UTC because every timestamp this console shows came out of a column
        that is UTC, and a console that rendered local time would be inviting
        an operator to compare it against a log line that did not.
        """
        if value is None:
            return "—"
        value = value.astimezone(_dt.timezone.utc)
        return f"{self.date(value)} {value:%H:%M:%S} UTC"

    # -- durations

    def cadence(self, seconds: int | None) -> str:
        """``21600`` as *every 6 hours*, in the locale's own plural."""
        if not seconds:
            return "—"
        for unit, size in (("day", 86400), ("hour", 3600), ("minute", 60)):
            if seconds % size == 0:
                count = seconds // size
                return self.translator.t(f"cadence.{unit}", count=count)
        return self.translator.t("cadence.second", count=seconds)

    def days(self, count: int) -> str:
        return self.translator.t("unit.day", count=count)


def _group(digits: str, separator: str) -> str:
    if len(digits) <= 3 or not separator:
        return digits
    head = len(digits) % 3 or 3
    parts = [digits[:head]]
    parts += [digits[index:index + 3] for index in range(head, len(digits), 3)]
    return separator.join(parts)


def for_locale(locale: str) -> tuple[Translator, Formats]:
    translator = Translator(locale)
    return translator, Formats(locale, translator)


def keys(locale: str) -> Iterable[str]:
    return CATALOGUES[locale].keys()


__all__ = ["CATALOGUES", "COOKIE", "COOKIE_MAX_AGE", "DEFAULT", "Formats",
           "NATIVE_NAMES", "QUERY", "SUPPORTED",
           "Translator", "for_locale", "keys", "negotiate", "plural_category",
           "resolve", "supported", "switch_links"]
