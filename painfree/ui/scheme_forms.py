"""The two shapes the console needs a scheme configuration in.

Split out of :mod:`painfree.ui.views`, which was six lines under the
repository's file-size cap. Nothing here decides anything: it turns a
:class:`~painfree.schemes.SchemeProfiles` into rows a table can draw, and an
HTML form back into one. The rules are in :mod:`painfree.schemes` and the
validation is that module's own -- a second set in a form handler would be a
second answer to the same question.
"""

from __future__ import annotations

import decimal

from painfree.schemes import (Code, PaymentScheme, SchemeProfile,
                              SchemeProfiles)

__all__ = ["scheme_rows", "schemes_from"]


def scheme_rows(connection) -> list[tuple[str, SchemeProfile]]:
    """The profiles this connection actually sends under, normal first.

    An unconfigured instant is left out rather than shown empty: a table row
    for a scheme this connection cannot send is a row an operator reads as
    *available*.
    """
    rows = [(PaymentScheme.NORMAL.value, connection.schemes.normal)]
    if connection.schemes.instant_configured:
        rows.append((PaymentScheme.INSTANT.value, connection.schemes.instant))
    return rows



def schemes_from(form: dict[str, str]) -> SchemeProfiles:
    """The scheme configuration out of the edit form, validated by its own model.

    Nothing here checks a BTF field or a code length: :class:`SchemeProfile`
    and the engine's own ``Service`` do that, and a second set of rules in a
    form handler is a second answer to the same question. What this does is
    turn "empty means unset" into ``None``, which HTML forms cannot say for
    themselves.
    """
    def slot(prefix: str, key: str) -> Code | None:
        value = (form.get(f"{prefix}_{key}") or "").strip()
        if not value:
            return None
        return Code(value,
                    proprietary=form.get(f"{prefix}_{key}_kind") == "prtry")

    def profile(prefix: str, ceiling: str | None = None) -> SchemeProfile:
        return SchemeProfile(
            service_name=(form.get(f"{prefix}_service_name") or "").strip(),
            service_option=(form.get(f"{prefix}_service_option") or "").strip()
            or None,
            scope=(form.get(f"{prefix}_scope") or "").strip() or None,
            service_level=slot(prefix, "service_level"),
            local_instrument=slot(prefix, "local_instrument"),
            category_purpose=slot(prefix, "category_purpose"),
            max_amount=decimal.Decimal(ceiling) if ceiling else None,
        )

    offered = bool(form.get("instant_offered"))
    codes = tuple((form.get("instant_refusal_codes") or "").split())
    return SchemeProfiles(
        default=PaymentScheme(form.get("scheme_default") or "normal"),
        normal=profile("normal"),
        instant=profile("instant",
                        (form.get("instant_max_amount") or "").strip())
        if offered else None,
        instant_refusal_codes=codes,
    )
