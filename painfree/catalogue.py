"""What the bank publishes about itself, fetched and kept.

`HAA`, `HTD` and `HPD` answer the question an operator otherwise answers by
reading a PDF: which BTFs will this bank accept from this subscriber. This
module is the storage half -- one row per connection and order type, replaced
whenever it is fetched again, because a catalogue is a current fact rather than
a history.

**The document is kept beside the parse.** What the bank sent is the authority;
:mod:`painfree.ebics3.bankinfo` reading it is this service's opinion. Storing
both means a disagreement is settled later against what actually arrived, by a
person, which is the entire reason for asking the bank instead of trusting a
transcription.

**Nothing here can fetch anything.** The fetch needs the custody key to open the
response, so it is a key job the worker performs (:mod:`painfree.initialiser`)
and this module only records the outcome. The console reads these rows and can
ask for a refresh; it cannot produce one itself, exactly as it cannot produce an
`HPB`.
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass
from typing import Any

from sqlalchemy import Engine, delete, select

from painfree import ebics3
from painfree.logging import get_logger
from painfree.schema import bank_catalogue

log = get_logger("painfree.catalogue")

__all__ = ["Catalogue", "CatalogueEntry", "summarise"]


@dataclass(frozen=True)
class CatalogueEntry:
    """One stored answer, and when the bank gave it."""

    connection_id: str
    order_type: str
    fetched_at: _dt.datetime
    document: bytes
    summary: dict[str, Any] | None = None
    return_code: str | None = None
    report_text: str | None = None

    @property
    def uploads(self) -> list[dict[str, Any]]:
        """The `BTU` rows, for an `HTD`. Empty for anything else."""
        return [row for row in (self.summary or {}).get("orders", [])
                if row.get("admin_order_type") == "BTU"]

    @property
    def downloads(self) -> list[dict[str, Any]]:
        return [row for row in (self.summary or {}).get("orders", [])
                if row.get("admin_order_type") == "BTD"]


def _service_json(service: ebics3.Service | None) -> dict[str, Any] | None:
    if service is None:
        return None
    return {"name": service.name, "msg_name": service.msg_name,
            "scope": service.scope, "option": service.option,
            "container": service.container,
            "msg_version": service.msg_version}


def summarise(order_type: str, document: bytes) -> dict[str, Any]:
    """Read one order-data document into the shape a page can draw.

    Deliberately plain data rather than the dataclasses: this is written to a
    column, and a column that holds a pickled object is a column that breaks on
    the next refactor. The dataclasses stay the parsing interface; this is the
    stored projection of one.
    """
    if order_type == "HTD":
        info = ebics3.parse_htd_order_data(document)
        return {
            "partner_id": info.partner_id, "user_id": info.user_id,
            "name": info.name,
            "accounts": [{"account_id": a.account_id, "iban": a.iban,
                          "currency": a.currency, "description": a.description,
                          "holder": a.holder, "bank_code": a.bank_code}
                         for a in info.accounts],
            "orders": [{"admin_order_type": row.admin_order_type,
                        "description": row.description,
                        "num_sig_required": row.num_sig_required,
                        "service": _service_json(row.service)}
                       for row in info.orders],
        }
    if order_type == "HAA":
        return {"services": [_service_json(s)
                             for s in ebics3.parse_haa_order_data(document)]}
    if order_type == "HPD":
        parameters = ebics3.parse_hpd_order_data(document)
        return {
            "host_id": parameters.host_id,
            "protocol_versions": list(parameters.protocol_versions),
            "authentication_versions": list(parameters.authentication_versions),
            "encryption_versions": list(parameters.encryption_versions),
            "signature_versions": list(parameters.signature_versions),
            "recovery_supported": parameters.recovery_supported,
            "pre_validation_supported": parameters.pre_validation_supported,
            "client_data_download": parameters.client_data_download,
        }
    raise ValueError(f"{order_type!r} is not an order type this stores")


class Catalogue:
    """The stored answers, read by the console and written by the worker."""

    __slots__ = ("_engine",)

    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    def record(self, connection_id: str, order_type: str, *, document: bytes,
               return_code: str | None = None,
               report_text: str | None = None,
               now: _dt.datetime | None = None) -> CatalogueEntry:
        """Store what the bank answered, replacing whatever it said before.

        The parse is attempted and a failure is *kept* rather than raised: a
        document this service cannot read is exactly the case where having the
        bytes matters, and losing them because the reader was surprised would
        be the worst possible response to a bank changing something.
        """
        fetched = now or _dt.datetime.now(_dt.timezone.utc)
        try:
            summary: dict[str, Any] | None = summarise(order_type, document)
        except Exception as exc:  # noqa: BLE001 - the point is to keep going
            summary = None
            log.warning("catalogue.unreadable", connection_id=connection_id,
                        order_type=order_type, error=type(exc).__name__,
                        detail=str(exc),
                        reason="the document is stored; only the parse failed, "
                               "so the bytes are there to look at")
        with self._engine.begin() as connection:
            connection.execute(
                delete(bank_catalogue).where(
                    bank_catalogue.c.connection_id == connection_id,
                    bank_catalogue.c.order_type == order_type))
            connection.execute(bank_catalogue.insert().values(
                connection_id=connection_id, order_type=order_type,
                fetched_at=fetched, document=document, summary=summary,
                return_code=return_code, report_text=report_text))
        log.info("catalogue.recorded", connection_id=connection_id,
                 order_type=order_type, bytes=len(document),
                 readable=summary is not None)
        return CatalogueEntry(connection_id, order_type, fetched, document,
                              summary, return_code, report_text)

    def get(self, connection_id: str, order_type: str) -> CatalogueEntry | None:
        with self._engine.connect() as connection:
            row = connection.execute(
                select(bank_catalogue).where(
                    bank_catalogue.c.connection_id == connection_id,
                    bank_catalogue.c.order_type == order_type)
            ).mappings().first()
        return None if row is None else _entry(row)

    def all(self, connection_id: str) -> dict[str, CatalogueEntry]:
        """Everything fetched for one connection, keyed by order type."""
        with self._engine.connect() as connection:
            rows = connection.execute(
                select(bank_catalogue)
                .where(bank_catalogue.c.connection_id == connection_id)
            ).mappings().all()
        return {row["order_type"]: _entry(row) for row in rows}

    def offers(self, connection_id: str, service: ebics3.Service) -> bool | None:
        """Does the bank publish an upload matching this service?

        ``None`` when no `HTD` has been fetched, which is not the same answer as
        ``False``: one means the bank has not been asked and the other means it
        was asked and said no. A console that showed them the same way would be
        telling somebody their payment will be refused on no evidence.
        """
        entry = self.get(connection_id, "HTD")
        if entry is None or entry.summary is None:
            return None
        for row in entry.uploads:
            published = row.get("service") or {}
            if (published.get("name") == service.name
                    and published.get("scope") == service.scope
                    and published.get("option") == service.option
                    and published.get("msg_name") == service.msg_name):
                return True
        return False


def _entry(row) -> CatalogueEntry:
    return CatalogueEntry(
        connection_id=row["connection_id"], order_type=row["order_type"],
        fetched_at=row["fetched_at"], document=row["document"],
        summary=row["summary"], return_code=row["return_code"],
        report_text=row["report_text"])
