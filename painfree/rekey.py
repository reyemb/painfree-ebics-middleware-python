"""Rotating ``PAINFREE_KEY_ENCRYPTION_SECRET`` without stranding a key.

The custody secret is not a password: it is the only input to the key every
stored EBICS private half is sealed under. Changing the variable alone does not
re-encrypt anything — it makes every sealed row unreadable, and no restore of
the database brings them back, because the database was never what was missing.
Recovering from that means new keys and a fresh INI/HIA/HPB with each bank,
which involves a signed paper letter and the bank's own turnaround.

So a rotation is a **migration**, and this module is it: both secrets are
present at once, every sealed row is opened under the old key and re-sealed
under the new one, and the process exits non-zero if any row is left behind.

Three things make it safe to run, and each is a failure mode rather than a
feature:

**It is resumable.** Every row carries the id of the key it was sealed under,
in the ciphertext and in its own column, so a run interrupted halfway leaves a
database in a mixed state that the *next* run finishes. Rows already under the
new key are counted and skipped, not re-sealed.

**It refuses to lie about what it could not move.** A row sealed under some
third key — the custody secret before last, a restore from another deployment —
cannot be opened by either key this process holds. It is reported by name and
the run fails. Silently skipping it would produce a green rotation and a
connection that stops working at its next payment.

**It never widens the boundary.** This runs in a process holding the custody
secret, which is the worker's side of the custody boundary;
``PAINFREE_ROLE=api`` cannot hold either secret, so it cannot run this at all.
Nothing here logs key material — only key ids, row identities and counts.

Three kinds of sealed material exist and all three move:

============================  ==================================================
``key_material``              the EBICS private halves, symmetric ``pfk1`` seals
``webhook_subscription``      signing secrets, ``pfw1`` wrapped seals (and
                              ``pfk1`` for any registered before wrapping existed)
``webhook_wrapping_key``      the public half the request path seals *to*, which
                              is derived from the custody secret and therefore
                              changes with it
============================  ==================================================
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass

from sqlalchemy import Engine, select, update

from painfree import custody, wrapping
from painfree.audit import AuditLog
from painfree.keyring import seal_context
from painfree.logging import get_logger
from painfree.schema import key_material, webhook_subscription
from painfree.sealing import CustodyKey, SealingError
from painfree.webhooks import secret_context

log = get_logger("painfree.rekey")


@dataclass(frozen=True)
class Stranded:
    """A sealed row neither the old nor the new key can open."""

    table: str
    identity: str
    sealed_with: str | None


@dataclass(frozen=True)
class RekeyReport:
    """What one rotation run did, and what it could not do."""

    from_key_id: str
    to_key_id: str
    dry_run: bool
    keys_resealed: int = 0
    keys_already_current: int = 0
    webhook_secrets_resealed: int = 0
    webhook_secrets_already_current: int = 0
    wrapping_key_published: bool = False
    stranded: tuple[Stranded, ...] = ()

    @property
    def complete(self) -> bool:
        """Whether every sealed row is now under the new key."""
        return not self.stranded

    @property
    def resealed(self) -> int:
        return self.keys_resealed + self.webhook_secrets_resealed

    def as_detail(self) -> dict[str, object]:
        return {
            "from_custody_key_id": self.from_key_id,
            "to_custody_key_id": self.to_key_id,
            "dry_run": self.dry_run,
            "keys_resealed": self.keys_resealed,
            "keys_already_current": self.keys_already_current,
            "webhook_secrets_resealed": self.webhook_secrets_resealed,
            "webhook_secrets_already_current":
                self.webhook_secrets_already_current,
            "wrapping_key_published": self.wrapping_key_published,
            "stranded": [
                {"table": row.table, "row": row.identity,
                 "sealed_with_key_id": row.sealed_with}
                for row in self.stranded
            ],
        }


def sealed_key_id(blob: bytes | None) -> str | None:
    """The custody key id an envelope names, whichever envelope it is.

    Needs no key: both the symmetric ``pfk1`` seal and the wrapped ``pfw1`` one
    carry the id in the same place, which is what makes "which secret does this
    database want" answerable by a process that holds neither.
    """
    if not blob:
        return None
    for magic in (b"pfk1", wrapping.MAGIC):
        if blob.startswith(magic) and len(blob) >= len(magic) + 1 + 16:
            return blob[len(magic) + 1:len(magic) + 1 + 16].decode("ascii",
                                                                   "replace")
    return None


def survey(engine: Engine) -> dict[str, int]:
    """Which custody keys the stored material is sealed under, and how many rows.

    The diagnostic an operator runs *before* a rotation, and the one that
    answers "did the last one finish". Opens nothing.
    """
    counts: dict[str, int] = {}
    with engine.connect() as connection:
        for blob in connection.execute(
                select(key_material.c.sealed_private)
                .where(key_material.c.sealed_private.is_not(None))).scalars():
            key_id = sealed_key_id(bytes(blob)) or "unrecognised"
            counts[key_id] = counts.get(key_id, 0) + 1
        for row in connection.execute(
                select(webhook_subscription.c.sealed_secret,
                       webhook_subscription.c.sealed_secret_previous)).all():
            for blob in row:
                if blob is None:
                    continue
                key_id = sealed_key_id(bytes(blob)) or "unrecognised"
                counts[key_id] = counts.get(key_id, 0) + 1
    return counts


def rekey(engine: Engine, *, previous: CustodyKey, current: CustodyKey,
          audit: AuditLog | None = None, dry_run: bool = False) -> RekeyReport:
    """Re-seal every stored secret from ``previous`` to ``current``.

    Idempotent: a second run over a finished database re-seals nothing and
    reports every row as already current.
    """
    custody.assert_outside_request_path("rotating the custody secret")
    if previous.key_id == current.key_id:
        raise SealingError(
            "the previous and current custody keys are the same; there is "
            "nothing to rotate")

    log.info("rekey.started", from_custody_key_id=previous.key_id,
             to_custody_key_id=current.key_id, dry_run=dry_run)

    stranded: list[Stranded] = []
    keys_resealed, keys_current = _rekey_private_keys(
        engine, previous, current, dry_run, stranded)
    secrets_resealed, secrets_current = _rekey_webhook_secrets(
        engine, previous, current, dry_run, stranded)

    published = False
    if not dry_run:
        # The request path seals new webhook secrets to whatever the newest
        # published wrapping key is, so publishing has to happen even when no
        # subscription exists yet -- otherwise the first registration after a
        # rotation is sealed to a key no worker can open.
        wrapping.publish(engine, current)
        published = True

    report = RekeyReport(
        from_key_id=previous.key_id, to_key_id=current.key_id, dry_run=dry_run,
        keys_resealed=keys_resealed, keys_already_current=keys_current,
        webhook_secrets_resealed=secrets_resealed,
        webhook_secrets_already_current=secrets_current,
        wrapping_key_published=published, stranded=tuple(stranded),
    )

    if report.complete:
        log.info("rekey.completed", **report.as_detail())
    else:
        # Loud, and where it is decided: a partial rotation is the state in
        # which a connection still works today and stops working at its next
        # key operation, which is the worst time to find out.
        log.error("rekey.incomplete",
                  reason="rows are sealed under a key this process does not hold",
                  **report.as_detail())
    if audit is not None and not dry_run:
        audit.record("custody.rekeyed",
                     outcome="success" if report.complete else "failure",
                     detail=report.as_detail())
    return report


def _rekey_private_keys(engine: Engine, previous: CustodyKey,
                        current: CustodyKey, dry_run: bool,
                        stranded: list[Stranded]) -> tuple[int, int]:
    resealed = already = 0
    with engine.connect() as connection:
        rows = connection.execute(
            select(key_material.c.seq, key_material.c.connection_id,
                   key_material.c.holder, key_material.c.version,
                   key_material.c.generation, key_material.c.sealed_private)
            .where(key_material.c.sealed_private.is_not(None))
            .order_by(key_material.c.seq)).mappings().all()

    for row in rows:
        blob = bytes(row["sealed_private"])
        identity = (f"{row['connection_id']}/{row['holder']}/"
                    f"{row['version']}/generation {row['generation']}")
        sealed_with = sealed_key_id(blob)
        if sealed_with == current.key_id:
            already += 1
            continue
        if sealed_with != previous.key_id:
            stranded.append(Stranded("key_material", identity, sealed_with))
            log.error("rekey.stranded", table="key_material", row=identity,
                      sealed_with_key_id=sealed_with,
                      from_custody_key_id=previous.key_id,
                      to_custody_key_id=current.key_id)
            continue

        context = seal_context(row["connection_id"], row["holder"],
                               row["version"], row["generation"])
        plaintext = previous.open(blob, context=context)
        if dry_run:
            resealed += 1
            continue
        sealed = current.seal(plaintext, context=context)
        with engine.begin() as connection:
            connection.execute(
                update(key_material)
                .where(key_material.c.seq == row["seq"])
                .values(sealed_private=sealed, custody_key_id=current.key_id,
                        updated_at=_dt.datetime.now(_dt.timezone.utc)))
        resealed += 1
        log.info("rekey.resealed", table="key_material", row=identity,
                 from_custody_key_id=previous.key_id,
                 to_custody_key_id=current.key_id)
    return resealed, already


def _rekey_webhook_secrets(engine: Engine, previous: CustodyKey,
                           current: CustodyKey, dry_run: bool,
                           stranded: list[Stranded]) -> tuple[int, int]:
    recipient = wrapping.recipient_for(current)
    resealed = already = 0
    with engine.connect() as connection:
        rows = connection.execute(
            select(webhook_subscription.c.subscription_id,
                   webhook_subscription.c.sealed_secret,
                   webhook_subscription.c.sealed_secret_previous)
            .order_by(webhook_subscription.c.seq)).mappings().all()

    for row in rows:
        subscription_id = row["subscription_id"]
        context = secret_context(subscription_id)
        replacements: dict[str, bytes] = {}
        for column in ("sealed_secret", "sealed_secret_previous"):
            if row[column] is None:
                continue
            blob = bytes(row[column])
            identity = f"{subscription_id}.{column}"
            sealed_with = sealed_key_id(blob)
            if sealed_with == current.key_id:
                already += 1
                continue
            if sealed_with != previous.key_id:
                stranded.append(
                    Stranded("webhook_subscription", identity, sealed_with))
                log.error("rekey.stranded", table="webhook_subscription",
                          row=identity, sealed_with_key_id=sealed_with,
                          from_custody_key_id=previous.key_id,
                          to_custody_key_id=current.key_id)
                continue
            # Either envelope opens with the custody key; both are re-sealed as
            # `pfw1`, so a rotation also finishes the migration that was
            # deliberately not forced on existing rows.
            plaintext = (wrapping.unseal(previous, blob, context=context)
                         if wrapping.is_wrapped(blob)
                         else previous.open(blob, context=context))
            resealed += 1
            if not dry_run:
                replacements[column] = recipient.seal(plaintext,
                                                      context=context)
        if replacements and not dry_run:
            with engine.begin() as connection:
                connection.execute(
                    update(webhook_subscription)
                    .where(webhook_subscription.c.subscription_id
                           == subscription_id)
                    .values(custody_key_id=current.key_id,
                            updated_at=_dt.datetime.now(_dt.timezone.utc),
                            **replacements))
            log.info("rekey.resealed", table="webhook_subscription",
                     row=subscription_id,
                     from_custody_key_id=previous.key_id,
                     to_custody_key_id=current.key_id)
    return resealed, already


__all__ = ["RekeyReport", "Stranded", "rekey", "sealed_key_id", "survey"]
