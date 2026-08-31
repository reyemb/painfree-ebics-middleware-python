"""``python -m painfree`` -- serve, work, migrate, and look after the keys and the accounts.

Nine subcommands, because a deployment needs all nine: the long-running HTTP
server, the long-running upload worker, a one-shot schema upgrade for
deployments that would rather migrate in a job than at startup
(``PAINFREE_MIGRATE_ON_STARTUP=false``), a generator for
``PAINFREE_KEY_ENCRYPTION_SECRET`` -- the secret every stored EBICS private key
is sealed under, which is meant to be generated rather than chosen -- and the
two commands that exist because that secret can be rotated or lost:
``custody-status``, which says which custody keys the stored material wants
without holding any of them, and ``rekey``, which re-seals every row from the
previous secret to the new one.

The last three exist because a deployment may have no identity provider, and
therefore no way to have a first administrator. ``create-admin`` makes one,
``set-password`` changes any account's password -- including the last
administrator's, which is the recovery path when there is nobody left who can
sign in -- and ``unlock`` clears a sign-in lockout, which is the recovery path
when the per-source throttle has locked the office out of the console the
lockouts are otherwise cleared from. **No account is ever created by anything
else**: no migration writes one, no first request bootstraps one, and no
default credential exists to be found on an installation that was never
hardened. The trade is that a fresh deployment refuses every credential until a
person with a shell on the host runs one command, which is the correct set of
people.

A password is never a command-line argument -- ``ps`` is world-readable and a
shell keeps a history -- so it is read from a terminal, read from standard input
when there is no terminal, or generated here and printed once.

``serve`` and ``worker`` are the same image and the same configuration with one
variable different, and the difference is the security boundary: only the
worker's environment carries the custody secret, and ``PAINFREE_ROLE=api``
refuses to start with it. Running ``worker`` in a process configured as ``api``
-- or ``serve`` in one configured as ``worker`` -- is a configuration error,
not a warning.

Configuration errors are printed as one JSON line and exit non-zero, in the same
shape as everything else on stdout, so a container that refuses to start is read
with the same tooling as one that ran.
"""

from __future__ import annotations

import argparse
import signal
import sys
import threading
import time
from typing import Any

from painfree.config import ConfigurationError, Settings, load_settings
from painfree.identity import Role
from painfree.logging import configure_logging, get_logger

log = get_logger("painfree.main")

#: How long a worker waits for the API process to bring the schema to head
#: before giving up and letting the restart policy try again. Two processes
#: start together and only one migrates, so the other one necessarily races it
#: on a fresh deployment; waiting is the correct answer and crashing with a
#: traceback about a missing table is not.
SCHEMA_WAIT_SECONDS = 120.0
SCHEMA_POLL_SECONDS = 2.0


def wait_for_schema(settings: Settings, *,
                    timeout_s: float = SCHEMA_WAIT_SECONDS,
                    interval_s: float = SCHEMA_POLL_SECONDS) -> bool:
    """Block until the database is reachable and at the revision this code wants.

    Returns ``False`` on timeout, having said why on every attempt. The wait is
    bounded so a worker pointed at a database that will never appear exits and
    is restarted, rather than sitting silent for ever.
    """
    from painfree.db import build_engine, check_ready

    engine = build_engine(settings)
    deadline = time.monotonic() + timeout_s
    attempt = 0
    try:
        while True:
            attempt += 1
            status = check_ready(engine)
            if status.get("ready"):
                if attempt > 1:
                    log.info("worker.schema_ready", attempts=attempt,
                             revision=status.get("revision"))
                return True
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                log.error("worker.schema_unavailable",
                          reason=status.get("reason"), attempts=attempt,
                          waited_s=round(timeout_s, 1),
                          revision=status.get("revision"),
                          head=status.get("head"))
                return False
            log.warning("worker.waiting_for_schema",
                        reason=status.get("reason"), attempt=attempt,
                        revision=status.get("revision"),
                        head=status.get("head"),
                        remaining_s=round(remaining, 1))
            time.sleep(min(interval_s, remaining))
    finally:
        engine.dispose()


def read_password(*, generate: bool) -> str:
    """A password, from the safest source available, and never from `argv`.

    Three sources and the order is the order of how private each is:

    - ``--generate`` prints one this service chose. It goes to **stdout** and
      nowhere else -- not to the log stream, which is the one place a credential
      must never appear, and which is also where every other line this process
      writes goes.
    - A terminal is asked twice, with no echo.
    - No terminal means standard input, one line, so
      ``… | python -m painfree create-admin alice`` works in a deployment
      script. The trailing newline a shell adds is not part of it.
    """
    import getpass

    from painfree.accounts import check_password_policy, generate_password

    if generate:
        generated = generate_password()
        print(generated)
        return generated
    if sys.stdin.isatty():
        first = getpass.getpass("password: ")
        if first != getpass.getpass("again: "):
            raise ValueError("the two passwords are not the same")
        check_password_policy(first)
        return first
    line = sys.stdin.readline()
    if not line:
        raise ValueError(
            "no password on standard input; pipe one in, or pass --generate")
    password = line.rstrip("\n")
    check_password_policy(password)
    return password


def _account_command(settings: Settings, arguments: Any) -> int:
    """``create-admin`` and ``set-password``: the two ways an account is made usable.

    They share everything except the statement they end in, so they share a
    function: the schema check, the way the password is read, and the refusal to
    say anything about the password afterwards beyond that it was set.
    """
    import getpass

    from painfree.accounts import PasswordRejected
    from painfree.audit import Actor, AuditLog
    from painfree.db import build_engine, check_ready
    from painfree.errors import ConflictError, NotFoundError

    if not arguments.subject:
        log.error("service.misconfigured",
                  reason=f"`{arguments.command}` needs an account name: "
                         f"`python -m painfree {arguments.command} <name>`")
        return 2

    engine = build_engine(settings)
    try:
        status = check_ready(engine)
        if not status.get("ready"):
            # The one ordering this command has: the tables have to exist. Said
            # with the command that creates them rather than as a traceback
            # about a missing relation.
            log.error("account.schema_unavailable", reason=status.get("reason"),
                      revision=status.get("revision"), head=status.get("head"),
                      remedy="run `python -m painfree migrate` first")
            return 4
        try:
            password = read_password(generate=arguments.generate)
        except (ValueError, PasswordRejected) as exc:
            # The message names the rule, never the value: this line goes to
            # the log stream like every other line this process writes.
            log.error("account.password_rejected", reason=str(exc))
            return 2
        except (EOFError, KeyboardInterrupt):
            log.error("account.cancelled", reason="no password was entered")
            return 2

        accounts = _accounts_store(engine, settings, AuditLog(engine))
        try:
            who = getpass.getuser()
        except Exception:  # pragma: no cover - no passwd entry in a container
            who = "unknown"
        # The command line cannot identify a person the way a signed token can.
        # It names the operating-system user and says where it came from, which
        # is the true statement available; who may run it is a question about
        # who has a shell on this host.
        actor = Actor("cli", f"{who}@cli")
        try:
            if arguments.command == "create-admin":
                account = accounts.create(
                    arguments.subject, password,
                    role=Role.member if arguments.member else Role.admin,
                    display_name=arguments.display_name, actor=actor)
            else:
                account = accounts.set_password(
                    arguments.subject, password, actor=actor)
        except ConflictError as exc:
            log.error("account.refused", subject=arguments.subject,
                      reason=str(exc))
            return 2
        except NotFoundError as exc:
            log.error("account.not_found", subject=arguments.subject,
                      reason=str(exc))
            return 2
        log.info("account.ready", subject=account.subject,
                 account_role=account.role.value,
                 auth_mode=settings.auth_mode.value,
                 note="the password was not written to this stream and cannot "
                      "be read back out of the database")
        return 0
    finally:
        engine.dispose()


def _unlock_command(settings: Settings, arguments: Any) -> int:
    """``unlock`` -- the recovery path when the throttle has locked *everybody* out.

    The per-source counter is the one that can do that: it is deliberately not
    per account, so a burst of guesses from an office address locks the
    administrator who would otherwise clear it from the console. There has to be
    a lever that does not go through the front door, and this is it. It clears
    both counters for the value given, because whoever is running it does not
    have to know which one caught them.
    """
    import getpass

    from painfree.accounts import LOCKOUT_SCOPES
    from painfree.audit import Actor, AuditLog
    from painfree.db import build_engine

    if not arguments.subject:
        log.error("service.misconfigured",
                  reason="`unlock` needs an account name or a source address: "
                         "`python -m painfree unlock <name-or-address>`")
        return 2
    engine = build_engine(settings)
    try:
        accounts = _accounts_store(engine, settings, AuditLog(engine))
        try:
            who = getpass.getuser()
        except Exception:  # pragma: no cover - no passwd entry in a container
            who = "unknown"
        actor = Actor("cli", f"{who}@cli")
        cleared = [scope for scope in LOCKOUT_SCOPES
                   if accounts.clear_lockout(scope, arguments.subject,
                                             actor=actor)]
        if not cleared:
            log.warning("account.nothing_to_unlock", value=arguments.subject,
                        reason="no lockout is recorded against that name or "
                               "address")
            return 0
        log.info("account.unlocked", value=arguments.subject,
                 lockout_scopes=cleared)
        return 0
    finally:
        engine.dispose()


def _accounts_store(engine: Any, settings: Settings, audit: Any):
    """The same store the request path verifies against, built the same way."""
    from painfree.accounts import Accounts

    return Accounts(
        engine, audit,
        subject_threshold=settings.basic_lockout_threshold,
        source_threshold=settings.basic_source_lockout_threshold,
        window_minutes=settings.basic_lockout_window_minutes,
        lockout_minutes=settings.basic_lockout_minutes)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="painfree", description="JSON in, EBICS out.")
    parser.add_argument(
        "command", nargs="?", default="serve",
        choices=("serve", "worker", "migrate", "new-secret", "rekey",
                 "custody-status", "create-admin", "set-password",
                 "unlock"),
        help="serve the API (default), run the upload worker, bring the schema "
             "to head and exit, print a fresh key encryption secret, re-seal "
             "every stored secret under a rotated one, report which custody "
             "keys the stored material is sealed under, create the first local "
             "administrator, set a local account's password, or clear a "
             "sign-in lockout",
    )
    parser.add_argument(
        "subject", nargs="?", default=None,
        help="create-admin and set-password: the account name. unlock: the "
             "account name or source address to stop throttling",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="rekey only: open every sealed row and report what would move, "
             "writing nothing",
    )
    parser.add_argument(
        "--generate", action="store_true",
        help="create-admin and set-password only: generate the password and "
             "print it to stdout once, instead of asking for one",
    )
    parser.add_argument(
        "--member", action="store_true",
        help="create-admin only: create an ordinary member instead of an "
             "administrator. A member signs in and holds nothing until an "
             "administrator grants it a bank connection",
    )
    parser.add_argument(
        "--display-name", default=None,
        help="create-admin only: the name the console shows for this account",
    )
    arguments = parser.parse_args(argv)

    if arguments.command == "new-secret":
        # Printed bare, and before the configuration is read: generating a
        # secret is what an operator does *because* they have none yet. It goes
        # to stdout and never to the log stream, which is the one place it must
        # not appear.
        from painfree.sealing import new_secret

        print(new_secret())
        return 0

    try:
        settings = load_settings()
    except ConfigurationError as exc:
        configure_logging("ERROR")
        log.error("service.misconfigured", reason=str(exc))
        return 2

    configure_logging(settings.log_level)

    if arguments.command == "worker":
        # The one process that holds the custody key. It is started the same
        # way as the server and from the same image; what differs is the
        # environment it is given.
        from painfree.worker import run_worker

        # The API process is the one that migrates. A worker that started first
        # used to die on `relation "audit_log" does not exist` and be restarted
        # by the orchestrator, which worked and read like a crash.
        if not wait_for_schema(settings):
            return 4

        stop = threading.Event()
        for name in (signal.SIGTERM, signal.SIGINT):
            # A worker in the middle of a multi-segment upload finishes it
            # rather than dropping a transaction the bank has open. The order
            # would be reclaimed after its lease and re-sent, which is a
            # duplicate the bank has to catch -- avoidable, so avoided.
            signal.signal(name, lambda *_: stop.set())
        return run_worker(settings, stop=stop)

    if arguments.command == "custody-status":
        # Deliberately needs no secret: the question "which key does this
        # database want" is the one an operator has when the answer to "which
        # key do I have" is wrong.
        from painfree.db import build_engine
        from painfree.rekey import survey

        engine = build_engine(settings)
        try:
            counts = survey(engine)
        finally:
            engine.dispose()
        log.info("custody.status",
                 configured_key_id=settings.custody_key_id,
                 previous_key_id=settings.previous_custody_key_id,
                 sealed_rows_by_key_id=counts,
                 readable=(settings.custody_key_id is not None
                           and set(counts) <= {settings.custody_key_id}))
        return 0

    if arguments.command == "rekey":
        from painfree.audit import AuditLog
        from painfree.db import build_engine
        from painfree.rekey import rekey

        try:
            previous, current = (settings.previous_custody_key(),
                                 settings.custody_key())
        except ConfigurationError as exc:
            log.error("service.misconfigured", reason=str(exc))
            return 2
        engine = build_engine(settings)
        try:
            report = rekey(engine, previous=previous, current=current,
                           audit=AuditLog(engine), dry_run=arguments.dry_run)
        finally:
            engine.dispose()
        # Non-zero on an incomplete run: a rotation that left a row behind must
        # not look like a success to whatever ran it.
        return 0 if report.complete else 3

    if arguments.command in ("create-admin", "set-password"):
        return _account_command(settings, arguments)

    if arguments.command == "unlock":
        return _unlock_command(settings, arguments)

    if arguments.command == "migrate":
        from painfree.db import build_engine, migrate

        engine = build_engine(settings)
        try:
            migrate(engine)
        finally:
            engine.dispose()
        return 0

    import uvicorn

    from painfree.app import create_app

    # `log_config=None` leaves our handler in place; uvicorn's default config
    # would otherwise reinstall its own formatters and split the stream.
    uvicorn.run(
        create_app(settings),
        host=settings.http_host,
        port=settings.http_port,
        log_config=None,
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    try:
        code = main()
    except SystemExit:
        # Not a crash: `--help` and an argparse usage error both leave this way,
        # carrying the status they mean. Catching them below reported `painfree
        # --help` as `service.crashed` with a traceback and turned its exit 0
        # into a 1, which is a container that looks broken every time somebody
        # asks it what its arguments are.
        raise
    except BaseException:  # noqa: BLE001 - the last line of defence
        # Nothing may leave this process except JSON on stdout. An exception
        # escaping `main` would otherwise be printed by the interpreter as a
        # bare multi-line traceback on stderr -- unparseable, uncorrelated, and
        # the one shape `podman logs` cannot be grepped for.
        configure_logging("ERROR")
        log.exception("service.crashed", command=" ".join(sys.argv[1:]) or "serve")
        code = 1
    sys.exit(code)
