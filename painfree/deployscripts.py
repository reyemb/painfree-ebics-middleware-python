"""Hand the operator scripts out of the image, as a tar on stdout.

``deploy/*.sh`` are *host* scripts. They run in a normal shell beside
``compose.yaml``, they drive the compose implementation, and they read files --
``deploy/secrets/custody_secret`` above all -- that the container deliberately
cannot reach. None of them is importable Python and none of them is ever run
inside the container that ships them.

So why are they in the image at all? Because of who needs them and when. A
deployment made from this repository has ``deploy/`` already. A deployment made
the way the readme recommends -- pull the published image, write a
``compose.yaml``, run it -- has the stack and no scripts, and the moment that
operator most needs ``snapshot.sh`` is the moment the machine is being replaced.
Telling them to clone a repository to back up a running service is telling them
to fetch a moving target: the scripts that match *this* image are the ones built
into it, and they cannot drift from it the way a checkout can.

The transport is a tar written to stdout rather than a file written to a mounted
directory, because a mount is a second thing to get right and a tar is not::

    podman run --rm ghcr.io/reyemb/painfree:TAG deploy-scripts | tar x

The scripts are found beside the interpreter (``/opt/painfree/deploy`` in the
image, since the image installs into a prefix at ``/opt/painfree``) or beside
the package in a checkout, and a marker file is checked rather than the
directory's existence -- an empty ``deploy/`` that produced an empty tar would
be a backup tool that silently handed out nothing.
"""

from __future__ import annotations

import sys
import tarfile
from pathlib import Path
from typing import BinaryIO

# What an operator gets, named rather than globbed. A checkout's `deploy/` also
# holds `build-image.sh` and the requirements locks, which build the image
# rather than run it, and on a running deployment it holds `secrets/` as well.
# Globbing the directory would hand out a different set depending on where the
# command was run, and the one place it must not over-share is the one place it
# is most likely to be run.
#
# `tests/test_deploy_scripts.py` checks this list against the Dockerfile and
# `.dockerignore`, so the image cannot ship a set that differs from it.
SCRIPTS = (
    "Caddyfile",
    "backup-secrets.sh",
    "backup.sh",
    "init-secrets.sh",
    "restore.sh",
    "snapshot.sh",
    "verify-keys.py",
)

# The file whose presence means "this directory is the operator scripts". Any
# of them would do; this is the one whose absence matters most.
MARKER = "snapshot.sh"


def directory() -> Path:
    """Where the scripts are: beside the interpreter, or beside the package."""
    candidates = (
        Path(sys.prefix) / "deploy",
        Path(__file__).resolve().parent.parent / "deploy",
    )
    for candidate in candidates:
        if (candidate / MARKER).is_file():
            return candidate
    raise FileNotFoundError(
        "no operator scripts in this build; looked for "
        + " and ".join(str(candidate / MARKER) for candidate in candidates))


def write_tar(out: BinaryIO) -> None:
    """Write every script as an uncompressed tar, rooted at ``deploy/``.

    Rooted rather than flat so ``| tar x`` in a deployment directory puts them
    where every other instruction in the readme says they are, and so an
    operator who runs it in the wrong directory creates one stray folder rather
    than scattering seven files.
    """
    source = directory()
    # Stream mode: this is a pipe, and a pipe cannot be seeked back to patch a
    # header. It also means the first bytes leave before the last file is read.
    with tarfile.open(fileobj=out, mode="w|") as archive:
        for name in SCRIPTS:
            path = source / name
            if not path.is_file():
                # A build that dropped one is a backup tool missing a piece,
                # and the operator finds out when they need it. Say so now.
                raise FileNotFoundError(f"{path} is missing from this build")
            archive.add(path, arcname=f"deploy/{name}")


def main(out: BinaryIO, *, isatty: bool) -> int:
    """Refuse a terminal, then write the tar.

    A tar on a terminal is a screenful of binary and a wedged session, and the
    mistake is easy to make: the command reads like one that prints something.
    """
    if isatty:
        print("deploy-scripts writes a tar to stdout, and stdout is a "
              "terminal.\n\n"
              "    podman run --rm IMAGE deploy-scripts | tar x\n"
              "    podman run --rm IMAGE deploy-scripts > deploy.tar\n",
              file=sys.stderr)
        return 2
    write_tar(out)
    return 0
