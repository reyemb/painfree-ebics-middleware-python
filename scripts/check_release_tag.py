#!/usr/bin/env python3
"""Refuse a release whose tag disagrees with the version the package claims.

A tag that says one thing and a wheel that says another is how the wrong
artefact reaches an index, and an index does not let you take it back: a
version number on PyPI is spent whether or not what was under it was right.
So the tag is checked against `painfree/__init__.py` -- the one place the
version is written -- and against the artefacts actually sitting in `dist/`,
before anything is uploaded.

    scripts/check_release_tag.py v0.1.0
    scripts/check_release_tag.py v0.1.0 --dist dist

The version is read by parsing rather than by importing, so this runs before
the package or any of its dependencies are installed, and cannot be fooled by
a stale installation shadowing the checkout.

Exits 0 when the tag, the module and every artefact agree, and 1 with a
message naming the disagreement when they do not.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
VERSION_FILE = REPO_ROOT / "painfree" / "__init__.py"

#: `__version__ = "0.1.0"` and nothing else -- a computed version would defeat
#: the point of reading the file instead of importing it.
_VERSION_LINE = re.compile(r'^__version__ = "([^"]+)"$', re.MULTILINE)

#: Releases are numbered, not named. Anything a person might tag by hand that
#: an index would silently normalise into something else is refused here, while
#: it is still a tag and not yet a filename.
_RELEASE = re.compile(r"^[0-9]+(\.[0-9]+)*((a|b|rc)[0-9]+)?$")

#: `painfree-0.1.0.tar.gz`, `painfree-0.1.0-py3-none-any.whl`.
_ARTEFACT = re.compile(r"^painfree-(?P<version>[^-]+)(-py3-none-any\.whl|\.tar\.gz)$")


class Mismatch(Exception):
    """A disagreement worth stopping a release for."""


def read_version(path: Path = VERSION_FILE) -> str:
    """The version written in `painfree/__init__.py`."""
    match = _VERSION_LINE.search(path.read_text(encoding="utf-8"))
    if match is None:
        raise Mismatch(f"no `__version__ = \"...\"` line in {path}")
    return match.group(1)


def version_from_tag(tag: str) -> str:
    """`v0.1.0` -> `0.1.0`, with the shapes this project does not tag refused."""
    if not tag:
        raise Mismatch("no tag given: this runs on a tag push")
    if not tag.startswith("v"):
        raise Mismatch(f"tag {tag!r} does not start with `v`; releases are tagged `v<version>`")
    version = tag[1:]
    if not _RELEASE.match(version):
        raise Mismatch(
            f"tag {tag!r} is not a release number: expected `v` followed by "
            "digits and dots, optionally with an a/b/rc suffix"
        )
    return version


def check(tag: str, dist: Path | None, *, version_file: Path = VERSION_FILE) -> str:
    """Return the agreed version, or raise `Mismatch` saying who disagreed."""
    tagged = version_from_tag(tag)
    declared = read_version(version_file)
    if tagged != declared:
        raise Mismatch(
            f"tag {tag!r} wants version {tagged}, but {version_file.name} says "
            f"{declared}.\nEither the tag is wrong or the version was never "
            f"bumped. Nothing is published until they agree."
        )

    if dist is not None:
        # Dotfiles are skipped: `uv build` drops its own `.gitignore` in here,
        # and no uploader treats a dotfile as a distribution.
        artefacts = sorted(
            p.name for p in dist.iterdir() if p.is_file() and not p.name.startswith(".")
        )
        if not artefacts:
            raise Mismatch(f"{dist} holds no artefacts to check")
        for name in artefacts:
            match = _ARTEFACT.match(name)
            if match is None:
                raise Mismatch(
                    f"{dist}/{name} is not a painfree artefact this release "
                    "builds; a stale file in the upload directory is uploaded too"
                )
            if match.group("version") != declared:
                raise Mismatch(
                    f"{dist}/{name} is version {match.group('version')}, not "
                    f"{declared}: the artefacts are stale, rebuild them"
                )
    return declared


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "tag",
        nargs="?",
        default=os.environ.get("GITHUB_REF_NAME", ""),
        help="the release tag, e.g. v0.1.0; defaults to $GITHUB_REF_NAME",
    )
    parser.add_argument(
        "--dist",
        type=Path,
        default=None,
        help="a directory of built artefacts to check the version of as well",
    )
    arguments = parser.parse_args(argv)

    try:
        version = check(arguments.tag, arguments.dist)
    except Mismatch as mismatch:
        print(f"refusing to release: {mismatch}", file=sys.stderr)
        return 1
    print(f"tag {arguments.tag} matches painfree {version}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
