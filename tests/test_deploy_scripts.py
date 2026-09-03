"""``deploy-scripts`` hands the operator scripts out of the image.

The command exists for a host that has podman, this image, and no checkout --
so the thing worth testing is not that tar works, but that the set of files is
the same wherever it is read from. Three places name that set: this package,
the Dockerfile's ``COPY``, and the ``.dockerignore`` allow-list. If they drift,
the image ships a snapshot tool with a piece missing and nobody finds out until
a machine is being replaced.
"""

from __future__ import annotations

import io
import stat
import tarfile
from pathlib import Path

import pytest

from painfree.deployscripts import SCRIPTS, directory, main, write_tar

REPO = Path(__file__).resolve().parent.parent


def test_every_named_script_exists_in_the_checkout():
    for name in SCRIPTS:
        assert (REPO / "deploy" / name).is_file(), name


def test_the_tar_holds_exactly_the_named_scripts():
    buffer = io.BytesIO()
    write_tar(buffer)
    buffer.seek(0)
    with tarfile.open(fileobj=buffer) as archive:
        names = sorted(archive.getnames())
    assert names == sorted(f"deploy/{name}" for name in SCRIPTS)


def test_the_shell_scripts_stay_executable_through_the_tar():
    # `| tar x` has to produce something runnable. tar carries the mode, so the
    # only way this breaks is a script losing +x in the repository -- which is
    # exactly the failure worth catching, because it survives review.
    buffer = io.BytesIO()
    write_tar(buffer)
    buffer.seek(0)
    with tarfile.open(fileobj=buffer) as archive:
        for member in archive.getmembers():
            if member.name.endswith(".sh"):
                assert member.mode & stat.S_IXUSR, member.name


def test_nothing_secret_can_be_handed_out():
    # `deploy/secrets/` lives in this directory on a running deployment. The
    # list is explicit rather than globbed precisely so that a snapshot taken
    # on such a host cannot post the custody secret to stdout.
    buffer = io.BytesIO()
    write_tar(buffer)
    buffer.seek(0)
    with tarfile.open(fileobj=buffer) as archive:
        for member in archive.getmembers():
            assert member.isfile(), f"{member.name} is not a plain file"
            assert "secrets/" not in member.name


def test_a_terminal_is_refused_rather_than_filled_with_binary():
    buffer = io.BytesIO()
    assert main(buffer, isatty=True) == 2
    assert buffer.getvalue() == b""
    assert main(buffer, isatty=False) == 0
    assert buffer.getvalue().startswith(b"deploy/") or buffer.getvalue()


def test_a_missing_script_is_reported_and_not_silently_skipped(tmp_path, monkeypatch):
    (tmp_path / "deploy").mkdir()
    for name in SCRIPTS:
        if name != "backup.sh":
            (tmp_path / "deploy" / name).write_text("#!/bin/sh\n")
    monkeypatch.setattr("painfree.deployscripts.directory",
                        lambda: tmp_path / "deploy")
    with pytest.raises(FileNotFoundError, match="backup.sh"):
        write_tar(io.BytesIO())


def test_directory_refuses_a_folder_that_is_not_the_scripts(tmp_path, monkeypatch):
    # The marker is checked rather than the directory's existence: an empty
    # `deploy/` would otherwise produce an empty tar and look like success.
    monkeypatch.setattr("painfree.deployscripts.sys.prefix", str(tmp_path))
    monkeypatch.setattr("painfree.deployscripts.__file__",
                        str(tmp_path / "painfree" / "deployscripts.py"))
    with pytest.raises(FileNotFoundError):
        directory()


def test_the_dockerfile_copies_exactly_what_this_module_names():
    # The Dockerfile uses a glob for the shell scripts, so compare what the
    # glob resolves to in the checkout rather than the literal text.
    dockerfile = (REPO / "Dockerfile").read_text()
    line = next(block for block in dockerfile.split("COPY ")
                if "/opt/painfree/deploy/" in block)
    copied: set[str] = set()
    for token in line.split():
        token = token.strip("\\")
        if not token.startswith("deploy/"):
            continue
        copied.update(path.name for path in REPO.glob(token))
    assert copied == set(SCRIPTS)


def test_the_dockerignore_admits_exactly_what_this_module_names():
    allowed = {
        line[len("!deploy/"):]
        for line in (REPO / ".dockerignore").read_text().splitlines()
        if line.startswith("!deploy/")
    }
    # The requirements locks are allowed for the build stage and are not
    # operator scripts; everything else admitted under deploy/ must be one.
    assert allowed - {"requirements.lock", "requirements-build.lock"} == set(SCRIPTS)


def test_the_directory_itself_is_never_admitted_to_the_image():
    # `!deploy/` would admit `deploy/secrets/` on any host that had run the
    # stack from a checkout, baking the custody secret into a published image.
    for line in (REPO / ".dockerignore").read_text().splitlines():
        assert line.strip() not in ("!deploy", "!deploy/", "!deploy/*", "!deploy/**")
