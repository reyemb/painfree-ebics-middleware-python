"""What the distribution says about itself.

Three things are checked here, and each of them is a way a release goes wrong
quietly:

* **The version is written once.** A version duplicated between the package and
  the build configuration is a version that will eventually disagree with
  itself, and the disagreement shows up as a wheel on an index claiming to be
  something it is not.
* **The tag guard refuses a mismatch.** It is the only thing standing between a
  mistyped tag and a version number spent on PyPI for the wrong artefact, so it
  is tested for what it rejects rather than for what it accepts.
* **The licence notices are present and intact.** MIT obliges this distribution
  to carry both its own notice and the one belonging to the project the engine
  was ported from. A missing file is a licence breach, not a formatting slip,
  and nothing else in the build would notice it going.

Some of what this checks lives only in the repository and not in the source
distribution -- the container build, the release workflows. Those cases skip
rather than fail when the file is not there, so the suite shipped inside an
sdist still runs green.
"""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest

import painfree

REPO_ROOT = Path(__file__).resolve().parent.parent


def repo_file(relative: str) -> Path:
    """A repository file, skipping the test when only the sdist is unpacked."""
    path = REPO_ROOT / relative
    if not path.exists():
        pytest.skip(f"{relative} is not part of a source distribution")
    return path


@pytest.fixture(scope="module")
def guard():
    """`scripts/check_release_tag.py`, loaded by path -- `scripts/` is not a package."""
    path = repo_file("scripts/check_release_tag.py")
    spec = importlib.util.spec_from_file_location("check_release_tag", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# --- the version is written once ---------------------------------------------


def test_pyproject_takes_the_version_from_the_package():
    """No second copy of the version string, and the backend knows where it is."""
    pyproject = repo_file("pyproject.toml").read_text(encoding="utf-8")

    assert re.search(r'^\s*dynamic\s*=\s*\[\s*"version"\s*\]', pyproject, re.MULTILINE), (
        "pyproject.toml must declare the version dynamic"
    )
    assert not re.search(r'^version\s*=\s*"', pyproject, re.MULTILINE), (
        "a literal version in pyproject.toml is a second source of truth"
    )
    assert re.search(
        r'^\[tool\.hatch\.version\]\s*\npath\s*=\s*"painfree/__init__\.py"',
        pyproject,
        re.MULTILINE,
    ), "the build backend must read the version from painfree/__init__.py"


def test_the_build_script_reads_the_same_file():
    """The image build argument comes from the package, not from pyproject.toml."""
    script = repo_file("deploy/build-image.sh").read_text(encoding="utf-8")
    assert "painfree/__init__.py" in script
    assert "pyproject.toml" not in script.split("version=")[1].splitlines()[0]


def test_the_configuration_reports_the_package_version():
    """Whatever the startup line prints is the version the package holds."""
    from painfree.config import Settings

    settings = Settings(database_url="sqlite://")
    assert settings.version == painfree.__version__


def test_the_engine_carries_its_own_version():
    """The engine is meant to be releasable separately, so it is versioned separately.

    They happen to be equal today. This asserts only that the engine has one of
    its own -- not that the two are locked together, because the point of the
    subpackage is that they can move apart.
    """
    from painfree import ebics3

    assert isinstance(ebics3.__version__, str)
    assert ebics3.__version__


# --- the tag guard ------------------------------------------------------------


def test_the_guard_accepts_the_matching_tag(guard):
    assert guard.check(f"v{painfree.__version__}", None) == painfree.__version__


def test_the_guard_refuses_a_tag_that_disagrees(guard):
    with pytest.raises(guard.Mismatch, match="Nothing is published"):
        guard.check("v99.99.99", None)


def test_the_guard_refuses_a_tag_that_is_not_a_release(guard):
    for tag in ["v0.1.0-rc1", "release-1", "v1.0.0.post1", ""]:
        with pytest.raises(guard.Mismatch):
            guard.check(tag, None)


def test_the_guard_refuses_a_tag_without_the_v(guard):
    with pytest.raises(guard.Mismatch, match="does not start with"):
        guard.check(painfree.__version__, None)


def test_the_guard_refuses_a_stale_artefact(guard, tmp_path):
    """A leftover wheel in the upload directory is uploaded along with the rest."""
    (tmp_path / f"painfree-{painfree.__version__}-py3-none-any.whl").touch()
    (tmp_path / "painfree-0.0.1-py3-none-any.whl").touch()
    with pytest.raises(guard.Mismatch, match="stale"):
        guard.check(f"v{painfree.__version__}", tmp_path)


def test_the_guard_refuses_a_foreign_file(guard, tmp_path):
    (tmp_path / f"painfree-{painfree.__version__}.tar.gz").touch()
    (tmp_path / "something-else-1.0.tar.gz").touch()
    with pytest.raises(guard.Mismatch, match="not a painfree artefact"):
        guard.check(f"v{painfree.__version__}", tmp_path)


def test_the_guard_ignores_the_dotfile_uv_leaves_behind(guard, tmp_path):
    (tmp_path / f"painfree-{painfree.__version__}.tar.gz").touch()
    (tmp_path / ".gitignore").write_text("*\n")
    assert guard.check(f"v{painfree.__version__}", tmp_path) == painfree.__version__


def test_the_guard_notices_an_empty_upload_directory(guard, tmp_path):
    with pytest.raises(guard.Mismatch, match="no artefacts"):
        guard.check(f"v{painfree.__version__}", tmp_path)


# --- the licence notices ------------------------------------------------------

#: The operative sentence of MIT. Reformatted text would still be the licence;
#: text with this sentence missing would not be.
PERMISSION = (
    "The above copyright notice and this permission notice shall be included in all "
    "copies or substantial portions of the Software."
)


def normalised(text: str) -> str:
    """Collapse the line wrapping, so an indented quotation compares equal."""
    return " ".join(text.split())


def test_the_project_carries_its_own_licence():
    licence = (REPO_ROOT / "LICENSE").read_text(encoding="utf-8")
    assert "MIT License" in licence
    assert "Copyright (c) 2026 reyemb" in licence
    assert PERMISSION in normalised(licence)


def test_the_notice_reproduces_the_ported_from_licence():
    """The engine is a port of an MIT project, whose notice has to travel with it."""
    notice = normalised((REPO_ROOT / "NOTICE").read_text(encoding="utf-8"))
    assert "Copyright (c) 2026 reyemb" in notice
    assert "Copyright (c) 2019-2020 EBICS API" in notice
    assert "ebics-api/ebics-client-php" in notice
    # Once, for the upstream notice reproduced here in full. painfree's own
    # full text is in LICENSE, which this file points at rather than repeats.
    assert notice.count(PERMISSION) == 1
    assert "LICENSE" in notice


def test_the_metadata_declares_the_licence_and_ships_both_files():
    pyproject = repo_file("pyproject.toml").read_text(encoding="utf-8")
    assert re.search(r'^license\s*=\s*"MIT"', pyproject, re.MULTILINE)
    assert re.search(
        r'^license-files\s*=\s*\[\s*"LICENSE",\s*"NOTICE"\s*\]', pyproject, re.MULTILINE
    )
    # PyPI refuses a distribution that declares the licence twice, once as an
    # expression and once as a classifier. Comments are not classifiers, so
    # this looks for the string where a classifier would actually be written.
    assert not re.search(r'^\s*"License ::', pyproject, re.MULTILINE)


def test_the_image_build_context_includes_the_licence_files():
    """The wheel the image builds embeds them, so the build fails without them."""
    dockerignore = repo_file(".dockerignore").read_text(encoding="utf-8").split()
    for needed in ["!README.md", "!LICENSE", "!NOTICE"]:
        assert needed in dockerignore


# --- what the wheel must not carry --------------------------------------------


def test_the_wheel_ships_only_the_package():
    """An installed painfree is the application, not a copy of the repository."""
    pyproject = repo_file("pyproject.toml").read_text(encoding="utf-8")
    wheel_section = pyproject.split("[tool.hatch.build.targets.wheel]")[1]
    wheel_section = wheel_section.split("\n[", 1)[0]
    assert 'packages = ["painfree"]' in wheel_section
    for internal in ["tests", "deploy"]:
        assert internal not in wheel_section


def test_every_oidc_setting_reaches_the_api_container():
    """A setting a deployment cannot set is a setting that does not exist.

    `PAINFREE_OIDC_AUDIENCE` was defined, used to verify every bearer token, and
    passed to nothing -- so the audience was silently pinned to the client id and
    a service account from a second client was refused with a message that
    deliberately does not say why. It was found by someone standing up a real
    deployment, which is the expensive way.

    So the check is mechanical: every `oidc_` setting the configuration declares
    has to appear in the `api` service's environment, or be named here as one
    that deliberately does not.
    """
    from painfree.config import Settings

    compose = repo_file("compose.yaml").read_text(encoding="utf-8")
    api = compose.split("  api:")[1].split("\n  worker:")[0]

    #: Read from a file rather than an environment variable, because it is a
    #: secret and a container's environment is not where those go.
    from_a_file = {"oidc_client_secret"}
    #: Not configurable on purpose: a skew wide enough to matter is a clock
    #: nobody is fixing, and the refusal is the signal.
    fixed = {"oidc_clock_skew_seconds"}

    declared = {name for name in Settings.model_fields if name.startswith("oidc_")}
    for name in sorted(declared - from_a_file - fixed):
        assert f"PAINFREE_{name.upper()}:" in api, (
            f"{name} is declared in the configuration and reaches no container: "
            f"a deployment cannot set it")
