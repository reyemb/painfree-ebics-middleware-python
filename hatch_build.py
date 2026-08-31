"""Keep `.gitignore` out of the source distribution.

The build backend force-includes every VCS exclusion file in an sdist, and a
force-include is not subject to the target's `exclude` patterns, so this is the
only place it can be dropped.

It matters because `.gitignore` in this repository is not just build noise: it
names the working paths that are deliberately kept local, and a source
distribution published to an index is exactly where that list should not
appear. The sdist is meant to be the source a rebuild needs, and a rebuild
needs none of it.

Scoped to the sdist target, so the wheel build -- which is what the container
image runs, from a directory that holds only `pyproject.toml` and the package
-- never has to find this file.
"""

from __future__ import annotations

import os
from typing import Any

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class GitignoreOutOfSdistHook(BuildHookInterface):
    PLUGIN_NAME = "gitignore-out-of-sdist"

    def initialize(self, version: str, build_data: dict[str, Any]) -> None:
        forced = build_data.get("force_include", {})
        for source in [p for p in forced if os.path.basename(p) == ".gitignore"]:
            del forced[source]
