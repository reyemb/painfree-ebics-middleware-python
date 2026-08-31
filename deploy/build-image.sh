#!/usr/bin/env bash
# Build the deployment image with the version and commit it has to record.
#
# Both are build arguments the Dockerfile requires, so there is no such thing
# as an image that cannot say what it is. A dirty working tree produces a sha
# suffixed `-dirty`, because a clean sha on an image built from uncommitted
# code is worse than no sha at all.
#
#   deploy/build-image.sh [extra podman/docker build arguments…]
#
# Prints the PAINFREE_IMAGE line to put in .env.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

engine=${ENGINE:-}
if [ -z "$engine" ]; then
    if command -v podman >/dev/null 2>&1; then engine=podman
    elif command -v docker >/dev/null 2>&1; then engine=docker
    else
        echo "no container engine: install podman or docker, or set ENGINE" >&2
        exit 1
    fi
fi

# `painfree/__init__.py` is the one place the version is written; pyproject.toml
# reads it from there and so does this. Read with sed rather than by importing,
# so that building an image does not need the application's dependencies
# installed on the host.
version=$(sed -n 's/^__version__ = "\(.*\)"$/\1/p' painfree/__init__.py | head -1)
if [ -z "$version" ]; then
    echo "could not read __version__ from painfree/__init__.py" >&2
    exit 1
fi

if ! git rev-parse --git-dir >/dev/null 2>&1; then
    echo "not a git checkout: the image records the commit it was built from" >&2
    exit 1
fi
sha=$(git rev-parse --short=12 HEAD)
if ! git diff --quiet HEAD -- ':!deploy/secrets'; then
    sha="${sha}-dirty"
    echo "warning: the working tree is dirty; the image records ${sha}" >&2
fi

image=${PAINFREE_IMAGE:-localhost/painfree:${version}}

echo "building ${image} (version ${version}, sha ${sha}) with ${engine}" >&2
"$engine" build \
    --build-arg "PAINFREE_VERSION=${version}" \
    --build-arg "GIT_SHA=${sha}" \
    --tag "${image}" \
    "$@" \
    "$root"

echo
echo "PAINFREE_IMAGE=${image}"
