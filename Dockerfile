# painfree — the deployment image. One image, two roles.
#
# `serve` and `worker` are the same bytes with one environment variable
# different, and that difference is the security boundary: only the worker's
# environment carries PAINFREE_KEY_ENCRYPTION_SECRET, and PAINFREE_ROLE=api
# refuses to start with it. Building two images would make the
# boundary a property of what was deployed rather than of what was configured.
#
# Four properties this file is written for, each of them a failure it prevents:
#
#   Pinned, by digest.  Both stages start from one immutable image. A tag can
#   be moved; a digest cannot, so a rebuild six months from now produces the
#   same base or fails saying it cannot find it.
#
#   No silent fallbacks.  Every dependency is installed from a hash-pinned lock
#   file with --require-hashes, --only-binary and --no-index where nothing
#   should be fetched. A build that cannot get exactly what the lock names
#   fails; it never quietly resolves something else, compiles from source, or
#   produces an image whose contents nobody chose.
#
#   The image knows what it is.  The version and the git sha are build
#   arguments, both required, both checked, both baked in as labels and as
#   PAINFREE_GIT_SHA — which the startup line emits together with the resolved
#   configuration.
#
#   It fails at build time, not at 3am.  The build imports the application and
#   runs the CLI inside the image it just produced. A missing shared library or
#   a dependency the lock file forgot is a red build, not a container that
#   crash-loops in production.

# python:3.12.13-slim-bookworm — resolved 2026-08-30.
# Tag kept beside the digest so a human reading this knows what it is; the
# digest is what actually gets pulled.
ARG BASE_IMAGE=docker.io/library/python@sha256:4766d8b510c428e595d74b9cc5bbb2fae8e26316fffb4adc89908d79aacd58a2

# --- build -------------------------------------------------------------------

FROM ${BASE_IMAGE} AS build

ARG PAINFREE_VERSION
ARG GIT_SHA

# Both are required. An image that cannot say which commit it is built from
# cannot satisfy the diagnosability rules this repo holds itself to, and a
# default here would be a lie that survives into production.
RUN test -n "${PAINFREE_VERSION}" || { \
        echo "build argument PAINFREE_VERSION is required" >&2; \
        echo "  podman build --build-arg PAINFREE_VERSION=\$(…) …" >&2; \
        exit 1; }; \
    test -n "${GIT_SHA}" || { \
        echo "build argument GIT_SHA is required: the image records the commit" >&2; \
        echo "  podman build --build-arg GIT_SHA=\$(git rev-parse HEAD) …" >&2; \
        exit 1; }

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_ROOT_USER_ACTION=ignore

WORKDIR /src

# The runtime environment. --require-hashes makes every artefact exact and
# --only-binary=:all: means a missing wheel is an error rather than a source
# build that needs a compiler this image deliberately does not have.
COPY deploy/requirements.lock ./
RUN python -m venv /opt/painfree \
 && /opt/painfree/bin/pip install --require-hashes --only-binary=:all: \
        -r requirements.lock

# The build environment, kept separate so hatchling never lands in the image
# that ships. --no-build-isolation stops pip from fetching an unpinned build
# backend from the network behind the lock file's back.
COPY deploy/requirements-build.lock ./
RUN python -m venv /opt/build \
 && /opt/build/bin/pip install --require-hashes --only-binary=:all: \
        -r requirements-build.lock

COPY pyproject.toml ./
# The readme is the wheel's long description and both licence files are baked
# into its metadata, so the build stops here without all three rather than
# producing a distribution that has quietly dropped the notice it must keep.
COPY README.md LICENSE NOTICE ./
COPY painfree ./painfree
RUN /opt/build/bin/python -m hatchling build --target wheel \
 && ls dist/painfree-${PAINFREE_VERSION}-py3-none-any.whl >/dev/null || { \
        echo "the wheel hatchling built is not version ${PAINFREE_VERSION}:" >&2; \
        ls dist >&2; \
        echo "PAINFREE_VERSION disagrees with painfree/__init__.py" >&2; \
        exit 1; }

# --no-index: the wheel and nothing else. Every dependency is already installed
# from the lock file, so any resolution attempt here would be a bug.
RUN /opt/painfree/bin/pip install --no-deps --no-index \
        dist/painfree-${PAINFREE_VERSION}-py3-none-any.whl

# The build's own smoke test. Importing the application exercises every
# dependency the lock file is supposed to carry; the version check catches a
# stale wheel picked up from a cached layer.
RUN /opt/painfree/bin/python -c "\
import painfree, painfree.app, painfree.worker, painfree.rekey;\
assert painfree.__version__ == '${PAINFREE_VERSION}', painfree.__version__;\
print('build check ok:', painfree.__version__)"

# --- runtime -----------------------------------------------------------------

FROM ${BASE_IMAGE} AS runtime

ARG PAINFREE_VERSION
ARG GIT_SHA

LABEL org.opencontainers.image.title="painfree" \
      org.opencontainers.image.description="Self-hosted middleware that accepts JSON payment instructions and submits them to banks over EBICS 3.0" \
      org.opencontainers.image.version="${PAINFREE_VERSION}" \
      org.opencontainers.image.revision="${GIT_SHA}" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.base.name="docker.io/library/python:3.12.13-slim-bookworm"

# uid 10001: high enough not to collide with anything the base image ships, and
# fixed rather than allocated so a bind-mounted volume has one owner to match.
RUN groupadd --gid 10001 painfree \
 && useradd --uid 10001 --gid 10001 --home-dir /var/lib/painfree \
        --no-create-home --shell /usr/sbin/nologin painfree \
 && install -d -o painfree -g painfree /var/lib/painfree

COPY --from=build --chown=root:root /opt/painfree /opt/painfree

ENV PATH="/opt/painfree/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PAINFREE_GIT_SHA="${GIT_SHA}" \
    PAINFREE_HTTP_HOST="0.0.0.0"

# 0.0.0.0 rather than the configuration default of 127.0.0.1: inside a
# container the loopback default binds where nothing can reach it. The image
# says so once, here, instead of every deployment repeating it — and a
# deployment that wants otherwise still sets PAINFREE_HTTP_HOST.

USER painfree
WORKDIR /var/lib/painfree
EXPOSE 8000

# curl is not installed and will not be: the health check is the same Python
# that serves the request. Only meaningful for the API role — compose gives the
# worker its own check, because a worker serves no HTTP at all.
#
# podman builds OCI images, and the OCI image spec has no health check field:
# `podman build` prints a warning and drops this. It is kept for `docker build`
# and for `podman build --format docker`, and compose declares both services'
# checks explicitly so the stack does not depend on which one built the image.
HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=3 \
    CMD ["python", "-c", "import os,urllib.request,sys;\
sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('PAINFREE_HTTP_PORT','8000')+'/healthz', timeout=4).status==200 else 1)"]

# Exec form, no shell: python is pid 1 and receives SIGTERM directly. Both
# long-running commands install their own handler — uvicorn stops the server,
# the worker finishes the segment it is uploading rather than dropping a
# transaction the bank has open — so no init process is needed to translate a
# signal, and one process means there is nothing to reap.
ENTRYPOINT ["python", "-m", "painfree"]
CMD ["serve"]
