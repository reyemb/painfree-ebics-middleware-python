#!/usr/bin/env bash
# Restore a painfree database dump, and check the custody secret matches it.
#
# The order matters and is not negotiable: the custody secret has to be in
# place *before* this runs, because a database restored without it contains
# nothing usable. This script checks that rather than assuming it — it compares
# the custody key id the restored rows name against the one the running worker
# derives, and says so when they differ.
#
#   deploy/restore.sh backups/painfree-….dump
#
# It overwrites the current database. Everything in it is dropped first
# (pg_restore --clean --if-exists), so run it against a stack you intend to
# replace.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
dump=${1:?usage: deploy/restore.sh <dump-file>}
[ -f "$dump" ] || { echo "no such dump: $dump" >&2; exit 1; }

compose=${COMPOSE:-}
if [ -z "$compose" ]; then
    if command -v podman-compose >/dev/null 2>&1; then compose="podman-compose"
    elif docker compose version >/dev/null 2>&1; then compose="docker compose"
    else echo "no compose implementation found; set COMPOSE" >&2; exit 1; fi
fi

if [ -f "$dump.manifest.json" ]; then
    checksum=$(sha256sum "$dump" | cut -d' ' -f1)
    recorded=$(sed -n 's/.*"sha256": *"\([0-9a-f]*\)".*/\1/p' "$dump.manifest.json")
    if [ -n "$recorded" ] && [ "$checksum" != "$recorded" ]; then
        echo "the dump does not match its manifest checksum; refusing" >&2
        echo "  manifest: $recorded" >&2
        echo "  file:     $checksum" >&2
        exit 1
    fi
fi

# --- the schema the dump was taken at -----------------------------------------
#
# The custody check below is good and it was the only one. Nothing compared the
# *schema* version, so restoring a dump taken before an upgrade rolls
# `alembic_version` backwards while the container stays where it is, and the
# worker then queries columns that no longer exist:
#
#   (psycopg.errors.UndefinedColumn) column payment_order.refused_request
#   does not exist
#
# It fails in the direction nobody watches. `restore.sh` said nothing, the API
# kept answering because it migrated at startup and holds no queue, and only
# the worker -- the process with no user in front of it -- was broken, retrying
# every two seconds.
#
# Revision ids in this project are `NNNN_slug`, so the four digits order them.
# A format this does not recognise is not guessed at: the check says so and
# stands aside rather than refusing a restore over a naming convention.
dump_revision=$($compose exec -T db pg_restore --data-only \
                    --table=alembic_version -f /dev/stdout < "$dump" 2>/dev/null \
                | grep -oE '^[0-9]{4}_[a-z0-9_]+' | head -1 || true)
head_revision=$($compose exec -T api python -c \
                    'from painfree.db import head_revision; print(head_revision())' \
                2>/dev/null | tr -d '\r' | tail -1 || true)

if [ -n "$dump_revision" ] && [ -n "$head_revision" ]; then
    dump_number=${dump_revision%%_*}
    head_number=${head_revision%%_*}
    if [ "$dump_revision" = "$head_revision" ]; then
        echo "schema: dump and image are both at $head_revision" >&2
    elif [ "$dump_number" -gt "$head_number" ] 2>/dev/null; then
        cat >&2 <<NOTE

This dump is at $dump_revision and this image expects $head_revision.

The dump is NEWER than the code. Restoring it would leave tables this image
does not know how to read, and there is no downgrade path that recovers the
data those columns hold. Run the image the dump came from, or take a dump from
a deployment at $head_revision.
NOTE
        exit 2
    elif [ "$dump_number" -lt "$head_number" ] 2>/dev/null; then
        cat >&2 <<NOTE

Note: this dump is at $dump_revision and this image expects $head_revision.

The restore will roll the schema backwards. The API migrated at startup and
will not do it again, so the worker will query columns that no longer exist and
retry every two seconds with nobody watching. After the restore finishes:

    $compose exec api python -m painfree migrate
    $compose restart worker

NOTE
    fi
else
    echo "note: could not read the schema version from the dump or the image;" >&2
    echo "      restoring anyway, and \`painfree migrate\` afterwards is cheap" >&2
fi

echo "restoring $dump into the running database…" >&2
# --clean --if-exists so a restore over a schema the API already migrated does
# not fail on every existing object. Exit status is checked below rather than
# by `set -e`: pg_restore warns about dropping objects that were never there.
if ! $compose exec -T db sh -c \
        'PGPASSWORD=$(cat /run/secrets/painfree_db_password) \
         pg_restore -U painfree -d painfree --clean --if-exists \
                    --no-owner --no-privileges' < "$dump"; then
    echo "pg_restore reported errors; read them before continuing" >&2
    exit 1
fi

echo "checking the custody secret against what the restored rows want…" >&2
status=$($compose exec -T worker python -m painfree custody-status 2>/dev/null \
         | grep '"event": *"custody.status"' | tail -1 || true)
if [ -z "$status" ]; then
    echo "could not ask the worker which custody key the material wants" >&2
    echo "(is the worker running? \`$compose ps\`)" >&2
    exit 1
fi
echo "$status" >&2
if ! printf '%s' "$status" | grep -q '"readable": *true'; then
    cat >&2 <<'NOTE'

The restored database is sealed under a custody key this deployment does not
hold. The database is fine; the secret is wrong or missing. Put the matching
deploy/secrets/custody_secret in place and restart the worker.

If that secret is genuinely lost, no restore recovers these keys: they have to
be regenerated and re-registered with each bank (INI/HIA/HPB, on paper).
NOTE
    exit 2
fi

echo >&2
echo "restored, and the custody secret opens it." >&2
