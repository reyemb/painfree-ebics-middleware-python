#!/usr/bin/env bash
# Take a COMPLETE, portable snapshot of this deployment: one .tar.gz that
# restores on another machine.
#
# Why this exists rather than `tar czf everything.tar.gz .`:
#
#   state/db is owned by a uid inside podman's subuid range, not by you. A tar
#   run as your user cannot read it, SKIPS IT, and still writes an archive —
#   one that contains the custody secret and the certificates but not the
#   database. That archive looks complete and restores to nothing. See
#   the note beside the db volume in compose.yaml.
#
# So the database goes in as a `pg_dump`, taken inside the container that can
# actually read it. That is also the only form that survives a change of
# PostgreSQL major version or a move to a different CPU architecture, which a
# byte copy of PGDATA does not.
#
# What goes in:
#   - the database, as a custom-format pg_dump          (the sealed EBICS keys)
#   - deploy/secrets/                                    (incl. custody_secret)
#   - state/caddy-data, state/caddy-config               (TLS certs + local CA)
#   - compose.yaml, .env, deploy/, and the .md files     (how to run it again)
#
#   deploy/snapshot.sh [destination-directory]      # default: ./backups
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
destination=${1:-$root/backups}

compose=${COMPOSE:-}
if [ -z "$compose" ]; then
    if command -v podman-compose >/dev/null 2>&1; then compose="podman-compose"
    elif docker compose version >/dev/null 2>&1; then compose="docker compose"
    else echo "no compose implementation found; set COMPOSE" >&2; exit 1; fi
fi

mkdir -p "$destination"
stamp=$(date -u +%Y%m%dT%H%M%SZ)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
staging="$work/painfree-$stamp"
mkdir -p "$staging"

echo "dumping the database (inside the container that can read it)…" >&2
# The password is read from the secret already mounted in the db container: it
# never passes through this shell or the host's process list.
$compose exec -T db sh -c \
    'PGPASSWORD=$(cat /run/secrets/painfree_db_password) \
     pg_dump -U painfree -d painfree -Fc' > "$staging/painfree.dump"

# A zero-byte dump means the exec failed while the pipe still created the file.
if [ ! -s "$staging/painfree.dump" ]; then
    echo "the database dump is empty; refusing to write a snapshot" >&2
    echo "(is the stack up? \`$compose ps\`)" >&2
    exit 1
fi

echo "copying the secrets, the certificates and the configuration…" >&2
cp -a deploy/secrets "$staging/secrets"
mkdir -p "$staging/state"
cp -a state/caddy-data state/caddy-config "$staging/state/"
cp -a compose.yaml .env "$staging/"
mkdir -p "$staging/deploy"
cp -a deploy/Caddyfile deploy/*.sh deploy/verify-keys.py "$staging/deploy/"
# Whatever notes this deployment keeps beside its stack: the bank's parameter
# sheet, an operating note, whatever the operator wrote down. Best effort.
for doc in *.md *.pdf; do
    [ -e "$doc" ] && cp -a "$doc" "$staging/" || true
done

# Which custody key the sealed rows name — a hash, safe to store, and what lets
# a restore say *before it starts* whether the secret in this archive is the
# one the dump wants.
status=$($compose exec -T worker python -m painfree custody-status 2>/dev/null \
         | grep '"event": *"custody.status"' | tail -1 || true)

cat > "$staging/MANIFEST.json" <<JSON
{
  "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "dump_sha256": "$(sha256sum "$staging/painfree.dump" | cut -d' ' -f1)",
  "dump_bytes": $(stat -c%s "$staging/painfree.dump"),
  "image": "$(sed -n 's/^PAINFREE_IMAGE=//p' .env | head -1)",
  "custody_status": ${status:-null},
  "contains_custody_secret": true,
  "note": "This archive contains deploy/secrets/custody_secret AND the ciphertext it opens. That is the one combination that must never be stored where the two are not both protected. Encrypt this file at rest."
}
JSON

archive="$destination/painfree-$stamp.tar.gz"
tar -C "$work" -czf "$archive" "painfree-$stamp"
chmod 600 "$archive"

cat >&2 <<NOTE

wrote $archive
      $(du -h "$archive" | cut -f1), mode 0600

It contains the custody secret AND the database it opens. Encrypt it before it
goes anywhere you do not fully control:

    age -p $archive          # or gpg -c $archive

To restore on another machine: unpack it, put secrets/ back at deploy/secrets/
and state/ back at state/, \`podman-compose up -d\`, then
\`deploy/restore.sh painfree.dump\`.
NOTE
