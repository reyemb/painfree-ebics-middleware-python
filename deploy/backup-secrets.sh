#!/usr/bin/env bash
# Take the copy that makes this deployment recoverable, off this host.
#
# `init-secrets.sh` generates the secrets once, at provisioning. This takes a
# copy of them afterwards, which is a different act at a different time and by
# a different person as often as not -- so it is a different script.
#
# What goes in:
#   - deploy/secrets/         the custody secret, the database password
#   - the local CA root       so a browser can trust this deployment again
#   - RECOVERY.txt            which custody key these secrets are, and what to
#                             do with them. The same card the console shows.
#
# What does NOT go in: the database. That is `deploy/snapshot.sh`, and the two
# are deliberately separate. This archive is the key; that one is the lock. An
# operator who keeps both in one place has stored the safe with its combination
# taped to the door, and the whole custody boundary was for nothing.
#
#   deploy/backup-secrets.sh [destination-directory]     # default: ./backups
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
destination=${1:-$root/backups}
secrets="$root/deploy/secrets"

if [ ! -d "$secrets" ]; then
    echo "no deploy/secrets/: run deploy/init-secrets.sh first" >&2
    exit 1
fi
if [ ! -s "$secrets/custody_secret" ]; then
    echo "deploy/secrets/custody_secret is missing or empty; there is nothing" >&2
    echo "here worth backing up, and that is itself the problem." >&2
    exit 1
fi

compose=${COMPOSE:-}
if [ -z "$compose" ]; then
    if command -v podman-compose >/dev/null 2>&1; then compose="podman-compose"
    elif docker compose version >/dev/null 2>&1; then compose="docker compose"
    else compose=""; fi
fi

# Which custody key the stored material is sealed under. Read from the running
# worker when there is one, because that is the process that can answer; absent
# when the stack is down, which is not an error -- a fresh deployment has no
# keys yet, and taking this copy before it does is the point.
key_id="unknown (the stack is not running)"
if [ -n "$compose" ]; then
    reported=$($compose exec -T worker python -m painfree custody-status 2>/dev/null \
               | sed -n 's/.*"configured_key_id": *"\([^"]*\)".*/\1/p' | tail -1 || true)
    [ -n "$reported" ] && key_id="$reported"
fi

mkdir -p "$destination"
stamp=$(date -u +%Y%m%dT%H%M%SZ)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
staging="$work/painfree-secrets-$stamp"
mkdir -p "$staging"

cp -a "$secrets" "$staging/secrets"

ca="$root/state/caddy-data/caddy/pki/authorities/local/root.crt"
if [ -r "$ca" ]; then
    cp -a "$ca" "$staging/local-ca.crt"
fi

cat > "$staging/RECOVERY.txt" <<NOTE
painfree recovery archive

created           $(date -u +%Y-%m-%dT%H:%M:%SZ)
custody key id    $key_id
image             $(sed -n 's/^PAINFREE_IMAGE=//p' .env 2>/dev/null | head -1)

secrets/custody_secret is the value every stored EBICS private key is sealed
under. Nothing else recovers those keys: not a database dump, not this service,
not the bank. The key id above says which secret this is, so a restore can tell
before it starts whether this archive matches the database it is being restored
beside.

To restore: put secrets/ back at deploy/secrets/, bring the stack up, and
restore the database from a deploy/snapshot.sh archive.

local-ca.crt, if present, is the local CA's public root. Import it and a browser
stops warning about this deployment. It is public and safe to hand around.

THIS ARCHIVE IS THE KEY TO EVERY BANK CONNECTION. Encrypt it, and do not store
it next to a database snapshot: together they are the safe and its combination.

    age -p <this file>            # or: gpg -c <this file>
NOTE

archive="$destination/painfree-secrets-$stamp.tar.gz"
tar -C "$work" -czf "$archive" "painfree-secrets-$stamp"
chmod 600 "$archive"

cat >&2 <<NOTE

wrote $archive
      $(du -h "$archive" | cut -f1), mode 0600, custody key $key_id

Encrypt it and move it off this host. Then confirm it in the console, on
/ui/recovery, which is what unblocks generating a connection's first keys.
NOTE
