#!/usr/bin/env bash
# Back up the half of a painfree deployment that lives in the database.
#
# There are two halves and this script can only take one of them:
#
#   1. the database volume — the sealed keys, the order history, the
#      idempotency ledger and the audit trail. That is what is dumped here.
#   2. deploy/secrets/custody_secret — the key those sealed rows are sealed
#      under. It is NOT in the dump, cannot be, and this script will not copy
#      it: a secret that travels with its own ciphertext is not a secret.
#
# The manifest written beside each dump records the custody key *id* — a hash,
# safe to store — so a restore can tell before it starts whether the secret on
# the host is the one this dump wants. That is the check that turns "restored,
# and nothing works" into a message naming both key ids.
#
#   deploy/backup.sh [destination-directory]     # default: ./backups
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
dump="$destination/painfree-$stamp.dump"

echo "dumping the painfree database…" >&2
# Custom format: restorable with --clean --if-exists into an existing cluster,
# and it carries the large binary columns without a text round trip.
# The password comes from the secret the db container already has mounted,
# read inside the container: it never passes through this shell, this script's
# environment, or the process list on the host.
$compose exec -T db sh -c \
    'PGPASSWORD=$(cat /run/secrets/painfree_db_password) \
     pg_dump -U painfree -d painfree -Fc' > "$dump"

# Which custody key the stored material is sealed under, asked of the database
# rather than of the configuration. `custody-status` holds no secret to answer.
status=$($compose exec -T worker python -m painfree custody-status 2>/dev/null \
         | grep '"event": *"custody.status"' | tail -1 || true)

checksum=$(sha256sum "$dump" | cut -d' ' -f1)
cat > "$dump.manifest.json" <<JSON
{
  "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "dump": "$(basename "$dump")",
  "sha256": "$checksum",
  "bytes": $(stat -c%s "$dump"),
  "custody_status": ${status:-null},
  "note": "The custody secret is NOT in this backup. Restoring this dump without deploy/secrets/custody_secret gives you unreadable ciphertext where the EBICS private keys were."
}
JSON

echo >&2
echo "wrote $dump" >&2
echo "      $dump.manifest.json" >&2
echo >&2
echo "The custody secret is not in it. Confirm your copy of" >&2
echo "deploy/secrets/custody_secret is somewhere this host cannot lose." >&2
