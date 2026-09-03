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
# This archive is the bank access. It carries the custody secret and the
# ciphertext that secret opens, together, which is the one combination that is
# never supposed to sit in one place unprotected -- so the encryption is not a
# step you remember afterwards, it is how the file is written:
#
#   deploy/snapshot.sh --encrypt-to age1… [destination]   # a public key
#   deploy/snapshot.sh --encrypt-to recipients.txt [dest] # or a file of them
#   deploy/snapshot.sh --passphrase [destination]         # prompts twice
#   deploy/snapshot.sh --plaintext [destination]          # deliberate, and said
#
# There is no default. A snapshot with no choice made refuses, because the
# failure it prevents is silent: an unencrypted archive works perfectly, and is
# indistinguishable from a good one until somebody else reads it.
#
# The tar is piped straight into `age` and never becomes a file, so the
# plaintext does not touch the disk even briefly -- it cannot be left behind by
# an interrupted run, and it cannot be recovered from free space afterwards.
#
#   destination defaults to ./backups
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

mode=""
recipient=""
while [ $# -gt 0 ]; do
    case $1 in
        --encrypt-to) mode=recipient; recipient=${2:?--encrypt-to needs a recipient or a file}; shift 2 ;;
        --passphrase) mode=passphrase; shift ;;
        --plaintext)  mode=plaintext;  shift ;;
        -h|--help)    sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        --*)          echo "unknown option: $1" >&2; exit 2 ;;
        *)            break ;;
    esac
done
destination=${1:-$root/backups}

if [ -z "$mode" ]; then
    cat >&2 <<'REFUSE'
snapshot.sh writes an archive containing the custody secret AND the database it
opens. Say how it should be protected -- there is no default, on purpose:

    deploy/snapshot.sh --encrypt-to age1…          a recipient's public key
    deploy/snapshot.sh --encrypt-to recipients.txt a file of public keys
    deploy/snapshot.sh --passphrase                a passphrase, typed twice
    deploy/snapshot.sh --plaintext                 no encryption, deliberately

`age-keygen -o key.age` makes a key pair; the line it prints as "public key" is
what --encrypt-to takes, and the file it writes is what decrypts. Keep that file
somewhere other than the machine being backed up -- a key stored beside its own
ciphertext protects nothing.

Without age installed, use --plaintext and encrypt it yourself:

    deploy/snapshot.sh --plaintext
    openssl enc -aes-256-ctr -pbkdf2 -iter 600000 -salt \
        -in backups/painfree-….tar.gz -out backups/painfree-….tar.gz.enc
    shred -u backups/painfree-….tar.gz

That leaves the plaintext on disk between the two commands, which is why it is
the fallback and not the recommendation.
REFUSE
    exit 2
fi

if [ "$mode" != "plaintext" ] && ! command -v age >/dev/null 2>&1; then
    echo "age is not installed, and --encrypt-to/--passphrase need it." >&2
    echo "Install it (apt install age, brew install age, nix profile install nixpkgs#age)" >&2
    echo "or run --plaintext and encrypt the result yourself; see --help." >&2
    exit 2
fi

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

# umask before the file exists, not chmod after it: between a create at 0644 and
# a chmod there is a window in which anything on the host can open it, and this
# is the file that is worth opening.
old_umask=$(umask)
umask 077

case $mode in
    recipient)
        # -R for a file of public keys, -r for one on the command line. A public
        # key is not secret, so passing it as an argument is fine -- unlike the
        # passphrase, which age reads from the terminal for that reason.
        archive="$archive.age"
        if [ -f "$recipient" ]; then
            tar -C "$work" -czf - "painfree-$stamp" | age -R "$recipient" > "$archive"
        else
            tar -C "$work" -czf - "painfree-$stamp" | age -r "$recipient" > "$archive"
        fi
        ;;
    passphrase)
        archive="$archive.age"
        tar -C "$work" -czf - "painfree-$stamp" | age -p > "$archive"
        ;;
    plaintext)
        tar -C "$work" -czf - "painfree-$stamp" > "$archive"
        ;;
esac
umask "$old_umask"

# `set -o pipefail` is on, so a failed tar or a failed age has already stopped
# the script -- but a zero-length archive is the shape a half-written one takes,
# and an operator who is told "wrote 0 B" and reads past it has no backup.
if [ ! -s "$archive" ]; then
    rm -f "$archive"
    echo "the archive came out empty; nothing was written" >&2
    exit 1
fi

cat >&2 <<NOTE

wrote $archive
      $(du -h "$archive" | cut -f1), mode 0600
NOTE

if [ "$mode" = "plaintext" ]; then
    cat >&2 <<NOTE
      NOT ENCRYPTED

This file contains the custody secret AND the database it opens. Anyone who
reads it has your bank access. Encrypt it before it is copied anywhere, and
remove the plaintext afterwards:

    openssl enc -aes-256-ctr -pbkdf2 -iter 600000 -salt \\
        -in $archive -out $archive.enc
    shred -u $archive
NOTE
fi

cat >&2 <<NOTE

To restore on another machine, on a host with podman and nothing else:

    age -d painfree-$stamp.tar.gz.age | tar xz     # or: tar xzf … if plaintext
    cd painfree-$stamp
    mkdir -p deploy && mv secrets deploy/secrets
    chmod 700 deploy/secrets && chmod 444 deploy/secrets/*
    podman-compose up -d
    deploy/restore.sh painfree.dump

The two chmods are not decoration. The secret files are bind-mounted into a
container that runs as an unprivileged uid of its own, so they have to be
readable by *other*; the 0700 directory is what keeps them private. A 0600 file
owned by you is a stack that restart-loops on "Permission denied".
NOTE
