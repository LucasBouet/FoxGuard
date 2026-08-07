#!/usr/bin/env bash
#
# Foxguard backup.
#
# Produces one restricted-permission tarball holding everything that cannot be
# rebuilt from the repository:
#
#   * the PostgreSQL database  -- peers, accounts, ACLs, audit log
#   * /etc/foxguard/*.env      -- admin and agent tokens, database password
#   * the WireGuard interface's private key
#
# The policy export (GET /api/v1/policies/export) covers groups and ACL rules
# only. Everything else -- every peer's public key and tunnel address, every
# account's password hash and TOTP secret -- lives solely in the database. Lose
# it and every device needs re-registering, which means every client config
# changes.
#
# THE OUTPUT IS A CREDENTIAL. It contains the tokens that administer this
# gateway, the WireGuard private key that *is* this gateway's identity, and TOTP
# secrets in plaintext (they have to be usable to verify a code). Treat a backup
# file exactly as you would treat root on this box.
#
# Usage:
#   ./foxguard-backup.sh                      # -> /var/backups/foxguard
#   ./foxguard-backup.sh --dest /mnt/nas/fg --keep 30
#   ./foxguard-backup.sh --verify FILE        # check an archive without restoring
#
set -euo pipefail

DEST=/var/backups/foxguard
KEEP=14
CONFDIR=/etc/foxguard
VERIFY=""

if [[ -t 1 ]]; then G=$'\033[32m'; Y=$'\033[33m'; R=$'\033[31m'; B=$'\033[1m'; N=$'\033[0m'
else G=""; Y=""; R=""; B=""; N=""; fi
ok()   { printf '  %s✓%s %s\n' "$G" "$N" "$*"; }
warn() { printf '  %s!%s %s\n' "$Y" "$N" "$*"; }
die()  { printf '\n%sBackup failed:%s %s\n\n' "$R" "$N" "$*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case $1 in
    --dest)   DEST=$2; shift 2 ;;
    --keep)   KEEP=$2; shift 2 ;;
    --verify) VERIFY=$2; shift 2 ;;
    -h|--help) sed -n '3,26p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

# --------------------------------------------------------------------------- #
# verify mode
# --------------------------------------------------------------------------- #

if [[ -n $VERIFY ]]; then
  [[ -f $VERIFY ]] || die "$VERIFY does not exist."
  printf '\n%sVerifying %s%s\n' "$B" "$VERIFY" "$N"
  tar -tzf "$VERIFY" >/dev/null 2>&1 || die "the archive is not readable."
  ok "archive is intact"
  for want in database.sql backend.env agent.env; do
    tar -tzf "$VERIFY" | grep -q "$want" && ok "contains $want" || warn "missing $want"
  done
  # A dump that never reached its final COPY is worse than no dump: it restores
  # cleanly and silently drops rows.
  if tar -xzOf "$VERIFY" --wildcards '*/database.sql' 2>/dev/null | tail -5 | grep -q 'PostgreSQL database dump complete'; then
    ok "the database dump is complete"
  else
    die "the database dump is truncated — do not rely on this archive."
  fi
  ROWS=$(tar -xzOf "$VERIFY" --wildcards '*/database.sql' 2>/dev/null | grep -c '^COPY ' || true)
  ok "$ROWS table(s) in the dump"
  printf '\n%sUsable.%s\n\n' "$G" "$N"
  exit 0
fi

# --------------------------------------------------------------------------- #
# backup
# --------------------------------------------------------------------------- #

[[ $EUID -eq 0 ]] || die "run this as root — it reads $CONFDIR and the WireGuard key."
[[ -r $CONFDIR/backend.env ]] || die "cannot read $CONFDIR/backend.env"

# shellcheck disable=SC1090
set -a; . "$CONFDIR/backend.env"; set +a

# Named rather than left to `set -u`: a hand-written backend.env that leaves the
# URL out is a plausible thing to find, and "FOXGUARD_DATABASE_URL: unbound
# variable" does not tell whoever is holding a broken gateway which file to fix.
# shellcheck disable=SC2154  # comes from backend.env, sourced two lines up
: "${FOXGUARD_DATABASE_URL:?not set in $CONFDIR/backend.env — there is no database to back up}"
DB_NAME=${FOXGUARD_DATABASE_URL##*/}; DB_NAME=${DB_NAME%%\?*}
WG_IF=${FOXGUARD_WG_INTERFACE:-wg0}

STAMP=$(date +%Y%m%d-%H%M%S)
WORK=$(mktemp -d)
STAGE="$WORK/foxguard-$STAMP"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$STAGE"

printf '\n%sBacking up Foxguard%s\n' "$B" "$N"

# pg_dump as the postgres superuser: the foxguard role may not own everything,
# and a partial dump is the kind of thing you discover during a restore.
# shellcheck disable=SC2024  # the redirect is performed by root, which is us
sudo -u postgres pg_dump --format=plain --no-owner --no-privileges "$DB_NAME" \
  > "$STAGE/database.sql" 2>/dev/null || die "pg_dump of $DB_NAME failed."
tail -5 "$STAGE/database.sql" | grep -q 'PostgreSQL database dump complete' \
  || die "pg_dump produced a truncated file."
ok "database $DB_NAME dumped ($(du -h "$STAGE/database.sql" | cut -f1))"

for f in backend.env agent.env dashboard.env; do
  [[ -f $CONFDIR/$f ]] && { cp -a "$CONFDIR/$f" "$STAGE/"; ok "$f"; }
done

# The interface's private key is this gateway's identity: restore without it and
# every peer's config points at a server that can no longer decrypt them.
if [[ -f /etc/wireguard/${WG_IF}.conf ]]; then
  cp -a "/etc/wireguard/${WG_IF}.conf" "$STAGE/"
  ok "${WG_IF}.conf (contains the interface private key)"
else
  warn "/etc/wireguard/${WG_IF}.conf not found — back the interface key up yourself"
fi

# Handy for a human reading an old archive months later.
cat > "$STAGE/MANIFEST" <<EOF
Foxguard backup
taken       $(date -Iseconds)
host        $(hostname)
database    $DB_NAME
interface   $WG_IF
peers       $(sudo -u postgres psql -tAqc "SELECT count(*) FROM peers" "$DB_NAME" 2>/dev/null || echo '?')
accounts    $(sudo -u postgres psql -tAqc "SELECT count(*) FROM users" "$DB_NAME" 2>/dev/null || echo '?')
acl rules   $(sudo -u postgres psql -tAqc "SELECT count(*) FROM acl_rules" "$DB_NAME" 2>/dev/null || echo '?')

Restore: see docs/deployment.md, "Backup and restore".
This file's siblings include secrets. Keep the archive as protected as root.
EOF

install -d -m 0700 "$DEST"
ARCHIVE="$DEST/foxguard-$STAMP.tar.gz"
tar -czf "$ARCHIVE" -C "$WORK" "foxguard-$STAMP"
chmod 0600 "$ARCHIVE"
ok "written to $ARCHIVE ($(du -h "$ARCHIVE" | cut -f1), mode 0600)"

# Prove it before trusting it. A backup nobody has read back is a hope.
tar -tzf "$ARCHIVE" >/dev/null 2>&1 || die "the archive just written is unreadable."
ok "archive verified"

if [[ $KEEP -gt 0 ]]; then
  mapfile -t OLD < <(ls -1t "$DEST"/foxguard-*.tar.gz 2>/dev/null | tail -n +$((KEEP + 1)))
  if [[ ${#OLD[@]} -gt 0 ]]; then
    rm -f "${OLD[@]}"
    ok "pruned ${#OLD[@]} archive(s), keeping $KEEP"
  fi
fi

cat <<EOF

$Y This archive holds the admin and agent tokens, the database password, the
 WireGuard private key and TOTP secrets in plaintext. Copy it somewhere off
 this box, and protect it there as you protect root here.$N

EOF
