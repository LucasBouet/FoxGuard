#!/usr/bin/env bash
#
# Foxguard uninstaller.
#
# Removes what foxguard-install.sh created, and nothing else. Three things are
# opt-in, because each one can take something down that Foxguard did not put
# there:
#
#   --remove-wireguard   tears down the tunnel interface and deletes its keys.
#                        If you reached this box through that tunnel, this is
#                        the command that ends the session.
#   --remove-packages    purges apt packages. PostgreSQL takes every database on
#                        the machine with it, not just Foxguard's.
#   --remove-database    drops the database and role. A dump is taken first.
#
# By default it stops the services, removes the nftables table, deletes the
# install and its configuration, and leaves the tunnel, the packages and the
# database alone.
#
# Usage:
#   ./foxguard-uninstall.sh --dry-run           # print the plan, change nothing
#   ./foxguard-uninstall.sh                     # interactive
#   ./foxguard-uninstall.sh --yes --remove-database
#   ./foxguard-uninstall.sh --yes --remove-database --remove-wireguard --remove-packages
#
set -euo pipefail

# --------------------------------------------------------------------------- #
# defaults
# --------------------------------------------------------------------------- #

PREFIX=${PREFIX:-/opt/foxguard}
CONFDIR=${CONFDIR:-/etc/foxguard}
STATEDIR=${STATEDIR:-/var/lib/foxguard}
UNITDIR=${UNITDIR:-/etc/systemd/system}
WGDIR=${WGDIR:-/etc/wireguard}
SERVICE_USER=${SERVICE_USER:-foxguard}
DB_NAME=${DB_NAME:-foxguard}
DB_USER=${DB_USER:-foxguard}
BACKUP_DIR=${BACKUP_DIR:-/root}

ASSUME_YES=0
DRY_RUN=0
REMOVE_WG=0
REMOVE_PACKAGES=0
REMOVE_DATABASE=0

# Agent first: it is what writes the nft table, the DNS zone and the routes, so
# stopping anything else before it just gives it a chance to put them back.
UNITS=(foxguard-agent foxguard-dns foxguard-proxy foxguard-dashboard foxguard-api)

# What the installer apt-installs and what is safe to purge afterwards.
#
# python3, curl and iproute2 are installed by foxguard-install.sh and are
# deliberately NOT here. On Debian, apt's own tooling pulls in python3, and
# iproute2 is how the box configures its networking -- removing either to tidy
# up after Foxguard trades a clean uninstall for an unbootable-ish machine.
# They were almost certainly present before Foxguard anyway.
REMOVABLE=(nftables wireguard-tools postgresql python3-venv python3-dev
           libpq-dev build-essential jq nodejs npm dnsmasq-base haproxy
           certbot python3-certbot-dns-cloudflare socat)
NEVER_REMOVE=(python3 curl iproute2)

# --------------------------------------------------------------------------- #
# output
# --------------------------------------------------------------------------- #

if [[ -t 1 ]]; then
  R=$'\033[31m'; G=$'\033[32m'; Y=$'\033[33m'; B=$'\033[1m'; N=$'\033[0m'
else
  R=""; G=""; Y=""; B=""; N=""
fi

step() { printf '\n%s==> %s%s\n' "$B" "$*" "$N"; }
ok()   { printf '  %s✓%s %s\n' "$G" "$N" "$*"; }
warn() { printf '  %s!%s %s\n' "$Y" "$N" "$*"; }
skip() { printf '  %s·%s %s\n' "$Y" "$N" "$*"; }
die()  { printf '\n%sUninstall stopped:%s %s\n\n' "$R" "$N" "$*" >&2; exit 1; }

confirm() {
  [[ $ASSUME_YES -eq 1 ]] && return 0
  local reply
  read -r -p "  ${1} [y/N] " reply </dev/tty || die "no terminal to prompt on; pass --yes"
  # ${reply,,} is compared against a bare "y", and a console that sends CRLF --
  # Proxmox noVNC, a serial line, some SSH clients -- makes reply $'y\r', which
  # matches nothing. The prompt then cancels an installation the operator just
  # agreed to. Strip it rather than trusting the terminal.
  reply=${reply//$'\r'/}
  [[ ${reply,,} == y || ${reply,,} == yes ]]
}

# Every mutation goes through this, so --dry-run is honest by construction
# rather than by remembering to check a flag at each call site.
run() {
  if [[ $DRY_RUN -eq 1 ]]; then
    printf '  %swould run:%s %s\n' "$Y" "$N" "$*"
    return 0
  fi
  "$@"
}

# Says a thing was done. Silent under --dry-run, where `run` has already said
# what it *would* do -- a dry run that also prints "✓ removed /etc/foxguard" is
# worse than no dry run at all.
did() { [[ $DRY_RUN -eq 1 ]] || ok "$*"; }

# Nothing below is allowed to abort the run.
#
# `set -e` plus a step that can fail for reasons unrelated to Foxguard -- a
# daemon-reload on a box whose systemd is not reachable, a DROP DATABASE with a
# session still attached -- stops the uninstall halfway and leaves a machine
# with its unit files deleted and its install directory still there. Worse than
# either finishing or not starting. So every failure is collected and reported
# at the end, and the exit code says whether anything was left behind.
PROBLEMS=()
DB_DROPPED=0
attempt() { # attempt <what it did> <command...>
  local desc=$1; shift
  if run "$@"; then
    did "$desc"
  else
    warn "could not: $desc"
    PROBLEMS+=("$desc")
  fi
}

# --------------------------------------------------------------------------- #
# arguments
# --------------------------------------------------------------------------- #

usage() {
  sed -n '3,25p' "$0" | sed 's/^# \{0,1\}//'
  cat <<EOF

Options:
  --dry-run              Print what would happen. Changes nothing.
  --yes                  Do not prompt.
  --remove-database      Drop the '$DB_NAME' database and the '$DB_USER' role
                         (a dump is written to $BACKUP_DIR first).
  --remove-wireguard     Tear down the tunnel and delete its keys.
  --remove-packages      Purge apt packages Foxguard installed.
  --prefix DIR           Install prefix (default: $PREFIX)
  -h, --help             This.

EOF
  exit 0
}

while [[ $# -gt 0 ]]; do
  case $1 in
    --dry-run)          DRY_RUN=1; shift ;;
    --yes|-y)           ASSUME_YES=1; shift ;;
    --remove-database)  REMOVE_DATABASE=1; shift ;;
    --remove-wireguard) REMOVE_WG=1; shift ;;
    --remove-packages)  REMOVE_PACKAGES=1; shift ;;
    --prefix)           PREFIX=$2; shift 2 ;;
    -h|--help)          usage ;;
    *)                  die "unknown option: $1 (try --help)" ;;
  esac
done

[[ $EUID -eq 0 || $DRY_RUN -eq 1 ]] || die "run this as root."

# --------------------------------------------------------------------------- #
# what is actually here
#
# Read before anything is touched, so the plan below describes the machine as it
# is rather than as the defaults assume.
# --------------------------------------------------------------------------- #

NFT_TABLE=foxguard
WG_IF=wg0
if [[ -r $CONFDIR/backend.env ]]; then
  NFT_TABLE=$(sed -n 's/^FOXGUARD_NFT_TABLE_NAME=//p' "$CONFDIR/backend.env" | head -1)
  WG_IF=$(sed -n 's/^FOXGUARD_WG_INTERFACE=//p' "$CONFDIR/backend.env" | head -1)
  NFT_TABLE=${NFT_TABLE:-foxguard}
  WG_IF=${WG_IF:-wg0}
fi

NFT=$(command -v nft || echo /usr/sbin/nft)
FOUND=0
for probe in "$PREFIX" "$CONFDIR" "$STATEDIR" "$UNITDIR/foxguard-api.service"; do
  [[ -e $probe ]] && FOUND=1
done

cat <<EOF

  ${B}Foxguard uninstall${N}

  prefix            $PREFIX
  configuration     $CONFDIR
  state             $STATEDIR
  service user      $SERVICE_USER
  nftables table    inet $NFT_TABLE
  units             ${UNITS[*]}

  database          $(if [[ $REMOVE_DATABASE -eq 1 ]]; then printf '%sDROP %s (dump first)%s' "$R" "$DB_NAME" "$N"; else printf 'kept — pass --remove-database to drop it'; fi)
  wireguard         $(if [[ $REMOVE_WG -eq 1 ]]; then printf '%sTEAR DOWN %s and delete its keys%s' "$R" "$WG_IF" "$N"; else printf 'kept — pass --remove-wireguard to remove it'; fi)
  packages          $(if [[ $REMOVE_PACKAGES -eq 1 ]]; then printf '%sPURGE%s (confirmed separately)' "$R" "$N"; else printf 'kept — pass --remove-packages to purge them'; fi)
$( [[ $DRY_RUN -eq 1 ]] && printf '\n  %sDRY RUN — nothing will be changed.%s\n' "$Y" "$N" )
EOF

if [[ $FOUND -eq 0 ]]; then
  warn "no Foxguard install found under $PREFIX / $CONFDIR"
  # The opt-in removals live outside the install directories, so a half-cleaned
  # box -- files gone, database still there -- must still be finishable.
  if [[ $REMOVE_PACKAGES -eq 0 && $REMOVE_WG -eq 0 && $REMOVE_DATABASE -eq 0 ]]; then
    warn "nothing to remove"
    exit 0
  fi
  warn "continuing for the --remove-* flags you passed"
fi

if [[ $REMOVE_WG -eq 1 ]]; then
  printf '\n  %sRemoving %s ends every tunnel session, including yours if you\n  reached this box through it.%s\n' "$R" "$WG_IF" "$N"
fi

confirm "Proceed?" || die "cancelled. Nothing was changed."

# --------------------------------------------------------------------------- #
# 1. services
#
# The agent goes first: it is the only thing that writes the nftables table, and
# stopping it after the flush would just let it put the table back.
# --------------------------------------------------------------------------- #

step "Stopping services"

# The unit file on disk is the signal, not `systemctl list-unit-files`: on a box
# where systemd is not reachable (a chroot, a container) the query fails and
# every unit would be reported as absent while its file sits right there.
for unit in "${UNITS[@]}"; do
  if [[ -e $UNITDIR/$unit.service ]]; then
    run systemctl disable --now "$unit" 2>/dev/null || true
    did "$unit stopped and disabled"
  else
    skip "$unit is not installed"
  fi
done

# --------------------------------------------------------------------------- #
# 2. the dataplane
#
# nftables rules are not persistent, so a reboot would clear this anyway -- but
# leaving a live table that nothing maintains is how a box ends up filtering
# traffic according to a policy no longer stored anywhere.
# --------------------------------------------------------------------------- #

step "Removing the nftables table"

if "$NFT" list table inet "$NFT_TABLE" >/dev/null 2>&1; then
  attempt "deleted table inet $NFT_TABLE" "$NFT" delete table inet "$NFT_TABLE"
else
  skip "table inet $NFT_TABLE is not loaded"
fi

# --------------------------------------------------------------------------- #
# 3. the database
# --------------------------------------------------------------------------- #

step "Database"

if [[ $REMOVE_DATABASE -eq 0 ]]; then
  skip "keeping database '$DB_NAME' and role '$DB_USER'"
elif ! command -v psql >/dev/null; then
  skip "psql is not available — nothing to drop"
else
  if sudo -u postgres psql -tAc \
       "SELECT 1 FROM pg_database WHERE datname='$DB_NAME'" 2>/dev/null | grep -q 1; then
    # Taken before the drop, not offered afterwards. An uninstall is exactly
    # when someone discovers they wanted the audit log.
    dump="$BACKUP_DIR/foxguard-final-$(date +%Y%m%d%H%M%S).sql.gz"
    if [[ $DRY_RUN -eq 1 ]]; then
      printf '  %swould run:%s pg_dump %s > %s\n' "$Y" "$N" "$DB_NAME" "$dump"
    else
      ( umask 077; sudo -u postgres pg_dump "$DB_NAME" | gzip > "$dump" )
      [[ -s $dump ]] || die "the dump came out empty; refusing to drop $DB_NAME"
      ok "dumped to $dump ($(du -h "$dump" | cut -f1))"
    fi
    if run sudo -u postgres psql -qc "DROP DATABASE $DB_NAME"; then
      did "dropped database $DB_NAME"; DB_DROPPED=1
    else
      warn "could not: dropped database $DB_NAME"
      PROBLEMS+=("dropped database $DB_NAME")
    fi
  else
    skip "database $DB_NAME does not exist"
  fi

  if sudo -u postgres psql -tAc \
       "SELECT 1 FROM pg_roles WHERE rolname='$DB_USER'" 2>/dev/null | grep -q 1; then
    attempt "dropped role $DB_USER" \
      sudo -u postgres psql -qc "DROP ROLE $DB_USER"
  else
    skip "role $DB_USER does not exist"
  fi
fi

# --------------------------------------------------------------------------- #
# 4. kernel routes the agent installed
#
# Not opt-in, and not left behind either: these point into a tunnel interface
# whose peers nothing manages any more, so leaving them is leaving a black hole
# in the routing table. Only the ones recorded in the state file are removed --
# the same rule the agent itself follows, so a route an operator added by hand
# to the same network survives.
# --------------------------------------------------------------------------- #

step "Kernel routes"

ROUTES_FILE=$STATEDIR/routes.json
if [[ ! -f $ROUTES_FILE ]]; then
  skip "no routes recorded in $ROUTES_FILE"
elif ! command -v jq >/dev/null; then
  warn "jq is gone, so $ROUTES_FILE cannot be read; remove its routes by hand:"
  warn "  ip route show dev $WG_IF"
  PROBLEMS+=("removed the routes listed in $ROUTES_FILE")
else
  mapfile -t recorded < <(jq -r '.[]?' "$ROUTES_FILE" 2>/dev/null)
  if [[ ${#recorded[@]} -eq 0 ]]; then
    skip "no routes recorded in $ROUTES_FILE"
  fi
  for cidr in "${recorded[@]}"; do
    [[ -n $cidr ]] || continue
    family=-4; [[ $cidr == *:* ]] && family=-6
    if ip "$family" route show exact "$cidr" 2>/dev/null | grep -q .; then
      attempt "removed route $cidr" ip "$family" route del "$cidr" dev "$WG_IF"
    else
      skip "route $cidr is already gone"
    fi
  done
fi

# --------------------------------------------------------------------------- #
# 5. units, files, user
# --------------------------------------------------------------------------- #

step "Removing files"

for unit in "${UNITS[@]}"; do
  if [[ -e $UNITDIR/$unit.service ]]; then
    attempt "removed $UNITDIR/$unit.service" rm -f "$UNITDIR/$unit.service"
  fi
done
run systemctl daemon-reload 2>/dev/null || true
run systemctl reset-failed 2>/dev/null || true

# Certificate private keys before the directory containing them.
#
# `rm -rf` unlinks; it does not overwrite. The wildcard key here covers the
# whole domain, which makes it the highest-value secret on this box, and a
# recovered one lets somebody impersonate every service the domain names.
if [[ -d $CONFDIR/proxy/certs ]]; then
  if command -v shred >/dev/null 2>&1; then
    while IFS= read -r pem; do
      attempt "shredded $(basename "$pem")" shred -u "$pem"
    done < <(find "$CONFDIR/proxy/certs" -type f -name '*.pem' 2>/dev/null)
  else
    warn "shred is not available: certificate keys are only unlinked, not overwritten"
  fi
fi
if [[ -e /usr/local/bin/foxguard-cert-deploy ]]; then
  attempt "removed the certbot deploy hook" rm -f /usr/local/bin/foxguard-cert-deploy
fi
# The Let's Encrypt lineage is deliberately left alone: certbot owns
# /etc/letsencrypt, other things on this box may use the same certificate, and
# re-issuing after an accidental deletion runs into rate limits.
[[ -d /etc/letsencrypt/live ]] && \
  skip "/etc/letsencrypt is certbot's -- remove the lineage yourself if you want it gone"

for dir in "$PREFIX" "$STATEDIR" "$CONFDIR"; do
  if [[ -d $dir ]]; then
    attempt "removed $dir" rm -rf "$dir"
  else
    skip "$dir does not exist"
  fi
done

if id -u "$SERVICE_USER" >/dev/null 2>&1; then
  attempt "removed service user $SERVICE_USER" userdel "$SERVICE_USER"
else
  skip "no service user $SERVICE_USER"
fi

# --------------------------------------------------------------------------- #
# 6. WireGuard (opt-in)
# --------------------------------------------------------------------------- #

step "WireGuard"

if [[ $REMOVE_WG -eq 0 ]]; then
  skip "keeping $WG_IF, $WGDIR/$WG_IF.conf and its keys"
  warn "the tunnel still works, but nothing manages its peers now"
else
  if systemctl is-enabled "wg-quick@$WG_IF" >/dev/null 2>&1 || \
     ip link show "$WG_IF" >/dev/null 2>&1; then
    run systemctl disable --now "wg-quick@$WG_IF" 2>/dev/null || true
    if ip link show "$WG_IF" >/dev/null 2>&1; then
      attempt "$WG_IF is down" ip link delete "$WG_IF"
    else
      did "$WG_IF is down"
    fi
  else
    skip "$WG_IF is not up"
  fi
  for f in "$WGDIR/$WG_IF.conf" "$WGDIR/$WG_IF.private" "$WGDIR/$WG_IF.public"; do
    [[ -e $f ]] || continue
    attempt "removed $f" rm -f "$f"
  done
fi

# --------------------------------------------------------------------------- #
# 7. packages (opt-in)
#
# Simulated first and shown in full. apt is allowed to have the last word: if
# purging these would cascade into something else, that is exactly the thing
# worth seeing before it happens rather than after.
# --------------------------------------------------------------------------- #

step "Packages"

if [[ $REMOVE_PACKAGES -eq 0 ]]; then
  skip "keeping every apt package"
elif ! command -v apt-get >/dev/null; then
  skip "apt-get not found — this is not a Debian/Ubuntu box"
else
  present=()
  for pkg in "${REMOVABLE[@]}"; do
    dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "^install ok installed" \
      && present+=("$pkg")
  done

  if [[ ${#present[@]} -eq 0 ]]; then
    skip "none of the removable packages are installed"
  else
    printf '  never touched: %s\n' "${NEVER_REMOVE[*]}"
    printf '  asked for:     %s\n\n' "${present[*]}"

    # apt has the last word, and it is asked before anything is purged rather
    # than reported after. Naming ten packages routinely uninstalls several
    # hundred -- `nodejs` alone drags the whole node-* tree with it -- and that
    # cascade is the thing worth seeing while it is still a question.
    plan=$(apt-get -s purge "${present[@]}" 2>&1 || true)
    if grep -qi 'essential packages will be removed' <<<"$plan"; then
      warn "apt says this would remove ESSENTIAL packages. Refusing."
      printf '%s\n' "$plan" | grep -i -A3 essential | sed 's/^/    /'
      die "package removal aborted; everything else was uninstalled."
    fi

    total=$(sed -n 's/.*, \([0-9]*\) to remove.*/\1/p' <<<"$plan" | head -1)
    printf '  %sapt would remove %s package(s):%s\n' "$B" "${total:-?}" "$N"
    sed -n '/packages will be REMOVED/,/^[A-Z0-9]/p' <<<"$plan" \
      | sed '1d;$d' | sed 's/^/    /' | head -8
    if [[ ${total:-0} -gt 40 ]]; then
      printf '    %s… see the full list with:%s apt-get -s purge %s\n' \
        "$Y" "$N" "${present[*]}"
    fi
    printf '\n'

    if [[ " ${present[*]} " == *" postgresql "* ]]; then
      printf '  %sPurging postgresql destroys EVERY database on this machine,%s\n' "$R" "$N"
      printf '  %snot only Foxguard'"'"'s.%s\n\n' "$R" "$N"
    fi

    if confirm "Purge these packages?"; then
      attempt "purged ${#present[@]} package(s)" apt-get purge -y "${present[@]}"
      run apt-get autoremove -y --purge || true
    else
      skip "packages kept"
    fi
  fi
fi

# --------------------------------------------------------------------------- #

printf '\n%s────────────────────────────────────────────────────────────────%s\n' "$B" "$N"

if [[ $DRY_RUN -eq 1 ]]; then
  printf '%s Dry run finished.%s Nothing was changed.\n\n' "$Y" "$N"
  exit 0
fi

if [[ ${#PROBLEMS[@]} -gt 0 ]]; then
  printf '%s Foxguard mostly removed — %d step(s) failed:%s\n\n' "$Y" "${#PROBLEMS[@]}" "$N"
  printf '   • %s\n' "${PROBLEMS[@]}"
  printf '\n  Everything else was removed. Re-running is safe: each step checks\n'
  printf '  whether its target is still there.\n\n'
else
  printf '%s Foxguard removed.%s\n\n' "$G" "$N"
fi

[[ $REMOVE_DATABASE -eq 0 ]] && \
  printf '  Left behind: database '"'"'%s'"'"' and role '"'"'%s'"'"'.\n' "$DB_NAME" "$DB_USER"
[[ $REMOVE_WG -eq 0 ]] && \
  printf '  Left behind: %s and %s/%s.conf — peers are no longer managed.\n' "$WG_IF" "$WGDIR" "$WG_IF"
[[ $REMOVE_PACKAGES -eq 0 ]] && \
  printf '  Left behind: apt packages.\n'

printf '\n  Client .conf files on other machines still exist and are now dead\n'
printf '  keys. Nothing on this box can revoke them because the database that\n'
printf '  described them is %s.\n\n' \
  "$(if [[ $DB_DROPPED -eq 1 ]]; then echo gone; else echo orphaned; fi)"

exit $(( ${#PROBLEMS[@]} > 0 ? 1 : 0 ))
