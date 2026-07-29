#!/usr/bin/env bash
#
# Foxguard installer.
#
# Installs the control plane, the captive portal, the admin dashboard and the
# gateway agent onto a Debian/Ubuntu box that is *already* running WireGuard.
#
# Two rules shape everything below:
#
#   1. It never applies an nftables ruleset. The agent does that, and this
#      script deliberately leaves it in dry-run mode so a human reads the rules
#      before anything reaches the kernel. Getting that wrong costs you your
#      remote access to this machine.
#
#   2. It refuses rather than guesses. No WireGuard interface, no netlink, a
#      config file already present with different values -- it stops and says
#      what it found, instead of doing something plausible.
#
# Re-running is safe: existing secrets are reused, not regenerated, so the agent
# does not lose its token halfway through an upgrade.
#
# Usage:
#   ./foxguard-install.sh --check-only          # preflight only, changes nothing
#   ./foxguard-install.sh                       # interactive install
#   ./foxguard-install.sh --yes --wan-interface eth0
#
set -euo pipefail

# --------------------------------------------------------------------------- #
# defaults
# --------------------------------------------------------------------------- #

PREFIX=/opt/foxguard
CONFDIR=/etc/foxguard
STATEDIR=/var/lib/foxguard
SERVICE_USER=foxguard

WG_IF=wg0
TUNNEL_IP=""          # detected from the WireGuard interface
POOL=""               # detected from the WireGuard interface
STAGING_POOL=""
WAN_IF=""
API_PORT=8080         # the portal lives here too, so it must be the portal port
DASHBOARD_PORT=3000
DB_NAME=foxguard
DB_USER=foxguard

SRC=""
ASSUME_YES=0
CHECK_ONLY=0
SKIP_FRONTEND=0
ADMIN_USER="admin"

# Creating the interface that carries your only remote access is opt-in, never
# implicit. Both of these default to off.
BOOTSTRAP_WG=0
LISTEN_PORT=51820
BOOTSTRAP_PEER=""
ENDPOINT=""
DEFAULT_POOL=10.88.0.0/24

# --------------------------------------------------------------------------- #
# output
# --------------------------------------------------------------------------- #

if [[ -t 1 ]]; then
  R=$'\033[31m'; G=$'\033[32m'; Y=$'\033[33m'; B=$'\033[1m'; N=$'\033[0m'
else
  R=""; G=""; Y=""; B=""; N=""
fi

step()  { printf '\n%s==> %s%s\n' "$B" "$*" "$N"; }
ok()    { printf '  %s✓%s %s\n' "$G" "$N" "$*"; }
warn()  { printf '  %s!%s %s\n' "$Y" "$N" "$*"; }
fail()  { printf '  %s✗%s %s\n' "$R" "$N" "$*"; }
die()   { printf '\n%sInstallation stopped:%s %s\n\n' "$R" "$N" "$*" >&2; exit 1; }

PREFLIGHT_FAILED=0
require() { # require <description> <command...>
  local desc=$1; shift
  if "$@" >/dev/null 2>&1; then ok "$desc"; else fail "$desc"; PREFLIGHT_FAILED=1; fi
}

confirm() {
  [[ $ASSUME_YES -eq 1 ]] && return 0
  local reply
  read -r -p "  ${1} [y/N] " reply
  [[ ${reply,,} == y || ${reply,,} == yes ]]
}

# --------------------------------------------------------------------------- #
# arguments
# --------------------------------------------------------------------------- #

usage() {
  sed -n '3,30p' "$0" | sed 's/^# \{0,1\}//'
  cat <<EOF

Options:
  --src DIR              Foxguard checkout (default: the parent of this script)
  --prefix DIR           Install prefix (default: $PREFIX)
  --wg-interface NAME    WireGuard interface (default: $WG_IF)
  --tunnel-ip ADDR       Bind address; detected from the interface if omitted
  --pool CIDR            Peer address pool; detected if omitted
  --staging-pool CIDR    Pool for peers that have not enrolled yet (optional)
  --wan-interface NAME   Required only if a group will use internet_exit
  --api-port PORT        API + captive portal (default: $API_PORT)
  --dashboard-port PORT  Admin dashboard (default: $DASHBOARD_PORT)
  --admin-user NAME      First administrator account (default: $ADMIN_USER)
  --skip-frontend        Do not build the portal or dashboard
  --check-only           Run the preflight checks and exit
  -y, --yes              Do not prompt
  -h, --help             This text

WireGuard bootstrap (opt-in — normally you bring the interface up yourself):
  --bootstrap-wireguard  Create \$WG_IF and its wg-quick unit if absent.
                         Refuses if the interface or its config already exists.
  --listen-port PORT     UDP port for the new interface (default: $LISTEN_PORT)
  --bootstrap-peer NAME  Also register a first device and print a ready client
                         config. Its private key is generated here and shown
                         once — acceptable for the laptop you set this up from,
                         not the habit for everything else.
  --endpoint HOST[:PORT] Public address peers dial, for the printed config.
EOF
}

while [[ $# -gt 0 ]]; do
  case $1 in
    --src)             SRC=$2; shift 2 ;;
    --prefix)          PREFIX=$2; shift 2 ;;
    --wg-interface)    WG_IF=$2; shift 2 ;;
    --tunnel-ip)       TUNNEL_IP=$2; shift 2 ;;
    --pool)            POOL=$2; shift 2 ;;
    --staging-pool)    STAGING_POOL=$2; shift 2 ;;
    --wan-interface)   WAN_IF=$2; shift 2 ;;
    --api-port)        API_PORT=$2; shift 2 ;;
    --dashboard-port)  DASHBOARD_PORT=$2; shift 2 ;;
    --admin-user)      ADMIN_USER=$2; shift 2 ;;
    --skip-frontend)   SKIP_FRONTEND=1; shift ;;
    --bootstrap-wireguard) BOOTSTRAP_WG=1; shift ;;
    --listen-port)     LISTEN_PORT=$2; shift 2 ;;
    --bootstrap-peer)  BOOTSTRAP_PEER=$2; shift 2 ;;
    --endpoint)        ENDPOINT=$2; shift 2 ;;
    --check-only)      CHECK_ONLY=1; shift ;;
    -y|--yes)          ASSUME_YES=1; shift ;;
    -h|--help)         usage; exit 0 ;;
    *)                 die "unknown option: $1 (try --help)" ;;
  esac
done

[[ -n $SRC ]] || SRC=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
[[ -n $BOOTSTRAP_PEER && $BOOTSTRAP_WG -eq 0 ]] && \
  die "--bootstrap-peer needs --bootstrap-wireguard (or an interface you brought up yourself, in which case register the peer from the dashboard)."

# --------------------------------------------------------------------------- #
# WireGuard bootstrap
# --------------------------------------------------------------------------- #

bootstrap_wireguard() {
  local conf=/etc/wireguard/${WG_IF}.conf

  # Never touch an existing interface or config. If either is there, the person
  # who made it had reasons, and clobbering the file that carries their remote
  # access is not a recoverable mistake.
  [[ -e $conf ]] && die "$conf already exists — refusing to overwrite it. Drop --bootstrap-wireguard."
  ip link show "$WG_IF" >/dev/null 2>&1 && \
    die "$WG_IF already exists — refusing to reconfigure it. Drop --bootstrap-wireguard."

  install -d -m 0700 /etc/wireguard
  ( umask 077
    wg genkey > "/etc/wireguard/${WG_IF}.private"
    wg pubkey < "/etc/wireguard/${WG_IF}.private" > "/etc/wireguard/${WG_IF}.public"

    # No [Peer] sections: those belong to Foxguard. The agent rewrites them from
    # the control plane and reads this [Interface] block back verbatim, so the
    # private key below never leaves this machine.
    cat > "$conf" <<WGEOF
# Created by foxguard-install.sh.
# Foxguard owns the [Peer] sections of this interface -- add devices through the
# dashboard, not here. A peer added by hand is removed on the agent's next sync.
[Interface]
Address = $TUNNEL_IP/${POOL##*/}
ListenPort = $LISTEN_PORT
PrivateKey = $(cat "/etc/wireguard/${WG_IF}.private")
WGEOF
  )
  chmod 600 "$conf"

  systemctl enable --now "wg-quick@${WG_IF}" >/dev/null 2>&1 \
    || die "wg-quick@${WG_IF} failed to start. Check: journalctl -u wg-quick@${WG_IF} -n 30"
  ip link show "$WG_IF" >/dev/null 2>&1 \
    || die "$WG_IF still does not exist after starting wg-quick."

  ok "created $WG_IF ($TUNNEL_IP/${POOL##*/}, udp/$LISTEN_PORT) and enabled wg-quick@${WG_IF}"
  warn "open udp/$LISTEN_PORT on your router towards this box, or nothing will reach it"
}

# --------------------------------------------------------------------------- #
# preflight
# --------------------------------------------------------------------------- #

step "Preflight"

[[ $EUID -eq 0 ]] || die "run this as root."

require "Debian or Ubuntu"            test -f /etc/debian_version
require "systemd is running"          test -d /run/systemd/system
require "Foxguard source at $SRC"     test -f "$SRC/backend/pyproject.toml"

# CAP_NET_ADMIN and netlink. Without these the agent cannot do its job, and
# finding that out after installing everything wastes an afternoon.
if command -v nft >/dev/null 2>&1 || [[ -x /usr/sbin/nft ]]; then
  NFT=$(command -v nft || echo /usr/sbin/nft)
  require "nftables usable (CAP_NET_ADMIN)" "$NFT" list ruleset
else
  warn "nftables not installed yet — will be installed, but its capability cannot be checked first"
fi

if command -v ip >/dev/null 2>&1; then
  if ip link add dev fgcheck0 type wireguard >/dev/null 2>&1; then
    ip link del fgcheck0 >/dev/null 2>&1 || true
    ok "WireGuard kernel support"
  else
    fail "cannot create a WireGuard interface — this LXC/VM lacks kernel support or CAP_NET_ADMIN"
    PREFLIGHT_FAILED=1
  fi

  # Foxguard manages peers on an interface it does not create. If it is not
  # there, the install would produce a control plane governing nothing -- unless
  # the operator explicitly asked for it to be created.
  if [[ $BOOTSTRAP_WG -eq 1 ]] && ! ip link show "$WG_IF" >/dev/null 2>&1; then
    [[ -n $POOL ]] || POOL=$DEFAULT_POOL
    [[ -n $TUNNEL_IP ]] || TUNNEL_IP=$(python3 - "$POOL" <<'PY'
import ipaddress, sys
print(next(ipaddress.ip_network(sys.argv[1]).hosts()))
PY
)
    if [[ $CHECK_ONLY -eq 1 ]]; then
      ok "would create $WG_IF as $TUNNEL_IP in $POOL on udp/$LISTEN_PORT"
    else
      command -v wg >/dev/null 2>&1 || {
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq && apt-get install -y -qq wireguard-tools
      }
      confirm "Create interface $WG_IF as $TUNNEL_IP in $POOL?" \
        || die "cancelled — bring $WG_IF up yourself and re-run without --bootstrap-wireguard."
      bootstrap_wireguard
    fi
  fi

  if ip link show "$WG_IF" >/dev/null 2>&1; then
    ok "interface $WG_IF exists"
    DETECTED_IP=$(ip -4 -o addr show dev "$WG_IF" 2>/dev/null | awk '{print $4}' | head -1)
    if [[ -n $DETECTED_IP ]]; then
      ok "$WG_IF carries $DETECTED_IP"
      [[ -n $TUNNEL_IP ]] || TUNNEL_IP=${DETECTED_IP%/*}
      [[ -n $POOL ]] || POOL=$(python3 - "$DETECTED_IP" <<'PY' 2>/dev/null || true
import ipaddress, sys
print(ipaddress.ip_interface(sys.argv[1]).network)
PY
)
    else
      fail "$WG_IF has no IPv4 address — bring it up before installing"
      PREFLIGHT_FAILED=1
    fi
    if command -v wg >/dev/null 2>&1; then
      peers=$(wg show "$WG_IF" peers 2>/dev/null | wc -l)
      if [[ $peers -gt 0 ]]; then
        ok "$WG_IF has $peers peer(s) configured"
      else
        warn "$WG_IF has no peers yet — reach the gateway through the tunnel from one device before going live"
      fi
    fi
  elif [[ $BOOTSTRAP_WG -eq 1 && $CHECK_ONLY -eq 1 ]]; then
    : # reported above as "would create"
  else
    fail "interface $WG_IF does not exist — bring it up yourself, or pass --bootstrap-wireguard"
    PREFLIGHT_FAILED=1
  fi
else
  fail "iproute2 (ip) is not installed"
  PREFLIGHT_FAILED=1
fi

# Binding to the WAN would expose the admin API and the portal to the internet.
if [[ -n $TUNNEL_IP ]] && ip link show "$WG_IF" >/dev/null 2>&1; then
  if ip -o addr show 2>/dev/null | grep -q " $WG_IF .*\b${TUNNEL_IP}/"; then
    ok "bind address $TUNNEL_IP belongs to $WG_IF"
  else
    fail "bind address $TUNNEL_IP is not on $WG_IF — refusing to bind the API somewhere else"
    PREFLIGHT_FAILED=1
  fi
fi

for port in "$API_PORT" "$DASHBOARD_PORT"; do
  if ss -ltn 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${port}\$"; then
    fail "port $port is already in use"
    PREFLIGHT_FAILED=1
  else
    ok "port $port is free"
  fi
done

# IP forwarding: without it the gateway filters traffic it never routes.
if [[ $(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null) == 1 ]]; then
  ok "IPv4 forwarding is on"
else
  warn "IPv4 forwarding is off — peers will not be able to route through this box"
fi

if [[ $PREFLIGHT_FAILED -eq 1 ]]; then
  die "preflight checks failed. Nothing has been changed."
fi

cat <<EOF

  source            $SRC
  prefix            $PREFIX
  interface         $WG_IF
  bind address      $TUNNEL_IP
  peer pool         ${POOL:-<unset>}
  staging pool      ${STAGING_POOL:-<same as peer pool>}
  wan interface     ${WAN_IF:-<none — internet_exit unavailable>}
  api + portal      https://$TUNNEL_IP:$API_PORT (http)
  dashboard         http://$TUNNEL_IP:$DASHBOARD_PORT
EOF

[[ -n $POOL ]] || die "could not determine the peer pool; pass --pool"

if [[ $CHECK_ONLY -eq 1 ]]; then
  printf '\n%sPreflight passed.%s Nothing was changed.\n\n' "$G" "$N"
  exit 0
fi

confirm "Proceed with the installation?" || die "cancelled."

# --------------------------------------------------------------------------- #
# packages
# --------------------------------------------------------------------------- #

step "Installing packages"

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
PACKAGES=(nftables wireguard-tools iproute2 postgresql python3 python3-venv python3-dev
          libpq-dev build-essential curl jq)
[[ $SKIP_FRONTEND -eq 0 ]] && PACKAGES+=(nodejs npm)
apt-get install -y -qq "${PACKAGES[@]}"
ok "packages installed"

systemctl enable --now postgresql >/dev/null 2>&1 || true
systemctl is-active --quiet postgresql || die "PostgreSQL did not start."
ok "PostgreSQL is running"

# --------------------------------------------------------------------------- #
# user, directories, source
# --------------------------------------------------------------------------- #

step "Preparing $PREFIX"

id -u "$SERVICE_USER" >/dev/null 2>&1 || \
  useradd --system --home "$PREFIX" --shell /usr/sbin/nologin "$SERVICE_USER"
ok "service user $SERVICE_USER"

install -d -m 0750 "$PREFIX" "$CONFDIR"
install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_USER" "$STATEDIR"

if [[ $(readlink -f "$SRC") != $(readlink -f "$PREFIX/src") ]]; then
  install -d -m 0755 "$PREFIX/src"
  # -a keeps timestamps so pip and next can skip unchanged work on a re-run.
  cp -a "$SRC/." "$PREFIX/src/"
  ok "source copied to $PREFIX/src"
else
  ok "source already at $PREFIX/src"
fi
SRC="$PREFIX/src"

python3 -m venv "$PREFIX/venv" 2>/dev/null || true
"$PREFIX/venv/bin/pip" install -q --upgrade pip
"$PREFIX/venv/bin/pip" install -q -e "$SRC/backend" -e "$SRC/agent"
ok "Python packages installed"

# --------------------------------------------------------------------------- #
# secrets and configuration
# --------------------------------------------------------------------------- #

step "Configuration"

gen() { "$PREFIX/venv/bin/python" -c 'import secrets; print(secrets.token_urlsafe(32))'; }

# Re-running must not rotate secrets: the agent holds its token in a separate
# file and would silently stop reconciling.
read_existing() { # read_existing <file> <key>
  [[ -f $1 ]] && sed -n "s/^$2=//p" "$1" | head -1 || true
}

ADMIN_TOKEN=$(read_existing "$CONFDIR/backend.env" FOXGUARD_ADMIN_API_TOKEN)
AGENT_TOKEN=$(read_existing "$CONFDIR/backend.env" FOXGUARD_AGENT_API_TOKEN)
DB_PASS=$(read_existing "$CONFDIR/backend.env" FOXGUARD_DB_PASSWORD)

if [[ -z $ADMIN_TOKEN ]]; then
  ADMIN_TOKEN=$(gen); AGENT_TOKEN=$(gen); DB_PASS=$(gen)
  ok "generated new secrets"
else
  ok "reusing the existing secrets"
fi
[[ $ADMIN_TOKEN != "$AGENT_TOKEN" ]] || die "admin and agent tokens are identical; fix $CONFDIR/backend.env"

# PostgreSQL role and database, idempotently.
sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='$DB_USER'" | grep -q 1 || \
  sudo -u postgres psql -qc "CREATE ROLE $DB_USER LOGIN PASSWORD '$DB_PASS'"
sudo -u postgres psql -qc "ALTER ROLE $DB_USER PASSWORD '$DB_PASS'"

# The encoding is spelled out rather than inherited, and that is not pedantry.
# On a minimal LXC with no locale configured, initdb creates the cluster as
# SQL_ASCII; a database inheriting that makes psycopg return *bytes* for text
# columns, and the first thing SQLAlchemy does with a new connection is run a
# regex over the server version string. It fails with
# "cannot use a string pattern on a bytes-like object" before a single query of
# ours runs. template0 is the only template that allows overriding the encoding.
if ! sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='$DB_NAME'" | grep -q 1; then
  sudo -u postgres createdb -O "$DB_USER" \
    --template=template0 --encoding=UTF8 --lc-collate=C.UTF-8 --lc-ctype=C.UTF-8 \
    "$DB_NAME" \
    || die "could not create the database with UTF8 encoding."
  ok "database $DB_NAME created (UTF8)"
else
  ENC=$(sudo -u postgres psql -tAc \
        "SELECT pg_encoding_to_char(encoding) FROM pg_database WHERE datname='$DB_NAME'")
  if [[ $ENC == UTF8 ]]; then
    ok "database $DB_NAME ready (UTF8)"
  else
    die "database $DB_NAME exists with encoding $ENC, which psycopg cannot use.
  Foxguard needs UTF8. If the database is empty, recreate it:

    sudo -u postgres dropdb $DB_NAME
    sudo -u postgres createdb -O $DB_USER --template=template0 --encoding=UTF8 \\
      --lc-collate=C.UTF-8 --lc-ctype=C.UTF-8 $DB_NAME

  If it already holds data, dump it, recreate as above, and restore."
  fi
fi

[[ -f $CONFDIR/backend.env ]] && cp -a "$CONFDIR/backend.env" "$CONFDIR/backend.env.bak"

umask 077
cat > "$CONFDIR/backend.env" <<EOF
# Written by foxguard-install.sh. Mode 0600: this file is a credential.
FOXGUARD_DEV_MODE=false
FOXGUARD_LOG_LEVEL=INFO

FOXGUARD_DB_PASSWORD=$DB_PASS
FOXGUARD_DATABASE_URL=postgresql+psycopg://$DB_USER:$DB_PASS@127.0.0.1:5432/$DB_NAME

# For machines only. People sign in at /api/v1/admin/login, which is what makes
# the audit log name them; actions taken with this token are logged as
# 'admin-token'. Remove it once nothing automated calls the API.
FOXGUARD_ADMIN_API_TOKEN=$ADMIN_TOKEN
FOXGUARD_AGENT_API_TOKEN=$AGENT_TOKEN
FOXGUARD_ADMIN_SESSION_LIFETIME_SECONDS=43200

FOXGUARD_WG_INTERFACE=$WG_IF
FOXGUARD_WG_POOL_V4=$POOL
$( [[ -n $STAGING_POOL ]] && echo "FOXGUARD_WG_STAGING_POOL_V4=$STAGING_POOL" )
FOXGUARD_WG_GATEWAY_IP=$TUNNEL_IP

$( [[ -n $WAN_IF ]] && echo "FOXGUARD_WAN_INTERFACE=$WAN_IF" )
FOXGUARD_PORTAL_PORT=$API_PORT
FOXGUARD_INTERNAL_CIDRS=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
FOXGUARD_GATEWAY_INPUT_POLICY=open
FOXGUARD_LOG_DROPPED=true

FOXGUARD_DEFAULT_SESSION_LIFETIME_SECONDS=28800
FOXGUARD_SESSION_SWEEP_ENABLED=true
FOXGUARD_SESSION_SWEEP_INTERVAL_SECONDS=60

$( [[ $SKIP_FRONTEND -eq 0 ]] && echo "FOXGUARD_PORTAL_STATIC_DIR=$SRC/frontend/portal/out" )
EOF
chmod 0600 "$CONFDIR/backend.env"

cat > "$CONFDIR/agent.env" <<EOF
# Written by foxguard-install.sh. Mode 0600.
FOXGUARD_AGENT_API_URL=http://$TUNNEL_IP:$API_PORT
FOXGUARD_AGENT_API_TOKEN=$AGENT_TOKEN
FOXGUARD_AGENT_POLL_INTERVAL_SECONDS=10
FOXGUARD_AGENT_STATE_DIR=$STATEDIR
FOXGUARD_AGENT_LOG_LEVEL=INFO

# Left ON by this installer, on purpose. In dry run the agent fetches the
# ruleset and validates it with 'nft -c -f' but applies nothing. Read the rules,
# then set this to false and restart. See docs/deployment.md section 4.
FOXGUARD_AGENT_DRY_RUN=true
EOF
chmod 0600 "$CONFDIR/agent.env"

cat > "$CONFDIR/dashboard.env" <<EOF
# Written by foxguard-install.sh. Mode 0600.
FOXGUARD_API_URL=http://$TUNNEL_IP:$API_PORT
# Fallback until an administrator account exists and signs in.
FOXGUARD_ADMIN_API_TOKEN=$ADMIN_TOKEN
EOF
chmod 0600 "$CONFDIR/dashboard.env"
umask 022
ok "configuration written to $CONFDIR (mode 0600)"

# --------------------------------------------------------------------------- #
# database schema
# --------------------------------------------------------------------------- #

step "Database schema"

( cd "$SRC/backend" && set -a && . "$CONFDIR/backend.env" && set +a && \
  "$PREFIX/venv/bin/alembic" upgrade head >/dev/null )
ok "migrations applied"

# --------------------------------------------------------------------------- #
# frontends
# --------------------------------------------------------------------------- #

if [[ $SKIP_FRONTEND -eq 0 ]]; then
  step "Building the portal and the dashboard"
  ( cd "$SRC/frontend/portal" && npm ci --silent && npm run build --silent >/dev/null )
  ok "captive portal built (served by the API itself)"
  ( cd "$SRC/frontend/admin" && npm ci --silent && npm run build --silent >/dev/null )
  ok "admin dashboard built"
fi

chown -R "$SERVICE_USER:$SERVICE_USER" "$PREFIX"

# --------------------------------------------------------------------------- #
# services
# --------------------------------------------------------------------------- #

step "Installing services"

render_unit() { # render_unit <source> <dest>
  sed -e "s|/opt/foxguard|$PREFIX|g" \
      -e "s|--host 10.88.0.1 --port 8080|--host $TUNNEL_IP --port $API_PORT|" \
      -e "s|--hostname 10.88.0.1 --port 3000|--hostname $TUNNEL_IP --port $DASHBOARD_PORT|" \
      "$1" > "$2"
}

render_unit "$SRC/backend/systemd/foxguard-api.service"  /etc/systemd/system/foxguard-api.service
render_unit "$SRC/agent/systemd/foxguard-agent.service"  /etc/systemd/system/foxguard-agent.service
[[ $SKIP_FRONTEND -eq 0 ]] && \
  render_unit "$SRC/frontend/admin/systemd/foxguard-dashboard.service" \
              /etc/systemd/system/foxguard-dashboard.service
sed -i "s|wg-quick@wg0.service|wg-quick@$WG_IF.service|" /etc/systemd/system/foxguard-agent.service

systemctl daemon-reload
systemctl enable --now foxguard-api >/dev/null 2>&1
ok "foxguard-api enabled"

for _ in $(seq 1 40); do
  curl -sf "http://$TUNNEL_IP:$API_PORT/healthz" >/dev/null 2>&1 && break
  sleep 0.5
done
curl -sf "http://$TUNNEL_IP:$API_PORT/healthz" >/dev/null 2>&1 \
  || die "the API did not come up. Check: journalctl -u foxguard-api -n 50"
ok "API answering on http://$TUNNEL_IP:$API_PORT"

if [[ $SKIP_FRONTEND -eq 0 ]]; then
  systemctl enable --now foxguard-dashboard >/dev/null 2>&1
  ok "foxguard-dashboard enabled"
fi

# The agent is installed but NOT started. It is the only component that can
# change what this machine forwards, and it should not do so before a human has
# read the rules it intends to apply.
systemctl enable foxguard-agent >/dev/null 2>&1
ok "foxguard-agent installed, left stopped and in dry-run"

# --------------------------------------------------------------------------- #
# first administrator
# --------------------------------------------------------------------------- #

step "First administrator"

ADMIN_PASS=""
EXISTING=$(curl -sf -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://$TUNNEL_IP:$API_PORT/api/v1/users" | jq -r '[.[] | select(.is_admin)] | length' 2>/dev/null || echo 0)

if [[ ${EXISTING:-0} -gt 0 ]]; then
  ok "an administrator account already exists"
else
  ADMIN_PASS=$("$PREFIX/venv/bin/python" -c 'import secrets; print(secrets.token_urlsafe(18))')
  if curl -sf -X POST "http://$TUNNEL_IP:$API_PORT/api/v1/users" \
      -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
      -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\",\"is_admin\":true}" >/dev/null; then
    ok "created administrator '$ADMIN_USER'"
  else
    warn "could not create the administrator account — create one by hand"
    ADMIN_PASS=""
  fi
fi

# --------------------------------------------------------------------------- #
# first device
# --------------------------------------------------------------------------- #

CLIENT_CONF=""
if [[ -n $BOOTSTRAP_PEER ]]; then
  step "First device"

  # Registering it here rather than adding a [Peer] by hand is the point: a peer
  # the control plane does not know about is removed on the agent's first sync.
  CLIENT_PRIV=$(wg genkey)
  CLIENT_PUB=$(printf '%s' "$CLIENT_PRIV" | wg pubkey)

  ADMIN_ID=$(curl -sf -H "Authorization: Bearer $ADMIN_TOKEN" \
    "http://$TUNNEL_IP:$API_PORT/api/v1/users" \
    | jq -r --arg u "$ADMIN_USER" '.[] | select(.username==$u) | .id' 2>/dev/null || true)

  if [[ -n ${ADMIN_ID:-} ]]; then
    PEER_JSON=$(curl -sf -X POST "http://$TUNNEL_IP:$API_PORT/api/v1/peers" \
      -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
      -d "{\"name\":\"$BOOTSTRAP_PEER\",\"peer_type\":\"user\",\"wg_public_key\":\"$CLIENT_PUB\",\"owner_user_id\":\"$ADMIN_ID\",\"tags\":[\"bootstrap\"]}" || true)
    PEER_IP=$(printf '%s' "$PEER_JSON" | jq -r '.tunnel_ip // empty' 2>/dev/null || true)
  fi

  if [[ -n ${PEER_IP:-} ]]; then
    ok "registered '$BOOTSTRAP_PEER' at $PEER_IP, owned by $ADMIN_USER"
    SERVER_PUB=$(cat "/etc/wireguard/${WG_IF}.public" 2>/dev/null || wg show "$WG_IF" public-key)
    CLIENT_CONF=$(cat <<EOF
[Interface]
PrivateKey = $CLIENT_PRIV
Address = $PEER_IP/32

[Peer]
PublicKey = $SERVER_PUB
Endpoint = ${ENDPOINT:-<your-public-address>:$LISTEN_PORT}
AllowedIPs = $POOL
PersistentKeepalive = 25
EOF
)
  else
    warn "could not register the device — add it from the dashboard instead"
  fi
fi

# --------------------------------------------------------------------------- #
# what happens next
# --------------------------------------------------------------------------- #

cat <<EOF

$B────────────────────────────────────────────────────────────────$N
$G Installed.$N The dataplane is $B not$N live yet — that is deliberate.

$B1. Read the ruleset Foxguard wants to apply$N

   curl -s http://$TUNNEL_IP:$API_PORT/api/v1/ruleset/preview \\
     -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r .content

   Three things to confirm before going further:
     • 'iifname != "$WG_IF" accept' is the FIRST rule of chain input
       — this is what keeps your SSH alive.
     • both base chains say 'policy accept'.
     • the only delete statement is 'delete table inet foxguard'.

$B2. Watch the agent validate it without applying anything$N

   systemctl start foxguard-agent && journalctl -u foxguard-agent -f
   # expect: "dry run: ruleset <digest> validated, not applied"

$B3. Go live — keep a Proxmox console open$N

   sed -i 's/^FOXGUARD_AGENT_DRY_RUN=true/FOXGUARD_AGENT_DRY_RUN=false/' $CONFDIR/agent.env
   systemctl restart foxguard-agent
   nft list table inet foxguard      # ours
   nft list ruleset | grep -c table  # your other tables are still there

   If it goes wrong: systemctl stop foxguard-agent && nft delete table inet foxguard
   The tunnel keeps working — removing the filter table does not touch WireGuard.

$B4. Verify$N

   $SRC/deploy/foxguard-healthcheck.sh

EOF

if [[ -n $ADMIN_PASS || -n $CLIENT_CONF ]]; then
  printf '%s────────────────────────────────────────────────────────────────%s\n' "$B" "$N"
  printf '%s Shown once. Nothing below is stored anywhere you can read it back.%s\n' "$Y" "$N"
fi

if [[ -n $ADMIN_PASS ]]; then
  cat <<EOF

 $B Dashboard $N  http://$TUNNEL_IP:$DASHBOARD_PORT
   username    $ADMIN_USER
   password    $ADMIN_PASS

 Sign in, then enable TOTP on the account (Accounts → Manage). Until you
 sign in, the dashboard acts as 'admin-token' and the audit log cannot
 name you.
EOF
fi

if [[ -n $CLIENT_CONF ]]; then
  cat <<EOF

 $B Client config for '$BOOTSTRAP_PEER' $N — save as $BOOTSTRAP_PEER.conf

$CLIENT_CONF

 Its private key was generated on this gateway, which is a fair trade for
 the laptop you are setting up from and a bad habit for everything else:
 generate the keypair on the device and register only the public key.
$( [[ -z $ENDPOINT ]] && echo " Replace <your-public-address> with what your router forwards udp/$LISTEN_PORT to." )

 This device lands in quarantine, as every user peer does. Connect the
 tunnel, open http://$TUNNEL_IP:$API_PORT/ and sign in as $ADMIN_USER to
 leave it.
EOF
fi

if [[ -n $ADMIN_PASS || -n $CLIENT_CONF ]]; then
  printf '%s────────────────────────────────────────────────────────────────%s\n\n' "$B" "$N"
fi
