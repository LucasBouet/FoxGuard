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
# If you would rather be asked than remember flags, ./foxguard-setup.sh walks
# through the same options as questions and then calls this script.
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

# Internal DNS is opt-in: it puts a resolver on the gateway, which is a service
# nobody asked for by installing an access-control system.
DNS_ENABLED=0
DNS_ZONE="fox.internal"
DNS_MODE="forward"
DNS_UPSTREAMS=""
PROXY_ENABLED=0
PROXY_DOMAIN=""
PROXY_EXTERNAL_BINDS=""
ACME_EMAIL=""
ACME_CF_TOKEN=""
SSO_ENABLED=0

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
# Plain indented text, for the multi-line instructions that follow an ok/warn.
say()   { printf '  %s\n' "$*"; }
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
  # ${reply,,} is compared against a bare "y", and a console that sends CRLF --
  # Proxmox noVNC, a serial line, some SSH clients -- makes reply $'y\r', which
  # matches nothing. The prompt then cancels an installation the operator just
  # agreed to. Strip it rather than trusting the terminal.
  reply=${reply//$'\r'/}
  [[ ${reply,,} == y || ${reply,,} == yes ]]
}

# --------------------------------------------------------------------------- #
# client configuration
#
# The dashboard's generator is the reference implementation. It asks
# GET /peers/{id}/config-profile what belongs around the key -- addresses,
# resolver, AllowedIPs, MTU, keepalive -- and assembles the file in the browser.
# This script asks the same endpoint the same question, so --bootstrap-peer
# hands out the same configuration the dashboard would, rather than the subset
# somebody once typed into a heredoc here. That subset is how a device ends up
# with no DNS line on a deployment that runs a resolver, and with the pool on
# its AllowedIPs but none of the zone routes.
#
# Rendering the file a second time, in jq, is duplication and it is deliberate.
# The API returns structured data and never finished text -- that is what makes
# it impossible for a future caller to POST a private key up and ask the server
# to "just do it" -- so the cost is one renderer wherever a config is actually
# assembled. deploy/tests/test-client-config.sh pins this one to the browser's
# (frontend/admin/src/lib/wg-config.ts) so the two cannot drift apart quietly.
# --------------------------------------------------------------------------- #

render_client_config() { # render_client_config <profile-json> <private-key> <endpoint-fallback>
  # Placeholders, where the dashboard refuses outright: it can offer a button
  # again once the operator fixes the setting, while this runs once and a
  # nearly-complete file with an obvious gap in it beats no file at all on a
  # terminal that is about to scroll away.
  jq -r --arg key "$2" --arg fallback "$3" '
    def kv($k; $v): "\($k) = \($v)";
    [
      "# \(.peer_name)" + (if .fqdn then " (\(.fqdn))" else "" end),
      "# Written by foxguard-install.sh. This private key was generated on the",
      "# gateway; every config the dashboard makes generates it in the browser",
      "# instead, and never sends it anywhere.",
      "[Interface]",
      kv("PrivateKey"; $key),
      kv("Address"; (.addresses | join(", ")))
    ]
    + (if (.dns | length) > 0 then [kv("DNS"; (.dns | join(", ")))] else [] end)
    + (if .mtu then [kv("MTU"; (.mtu | tostring))] else [] end)
    + [
      "",
      "[Peer]",
      kv("PublicKey"; (.server_public_key // "<gateway-public-key>")),
      kv("Endpoint"; (.endpoint // $fallback)),
      kv("AllowedIPs"; (.allowed_ips | join(", ")))
    ]
    + (if .persistent_keepalive > 0
       then [kv("PersistentKeepalive"; (.persistent_keepalive | tostring))]
       else [] end)
    | join("\n")
  ' <<<"$1"
}

config_file_name() { # config_file_name <profile-json>
  # wg-quick takes the interface name from the file name: at most 15 characters
  # of [a-zA-Z0-9_=+.-], and it refuses anything else outright. The mobile apps
  # enforce the same rule on import, so "Ada's MacBook (2019).conf" is a file
  # every client rejects while its owner concludes the config is broken.
  local source cleaned
  source=$(jq -r '((.fqdn // "" | split(".") | .[0]) // "") as $label
                  | if $label == "" then .peer_name else $label end' <<<"$1")
  cleaned=$(printf '%s' "$source" | iconv -f utf-8 -t ascii//TRANSLIT 2>/dev/null \
            || printf '%s' "$source")
  cleaned=$(printf '%s' "$cleaned" \
            | sed -e 's/[^a-zA-Z0-9_=+.-]/-/g' -e 's/-\{2,\}/-/g' -e 's/^[-.]*//')
  cleaned=${cleaned:0:15}
  cleaned=$(printf '%s' "$cleaned" | sed -e 's/[-.]*$//')
  printf '%s.conf' "${cleaned:-foxguard}"
}

# Sourcing this file with FOXGUARD_INSTALL_SOURCE_ONLY=1 defines the two
# functions above and stops before anything is parsed, checked or installed. It
# is how deploy/tests/test-client-config.sh gets at the renderer, and it is the
# only reason this early return exists.
[[ -n ${FOXGUARD_INSTALL_SOURCE_ONLY:-} ]] && return 0

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
  --staging-pool CIDR    Separate pool for newly registered peers. Usually skip
                         this: addresses are permanent, so it does not mark
                         confinement, and it must be a SUBNET of --pool or peers
                         end up unroutable.
  --wan-interface NAME   Required only if a group will use internet_exit
  --api-port PORT        API + captive portal (default: $API_PORT)
  --dashboard-port PORT  Admin dashboard (default: $DASHBOARD_PORT)
  --admin-user NAME      First administrator account (default: $ADMIN_USER)
  --skip-frontend        Do not build the portal or dashboard
  --check-only           Run the preflight checks and exit

Client configurations (the dashboard builds them; the keypair is made in the
operator's browser and no private key ever reaches this box):
  --endpoint HOST[:PORT] Public address peers dial — what your router forwards
                         udp/$LISTEN_PORT to. Without it the generator reports
                         every configuration as incomplete rather than handing
                         out one that cannot connect. Valid on its own; it does
                         not require --bootstrap-wireguard.

Internal DNS (opt-in — a resolver on the gateway, for the tunnel only):
  --dns                  Install dnsmasq and serve names for peers and zones
  --dns-zone NAME        Zone every device lives in (default: $DNS_ZONE)
  --dns-mode MODE        forward (resolve everything, send the rest upstream)
                         or split (answer for the zone, REFUSE the rest). split
                         only works if clients are configured to send just
                         in-zone queries here. Default: $DNS_MODE
  --dns-upstream ADDR    Upstream resolver, repeatable. Forward mode only.

Reverse proxy (opt-in — publishes services that live behind peers):
  --proxy                Install HAProxy and serve published services
  --proxy-domain DOMAIN  Real domain services get names under, e.g. example.com.
                         Required: peer names live on the DNS zone, but a
                         service needs a name a public CA will sign, and
                         .internal never can be.
  --proxy-external IP    WAN address the external listener binds, repeatable.
                         Omit it and only the tunnel-side listener exists.
  --acme-email ADDR      Contact address for Let's Encrypt. Enables certbot.
  --sso                  Single sign-on for published services: a Foxguard
                         login page, a signed cookie every service accepts, and
                         revocation that takes effect immediately. Generates the
                         signing secret.
  --acme-cf-token TOKEN  Cloudflare API token for the DNS-01 challenge. Use a
                         token scoped to Zone:DNS:Edit on that one zone, never
                         the global API key: the wildcard it obtains covers the
                         whole domain.
  -y, --yes              Do not prompt
  -h, --help             This text

WireGuard bootstrap (opt-in — normally you bring the interface up yourself):
  --bootstrap-wireguard  Create \$WG_IF and its wg-quick unit if absent.
                         Refuses if the interface or its config already exists.
  --listen-port PORT     UDP port for the new interface (default: $LISTEN_PORT)
  --bootstrap-peer NAME  Also register a first device and print a ready client
                         config — built from the same API the dashboard's
                         generator uses, so it carries the resolver, the search
                         domain and the zone routes rather than the pool alone.
                         Its private key is generated here and shown once —
                         acceptable for the laptop you set this up from, not
                         the habit for everything else. Every device after it
                         should come from the dashboard's config generator,
                         which never puts a private key on this machine.
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
    --dns)             DNS_ENABLED=1; shift ;;
    --dns-zone)        DNS_ZONE=$2; DNS_ENABLED=1; shift 2 ;;
    --dns-mode)        DNS_MODE=$2; DNS_ENABLED=1; shift 2 ;;
    --dns-upstream)    DNS_UPSTREAMS="${DNS_UPSTREAMS:+$DNS_UPSTREAMS,}$2"; DNS_ENABLED=1; shift 2 ;;
    --proxy)           PROXY_ENABLED=1; shift ;;
    --proxy-domain)    PROXY_DOMAIN=$2; PROXY_ENABLED=1; shift 2 ;;
    --proxy-external)  PROXY_EXTERNAL_BINDS="${PROXY_EXTERNAL_BINDS:+$PROXY_EXTERNAL_BINDS,}$2"; PROXY_ENABLED=1; shift 2 ;;
    --sso)             SSO_ENABLED=1; PROXY_ENABLED=1; shift ;;
    --acme-email)      ACME_EMAIL=$2; shift 2 ;;
    --acme-cf-token)   ACME_CF_TOKEN=$2; shift 2 ;;
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

# Port 53. Checked separately from the two above because it is normal for
# something to already hold it -- systemd-resolved holds it on most desktops --
# and because the check has to be per address, not global: Foxguard's resolver
# binds only $TUNNEL_IP, so a stub listener on 127.0.0.53 is not a conflict.
if [[ $DNS_ENABLED -eq 1 ]]; then
  if [[ -z $TUNNEL_IP ]]; then
    # Without a bind address the match below would degenerate to ":53" and
    # report free for a resolver that will collide. Say so instead of guessing.
    warn "cannot check udp/53 yet: no tunnel address (the interface is missing above)"
  elif ss -lun 2>/dev/null | awk 'NR>1 {print $4}' \
       | grep -qE "^(${TUNNEL_IP//./\\.}|0\.0\.0\.0|\[?::\]?|\*):53\$"; then
    fail "udp/53 on $TUNNEL_IP is already taken -- stop that resolver, or bind it"
    fail "to its own address (systemd-resolved: DNSStubListener=no)"
    PREFLIGHT_FAILED=1
  else
    ok "udp/53 on $TUNNEL_IP is free"
  fi
  case $DNS_MODE in
    forward|split) ok "DNS mode $DNS_MODE, zone $DNS_ZONE" ;;
    *) fail "--dns-mode must be 'forward' or 'split', got $DNS_MODE"; PREFLIGHT_FAILED=1 ;;
  esac
  if [[ $DNS_MODE == split && -n $DNS_UPSTREAMS ]]; then
    warn "--dns-upstream is ignored in split mode: it has no upstream by design"
  fi
  # .local is mDNS. Serving it here fights with Avahi/Bonjour on every client.
  [[ $DNS_ZONE == *.local ]] && warn "$DNS_ZONE ends in .local, which is mDNS territory -- expect clients to resolve it inconsistently"
fi

if [[ $PROXY_ENABLED -eq 1 ]]; then
  if [[ -z $PROXY_DOMAIN ]]; then
    fail "--proxy needs --proxy-domain: services need a name a public CA will sign"
    PREFLIGHT_FAILED=1
  else
    ok "proxy domain $PROXY_DOMAIN"
  fi
  # The internal zone must not swallow the certificate domain. In split mode
  # dnsmasq answers NXDOMAIN for anything in-zone it does not know, which
  # includes _acme-challenge, and certbot's propagation check would fail.
  if [[ $DNS_ENABLED -eq 1 && $DNS_MODE == split && $PROXY_DOMAIN == *"$DNS_ZONE" ]]; then
    fail "the DNS zone $DNS_ZONE covers the proxy domain $PROXY_DOMAIN, and in"
    fail "split mode that makes the resolver answer NXDOMAIN for _acme-challenge"
    PREFLIGHT_FAILED=1
  fi
  # A listener can only bind an address the kernel already has. Behind NAT the
  # public address is on the router, and giving it here passes every other
  # check and then fails at HAProxy start-up with EADDRNOTAVAIL -- which is the
  # least useful moment to find out.
  PROXY_LOCAL_BINDS=""
  for addr in ${PROXY_EXTERNAL_BINDS//,/ }; do
    if ip -o addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | grep -qx "$addr"; then
      ok "$addr is on this box"
      PROXY_LOCAL_BINDS="${PROXY_LOCAL_BINDS:+$PROXY_LOCAL_BINDS }$addr"
    else
      fail "no interface here carries $addr -- that looks like a public address."
      fail "Bind this box's own address and forward tcp/80 and tcp/443 to it."
      PREFLIGHT_FAILED=1
    fi
  done

  # Only for addresses that exist: "the ports are free on 203.0.113.10" is not
  # a useful thing to say about an address this box does not have.
  # Column 4 of `ss -ltn` is the local address:port. Not 5 -- that is Peer.
  PROXY_PORTS_FREE=1
  for port in 80 443; do
    for addr in $PROXY_LOCAL_BINDS; do
      if ss -ltn 2>/dev/null | awk 'NR>1 {print $4}' | grep -qE "(^|[^0-9.])($addr|0\.0\.0\.0|\[::\]):$port$"; then
        fail "tcp/$port on $addr is already taken -- stop that service first"
        PREFLIGHT_FAILED=1
        PROXY_PORTS_FREE=0
      fi
    done
  done
  [[ -n $PROXY_LOCAL_BINDS && $PROXY_PORTS_FREE -eq 1 ]] && \
    ok "tcp/80 and tcp/443 free on $PROXY_LOCAL_BINDS"
  if [[ -n $ACME_EMAIL && -z $ACME_CF_TOKEN ]]; then
    warn "--acme-email without --acme-cf-token: certbot is installed but no"
    warn "certificate is requested, and the proxy runs on a self-signed one"
  fi
  if [[ $SSO_ENABLED -eq 1 && -z $PROXY_DOMAIN ]]; then
    fail "--sso needs --proxy-domain: the login page lives at auth.<domain>"
    PREFLIGHT_FAILED=1
  elif [[ $SSO_ENABLED -eq 1 ]]; then
    ok "single sign-on, login page at auth.$PROXY_DOMAIN"
  fi
  if [[ -n $PROXY_EXTERNAL_BINDS && -z $ACME_EMAIL ]]; then
    warn "external exposure without ACME: browsers will refuse the self-signed"
    warn "bootstrap certificate until you obtain a real one"
  fi
fi

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

# This script gives the interface the pool's own prefix (Address = $TUNNEL_IP/${POOL##*/}),
# so here -- unlike in the API, which may not even run on this box -- "inside the
# pool" and "reachable through the tunnel" are the same statement, and a hard
# error is warranted. wg syncconf adds no routes, so a peer outside that prefix
# gets its replies sent out of the default route: the handshake succeeds and
# nothing else does. Caught now rather than at first boot.
if [[ -n $STAGING_POOL ]]; then
  if python3 - "$STAGING_POOL" "$POOL" <<'PY'
import ipaddress, sys
sys.exit(0 if ipaddress.ip_network(sys.argv[1]).subnet_of(ipaddress.ip_network(sys.argv[2])) else 1)
PY
  then
    ok "staging pool $STAGING_POOL is inside $POOL"
  else
    die "--staging-pool $STAGING_POOL is not inside --pool $POOL.
  Peers there would be unroutable: wg syncconf adds no routes, so the only route
  to the tunnel is the one the interface address implies. Either widen --pool, or
  drop --staging-pool entirely -- addresses never change after registration, so a
  separate range buys nothing."
  fi
fi

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
# Generated once and written to backend.env. Rotating it signs everyone out,
# which is why it is not derived from anything that might change.
SSO_SECRET=""
# shellcheck disable=SC2034  # used inside the backend.env heredoc below
[[ $SSO_ENABLED -eq 1 ]] && SSO_SECRET=$(openssl rand -base64 48 | tr -d '\n')

PACKAGES=(nftables wireguard-tools iproute2 postgresql python3 python3-venv python3-dev
          libpq-dev build-essential curl jq)
[[ $SKIP_FRONTEND -eq 0 ]] && PACKAGES+=(nodejs npm)
# dnsmasq-base, not dnsmasq: the full package ships an /etc/dnsmasq.conf and a
# system unit that would bind :53 itself and fight with the instance Foxguard
# runs on its own configuration file.
[[ $DNS_ENABLED -eq 1 ]] && PACKAGES+=(dnsmasq-base)
# haproxy, plus certbot and the Cloudflare DNS-01 plugin. DNS-01 rather than
# HTTP-01 because HTTP-01 needs every name to resolve publicly to this box,
# which would force public records for internal-only services.
[[ $PROXY_ENABLED -eq 1 ]] && PACKAGES+=(haproxy openssl)
[[ -n $ACME_EMAIL ]] && PACKAGES+=(certbot python3-certbot-dns-cloudflare)
# socat: the deploy hook talks to HAProxy's runtime socket to load a renewed
# certificate without a reload, so a passthrough session is never dropped.
[[ -n $ACME_CF_TOKEN ]] && PACKAGES+=(socat)
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

# $PREFIX stays root-owned and world-readable, and $STATEDIR root-owned.
#
# Not laziness -- the alternative breaks the agent. Its unit hardens root down
# to CAP_NET_ADMIN/CAP_NET_RAW, which drops CAP_DAC_OVERRIDE with everything
# else, so root stops being able to ignore file permissions. A prefix owned by
# `foxguard` with mode 0750 is then unreadable to it: not the owner, not in the
# group, and "other" has no bits. The agent dies with a permission error on its
# own executable.
#
# Nothing secret lives here: credentials are in $CONFDIR at 0600. The API and
# the dashboard run as $SERVICE_USER and only need to read.
install -d -m 0755 "$PREFIX"
# 0751, not 0750: dnsmasq drops privileges at startup and re-reads its hosts
# file *as the unprivileged user*, so every directory on the way to
# $CONFDIR/dns must be traversable by "other". Without the x bit the daemon
# starts, serves the forward path, and answers NXDOMAIN for the whole zone --
# with one line in its log and nothing wrong anywhere else.
#
# Traversable is not readable: there is no o+r, so nothing can list this
# directory, and the credentials in it are 0600 root besides.
install -d -m 0751 "$CONFDIR"
install -d -m 0750 "$STATEDIR"

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

# Repair, not just prevent. The block above keeps a *fresh* prefix readable, but
# an existing one may have been laid down by an older installer that chowned it
# to the service user, or by a pip run under a restrictive umask. Either way the
# agent dies on its own executable with EACCES -- as root, which is the part
# that sends people looking in the wrong place for hours.
#
# Only read and traverse bits are added, and no ownership is touched: the
# dashboard's .next cache has to stay writable by $SERVICE_USER. Nothing secret
# lives under $PREFIX; the credentials are in $CONFDIR at 0600.
chmod -R a+rX "$PREFIX"
ok "$PREFIX readable by the agent (root without CAP_DAC_OVERRIDE)"

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

# The gateway's own public key, for the config generator. Either source is
# fine: --bootstrap-wireguard writes the .public file, and an interface that
# was already there answers `wg show`. Neither existing is not an error -- the
# dashboard says which variable is missing and the operator fills it in.
GW_PUBKEY=$(cat "/etc/wireguard/${WG_IF}.public" 2>/dev/null \
  || wg show "$WG_IF" public-key 2>/dev/null || true)
GW_PUBKEY=${GW_PUBKEY//[$'\t\r\n ']/}

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
FOXGUARD_WG_LISTEN_PORT=$LISTEN_PORT

# What the dashboard's config generator puts in a client file. Without both of
# these it can still be used, but it reports every configuration as incomplete
# rather than handing out one that cannot connect.
$( [[ -n $GW_PUBKEY ]] && echo "FOXGUARD_WG_PUBLIC_KEY=$GW_PUBKEY" || echo "# FOXGUARD_WG_PUBLIC_KEY=  # wg show $WG_IF public-key" )
$( [[ -n $ENDPOINT ]] && echo "FOXGUARD_WG_ENDPOINT_HOST=$ENDPOINT" || echo "# FOXGUARD_WG_ENDPOINT_HOST=  # what your router forwards udp/$LISTEN_PORT to" )
FOXGUARD_CLIENT_CONFIG_ALLOWED_IPS=routed
FOXGUARD_CLIENT_CONFIG_KEEPALIVE=25

$( [[ -n $WAN_IF ]] && echo "FOXGUARD_WAN_INTERFACE=$WAN_IF" )
FOXGUARD_PORTAL_PORT=$API_PORT
FOXGUARD_INTERNAL_CIDRS=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
FOXGUARD_GATEWAY_INPUT_POLICY=open
FOXGUARD_LOG_DROPPED=true

$( [[ $DNS_ENABLED -eq 1 ]] && cat <<DNSEOF
FOXGUARD_DNS_ENABLED=true
FOXGUARD_DNS_ZONE=$DNS_ZONE
FOXGUARD_DNS_MODE=$DNS_MODE
FOXGUARD_DNS_GATEWAY_LABEL=gw
# Tunnel addresses only. A WAN address here publishes an open resolver.
FOXGUARD_DNS_LISTEN_ADDRESSES=$TUNNEL_IP
FOXGUARD_DNS_UPSTREAMS=$DNS_UPSTREAMS
FOXGUARD_DNS_HOSTS_PATH=$CONFDIR/dns/hosts
FOXGUARD_DNS_CONF_PATH=$CONFDIR/dns/dnsmasq.conf
DNSEOF
)

$( [[ $PROXY_ENABLED -eq 1 ]] && cat <<PROXYEOF
FOXGUARD_PROXY_ENABLED=true
FOXGUARD_PROXY_DOMAIN=$PROXY_DOMAIN
# Tunnel address only. This is the one listener on which a source address is an
# identity, and binding it anywhere else would hand out that identity to
# packets that prove nothing.
FOXGUARD_PROXY_INTERNAL_BINDS=$TUNNEL_IP
FOXGUARD_PROXY_EXTERNAL_BINDS=$PROXY_EXTERNAL_BINDS
FOXGUARD_PROXY_CONF_PATH=$CONFDIR/proxy/haproxy.cfg
FOXGUARD_PROXY_MAPS_DIR=$CONFDIR/proxy/maps
FOXGUARD_PROXY_CERTS_DIR=$CONFDIR/proxy/certs
$( [[ $SSO_ENABLED -eq 1 ]] && printf 'FOXGUARD_PROXY_SSO_SECRET=%s\n' "$SSO_SECRET" )
PROXYEOF
)

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

# Dry run covers routes too: the agent reports what it would install and
# touches the routing table only once you turn it off.
FOXGUARD_AGENT_MANAGE_ROUTES=true
FOXGUARD_AGENT_MANAGE_DNS=$( [[ $DNS_ENABLED -eq 1 ]] && echo true || echo false )
FOXGUARD_AGENT_DNS_DIR=$CONFDIR/dns
FOXGUARD_AGENT_MANAGE_PROXY=$( [[ $PROXY_ENABLED -eq 1 ]] && echo true || echo false )
FOXGUARD_AGENT_PROXY_DIR=$CONFDIR/proxy
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

# Only what a service actually writes changes hands. `next start` keeps a cache
# under .next/; everything else is read-only to the service user.
if [[ $SKIP_FRONTEND -eq 0 && -d $SRC/frontend/admin/.next ]]; then
  chown -R "$SERVICE_USER:$SERVICE_USER" "$SRC/frontend/admin/.next"
fi

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
if [[ $DNS_ENABLED -eq 1 ]]; then
  # The zone itself is written by the agent on its first poll. The directory has
  # to exist first, and world-traversable: dnsmasq drops privileges at startup
  # and re-reads the hosts file as an unprivileged user, so 0700 here produces a
  # resolver that works until its first reload and then serves nothing.
  install -d -m 0755 "$CONFDIR/dns"
  render_unit "$SRC/agent/systemd/foxguard-dns.service" /etc/systemd/system/foxguard-dns.service
  sed -i "s|/etc/foxguard/dns|$CONFDIR/dns|g; s|wg-quick@wg0.service|wg-quick@$WG_IF.service|" \
      /etc/systemd/system/foxguard-dns.service
  ok "foxguard-dns unit installed (started by the agent once it has a zone)"
fi
if [[ $PROXY_ENABLED -eq 1 ]]; then
  # 0750: unlike dnsmasq, HAProxy reads its configuration, pattern files and
  # certificates *before* dropping privileges, so nothing here needs to be
  # world-readable. The private key in certs/ especially.
  install -d -m 0750 "$CONFDIR/proxy" "$CONFDIR/proxy/maps" "$CONFDIR/proxy/certs"
  # HAProxy refuses to start with an empty `crt` directory, and the agent cannot
  # write a certificate. A self-signed one lets the proxy come up before ACME
  # has ever run; certbot's deploy hook replaces it.
  if ! compgen -G "$CONFDIR/proxy/certs/*.pem" >/dev/null; then
    openssl req -x509 -newkey rsa:2048 -nodes -days 90 \
      -subj "/CN=${PROXY_DOMAIN:-foxguard.invalid}" \
      -addext "subjectAltName=DNS:${PROXY_DOMAIN:-foxguard.invalid},DNS:*.${PROXY_DOMAIN:-foxguard.invalid}" \
      -keyout /tmp/fg-boot.key -out /tmp/fg-boot.crt >/dev/null 2>&1
    cat /tmp/fg-boot.crt /tmp/fg-boot.key > "$CONFDIR/proxy/certs/bootstrap.pem"
    rm -f /tmp/fg-boot.key /tmp/fg-boot.crt
    chmod 0640 "$CONFDIR/proxy/certs/bootstrap.pem"
    warn "a self-signed bootstrap certificate is in place -- browsers will refuse"
    warn "it until certbot replaces it"
  fi
  render_unit "$SRC/agent/systemd/foxguard-proxy.service" /etc/systemd/system/foxguard-proxy.service
  sed -i "s|/etc/foxguard/proxy|$CONFDIR/proxy|g; s|wg-quick@wg0.service|wg-quick@$WG_IF.service|" \
      /etc/systemd/system/foxguard-proxy.service
  ok "foxguard-proxy unit installed (started by the agent once it has a config)"

  if [[ -n $ACME_CF_TOKEN ]]; then
    install -d -m 0700 "$CONFDIR/proxy"
    printf 'dns_cloudflare_api_token = %s\n' "$ACME_CF_TOKEN" > "$CONFDIR/proxy/cloudflare.ini"
    chmod 0600 "$CONFDIR/proxy/cloudflare.ini"
    # The deploy hook is where the two halves meet: certbot writes fullchain
    # and privkey separately, HAProxy wants them concatenated in one file, and
    # the Runtime API loads it without a reload so passthrough sessions survive.
    cat > /usr/local/bin/foxguard-cert-deploy <<'HOOKEOF'
#!/bin/bash
# Installed by foxguard-install.sh. Runs after every certbot renewal.
set -euo pipefail
CERTS=__CERTS__
SOCK=/run/foxguard/haproxy.sock
for live in /etc/letsencrypt/live/*/; do
  [[ -f "$live/fullchain.pem" ]] || continue
  name=$(basename "$live")
  cat "$live/fullchain.pem" "$live/privkey.pem" > "$CERTS/$name.pem.new"
  chmod 0640 "$CERTS/$name.pem.new"
  mv "$CERTS/$name.pem.new" "$CERTS/$name.pem"
  # Push it live without a reload. The file above is what makes it survive the
  # next reload -- a runtime commit alone reverts to whatever is on disk.
  if [[ -S $SOCK ]]; then
    { printf 'set ssl cert %s <<\n' "$CERTS/$name.pem"; cat "$CERTS/$name.pem"; printf '\n\n'; } | socat stdio "$SOCK" >/dev/null 2>&1 || true
    printf 'commit ssl cert %s\n' "$CERTS/$name.pem" | socat stdio "$SOCK" >/dev/null 2>&1 || true
  fi
done
HOOKEOF
    sed -i "s|__CERTS__|$CONFDIR/proxy/certs|" /usr/local/bin/foxguard-cert-deploy
    chmod 0755 /usr/local/bin/foxguard-cert-deploy
    ok "certbot deploy hook installed at /usr/local/bin/foxguard-cert-deploy"
    say "  request the wildcard with:"
    say "    certbot certonly --dns-cloudflare \\"
    say "      --dns-cloudflare-credentials $CONFDIR/proxy/cloudflare.ini \\"
    say "      -d '$PROXY_DOMAIN' -d '*.$PROXY_DOMAIN' \\"
    say "      --email $ACME_EMAIL --agree-tos --non-interactive \\"
    say "      --deploy-hook /usr/local/bin/foxguard-cert-deploy"
  fi
fi
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
  # Silence here is what a re-run looks like, and it is easy to read as "the
  # script forgot to print my password". It never had one to print: the
  # password is generated once and stored as an argon2 hash. Say so, and say
  # what to do about it, rather than leaving a gap where a secret used to be.
  say "  no password is shown on a re-run -- the first one was generated once"
  say "  and only its hash is stored. To set a new one:"
  say ""
  say "    TOKEN=\$(sed -n 's/^FOXGUARD_ADMIN_API_TOKEN=//p' $CONFDIR/backend.env)"
  say "    ID=\$(curl -s -H \"Authorization: Bearer \$TOKEN\" \\"
  say "         http://$TUNNEL_IP:$API_PORT/api/v1/users | jq -r '.[]|select(.is_admin)|.id' | head -1)"
  say "    curl -s -X PATCH -H \"Authorization: Bearer \$TOKEN\" -H 'Content-Type: application/json' \\"
  say "         -d '{\"password\":\"<a new one>\"}' http://$TUNNEL_IP:$API_PORT/api/v1/users/\$ID"
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
CLIENT_FILE=""
CLIENT_WARNINGS=""
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
    PEER_ID=$(printf '%s' "$PEER_JSON" | jq -r '.id // empty' 2>/dev/null || true)
  fi

  if [[ -n ${PEER_IP:-} ]]; then
    ok "registered '$BOOTSTRAP_PEER' at $PEER_IP, owned by $ADMIN_USER"

    # The same call the dashboard makes, so this device gets the same file:
    # resolver, search domain, MTU and every zone route, not just the pool.
    PROFILE=$(curl -sf -H "Authorization: Bearer $ADMIN_TOKEN" \
      "http://$TUNNEL_IP:$API_PORT/api/v1/peers/$PEER_ID/config-profile" 2>/dev/null || true)

    if [[ -n $PROFILE ]] && printf '%s' "$PROFILE" | jq -e '.addresses' >/dev/null 2>&1; then
      CLIENT_CONF=$(render_client_config "$PROFILE" "$CLIENT_PRIV" \
                    "<your-public-address>:$LISTEN_PORT")
      CLIENT_FILE=$(config_file_name "$PROFILE")
      # Reported rather than filtered: 'split mode refuses everything outside
      # the zone' and 'this network is left out because you carry it' are both
      # things the operator can only act on before the file scrolls away.
      CLIENT_WARNINGS=$(printf '%s' "$PROFILE" | jq -r '.warnings[]?' 2>/dev/null || true)
      ok "built its configuration from the API, the way the dashboard does"
    else
      # The API answered a moment ago, for the registration above, so this is
      # unlikely -- but a device that cannot reach the gateway is also the
      # device that cannot open the dashboard to try again.
      warn "could not read the config profile — falling back to a minimal file"
      SERVER_PUB=$(cat "/etc/wireguard/${WG_IF}.public" 2>/dev/null || wg show "$WG_IF" public-key)
      CLIENT_CONF=$(cat <<EOF
# Minimal fallback: no resolver, no zone routes. Replace it with a config from
# the dashboard's generator (Devices → the device → Configuration).
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
      CLIENT_FILE="foxguard.conf"
    fi
  else
    warn "could not register the device — add it from the dashboard instead"
  fi
fi

# --------------------------------------------------------------------------- #
# shown once
#
# Printed *before* the next-steps banner, not after it. Everything below is
# unrecoverable -- the password is stored only as an argon2 hash and the client
# private key is not stored at all -- while the instructions that follow are in
# docs/deployment.md and can be read again at any time. An install that dies
# between the two must lose the replaceable half, not this one.
#
# It has happened: `$B1.` in the banner below is the variable `B1`, which under
# `set -u` killed the script after the administrator and the first device had
# been created and before either secret reached the screen.
# --------------------------------------------------------------------------- #

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

 $B Client config for '$BOOTSTRAP_PEER' $N — save as ${CLIENT_FILE:-foxguard.conf}

$CLIENT_CONF

 The file name matters: wg-quick takes the interface name from it, and
 every client refuses more than 15 characters of [a-zA-Z0-9_=+.-].
$( [[ -n $CLIENT_WARNINGS ]] && printf '\n%s\n' "$(printf '%s\n' "$CLIENT_WARNINGS" | sed 's/^/ ! /')" )
 Its private key was generated on this gateway, which is a fair trade for
 the laptop you are setting up from and a bad habit for everything else:
 generate the keypair on the device and register only the public key.
$( [[ -z $ENDPOINT ]] && echo " Replace <your-public-address> with what your router forwards udp/$LISTEN_PORT to." )
$( [[ $DNS_ENABLED -eq 1 ]] && cat <<DNSNOTE

 The DNS line points at the resolver on this gateway, and the resolver is
 started by the agent — which is still stopped and in dry run. Until you
 finish the steps below, a device that connects with this file resolves
 nothing at all; comment the line out if you need it working sooner.
DNSNOTE
)

 This device lands in quarantine, as every user peer does. Connect the
 tunnel, open http://$TUNNEL_IP:$API_PORT/ and sign in as $ADMIN_USER to
 leave it.
EOF
fi

if [[ -n $ADMIN_PASS || -n $CLIENT_CONF ]]; then
  printf '%s────────────────────────────────────────────────────────────────%s\n\n' "$B" "$N"
fi

# --------------------------------------------------------------------------- #
# what happens next
# --------------------------------------------------------------------------- #

cat <<EOF

$B────────────────────────────────────────────────────────────────$N
$G Installed.$N The dataplane is $B not$N live yet — that is deliberate.

${B}1. Read the ruleset Foxguard wants to apply$N

   curl -s http://$TUNNEL_IP:$API_PORT/api/v1/ruleset/preview \\
     -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r .content

   Three things to confirm before going further:
     • 'iifname != "$WG_IF" accept' is the FIRST rule of chain input
       — this is what keeps your SSH alive.
     • both base chains say 'policy accept'.
     • the only delete statement is 'delete table inet foxguard'.

${B}2. Watch the agent validate it without applying anything$N

   systemctl start foxguard-agent && journalctl -u foxguard-agent -f
   # expect: "dry run: ruleset <digest> validated, not applied"

${B}3. Go live — keep a Proxmox console open$N

   sed -i 's/^FOXGUARD_AGENT_DRY_RUN=true/FOXGUARD_AGENT_DRY_RUN=false/' $CONFDIR/agent.env
   systemctl restart foxguard-agent
   nft list table inet foxguard      # ours
   nft list ruleset | grep -c table  # your other tables are still there

   If it goes wrong: systemctl stop foxguard-agent && nft delete table inet foxguard
   The tunnel keeps working — removing the filter table does not touch WireGuard.

${B}4. Verify$N

   $SRC/deploy/foxguard-healthcheck.sh

EOF
