#!/usr/bin/env bash
#
# Foxguard guided setup.
#
# The same installation as foxguard-install.sh, asked as questions instead of
# remembered as flags. Every answer has a default, an example, and a sentence
# about what it changes -- because the flags that matter most here are the ones
# whose consequences are not obvious from their names.
#
# **It is a front end, not a second installer.** It collects answers, shows you
# the exact command it built, and then runs foxguard-install.sh with it. There
# is one implementation of the install, so the two cannot drift apart, and
# anything you learn here transfers directly to the scripted form.
#
# Usage:
#   sudo ./foxguard-setup.sh              # ask, then install
#   sudo ./foxguard-setup.sh --dry-run    # ask, print the command, change nothing
#
set -euo pipefail

HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
INSTALLER="$HERE/foxguard-install.sh"
DRY_RUN=0
# Unknown arguments are refused rather than ignored: a typo in --dry-run must
# not quietly become a real installation.
case ${1:-} in
  "")        ;;
  --dry-run) DRY_RUN=1 ;;
  -h|--help)
    sed -n '2,18p' "${BASH_SOURCE[0]}" | sed 's/^#\s\?//'
    exit 0 ;;
  *)
    printf 'unknown option: %s\n\nUsage:\n  %s              ask, then install\n  %s --dry-run    ask, print the command, change nothing\n' \
      "$1" "$(basename "${BASH_SOURCE[0]}")" "$(basename "${BASH_SOURCE[0]}")" >&2
    exit 2 ;;
esac

# --------------------------------------------------------------------------- #
# output
# --------------------------------------------------------------------------- #

if [[ -t 1 ]]; then
  R=$'\033[31m'; G=$'\033[32m'; Y=$'\033[33m'; C=$'\033[36m'; D=$'\033[2m'
  B=$'\033[1m'; N=$'\033[0m'
else
  R=""; G=""; Y=""; C=""; D=""; B=""; N=""
fi

section() { printf '\n%s%s%s\n%s%s%s\n' "$B" "$1" "$N" "$D" "${1//?/─}" "$N"; }
why()     { printf '%s  %s%s\n' "$D" "$*" "$N"; }
eg()      { printf '%s  e.g. %s%s\n' "$C" "$*" "$N"; }
ok()      { printf '  %s✓%s %s\n' "$G" "$N" "$*"; }
warn()    { printf '  %s!%s %s\n' "$Y" "$N" "$*"; }
bad()     { printf '  %s✗%s %s\n' "$R" "$N" "$*"; }
die()     { printf '\n%sStopped:%s %s\n\n' "$R" "$N" "$*" >&2; exit 1; }

# --------------------------------------------------------------------------- #
# asking
# --------------------------------------------------------------------------- #

# Everything read from a human goes through this first.
#
# A carriage return is not whitespace to `read`: over a console that sends CRLF
# -- Proxmox's noVNC, a serial line, some SSH clients -- pressing Enter yields
# $'\r', which is *not empty*, so `${answer:-$default}` never fires and the
# default silently stops working. Worse, printing it back inside quotes puts the
# cursor at the start of the line, so the complaint renders as '' and looks like
# the script lost the input entirely. Observed exactly that way on a Proxmox
# LXC console.
clean() {
  local value=${1//$'\r'/}
  value=${value#"${value%%[![:space:]]*}"}
  value=${value%"${value##*[![:space:]]}"}
  printf '%s' "$value"
}

# ask <varname> <prompt> [default] [validator]
#
# The validator is a function name taking the answer and printing a complaint on
# failure. Rejecting here rather than three screens later is the whole point:
# the installer's preflight would catch most of these too, but by then you have
# answered twenty more questions.
ask() {
  local __var=$1 prompt=$2 default=${3:-} validator=${4:-} answer complaint
  while true; do
    if [[ -n $default ]]; then
      printf '  %s%s%s [%s]: ' "$B" "$prompt" "$N" "$default"
    else
      printf '  %s%s%s: ' "$B" "$prompt" "$N"
    fi
    read -r answer || answer=""
    answer=$(clean "$answer")
    answer=${answer:-$default}
    if [[ -z $answer && -z $default ]]; then
      bad "this one has no default -- an answer is needed"
      continue
    fi
    if [[ -n $validator ]]; then
      complaint=$("$validator" "$answer") || true
      if [[ -n $complaint ]]; then bad "$complaint"; continue; fi
    fi
    printf -v "$__var" '%s' "$answer"
    return 0
  done
}

# Never echoed, and never shown in the summary either.
ask_secret() {
  local __var=$1 prompt=$2 answer
  printf '  %s%s%s: ' "$B" "$prompt" "$N"
  read -rs answer || answer=""
  printf '\n'
  printf -v "$__var" '%s' "$(clean "$answer")"
}

# yesno <prompt> <default y|n>
yesno() {
  local prompt=$1 default=${2:-n} answer hint
  if [[ $default == y ]]; then hint="[Y/n]"; else hint="[y/N]"; fi
  while true; do
    printf '  %s%s%s %s: ' "$B" "$prompt" "$N" "$hint"
    read -r answer || answer=""
    answer=$(clean "$answer")
    answer=${answer:-$default}
    case ${answer,,} in
      y|yes) return 0 ;;
      n|no)  return 1 ;;
      *) bad "answer y or n" ;;
    esac
  done
}

# --------------------------------------------------------------------------- #
# validators
# --------------------------------------------------------------------------- #

v_cidr() {
  [[ $1 =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$ ]] || {
    echo "that is not an IPv4 network in a.b.c.d/len form"; return; }
}
v_ip() {
  [[ $1 =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || { echo "that is not an IPv4 address"; return; }
}

# A listener binds an address the kernel already has. Behind NAT the public
# address lives on the router, not here, and asking for it fails at start-up
# with EADDRNOTAVAIL -- long after the preflight said everything was fine.
v_local_ip() {
  local complaint; complaint=$(v_ip "$1"); [[ -n $complaint ]] && { echo "$complaint"; return; }
  ip -4 -o addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | grep -qx "$1" && return
  echo "this box has no address $1 -- a listener can only bind an address that is already here. It has: $(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | tr '\n' ' ')"
}
v_port() {
  [[ $1 =~ ^[0-9]+$ ]] && (( $1 >= 1 && $1 <= 65535 )) || { echo "a port is 1-65535"; return; }
}
# `ip a` displays a veth as "eth0@if30" -- the @ifNN is the peer index, not part
# of the name, and it is what people copy out of the output they are looking at.
strip_ifindex() { printf '%s' "${1%%@*}"; }

v_iface() {
  local name; name=$(strip_ifindex "$1")
  [[ -d /sys/class/net/$name ]] && return
  echo "no interface called '$name' here. This box has: $(ip -brief link show 2>/dev/null | awk '{print $1}' | sed 's/@.*//' | tr '\n' ' ')"
}
v_domain() {
  [[ $1 =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$ ]] || {
    echo "that is not a domain name"; return; }
}
v_zone() {
  v_domain "$1" && return
  echo "a DNS zone is a domain name"
}
v_username() {
  [[ $1 =~ ^[A-Za-z0-9._@-]{1,64}$ ]] || echo "letters, digits and . _ @ - only"
}
v_dir() {
  [[ $1 == /* ]] || echo "give an absolute path"
}
v_wgname() {
  [[ ${#1} -le 15 && $1 =~ ^[A-Za-z0-9_=+.-]+$ ]] || {
    echo "an interface name is at most 15 characters of [A-Za-z0-9_=+.-]"; return; }
}

# --------------------------------------------------------------------------- #
# detection -- so the defaults are yours, not the author's
# --------------------------------------------------------------------------- #

detect_wan() {
  ip route show default 2>/dev/null | awk '/^default/ {print $5; exit}'
}
detect_wg() {
  ip -brief link show type wireguard 2>/dev/null | awk '{print $1}' | head -1
}
detect_tunnel_ip() {
  ip -4 -brief addr show "$1" 2>/dev/null | awk '{print $3}' | cut -d/ -f1 | head -1
}
detect_pool() {
  ip -4 -brief addr show "$1" 2>/dev/null | awk '{print $3}' | head -1
}
detect_public_ip() {
  # No network call: whatever the default route hands out is the best guess a
  # script can make, and the operator corrects it. A wrong endpoint produces a
  # client config that cannot connect, which is worth one question.
  ip -4 addr show "$(detect_wan)" 2>/dev/null |
    awk '/inet /{print $2; exit}' | cut -d/ -f1
}

# --------------------------------------------------------------------------- #

[[ -x $INSTALLER ]] || die "cannot find foxguard-install.sh next to this script"
[[ $EUID -eq 0 || $DRY_RUN -eq 1 ]] || die "run this with sudo (or --dry-run to just see the command)"

cat <<EOF

${B}Foxguard guided setup${N}

${D}This asks what foxguard-install.sh takes as flags, then runs it for you.
Press Enter to accept the value in [brackets]. Nothing is changed until you
confirm at the end, and you will see the exact command first.${N}
EOF

ARGS=()
add() { ARGS+=("$@"); }

# --------------------------------------------------------------------------- #
section "1. Where"

if [[ -d /etc/foxguard ]]; then
  warn "there is already a Foxguard install on this box"
  why "Re-running is safe: existing tokens and passwords are reused, not"
  why "regenerated, so the agent does not lose its credentials mid-upgrade."
  why "Answer the same way as last time for anything you are not changing."
  why ""
  why "One consequence, because it surprises people: the administrator"
  why "password will NOT be printed again. It was generated once on the first"
  why "run and only its hash is kept. The installer will tell you how to set a"
  why "new one. The same goes for a device you already registered -- register"
  why "a different one, or use the dashboard's config generator."
fi

ask SRC "Path to the Foxguard source tree" "$(cd "$HERE/.." && pwd)" v_dir
ask PREFIX "Install directory" "/opt/foxguard" v_dir

# --------------------------------------------------------------------------- #
section "2. The tunnel"

WG_DETECTED=$(detect_wg || true)
if [[ -n $WG_DETECTED ]]; then
  ok "this box already has a WireGuard interface: $WG_DETECTED"
  why "Foxguard manages exactly one. If that one belongs to something else"
  why "(Tailscale, a site-to-site link), name a different one below and this"
  why "will offer to create it."
else
  warn "no WireGuard interface exists on this box"
fi
ask WG_IF "WireGuard interface for Foxguard" "${WG_DETECTED:-wg0}" v_wgname

BOOTSTRAP_WG=0
DET_IP=""
DET_POOL=""
if [[ -d /sys/class/net/$WG_IF ]]; then
  DET_IP=$(detect_tunnel_ip "$WG_IF" || true)
  DET_POOL=$(detect_pool "$WG_IF" || true)
  [[ -n $DET_IP ]] && ok "$WG_IF exists, address $DET_IP"
else
  # The gap this closes: naming an interface that does not exist used to sail
  # through here and fail in the installer's preflight several answers later.
  warn "$WG_IF does not exist yet"
  why "Creating the interface that carries your only remote access is opt-in,"
  why "never implicit -- so this asks rather than assuming."
  if yesno "Create $WG_IF now?" n; then
    BOOTSTRAP_WG=1
    eg "51820 is the usual port; open it on whatever sits in front of this box"
    ask LISTEN_PORT "UDP port it listens on" "51820" v_port
  else
    die "bring $WG_IF up yourself, then run this again"
  fi
fi

why "The gateway's own address inside the tunnel. Everything Foxguard serves"
why "-- the API, the portal, the resolver -- binds here and nowhere else."
eg "10.88.0.1"
ask TUNNEL_IP "Gateway address inside the tunnel" "${DET_IP:-10.88.0.1}" v_ip

why "The pool peers get their addresses from. It must contain the address"
why "above, and nothing else on your network may use it."
eg "10.88.0.0/24 gives you 254 devices"
ask POOL "Address pool for peers" "${DET_POOL:-10.88.0.0/24}" v_cidr

why "Optional second pool for devices that have registered a key but not yet"
why "proved who they are. Keeping them apart makes quarantine visible in"
why "'wg show' instead of being a firewall detail."
eg "10.88.9.0/24 -- leave empty to use the main pool"
ask STAGING_POOL "Staging pool (optional)" "none"
[[ $STAGING_POOL == none ]] && STAGING_POOL=""

WAN_DETECTED=$(detect_wan || true)
why "The interface facing the internet. Foxguard needs it to NAT traffic for"
why "peers you let out through the gateway."
eg "eth0 -- if 'ip a' shows eth0@if30, the name is just eth0"
ask WAN_IF "Internet-facing interface" "${WAN_DETECTED:-eth0}" v_iface
WAN_IF=$(strip_ifindex "$WAN_IF")

# --------------------------------------------------------------------------- #
section "3. The control plane"

why "The API and the captive portal share this port -- a peer in quarantine"
why "reaches the portal here, so it is opened in the firewall for them."
ask API_PORT "API and portal port" "8080" v_port

if yesno "Install the admin dashboard?" y; then
  SKIP_FRONTEND=0
  ask DASHBOARD_PORT "Dashboard port" "3000" v_port
else
  SKIP_FRONTEND=1
  why "Skipping it means no Node.js and no web UI; the API is still there."
fi

why "The first administrator account. You will be shown a generated password"
why "once, at the end. Sign in with it rather than the shared API token --"
why "that is what makes the audit log say who did something."
ask ADMIN_USER "Administrator username" "admin" v_username

why "The public address peers dial. Only you know what your router forwards"
why "udp/$( [[ $BOOTSTRAP_WG -eq 1 ]] && echo "$LISTEN_PORT" || echo 51820 ) to, so there is no default worth guessing --"
why "without it, generated client configs are marked incomplete."
eg "vpn.example.com  or  203.0.113.10  or  vpn.example.com:51820"
ask ENDPOINT "Public endpoint peers connect to" "$(detect_public_ip || echo skip)"
[[ $ENDPOINT == skip ]] && ENDPOINT=""

# --------------------------------------------------------------------------- #
section "4. Internal DNS (optional)"

why "Gives every device a name inside the tunnel -- laptop.fox.internal --"
why "and lets you write records by hand. Off by default: it makes the gateway"
why "a resolver, which is a service you did not ask for."
DNS_ENABLED=0
if yesno "Serve names inside the tunnel?" n; then
  DNS_ENABLED=1
  why "The zone every device lives in. Use something you control, or a name"
  why "reserved for the purpose. Avoid .local -- that is mDNS territory and"
  why "clients will resolve it inconsistently."
  eg "fox.internal  or  vpn.yourcompany.com"
  ask DNS_ZONE "Zone name" "fox.internal" v_zone

  why "forward: resolve everything and send the rest upstream. This is what"
  why "  makes 'DNS = <gateway>' in a client config work on its own."
  why "split:   answer for the zone and REFUSE everything else. Only works if"
  why "  the client is set up to send just in-zone queries here."
  while true; do
    ask DNS_MODE "Resolver mode (forward/split)" "forward"
    [[ $DNS_MODE == forward || $DNS_MODE == split ]] && break
    bad "answer forward or split"
  done

  DNS_UPSTREAMS=""
  if [[ $DNS_MODE == forward ]]; then
    why "Where queries outside the zone go. Empty uses this box's own"
    why "/etc/resolv.conf, which is usually what you want."
    eg "9.9.9.9,1.1.1.1  -- comma separated, or 'none'"
    ask DNS_UPSTREAMS "Upstream resolvers" "none"
    [[ $DNS_UPSTREAMS == none ]] && DNS_UPSTREAMS=""
  fi
fi

# --------------------------------------------------------------------------- #
section "5. Reverse proxy (optional)"

why "Publishes services that live behind a peer: a dashboard on a NAS, an"
why "internal wiki, an SSH jump host. The gateway fronts them, checks who is"
why "asking, and never exposes the device itself."
PROXY_ENABLED=0
SSO_ENABLED=0
GEO_NOW=0
PROXY_DOMAIN=""
PROXY_EXTERNAL=""
ACME_EMAIL=""
ACME_CF_TOKEN=""
if yesno "Publish services through the gateway?" n; then
  PROXY_ENABLED=1

  why "Services need a name a public certificate authority will sign, so this"
  why "must be a real domain you own. It cannot be the DNS zone above:"
  why ".internal can never have a public certificate."
  eg "example.com  ->  grafana.example.com, wiki.example.com"
  ask PROXY_DOMAIN "Domain services are published under" "" v_domain

  if [[ $DNS_ENABLED -eq 1 && $DNS_MODE == split && $PROXY_DOMAIN == *"$DNS_ZONE" ]]; then
    bad "the DNS zone $DNS_ZONE covers $PROXY_DOMAIN, and in split mode the"
    bad "resolver would answer NXDOMAIN for the ACME challenge -- renewals"
    bad "would stop. Use a different domain, or forward mode."
    die "pick a domain outside $DNS_ZONE and run this again"
  fi

  why "Reachable from the internet, or only from inside the tunnel?"
  why "Inside the tunnel a device's address proves which device it is, so"
  why "nothing else is needed. From the internet it proves nothing, so every"
  why "externally published service needs a token or a sign-in."
  if yesno "Publish anything to the internet?" n; then
    why "This is the address HAProxy binds on *this machine* -- not your public"
    why "IP. Behind a router they are different, and the public one does not"
    why "exist here, so binding it would fail at start-up."
    why ""
    why "Your public IP belongs in two other places: the A record for"
    why "*.<domain> in your public DNS, and a port forward on your router"
    why "sending tcp/80 and tcp/443 to the address you give below."
    eg "192.168.1.105 -- the LAN address of this box, not 203.0.113.x"
    ask PROXY_EXTERNAL "WAN-facing address to bind on this box" "$(detect_public_ip || echo '')" v_local_ip

    why "Let's Encrypt via the DNS-01 challenge, so nothing has to be publicly"
    why "reachable to prove ownership -- and internal-only services never get"
    why "a public DNS record. One wildcard covers everything."
    if yesno "Get certificates automatically (Cloudflare DNS)?" y; then
      ask ACME_EMAIL "Contact address for Let's Encrypt" ""
      why "Use a scoped API *token* with Zone:DNS:Edit on that one zone --"
      why "never the global API key. The wildcard it obtains covers your whole"
      why "domain, which makes it the most valuable secret on this machine."
      ask_secret ACME_CF_TOKEN "Cloudflare API token (not echoed)"
    else
      warn "the proxy will run on a self-signed certificate until you provide one"
    fi
  else
    ok "tunnel-side only -- nothing of yours is exposed to the internet"
  fi

  why "Single sign-on: a Foxguard login page and one session that opens every"
  why "published service, instead of a token per service. Revoking somebody"
  why "takes effect immediately."
  if yesno "Enable single sign-on?" y; then
    SSO_ENABLED=1
    ok "the login page will be at auth.$PROXY_DOMAIN"
  fi

  why "Country filters let a service refuse whole countries. This downloads a"
  why "prefix dataset (~4 MiB, from db-ip.com) now instead of waiting for the"
  why "weekly timer. Say no and nothing breaks -- the timer still runs, and you"
  why "can fetch it any time with: systemctl start foxguard-geo-refresh"
  warn "geo is noise reduction, not security: any VPN defeats it in one click"
  if yesno "Download the country dataset now?" n; then
    GEO_NOW=1
    ok "it will be fetched during the install"
  fi
fi

# --------------------------------------------------------------------------- #
section "6. A first device (optional)"

why "Registers one device and prints a ready-to-import config. Its private key"
why "is generated here and shown once -- acceptable for the laptop you are"
why "setting this up from, not the habit for everything else. Every device"
why "after it should come from the dashboard's generator, which never puts a"
why "private key on this machine."
BOOTSTRAP_PEER=""
if yesno "Register a first device now?" y; then
  eg "laptop, phone, admin-mbp"
  ask BOOTSTRAP_PEER "Name for it" "laptop"
fi

# --------------------------------------------------------------------------- #
# build the command
# --------------------------------------------------------------------------- #

add --src "$SRC" --prefix "$PREFIX"
add --wg-interface "$WG_IF" --tunnel-ip "$TUNNEL_IP" --pool "$POOL"
[[ -n $STAGING_POOL ]] && add --staging-pool "$STAGING_POOL"
add --wan-interface "$WAN_IF" --api-port "$API_PORT" --admin-user "$ADMIN_USER"
if [[ $SKIP_FRONTEND -eq 1 ]]; then
  add --skip-frontend
else
  add --dashboard-port "$DASHBOARD_PORT"
fi
[[ -n $ENDPOINT ]] && add --endpoint "$ENDPOINT"
if [[ $BOOTSTRAP_WG -eq 1 ]]; then
  add --bootstrap-wireguard --listen-port "$LISTEN_PORT"
fi
if [[ $DNS_ENABLED -eq 1 ]]; then
  add --dns --dns-zone "$DNS_ZONE" --dns-mode "$DNS_MODE"
  if [[ -n ${DNS_UPSTREAMS:-} ]]; then
    IFS=',' read -ra _ups <<< "$DNS_UPSTREAMS"
    for up in "${_ups[@]}"; do add --dns-upstream "${up// /}"; done
  fi
fi
if [[ $PROXY_ENABLED -eq 1 ]]; then
  add --proxy --proxy-domain "$PROXY_DOMAIN"
  [[ -n $PROXY_EXTERNAL ]] && add --proxy-external "$PROXY_EXTERNAL"
  [[ -n $ACME_EMAIL ]] && add --acme-email "$ACME_EMAIL"
  [[ -n $ACME_CF_TOKEN ]] && add --acme-cf-token "$ACME_CF_TOKEN"
  [[ $SSO_ENABLED -eq 1 ]] && add --sso
  [[ $GEO_NOW -eq 1 ]] && add --geo-now
fi
[[ -n $BOOTSTRAP_PEER ]] && add --bootstrap-peer "$BOOTSTRAP_PEER"

# The printable form redacts the token. The real one never reaches the screen,
# a log, or your shell history.
printable() {
  local out=() skip=0
  for a in "${ARGS[@]}"; do
    if [[ $skip -eq 1 ]]; then out+=("<redacted>"); skip=0; continue; fi
    [[ $a == --acme-cf-token ]] && skip=1
    out+=("$(printf '%q' "$a")")
  done
  printf '%s' "${out[*]}"
}

# --------------------------------------------------------------------------- #
section "Review"

printf '  %sTunnel%s      %s on %s, pool %s\n' "$B" "$N" "$WG_IF" "$TUNNEL_IP" "$POOL"
printf '  %sInternet%s    via %s%s\n' "$B" "$N" "$WAN_IF" \
  "$( [[ -n $ENDPOINT ]] && echo ", peers dial $ENDPOINT" )"
printf '  %sControl%s     API on %s' "$B" "$N" "$API_PORT"
[[ $SKIP_FRONTEND -eq 0 ]] && printf ', dashboard on %s' "$DASHBOARD_PORT"
printf ', admin "%s"\n' "$ADMIN_USER"
if [[ $DNS_ENABLED -eq 1 ]]; then
  printf '  %sDNS%s         zone %s, %s mode%s\n' "$B" "$N" "$DNS_ZONE" "$DNS_MODE" \
    "$( [[ -n ${DNS_UPSTREAMS:-} ]] && echo ", upstream $DNS_UPSTREAMS" )"
else
  printf '  %sDNS%s         off\n' "$B" "$N"
fi
if [[ $PROXY_ENABLED -eq 1 ]]; then
  printf '  %sProxy%s       services under %s, %s\n' "$B" "$N" "$PROXY_DOMAIN" \
    "$( [[ -n $PROXY_EXTERNAL ]] && echo "public on $PROXY_EXTERNAL" || echo "tunnel only" )"
  printf '  %sSign-on%s     %s\n' "$B" "$N" \
    "$( [[ $SSO_ENABLED -eq 1 ]] && echo "on, login page at auth.$PROXY_DOMAIN" || echo "off" )"
  printf '  %sCertificate%s %s\n' "$B" "$N" \
    "$( [[ -n $ACME_CF_TOKEN ]] && echo "Let's Encrypt wildcard via Cloudflare" || echo "self-signed until you provide one" )"
else
  printf '  %sProxy%s       off\n' "$B" "$N"
fi
[[ -n $BOOTSTRAP_PEER ]] && printf '  %sFirst device%s %s\n' "$B" "$N" "$BOOTSTRAP_PEER"

printf '\n%s  The command this becomes:%s\n' "$D" "$N"
printf '%s    %s %s%s\n\n' "$D" "$(basename "$INSTALLER")" "$(printable)" "$N"

if [[ $DRY_RUN -eq 1 ]]; then
  ok "dry run -- nothing was changed"
  exit 0
fi

# --------------------------------------------------------------------------- #
section "Preflight"

why "Checking the answers against this machine before touching anything."
if "$INSTALLER" --check-only "${ARGS[@]}"; then
  ok "preflight passed"
else
  bad "preflight found problems -- read them above"
  yesno "Continue anyway?" n || die "nothing was changed"
fi

if ! yesno "Install now?" y; then
  printf '\n%s  Nothing was changed. To do this later, run:%s\n' "$D" "$N"
  printf '%s    sudo %s %s%s\n\n' "$D" "$INSTALLER" "$(printable)" "$N"
  exit 0
fi

exec "$INSTALLER" --yes "${ARGS[@]}"
