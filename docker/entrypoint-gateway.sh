#!/usr/bin/env bash
#
# Entrypoint for the foxguard-gateway image.
#
# Stands in for the four systemd units this image replaces:
#
#   foxguard-agent.service        -> the process this script becomes
#   foxguard-dns.service          -> started on demand by fg-servicectl
#   foxguard-proxy.service        -> started on demand by fg-servicectl
#   foxguard-geo-refresh.timer    -> the background loop below
#
# Neither dnsmasq nor HAProxy is started here, deliberately. Before the agent
# has rendered a configuration there is nothing for either to serve, and a
# daemon restarting in a loop over a file that does not exist yet is noise that
# hides the real first-boot errors. The agent starts them when it has something
# to give them -- exactly as it does under systemd, where those units are
# installed but not enabled.
#
set -uo pipefail

state_dir=${FOXGUARD_AGENT_STATE_DIR:-/var/lib/foxguard}
run_dir=${FOXGUARD_RUN_DIR:-/run/foxguard}
dns_dir=${FOXGUARD_AGENT_DNS_DIR:-/etc/foxguard/dns}
proxy_dir=${FOXGUARD_AGENT_PROXY_DIR:-/etc/foxguard/proxy}
api_url=${FOXGUARD_AGENT_API_URL:-http://127.0.0.1:8080}
agent_pidfile="$run_dir/agent.pid"

log()  { printf '%s foxguard-gateway: %s\n' "$(date -Is)" "$*"; }
warn() { log "WARNING: $*" >&2; }
die()  { log "FATAL: $*" >&2; exit 1; }

# --------------------------------------------------------------------------- #
# healthcheck mode
# --------------------------------------------------------------------------- #
# Two questions, because either one alone lies. A live agent that cannot reach
# the control plane is applying nothing; a reachable control plane with a dead
# agent is a gateway drifting from its policy.
if [[ ${1:-} == "--healthcheck" ]]; then
  pid=$(cat "$agent_pidfile" 2>/dev/null) || exit 1
  kill -0 "$pid" 2>/dev/null || exit 1
  curl -fsS --max-time 5 -o /dev/null "${api_url%/}/healthz" || exit 1
  exit 0
fi

set -e

# --------------------------------------------------------------------------- #
# preflight
# --------------------------------------------------------------------------- #

: "${FOXGUARD_AGENT_API_TOKEN:?not set. It must match FOXGUARD_AGENT_API_TOKEN on the control plane.}"

mkdir -p "$state_dir" "$run_dir" "$dns_dir" "$proxy_dir/maps" "$proxy_dir/certs"
chmod 0750 "$run_dir"

# The single most common way to run this container wrong, and it produces an
# error thirty seconds later that mentions netlink and not permissions.
if ! nft list ruleset >/dev/null 2>&1; then
  die "cannot read the nftables ruleset. This container needs CAP_NET_ADMIN and
  the host's network namespace:

      docker run --network host --cap-add NET_ADMIN --cap-add NET_RAW ...

  or, in compose: network_mode: host, plus cap_add: [NET_ADMIN, NET_RAW]."
fi

# Docker mounts /proc/sys read-only, so this cannot be fixed from in here. Say
# what to run on the host rather than failing with a routing problem later.
if [[ $(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0) != 1 ]]; then
  warn "net.ipv4.ip_forward is 0 on the host. Peers will complete a handshake"
  warn "and reach nothing. On the host:  sysctl -w net.ipv4.ip_forward=1"
  warn "(persist it in /etc/sysctl.d/99-foxguard.conf)"
fi

# --------------------------------------------------------------------------- #
# optional: create the WireGuard interface
# --------------------------------------------------------------------------- #
# Off by default. On a gateway that already has wg0 -- the normal case, and what
# deploy/foxguard-install.sh builds -- creating it here would fight whatever
# manages it. Turn it on for a from-nothing deployment where this container IS
# the gateway.
wg_if=${FOXGUARD_WG_INTERFACE:-wg0}

bootstrap_wireguard() {
  local addr port key_file pub
  addr=${FOXGUARD_WG_ADDRESS:-10.88.0.1/24}
  port=${FOXGUARD_WG_LISTEN_PORT:-51820}
  key_file="$state_dir/wg-private.key"

  if ip link show "$wg_if" >/dev/null 2>&1; then
    log "$wg_if already exists, leaving it alone"
    # Leaving it alone is right -- something else owns that interface -- but it
    # is only harmless if it carries the key this deployment thinks it does.
    # Redeploy with a fresh .env onto a box that still has the old wg0 and every
    # generated client configuration names a public key the gateway cannot
    # decrypt for, with no error anywhere: the peer just never handshakes.
    if [[ -n ${FOXGUARD_WG_PUBLIC_KEY:-} ]]; then
      local live
      live=$(wg show "$wg_if" public-key 2>/dev/null || true)
      if [[ -n $live && $live != "$FOXGUARD_WG_PUBLIC_KEY" ]]; then
        warn "$wg_if carries a DIFFERENT key from the one the control plane"
        warn "publishes. Client configurations will name the wrong gateway and"
        warn "no peer will complete a handshake."
        warn "  on the interface : $live"
        warn "  in the config    : $FOXGUARD_WG_PUBLIC_KEY"
        warn "Fix one of them: set FOXGUARD_WG_PUBLIC_KEY to the interface's key,"
        warn "or delete $wg_if and let this container recreate it."
      fi
    fi
    return 0
  fi

  # The key is persisted in state_dir, not regenerated per start: it *is* this
  # gateway's identity. A new one on every restart would invalidate every client
  # configuration ever handed out.
  # The umask, not just the chmod after the fact: `wg genkey >` creates the file
  # world-readable and then warns about it, and a private key that was briefly
  # readable by everything on the box is a private key you have to replace.
  if [[ -n ${FOXGUARD_WG_PRIVATE_KEY:-} ]]; then
    ( umask 077; printf '%s\n' "$FOXGUARD_WG_PRIVATE_KEY" > "$key_file" )
  elif [[ ! -s $key_file ]]; then
    log "generating a new interface key (kept in $key_file)"
    ( umask 077; wg genkey > "$key_file" )
  fi
  chmod 0600 "$key_file"
  pub=$(wg pubkey < "$key_file")

  log "creating $wg_if ($addr, udp/$port)"
  ip link add "$wg_if" type wireguard \
    || die "could not create $wg_if. Is the wireguard module loaded on the host? (modprobe wireguard)"
  wg set "$wg_if" private-key "$key_file" listen-port "$port"
  ip address add "$addr" dev "$wg_if"
  ip link set "$wg_if" up

  # The control plane cannot work this out on its own and refuses to generate
  # client configurations without it, so it is printed rather than buried.
  log "interface public key: $pub"
  log "  -> set FOXGUARD_WG_PUBLIC_KEY to this on the API, or client configs stay incomplete"
}

if [[ ${FOXGUARD_BOOTSTRAP_WG:-false} == "true" ]]; then
  bootstrap_wireguard
elif ! ip link show "$wg_if" >/dev/null 2>&1; then
  warn "$wg_if does not exist. The agent will reconcile nftables but no peer"
  warn "can connect. Create it on the host, or set FOXGUARD_BOOTSTRAP_WG=true."
fi

# --------------------------------------------------------------------------- #
# optional: the geo dataset refresher
# --------------------------------------------------------------------------- #
# What foxguard-geo-refresh.timer does under systemd, and for the same reason it
# is a timer there: the reconcile loop installs firewall rules and must never
# depend on a third party's web server being up. If this fails, the previous
# dataset is still on disk and the agent keeps working from it.
geo_loop() {
  local interval=${FOXGUARD_GEO_REFRESH_INTERVAL_SECONDS:-604800}
  # Spread the first fetch: every Foxguard container in the world starting from
  # the same image should not hit DB-IP in the same minute.
  sleep $((RANDOM % 300))
  while true; do
    if foxguard-geo-refresh --rebuild >/dev/null 2>&1; then
      log "geo dataset refreshed"
    else
      log "geo dataset refresh failed; keeping the previous one"
    fi
    sleep "$interval"
  done
}

if [[ ${FOXGUARD_GEO_REFRESH_ENABLED:-true} == "true" ]]; then
  geo_loop &
  geo_pid=$!
else
  geo_pid=""
fi

# The daemons are children of this container, not of an init system that would
# outlive it, so shutting down means stopping them in the right order: the agent
# first, so it cannot render a new configuration into a proxy that is going
# away, then the daemons themselves.
shutdown() {
  log "shutting down"
  [[ -n ${agent_pid:-} ]] && kill -TERM "$agent_pid" 2>/dev/null
  [[ -n $geo_pid ]] && kill -TERM "$geo_pid" 2>/dev/null
  [[ -n ${agent_pid:-} ]] && wait "$agent_pid" 2>/dev/null
  fg-servicectl stop foxguard-proxy 2>/dev/null || true
  fg-servicectl stop foxguard-dns 2>/dev/null || true
  exit 0
}
trap shutdown TERM INT

# --------------------------------------------------------------------------- #
# wait for the control plane
# --------------------------------------------------------------------------- #
# Bounded and non-fatal. The agent handles an unreachable API by warning and
# retrying, so giving up here would be worse than starting anyway -- but a clean
# "waiting for the control plane" beats a screenful of connection errors.
wait_seconds=${FOXGUARD_API_WAIT_SECONDS:-120}
if (( wait_seconds > 0 )); then
  log "waiting up to ${wait_seconds}s for the control plane at $api_url"
  deadline=$((SECONDS + wait_seconds))
  until curl -fsS --max-time 5 -o /dev/null "${api_url%/}/healthz" 2>/dev/null; do
    if (( SECONDS >= deadline )); then
      warn "the control plane did not answer within ${wait_seconds}s; starting anyway"
      break
    fi
    sleep 2
  done
fi

# --------------------------------------------------------------------------- #
# run
# --------------------------------------------------------------------------- #
set +e
foxguard-agent &
agent_pid=$!
printf '%s' "$agent_pid" > "$agent_pidfile"
log "agent running (pid $agent_pid)"

# `wait` returns as soon as a signal is handled, so the loop is what keeps this
# process alive until the agent itself exits.
while kill -0 "$agent_pid" 2>/dev/null; do
  wait "$agent_pid"
  status=$?
done
log "the agent exited with status ${status:-0}"
fg-servicectl stop foxguard-proxy 2>/dev/null
fg-servicectl stop foxguard-dns 2>/dev/null
exit "${status:-0}"
