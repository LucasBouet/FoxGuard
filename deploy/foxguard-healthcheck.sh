#!/usr/bin/env bash
#
# Foxguard health check.
#
# Answers one question: is this gateway actually enforcing what its database
# says it should, and is it doing so safely? Read-only -- it changes nothing and
# is safe to run on a live gateway at any time.
#
# Exit code 0 = all good, 1 = something needs attention.
#
set -uo pipefail   # deliberately not -e: a failing check must not abort the run

CONFDIR=${CONFDIR:-/etc/foxguard}
WG_IF=${WG_IF:-}
NFT=$(command -v nft || echo /usr/sbin/nft)

if [[ -t 1 ]]; then
  R=$'\033[31m'; G=$'\033[32m'; Y=$'\033[33m'; B=$'\033[1m'; N=$'\033[0m'
else
  R=""; G=""; Y=""; B=""; N=""
fi

PASS=0; WARN=0; FAILED=0
section() { printf '\n%s%s%s\n' "$B" "$*" "$N"; }
ok()   { printf '  %s✓%s %s\n' "$G" "$N" "$*"; PASS=$((PASS+1)); }
warn() { printf '  %s!%s %s\n' "$Y" "$N" "$*"; WARN=$((WARN+1)); }
bad()  { printf '  %s✗%s %s\n' "$R" "$N" "$*"; FAILED=$((FAILED+1)); }

[[ -r $CONFDIR/backend.env ]] || { echo "cannot read $CONFDIR/backend.env (run as root)"; exit 1; }
# shellcheck disable=SC1090
set -a; . "$CONFDIR/backend.env"; set +a
[[ -n $WG_IF ]] || WG_IF=${FOXGUARD_WG_INTERFACE:-wg0}

TUNNEL_IP=${FOXGUARD_WG_GATEWAY_IP:-127.0.0.1}
PORT=${FOXGUARD_PORTAL_PORT:-8080}
API="http://$TUNNEL_IP:$PORT"
AUTH="Authorization: Bearer ${FOXGUARD_ADMIN_API_TOKEN:-}"

api() { curl -sf -m 10 -H "$AUTH" "$API$1" 2>/dev/null; }

# --------------------------------------------------------------------------- #
section "Services"

for unit in foxguard-api foxguard-agent foxguard-dashboard; do
  if ! systemctl list-unit-files "$unit.service" >/dev/null 2>&1 || \
     ! systemctl cat "$unit" >/dev/null 2>&1; then
    [[ $unit == foxguard-dashboard ]] && warn "$unit is not installed (optional)" \
                                      || bad "$unit is not installed"
    continue
  fi
  if systemctl is-active --quiet "$unit"; then
    ok "$unit is running"
  else
    [[ $unit == foxguard-dashboard ]] && warn "$unit is not running (optional)" \
                                      || bad "$unit is not running"
  fi
done

# --------------------------------------------------------------------------- #
section "Configuration safety"

if [[ ${FOXGUARD_DEV_MODE,,} == true ]]; then
  bad "FOXGUARD_DEV_MODE=true — admin authentication is weakened. Never on a gateway."
else
  ok "dev mode is off"
fi

if [[ -n ${FOXGUARD_ADMIN_API_TOKEN:-} && ${FOXGUARD_ADMIN_API_TOKEN:-} == "${FOXGUARD_AGENT_API_TOKEN:-}" ]]; then
  bad "the admin and agent tokens are the same value"
else
  ok "admin and agent tokens differ"
fi

for f in backend.env agent.env dashboard.env; do
  [[ -f $CONFDIR/$f ]] || continue
  mode=$(stat -c '%a' "$CONFDIR/$f")
  [[ $mode == 600 ]] && ok "$f is mode 0600" || bad "$f is mode $mode, expected 0600"
done

# The API must be started by foxguard-serve. Plain uvicorn enables proxy headers
# by default, which lets anything on loopback forge a peer's source address.
if systemctl cat foxguard-api 2>/dev/null | grep -q 'foxguard-serve'; then
  ok "the API is started with foxguard-serve (proxy headers disabled)"
else
  bad "the API is NOT started with foxguard-serve — X-Forwarded-For could be trusted"
fi

# Binding to anything routable from the WAN exposes the admin API.
if systemctl cat foxguard-api 2>/dev/null | grep -qE -- '--host (0\.0\.0\.0|::)'; then
  bad "the API binds 0.0.0.0 — bind the tunnel address or localhost instead"
else
  ok "the API is not bound to a wildcard address"
fi

# --------------------------------------------------------------------------- #
section "Control plane"

# A SQL_ASCII database makes psycopg hand SQLAlchemy bytes where it expects
# text, and the failure surfaces as an unrelated-looking TypeError at connection
# time. Worth naming explicitly.
DBNAME=${FOXGUARD_DATABASE_URL##*/}
ENC=$(sudo -u postgres psql -tAc \
      "SELECT pg_encoding_to_char(encoding) FROM pg_database WHERE datname='${DBNAME%%\?*}'" 2>/dev/null)
case ${ENC:-} in
  UTF8) ok "database encoding is UTF8" ;;
  "")   warn "could not read the database encoding" ;;
  *)    bad "database encoding is $ENC — psycopg needs UTF8" ;;
esac

if api /healthz >/dev/null; then
  ok "API answers on $API"
else
  bad "API does not answer on $API"
fi

if api /api/v1/dashboard >/dev/null; then
  ok "admin credentials work"
else
  bad "admin credentials rejected (or the API is down)"
fi

ADMINS=$(api /api/v1/users | jq -r '[.[] | select(.is_admin)] | length' 2>/dev/null || echo 0)
if [[ ${ADMINS:-0} -gt 0 ]]; then
  ok "$ADMINS administrator account(s) exist"
  WITH_TOTP=$(api /api/v1/users | jq -r '[.[] | select(.is_admin and .totp_enabled)] | length' 2>/dev/null || echo 0)
  [[ ${WITH_TOTP:-0} -gt 0 ]] && ok "$WITH_TOTP of them have TOTP" \
                              || warn "no administrator has TOTP enabled"
else
  warn "no administrator account — every action is attributed to 'admin-token'"
fi

# --------------------------------------------------------------------------- #
section "Dataplane"

DESIRED=$(api /api/v1/dashboard | jq -r '.ruleset.digest' 2>/dev/null)
APPLIED=$(api /api/v1/dashboard | jq -r '.ruleset.applied_digest' 2>/dev/null)
IN_SYNC=$(api /api/v1/dashboard | jq -r '.ruleset.in_sync' 2>/dev/null)

if [[ $IN_SYNC == true ]]; then
  ok "the agent has applied the current ruleset (${DESIRED:0:12})"
elif grep -q '^FOXGUARD_AGENT_DRY_RUN=true' "$CONFDIR/agent.env" 2>/dev/null; then
  warn "the agent is in DRY RUN — nothing is being enforced yet"
else
  bad "drift: database wants ${DESIRED:0:12}, agent last applied ${APPLIED:0:12}"
fi

if "$NFT" list table inet "${FOXGUARD_NFT_TABLE_NAME:-foxguard}" >/dev/null 2>&1; then
  ok "table inet ${FOXGUARD_NFT_TABLE_NAME:-foxguard} is live"

  # The one rule that keeps SSH alive if it does not transit the tunnel.
  if "$NFT" list table inet "${FOXGUARD_NFT_TABLE_NAME:-foxguard}" 2>/dev/null \
     | grep -q "iifname != \"$WG_IF\" accept"; then
    ok "non-tunnel traffic is accepted before anything else"
  else
    bad "the 'iifname != \"$WG_IF\" accept' guard is missing from the live table"
  fi

  if "$NFT" list table inet "${FOXGUARD_NFT_TABLE_NAME:-foxguard}" 2>/dev/null \
     | grep -qE 'hook (input|forward) .*policy drop'; then
    bad "a base chain uses 'policy drop' — this can cut your management access"
  else
    ok "base chains use 'policy accept' with an explicit final drop"
  fi
else
  warn "table inet foxguard is not loaded (expected while the agent is in dry run)"
fi

OTHER=$("$NFT" list ruleset 2>/dev/null | grep -c '^table' )
ok "$OTHER nftables table(s) present in total — Foxguard never flushes the others"

# --------------------------------------------------------------------------- #
section "WireGuard"

if ip link show "$WG_IF" >/dev/null 2>&1; then
  ok "interface $WG_IF is up"
  LIVE=$(wg show "$WG_IF" peers 2>/dev/null | wc -l)
  WANTED=$(curl -sf -m 10 -H "Authorization: Bearer ${FOXGUARD_AGENT_API_TOKEN:-}" \
           "$API/api/v1/agent/state" 2>/dev/null | jq -r '.wg_peers | length' 2>/dev/null)
  if [[ -n ${WANTED:-} && $LIVE == "$WANTED" ]]; then
    ok "$LIVE peer(s) on the interface, matching what the control plane wants"
  elif [[ -n ${WANTED:-} ]]; then
    warn "$LIVE peer(s) on the interface, control plane wants $WANTED"
  else
    warn "could not read the agent state to compare peers"
  fi
else
  bad "interface $WG_IF does not exist"
fi

if [[ $(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null) == 1 ]]; then
  ok "IPv4 forwarding is on"
else
  bad "IPv4 forwarding is off — peers cannot route through this gateway"
fi

# --------------------------------------------------------------------------- #
section "Portal exposure"

# The portal identifies peers by source address, so a proxy in front of it or a
# trusted forwarded header would let anyone claim to be any peer.
CODE=$(curl -s -o /dev/null -w '%{http_code}' -m 10 \
       -H "X-Forwarded-For: $TUNNEL_IP" "$API/api/v1/portal/status" 2>/dev/null)
[[ $CODE == 403 ]] && ok "a forwarded header is refused (got $CODE)" \
                   || bad "a forwarded header was NOT refused (got $CODE)"

CODE=$(curl -s -o /dev/null -w '%{http_code}' -m 10 "$API/api/v1/portal/status" 2>/dev/null)
[[ $CODE == 403 ]] && ok "the portal refuses a non-peer address (got $CODE)" \
                   || warn "the portal answered $CODE from this host — expected 403"

if [[ -n ${FOXGUARD_PORTAL_STATIC_DIR:-} ]]; then
  curl -sf -m 10 "$API/" 2>/dev/null | grep -q '<title>' \
    && ok "the captive portal page is served" \
    || bad "FOXGUARD_PORTAL_STATIC_DIR is set but the portal does not render"
else
  warn "no portal bundle configured — users would need curl to sign in"
fi

# --------------------------------------------------------------------------- #
section "Sessions"

if [[ ${FOXGUARD_SESSION_SWEEP_ENABLED:-true} == true ]]; then
  ok "session expiry runs in the API (every ${FOXGUARD_SESSION_SWEEP_INTERVAL_SECONDS:-60}s)"
else
  warn "session expiry is disabled — make sure a cron calls /api/v1/sessions/sweep"
fi

ACTIVE=$(api /api/v1/sessions | jq -r 'length' 2>/dev/null || echo "?")
ok "${ACTIVE} device session(s) currently active"

# --------------------------------------------------------------------------- #
printf '\n%s%d passed, %d warnings, %d failed%s\n\n' "$B" "$PASS" "$WARN" "$FAILED" "$N"
[[ $FAILED -eq 0 ]] || exit 1
