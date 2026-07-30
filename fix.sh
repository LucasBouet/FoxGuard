#!/usr/bin/env bash
#
# Throwaway repair script for the 2026-07-30 staging-pool problem.
# Run on the gateway, as root:
#
#     bash fix.sh            # everything, in order, with prompts
#     bash fix.sh pool       # 1. drop the staging pool, restart the API
#     bash fix.sh peer       # 2. re-register foxguard-admin in the right pool
#     bash fix.sh password   # 3. reset the admin password
#     bash fix.sh check      # 4. run the healthcheck
#
# Delete this file when you are done -- it is not part of Foxguard.
#
set -euo pipefail

R=$'\033[31m'; G=$'\033[32m'; Y=$'\033[33m'; B=$'\033[1m'; N=$'\033[0m'
say()  { printf '\n%s== %s ==%s\n' "$B" "$*" "$N"; }
ok()   { printf '  %s✓%s %s\n' "$G" "$N" "$*"; }
warn() { printf '  %s!%s %s\n' "$Y" "$N" "$*"; }
die()  { printf '\n%s✗ %s%s\n\n' "$R" "$*" "$N" >&2; exit 1; }
ask()  { local a=""; read -rp "  $1 [y/N] " a </dev/tty || die "no terminal to prompt on — run this interactively."
         [[ ${a,,} == y ]]; }

ENVFILE=/etc/foxguard/backend.env
[[ $EUID -eq 0 ]]   || die "run this as root."
[[ -r $ENVFILE ]]   || die "cannot read $ENVFILE — is Foxguard installed on this box?"
command -v jq >/dev/null || die "jq is missing: apt-get install -y jq"

# shellcheck disable=SC1090
reload_env() { set -a; . "$ENVFILE"; set +a
  API="http://${FOXGUARD_WG_GATEWAY_IP}:${FOXGUARD_PORTAL_PORT:-8080}"
  AUTH=(-H "Authorization: Bearer $FOXGUARD_ADMIN_API_TOKEN")
  JSON=("${AUTH[@]}" -H 'Content-Type: application/json')
}
reload_env

wait_for_api() {
  local tries=40
  while (( tries-- > 0 )); do
    curl -sf -m 2 "$API/healthz" >/dev/null && return 0
    sleep 0.5
  done
  return 1
}

# --------------------------------------------------------------------------- #
# 1. the staging pool
#
# An address is allocated once, at registration, and never changes, so with a
# staging pool set *every* peer lives in it permanently. Outside the prefix wg0
# carries, that means unroutable: wg syncconf adds no routes, so the only route
# to the tunnel is the one the interface address implies. The handshake succeeds
# and nothing else does.
# --------------------------------------------------------------------------- #
step_pool() {
  say "1. Staging pool"

  if ! grep -q '^FOXGUARD_WG_STAGING_POOL_V4=' "$ENVFILE"; then
    ok "no staging pool configured — nothing to do"
    return 0
  fi

  local current
  current=$(sed -n 's/^FOXGUARD_WG_STAGING_POOL_V4=//p' "$ENVFILE" | head -1)
  local wgif=${FOXGUARD_WG_INTERFACE:-wg0}
  printf '  %-16s %s\n' "$wgif carries" \
    "$(ip -4 -o addr show "$wgif" 2>/dev/null | awk '{print $4}' | paste -sd' ')"
  printf '  peer pool        %s\n' "${FOXGUARD_WG_POOL_V4:-<unset>}"
  printf '  staging pool     %s   %s<- to be removed%s\n' "$current" "$Y" "$N"

  ask "Remove the staging pool and restart the API?" || { warn "skipped"; return 0; }

  cp -a "$ENVFILE" "$ENVFILE.bak-$(date +%Y%m%d%H%M%S)"
  sed -i '/^FOXGUARD_WG_STAGING_POOL_V4=/d' "$ENVFILE"
  ok "removed (backup kept next to $ENVFILE)"

  systemctl restart foxguard-api
  wait_for_api || die "the API did not come back. Check: journalctl -u foxguard-api -n 40"
  reload_env
  ok "API restarted; new peers will be allocated in ${FOXGUARD_WG_POOL_V4}"
}

# --------------------------------------------------------------------------- #
# 2. the bootstrap peer
#
# There is no way to move an existing peer: the address is assigned at
# registration and PeerUpdate has no tunnel_ip field. Delete and re-register.
# --------------------------------------------------------------------------- #
step_peer() {
  say "2. Re-register the bootstrap peer"

  local name=${PEER_NAME:-foxguard-admin} peers old owner ip priv pub
  peers=$(curl -sf "${AUTH[@]}" "$API/api/v1/peers") || die "cannot reach the API at $API"
  old=$(jq -r   --arg n "$name" '.[]|select(.name==$n)|.id'            <<<"$peers")
  owner=$(jq -r --arg n "$name" '.[]|select(.name==$n)|.owner_user_id' <<<"$peers")

  if [[ -z $old ]]; then
    warn "no peer named '$name'. Peers that exist (first 20):"
    jq -r '.[]|"      \(.name)  \(.peer_type)  \(.state)  \(.tunnel_ip)"' <<<"$peers" | head -20
    warn "re-run as: PEER_NAME=<name> bash fix.sh peer"
    return 0
  fi

  jq -r --arg n "$name" '.[]|select(.name==$n)|"  current: \(.name)  \(.peer_type)  \(.state)  \(.tunnel_ip)"' <<<"$peers"
  ask "Delete it and register a new one with a fresh keypair?" || { warn "skipped"; return 0; }

  curl -sf -X DELETE "${AUTH[@]}" "$API/api/v1/peers/$old" >/dev/null
  priv=$(wg genkey); pub=$(printf '%s' "$priv" | wg pubkey)
  ip=$(curl -sf -X POST "${JSON[@]}" "$API/api/v1/peers" \
       -d "{\"name\":\"$name\",\"peer_type\":\"user\",\"wg_public_key\":\"$pub\",\"owner_user_id\":\"$owner\",\"tags\":[\"bootstrap\"]}" \
       | jq -r .tunnel_ip)
  [[ -n $ip && $ip != null ]] || die "re-registration failed. The old peer is gone; add one from the dashboard."
  ok "re-registered at $ip (owner and tags preserved)"

  systemctl restart foxguard-agent
  ok "agent restarted"

  cat <<EOF

  ${B}In the .conf on your client, change ONLY these two lines:${N}

    Address    = $ip/32
    PrivateKey = $priv

  Leave Endpoint, PublicKey and AllowedIPs alone -- they were already correct.

EOF
}

# --------------------------------------------------------------------------- #
# 3. the admin password
#
# The installer generates it and prints it once; it is never written to disk.
# The admin API token in $ENVFILE is the way back in.
# --------------------------------------------------------------------------- #
step_password() {
  say "3. Admin password"

  local users id name newpass
  users=$(curl -sf "${AUTH[@]}" "$API/api/v1/users") || die "cannot reach the API at $API"
  name=${ADMIN_USER:-admin}
  id=$(jq -r --arg u "$name" '.[]|select(.username==$u)|.id' <<<"$users")

  if [[ -z $id ]]; then
    warn "no account named '$name'. Administrators that exist:"
    jq -r '.[]|select(.is_admin)|"      \(.username)"' <<<"$users" | head -20
    warn "re-run as: ADMIN_USER=<name> bash fix.sh password"
    return 0
  fi

  ask "Set a new random password for '$name'?" || { warn "skipped"; return 0; }

  newpass=$(openssl rand -base64 18)
  curl -sf -X PATCH "${JSON[@]}" "$API/api/v1/users/$id" \
    -d "{\"password\":\"$newpass\"}" >/dev/null || die "the API refused the change."

  cat <<EOF

  ${B}Dashboard${N}  http://${FOXGUARD_WG_GATEWAY_IP}:3000
    username   $name
    password   $newpass

  Sign in (top right), then enable TOTP in Accounts -> Manage. Until you sign
  in, the dashboard acts as 'admin-token' and the audit log cannot name you.

EOF
}

# --------------------------------------------------------------------------- #
# 4. verify
# --------------------------------------------------------------------------- #
step_check() {
  say "4. Healthcheck"

  local hc
  for hc in "$(dirname "$(readlink -f "$0")")/deploy/foxguard-healthcheck.sh" \
            /opt/foxguard/src/deploy/foxguard-healthcheck.sh; do
    [[ -x $hc ]] || continue
    bash "$hc" || true
    return 0
  done
  warn "foxguard-healthcheck.sh not found — git pull, then run it from deploy/"
}

case ${1:-all} in
  pool)     step_pool ;;
  peer)     step_peer ;;
  password) step_password ;;
  check)    step_check ;;
  all)      step_pool; step_peer; step_password; step_check ;;
  *)        die "usage: bash fix.sh [pool|peer|password|check|all]" ;;
esac
