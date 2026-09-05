#!/usr/bin/env bash
#
# The installer's answer file, written and read back.
#
#   ./deploy/tests/test-install-profile.sh   (or: make test-install-profile)
#
# `--profile` exists so that updating a gateway does not depend on somebody
# remembering the flags they typed months ago, and so a second gateway can be
# built from the first. Both of those are only true if the file the installer
# writes is a file the installer can read: a key it emits and refuses to parse
# turns an update into an error at the worst possible moment, and a key it
# parses but never emits silently reverts to a default on the next run.
#
# So the round trip is the test. Everything else here is about what must NOT be
# in the file -- the Cloudflare token, and the two bootstrap actions that would
# abort a re-run because they refuse to touch an interface that already exists.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

PASS=0
FAIL=0
pass() { printf '  \033[32m✓\033[0m %s\n' "$1"; PASS=$((PASS + 1)); }
bad()  { printf '  \033[31m✗\033[0m %s\n' "$1"; FAIL=$((FAIL + 1)); }

# The functions only: nothing is parsed, checked or installed. See the guard's
# own comment in the installer.
FOXGUARD_INSTALL_SOURCE_ONLY=1 . "$ROOT/deploy/foxguard-install.sh"

# The installer's own `ok` and `die` come with it -- they are defined above the
# guard. `die` exits, so every refusal below is checked in a subshell; the round
# trip cannot be, because load_profile has to assign in this shell.

printf '\nAnswer files\n'

# --------------------------------------------------------------------------- #
# the round trip
# --------------------------------------------------------------------------- #

# Deliberately not the defaults: a round trip that only ever sees default values
# passes even when write_profile emits nothing at all.
CONFDIR=/etc/foxguard
PREFIX=/opt/fg-test
WG_IF=wg7
TUNNEL_IP=10.13.37.1
POOL=10.13.37.0/24
STAGING_POOL=10.13.38.0/24
WAN_IF=ens18
ENDPOINT=vpn.example.test
LISTEN_PORT=51821
API_PORT=8081
DASHBOARD_PORT=3001
ADMIN_USER=ada
SKIP_FRONTEND=1
DNS_ENABLED=1
DNS_ZONE=lab.internal
DNS_MODE="split"
DNS_UPSTREAMS=1.1.1.1,9.9.9.9
PROXY_ENABLED=1
PROXY_DOMAIN=lab.example.test
PROXY_EXTERNAL_BINDS=203.0.113.10,203.0.113.11
SSO_ENABLED=1
GEO_NOW=yes
ACME_EMAIL=ada@example.test
ACME_CF_TOKEN=cf-secret-token-value

VARS=(PREFIX WG_IF TUNNEL_IP POOL STAGING_POOL WAN_IF ENDPOINT LISTEN_PORT
      API_PORT DASHBOARD_PORT ADMIN_USER SKIP_FRONTEND DNS_ENABLED DNS_ZONE
      DNS_MODE DNS_UPSTREAMS PROXY_ENABLED PROXY_DOMAIN PROXY_EXTERNAL_BINDS
      SSO_ENABLED GEO_NOW)

declare -A BEFORE=()
for v in "${VARS[@]}"; do BEFORE[$v]=${!v}; done

write_profile "$WORK/p.conf" >/dev/null

# Wipe every one of them, so a key the writer forgot cannot be "kept" by the
# variable still holding its old value.
for v in "${VARS[@]}"; do printf -v "$v" '%s' "ZAPPED"; done

load_profile "$WORK/p.conf" >/dev/null

drift=0
for v in "${VARS[@]}"; do
  if [[ ${!v} != "${BEFORE[$v]}" ]]; then
    bad "$v: wrote '${BEFORE[$v]}', read back '${!v}'"
    drift=1
  fi
done
[[ $drift -eq 0 ]] && pass "every answer survives write then read (${#VARS[@]} keys)"

# --------------------------------------------------------------------------- #
# what must not be in it
# --------------------------------------------------------------------------- #

if grep -q "cf-secret-token-value" "$WORK/p.conf"; then
  bad "the Cloudflare token is in the file"
else
  pass "the Cloudflare token is not in the file"
fi

for action in bootstrap_wireguard bootstrap_peer; do
  if grep -qE "^${action}=" "$WORK/p.conf"; then
    bad "$action is recorded; replaying it would abort the next run"
  else
    pass "$action is not recorded (an action, not configuration)"
  fi
done

# --------------------------------------------------------------------------- #
# refusals
# --------------------------------------------------------------------------- #

refuses() { # refuses <label> <file-content>
  printf '%s' "$2" > "$WORK/bad.conf"
  if ( load_profile "$WORK/bad.conf" ) >/dev/null 2>&1; then
    bad "$1 is accepted"
  else
    pass "$1 is refused"
  fi
}

refuses "an unknown key"        $'wg_interface=wg0\nproxy_domian=typo\n'
refuses "a non-boolean boolean" $'dns=maybe\n'
refuses "a line with no ="      $'wg_interface\n'

if ( load_profile "$WORK/nope.conf" ) >/dev/null 2>&1; then
  bad "a missing file is accepted"
else
  pass "a missing file is refused"
fi

# Comments, blank lines, padding and CRLF are all things a hand-edited file
# will contain, and this one is meant to be hand-edited.
printf '# a comment\r\n\r\n  wg_interface  =  wg9  \r\n' > "$WORK/messy.conf"
WG_IF=ZAPPED
if load_profile "$WORK/messy.conf" >/dev/null && [[ $WG_IF == wg9 ]]; then
  pass "comments, padding and CRLF are tolerated"
else
  bad "a hand-edited file is misread (got '$WG_IF')"
fi

printf '\n%d passed, %d failed\n\n' "$PASS" "$FAIL"
[[ $FAIL -eq 0 ]]
