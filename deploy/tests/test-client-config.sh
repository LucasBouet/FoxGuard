#!/usr/bin/env bash
#
# The installer's client-config renderer, checked against the dashboard's.
#
#   ./deploy/tests/test-client-config.sh      (or: make test-install-config)
#
# `--bootstrap-peer` and the dashboard's generator both turn one
# GET /peers/{id}/config-profile response into a `.conf`. They have to, because
# the API returns structured data and never finished text -- that is the whole
# reason a private key cannot be handed to the server. The cost is two
# renderers, one in jq and one in TypeScript, and the risk is that they drift:
# the browser learns about MTU, the installer keeps writing configs without it,
# and the only symptom is a device that works slightly worse than the ones
# provisioned the other way.
#
# So every case below is rendered twice, by both implementations, and compared
# byte for byte. Two differences are deliberate and are handled here rather than
# hidden:
#
#   * comments -- the browser's say the key was generated there, and the
#     installer's say the opposite, because it was. Compared with comments off.
#   * incomplete profiles -- the browser throws, since it can offer the button
#     again once the operator fixes the setting; the installer substitutes a
#     placeholder, since it runs once and a file with a visible gap in it beats
#     no file on a terminal that is about to scroll away. Tested separately.
#
# The output is then put through the real `wg-quick strip`, which is the only
# opinion about INI syntax that matters.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
ADMIN=$ROOT/frontend/admin
BUILD=$ADMIN/.test-build

PASS=0
FAIL=0

pass() { printf '  \033[32m✓\033[0m %s\n' "$1"; PASS=$((PASS + 1)); }
bad()  { printf '  \033[31m✗\033[0m %s\n' "$1"; FAIL=$((FAIL + 1)); }
skip() { printf '  \033[33m-\033[0m %s (skipped: %s)\n' "$1" "$2"; }

command -v jq >/dev/null || { echo "jq is required"; exit 1; }

# Only the two rendering functions, not the installation. See the guard's own
# comment in the installer.
FOXGUARD_INSTALL_SOURCE_ONLY=1 . "$ROOT/deploy/foxguard-install.sh"

# --------------------------------------------------------------------------- #
# the profiles, in the shape the API actually returns
# --------------------------------------------------------------------------- #

profile() { # profile <jq-expression-of-overrides>
  jq -c --argjson overrides "$1" '. * $overrides' <<'EOF'
{
  "peer_id": "6f1b7c1e-0000-4000-8000-000000000001",
  "peer_name": "ada-laptop",
  "peer_state": "quarantined",
  "fqdn": null,
  "addresses": ["10.88.0.4/32"],
  "dns": [],
  "mtu": null,
  "server_public_key": "K7hEfUmZ5C3dQ2kR8vN1xY6jL0pT4sW9bA3cD5eF7gI=",
  "endpoint": "203.0.113.9:51820",
  "allowed_ips": ["10.88.0.0/24"],
  "persistent_keepalive": 25,
  "allowed_ips_mode": "routed",
  "excluded_routes": [],
  "warnings": [],
  "complete": true
}
EOF
}

CASES_NAMES=(
  "the plain case"
  "with the internal resolver and a search domain"
  "with a zone route and an MTU"
  "keepalive turned off"
  "dual stack"
  "full tunnel"
  "a carried network left out of AllowedIPs"
)
CASES_OVERRIDES=(
  '{}'
  '{"fqdn":"ada.fox.internal","dns":["10.88.0.1","fox.internal"]}'
  '{"dns":["10.88.0.1","fox.internal"],"mtu":1420,"allowed_ips":["10.88.0.0/24","192.168.30.0/24"]}'
  '{"persistent_keepalive":0}'
  '{"addresses":["10.88.0.4/32","fd00:88::4/128"],"allowed_ips":["10.88.0.0/24","fd00:88::/64"]}'
  '{"allowed_ips":["0.0.0.0/0"],"allowed_ips_mode":"full"}'
  '{"allowed_ips":["10.88.0.0/24"],"excluded_routes":["192.168.30.0/24"],"allowed_ips_mode":"routed","warnings":["192.168.30.0/24 left out of AllowedIPs: this device carries those networks for a zone"]}'
)

KEY="4B2s1XeSt7QhVQ8t0gJ3mP9uY6nC5xZ2wR1kL8dF7aE="

# --------------------------------------------------------------------------- #
# parity with the browser
# --------------------------------------------------------------------------- #

echo
echo "== installer vs dashboard =="

if [[ ! -f $BUILD/src/lib/wg-config.js ]]; then
  if [[ -d $ADMIN/node_modules ]]; then
    ( cd "$ADMIN" && npx tsc -p tsconfig.tests.json >/dev/null )
  fi
fi

if [[ -f $BUILD/src/lib/wg-config.js ]]; then
  DRIVER=$(mktemp); trap 'rm -f "$DRIVER"' EXIT
  cat > "$DRIVER" <<'JS'
// Renders on stdin, exactly as the dashboard does, with the comments off so
// what is compared is the directives.
const { renderClientConfig, configFileName } = require(process.argv[2]);
const profile = JSON.parse(require("node:fs").readFileSync(0, "utf8"));
if (process.argv[4] === "--file-name") {
  process.stdout.write(configFileName(profile));
} else {
  process.stdout.write(renderClientConfig(profile, process.argv[3], { comments: false }));
}
JS

  for i in "${!CASES_NAMES[@]}"; do
    json=$(profile "${CASES_OVERRIDES[$i]}")
    mine=$(render_client_config "$json" "$KEY" "unused:51820" | grep -v '^#')
    theirs=$(printf '%s' "$json" | node "$DRIVER" "$BUILD/src/lib/wg-config.js" "$KEY")
    if [[ $mine == "$(printf '%s' "$theirs")" ]]; then
      pass "${CASES_NAMES[$i]}"
    else
      bad "${CASES_NAMES[$i]}"
      diff <(printf '%s\n' "$mine") <(printf '%s' "$theirs") | sed 's/^/      /' || true
    fi
  done

  echo
  echo "== file names =="
  for name in "ada-laptop" "Ada's MacBook Pro (2019)" "Élise" "a-very-long-device-name-indeed" "!!!"; do
    json=$(profile "$(jq -nc --arg n "$name" '{peer_name:$n}')")
    mine=$(config_file_name "$json")
    theirs=$(printf '%s' "$json" | node "$DRIVER" "$BUILD/src/lib/wg-config.js" "$KEY" --file-name)
    if [[ $mine == "$theirs" ]]; then
      pass "$name → $mine"
    else
      bad "$name → $mine, but the dashboard says $theirs"
    fi
  done
else
  skip "parity with the dashboard" "frontend/admin is not built (npm ci in frontend/admin)"
fi

# --------------------------------------------------------------------------- #
# what only the installer does
# --------------------------------------------------------------------------- #

echo
echo "== the installer's own behaviour =="

conf=$(render_client_config "$(profile '{"dns":["10.88.0.1","fox.internal"],"fqdn":"ada.fox.internal"}')" "$KEY" "unused:51820")
if grep -q '^DNS = 10.88.0.1, fox.internal$' <<<"$conf"; then
  pass "the resolver and the search domain reach the file"
else
  bad "no DNS line -- this is the bug --bootstrap-peer had"
fi
if grep -q '^# ada-laptop (ada.fox.internal)$' <<<"$conf"; then
  pass "the name inside the zone is in the header comment"
else
  bad "the fqdn is missing from the header"
fi

# A gateway that has never been told its public address. The dashboard refuses;
# this must still print something, with the hole visible.
incomplete=$(profile '{"endpoint":null,"complete":false}')
conf=$(render_client_config "$incomplete" "$KEY" "<your-public-address>:51820")
if grep -q '^Endpoint = <your-public-address>:51820$' <<<"$conf"; then
  pass "a missing endpoint becomes a placeholder, not a crash"
else
  bad "the endpoint placeholder is missing"
fi

conf=$(render_client_config "$(profile '{"server_public_key":null}')" "$KEY" "unused:51820")
if grep -q '^PublicKey = <gateway-public-key>$' <<<"$conf"; then
  pass "a missing gateway key becomes a placeholder too"
else
  bad "the public-key placeholder is missing"
fi

# The private key is the one thing that must be verbatim: a mangled key is a
# tunnel that never handshakes, with nothing in any log to say why.
conf=$(render_client_config "$(profile '{}')" "$KEY" "unused:51820")
if grep -qx "PrivateKey = $KEY" <<<"$conf"; then
  pass "the private key is written verbatim"
else
  bad "the private key was mangled"
fi

# --------------------------------------------------------------------------- #
# the only opinion about syntax that counts
# --------------------------------------------------------------------------- #

echo
echo "== wg-quick =="

if command -v wg-quick >/dev/null 2>&1; then
  workdir=$(mktemp -d)
  for i in "${!CASES_NAMES[@]}"; do
    json=$(profile "${CASES_OVERRIDES[$i]}")
    render_client_config "$json" "$KEY" "unused:51820" > "$workdir/wgtest.conf"
    if out=$(wg-quick strip "$workdir/wgtest.conf" 2>&1); then
      if grep -q "^PublicKey = " <<<"$out"; then
        pass "wg-quick strip accepts: ${CASES_NAMES[$i]}"
      else
        bad "wg-quick strip lost the peer: ${CASES_NAMES[$i]}"
      fi
    else
      bad "wg-quick strip rejected: ${CASES_NAMES[$i]}"
      printf '%s\n' "$out" | sed 's/^/      /'
    fi
  done
  rm -rf "$workdir"
else
  skip "wg-quick strip" "wireguard-tools is not installed"
fi

echo
printf '%d passed, %d failed\n\n' "$PASS" "$FAIL"
[[ $FAIL -eq 0 ]]
