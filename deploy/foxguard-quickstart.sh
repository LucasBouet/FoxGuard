#!/usr/bin/env bash
#
# Deploy Foxguard on a fresh Linux box without cloning anything.
#
#   curl -fsSLO https://raw.githubusercontent.com/LucasBouet/FoxGuard/main/deploy/foxguard-quickstart.sh
#   less foxguard-quickstart.sh          # it installs Docker and edits your firewall
#   bash foxguard-quickstart.sh
#
# It downloads the three files a deployment actually needs -- docker-compose.yml,
# .env.example and gen-env.sh -- generates the secrets and the interface keypair,
# and starts the stack with the agent in DRY RUN.
#
# Dry run is not caution theatre. The agent programs this machine's nftables,
# and you are almost certainly reading this over SSH. The last step turns it off,
# deliberately, once you have seen what it would do.
#
# Override the source with FOXGUARD_BASE_URL (a raw.githubusercontent URL, or
# any HTTP root serving those three files).
#
set -euo pipefail

BASE=${FOXGUARD_BASE_URL:-https://raw.githubusercontent.com/LucasBouet/FoxGuard/main}
DIR=${FOXGUARD_DIR:-$HOME/foxguard}

if [[ -t 1 ]]; then G=$'\033[32m'; Y=$'\033[33m'; B=$'\033[1m'; N=$'\033[0m'
else G=""; Y=""; B=""; N=""; fi
step() { printf '\n%s==> %s%s\n' "$B" "$*" "$N"; }
warn() { printf '%s  ! %s%s\n' "$Y" "$*" "$N"; }
die()  { printf '\n%sFailed:%s %s\n\n' "$Y" "$N" "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] && die "run this as a normal user with sudo, not as root — the
  files it writes are yours, and one of them is a credential."
sudo -n true 2>/dev/null || sudo true || die "this needs sudo."

# --------------------------------------------------------------------------- #
step "Docker"
# --------------------------------------------------------------------------- #
if command -v docker >/dev/null 2>&1; then
  echo "  already here: $(docker --version)"
else
  curl -fsSL https://get.docker.com | sudo sh
  sudo usermod -aG docker "$USER"
  warn "added $USER to the docker group; that takes effect at your next login."
  warn "until then this script uses sudo."
fi
sudo docker compose version >/dev/null 2>&1 || die "the docker compose plugin is missing."

# --------------------------------------------------------------------------- #
step "Host prerequisites"
# --------------------------------------------------------------------------- #
# Neither can be done from inside a container: /proc/sys is read-only there and
# loading a module needs CAP_SYS_MODULE, which this deployment does not ask for.
sudo modprobe wireguard || die "no wireguard module on this kernel. Install
  wireguard-dkms, or use a kernel that has it (anything 5.6+ normally does)."
echo wireguard | sudo tee /etc/modules-load.d/wireguard.conf >/dev/null

sudo sysctl -q -w net.ipv4.ip_forward=1
echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/99-foxguard.conf >/dev/null
echo "  wireguard module loaded, ip_forward on"

# --------------------------------------------------------------------------- #
step "Files"
# --------------------------------------------------------------------------- #
mkdir -p "$DIR/docker" "$DIR/certs"
cd "$DIR"
for f in docker-compose.yml .env.example docker/gen-env.sh; do
  curl -fsSL "$BASE/$f" -o "$f" || die "could not fetch $f from $BASE"
  echo "  $f"
done
chmod +x docker/gen-env.sh

# A compose file that also knows how to build is right in the repository and
# wrong here: there is no source tree to build from, so a failed pull would turn
# into a confusing build error instead of "that image is not published".
python3 - <<'PY' || die "could not strip the build sections from docker-compose.yml"
import re, pathlib
p = pathlib.Path("docker-compose.yml")
text = p.read_text()
out, skip = [], False
for line in text.splitlines(True):
    if re.match(r"^    build:\s*$", line):
        skip = True
        continue
    if skip:
        if re.match(r"^      \S", line):
            continue
        skip = False
    out.append(line)
p.write_text("".join(out))
PY
echo "  docker-compose.yml set to pull, not build"

# --------------------------------------------------------------------------- #
step "Secrets"
# --------------------------------------------------------------------------- #
if [[ -f .env ]]; then
  echo "  .env already here, leaving it alone"
else
  ./docker/gen-env.sh
fi

# --------------------------------------------------------------------------- #
step "This machine"
# --------------------------------------------------------------------------- #
WAN=$(ip -o route get 1.1.1.1 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -1)
PUBIP=$(curl -fsS --max-time 5 https://api.ipify.org 2>/dev/null || true)

set_env() {
  local key=$1 val=$2 tmp
  tmp=$(mktemp)
  while IFS= read -r line; do
    if [[ $line == "$key="* ]]; then printf '%s=%s\n' "$key" "$val"; else printf '%s\n' "$line"; fi
  done < .env > "$tmp"
  mv "$tmp" .env
  chmod 0600 .env
}

[[ -n $WAN ]] && { set_env FOXGUARD_WAN_INTERFACE "$WAN"; echo "  WAN interface: $WAN"; }
if [[ -n $PUBIP ]]; then
  set_env FOXGUARD_WG_ENDPOINT_HOST "$PUBIP"
  echo "  public address: $PUBIP"
else
  warn "could not work out this box's public address — set"
  warn "FOXGUARD_WG_ENDPOINT_HOST in .env to whatever forwards udp/51820 here."
fi
set_env FOXGUARD_AGENT_DRY_RUN true

# --------------------------------------------------------------------------- #
step "Start"
# --------------------------------------------------------------------------- #
sudo docker compose pull 2>&1 | tail -3 || die "could not pull the images. If they
  are not published yet, clone the repository and run 'docker compose build'
  instead — see docs/docker.md."
sudo docker compose up -d
sleep 20
sudo docker compose ps --format 'table {{.Service}}\t{{.Status}}'

cat <<NEXT

${G}Up, with the agent in dry run.${N}  Everything lives in $DIR.

  1. See what it would apply to this machine's firewall:

       sudo docker compose logs gateway | grep -i 'dry run'

  2. Happy with it? Turn the dry run off — ${B}keep this SSH session open${N}:

       sed -i 's/^FOXGUARD_AGENT_DRY_RUN=true/FOXGUARD_AGENT_DRY_RUN=false/' .env
       sudo docker compose up -d gateway

  3. Make yourself an administrator, then blank FOXGUARD_ADMIN_API_TOKEN:

       source .env
       curl -sf -X POST "http://\$FOXGUARD_TUNNEL_IP:8080/api/v1/users" \\
         -H "Authorization: Bearer \$FOXGUARD_ADMIN_API_TOKEN" \\
         -H 'Content-Type: application/json' \\
         -d '{"username":"you","password":"<12 characters minimum>","is_admin":true}'

  4. Open udp/51820 inbound on whatever is in front of this box. Nothing in the
     logs will tell you it is closed; peers will simply never handshake.

  The dashboard is on the tunnel address, port 3000, and so is everything else.
  From elsewhere:  ssh -L 3000:\$FOXGUARD_TUNNEL_IP:3000 <this box>

${Y}.env is a credential.${N} Admin token, database password, and the WireGuard
private key that is this gateway's identity. Back it up like you back up root.

NEXT
