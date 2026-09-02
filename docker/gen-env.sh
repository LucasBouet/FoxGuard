#!/usr/bin/env bash
#
# Fill .env with the secrets a container deployment needs.
#
#   ./docker/gen-env.sh              # writes ./.env from ./.env.example
#   ./docker/gen-env.sh --force      # overwrite an existing .env
#   ./docker/gen-env.sh --print      # show what it would generate, write nothing
#
# What it generates, and why each one has to exist before the first start:
#
#   POSTGRES_PASSWORD          the database's own credential
#   FOXGUARD_ADMIN_API_TOKEN   administers the API until an account exists
#   FOXGUARD_AGENT_API_TOKEN   the only thing that distinguishes the agent from
#                              anyone else who can reach the control plane
#   FOXGUARD_PROXY_SSO_SECRET  signs the SSO cookie; the proxy verifies with the
#                              same value, so both halves must agree
#   FOXGUARD_WG_PRIVATE_KEY    this gateway's identity
#   FOXGUARD_WG_PUBLIC_KEY     the same key's public half, which the control
#                              plane cannot derive and refuses to hand out
#                              client configurations without
#
# The keypair is generated here rather than on first boot on purpose: the two
# halves go to two different containers, and a gateway that mints its own key
# after the API has already been told a different one produces client
# configurations that connect to nothing.
#
set -euo pipefail

# Two layouts, because this script is handed around on its own. In the
# repository it lives in docker/ and the template is one level up; downloaded
# next to a bare docker-compose.yml, both are in the current directory. Guessing
# beats making whoever is deploying pass a flag they cannot know about.
if [[ -f "$(dirname "$0")/../.env.example" ]]; then
  cd "$(dirname "$0")/.."
elif [[ -f "$(dirname "$0")/.env.example" ]]; then
  cd "$(dirname "$0")"
fi

FORCE=false
PRINT_ONLY=false
TEMPLATE=.env.example
TARGET=.env

while [[ $# -gt 0 ]]; do
  case $1 in
    --force) FORCE=true; shift ;;
    --print) PRINT_ONLY=true; shift ;;
    -h|--help) sed -n '3,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) printf 'unknown option: %s\n' "$1" >&2; exit 64 ;;
  esac
done

if [[ -t 1 ]]; then G=$'\033[32m'; Y=$'\033[33m'; B=$'\033[1m'; N=$'\033[0m'
else G=""; Y=""; B=""; N=""; fi

[[ -f $TEMPLATE ]] || { printf 'no %s here — run this from the repository.\n' "$TEMPLATE" >&2; exit 1; }
if [[ -f $TARGET && $FORCE == false && $PRINT_ONLY == false ]]; then
  printf '%s already exists. Refusing to overwrite it: it holds the tokens this\n' "$TARGET" >&2
  printf 'deployment is already using. Pass --force if you mean to replace them.\n' >&2
  exit 1
fi

# --------------------------------------------------------------------------- #
# generators
# --------------------------------------------------------------------------- #

# URL-safe on purpose: the database password is substituted into a URI, and a
# `/` or a `+` there produces a connection error that looks like a wrong
# password rather than a quoting bug.
secret() {
  if command -v python3 >/dev/null 2>&1; then
    python3 -c 'import secrets; print(secrets.token_urlsafe(32))'
  else
    openssl rand -base64 36 | tr '+/' '-_' | tr -d '='
  fi
}

# `wg` when it is here, X25519 through openssl when it is not -- verified to
# produce the same public key for the same private key, which is what lets a
# machine without wireguard-tools still prepare a deployment.
wg_private() {
  if command -v wg >/dev/null 2>&1; then
    wg genkey
  else
    openssl genpkey -algorithm X25519 2>/dev/null \
      | openssl pkey -outform DER 2>/dev/null | tail -c 32 | base64
  fi
}

wg_public() {
  local priv=$1
  if command -v wg >/dev/null 2>&1; then
    printf '%s\n' "$priv" | wg pubkey
  else
    # Rebuild a DER-encoded private key around the raw 32 bytes so openssl will
    # read it back and derive the public half.
    { printf '\x30\x2e\x02\x01\x00\x30\x05\x06\x03\x2b\x65\x6e\x04\x22\x04\x20'
      printf '%s' "$priv" | base64 -d
    } | openssl pkey -inform DER -pubout -outform DER 2>/dev/null | tail -c 32 | base64
  fi
}

PG_PASS=$(secret)
ADMIN_TOKEN=$(secret)
AGENT_TOKEN=$(secret)
SSO_SECRET=$(openssl rand -base64 48 2>/dev/null || secret)
WG_PRIV=$(wg_private)
WG_PUB=$(wg_public "$WG_PRIV")

[[ -n $WG_PRIV && -n $WG_PUB ]] || {
  printf 'could not generate a WireGuard keypair (needs wg or openssl).\n' >&2
  exit 1
}

if [[ $PRINT_ONLY == true ]]; then
  printf '%sWould generate:%s\n' "$B" "$N"
  printf '  POSTGRES_PASSWORD        %s\n' "$PG_PASS"
  printf '  FOXGUARD_ADMIN_API_TOKEN %s\n' "$ADMIN_TOKEN"
  printf '  FOXGUARD_AGENT_API_TOKEN %s\n' "$AGENT_TOKEN"
  printf '  FOXGUARD_PROXY_SSO_SECRET %s\n' "$SSO_SECRET"
  printf '  FOXGUARD_WG_PRIVATE_KEY  %s\n' "$WG_PRIV"
  printf '  FOXGUARD_WG_PUBLIC_KEY   %s\n' "$WG_PUB"
  exit 0
fi

# --------------------------------------------------------------------------- #
# write
# --------------------------------------------------------------------------- #
# Line by line rather than with sed: these values contain `/`, `+` and `=`, and
# every one of those is a sed metacharacter or delimiter waiting to corrupt a
# credential silently.

PG_USER=$(grep -E '^POSTGRES_USER=' "$TEMPLATE" | cut -d= -f2-)
PG_DB=$(grep -E '^POSTGRES_DB=' "$TEMPLATE" | cut -d= -f2-)
PG_PORT=$(grep -E '^POSTGRES_PORT=' "$TEMPLATE" | cut -d= -f2-)
DB_URL="postgresql+psycopg://${PG_USER:-foxguard}:${PG_PASS}@127.0.0.1:${PG_PORT:-5432}/${PG_DB:-foxguard}"

umask 077
: > "$TARGET"
while IFS= read -r line; do
  case $line in
    POSTGRES_PASSWORD=*)         printf 'POSTGRES_PASSWORD=%s\n' "$PG_PASS" ;;
    FOXGUARD_DATABASE_URL=*)     printf 'FOXGUARD_DATABASE_URL=%s\n' "$DB_URL" ;;
    FOXGUARD_ADMIN_API_TOKEN=*)  printf 'FOXGUARD_ADMIN_API_TOKEN=%s\n' "$ADMIN_TOKEN" ;;
    FOXGUARD_AGENT_API_TOKEN=*)  printf 'FOXGUARD_AGENT_API_TOKEN=%s\n' "$AGENT_TOKEN" ;;
    FOXGUARD_PROXY_SSO_SECRET=*) printf 'FOXGUARD_PROXY_SSO_SECRET=%s\n' "$SSO_SECRET" ;;
    FOXGUARD_WG_PRIVATE_KEY=*)   printf 'FOXGUARD_WG_PRIVATE_KEY=%s\n' "$WG_PRIV" ;;
    FOXGUARD_WG_PUBLIC_KEY=*)    printf 'FOXGUARD_WG_PUBLIC_KEY=%s\n' "$WG_PUB" ;;
    *)                           printf '%s\n' "$line" ;;
  esac
done < "$TEMPLATE" >> "$TARGET"
chmod 0600 "$TARGET"

cat <<SUMMARY

${G}Wrote $TARGET${N} (mode 0600) with fresh secrets and a new interface keypair.

  interface public key   ${B}$WG_PUB${N}

${Y}This file is a credential.${N} It holds the token that administers this gateway,
the database password and the WireGuard private key that *is* this gateway's
identity. Back it up somewhere you would be comfortable keeping root.

Next, and in this order:

  1. Set the ones only you know:
       FOXGUARD_WG_ENDPOINT_HOST   what your router forwards udp/51820 to
       FOXGUARD_WAN_INTERFACE      the host's internet-facing interface
       FOXGUARD_TUNNEL_IP          if 10.88.0.1/24 collides with your network

  2. On the host, once:
       sysctl -w net.ipv4.ip_forward=1
       modprobe wireguard

  3. docker compose up -d

  4. Create a real administrator account and drop FOXGUARD_ADMIN_API_TOKEN.
     docs/docker.md, "First administrator".

SUMMARY
