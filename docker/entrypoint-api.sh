#!/usr/bin/env bash
#
# Entrypoint for the foxguard-api image.
#
# Three jobs, in order: wait for PostgreSQL, bring the schema to head, then
# become the API. Everything is driven by environment variables so the same
# image runs in a compose file, on a gateway, and in CI.
#
set -euo pipefail

BIND_HOST=${FOXGUARD_BIND_HOST:-0.0.0.0}
BIND_PORT=${FOXGUARD_BIND_PORT:-8080}
DB_WAIT=${FOXGUARD_DB_WAIT_SECONDS:-60}
AUTO_MIGRATE=${FOXGUARD_AUTO_MIGRATE:-true}

log() { printf '%s foxguard-entrypoint: %s\n' "$(date -Is)" "$*"; }
die() { log "$*" >&2; exit 1; }

# --------------------------------------------------------------------------- #
# healthcheck mode
# --------------------------------------------------------------------------- #
# The API binds the *tunnel* address, not loopback, so a healthcheck aimed at
# 127.0.0.1 would fail on a perfectly healthy container -- and with the
# dashboard waiting on `condition: service_healthy`, the whole stack would sit
# there never coming up. Ask the address it actually listens on.
if [[ ${1:-} == "--healthcheck" ]]; then
  # Written out rather than as `[[ ... ]] && x`, which under `set -e` depends on
  # a subtlety of how errexit treats the left operand of &&. Not worth being
  # clever about in the one code path whose job is to say whether this container
  # is alive.
  target=$BIND_HOST
  if [[ $target == "0.0.0.0" || $target == "::" ]]; then
    target=127.0.0.1
  elif [[ $target == *:* ]]; then
    target="[$target]"   # an IPv6 literal has to be bracketed in a URL
  fi
  exec curl -fsS --max-time 5 -o /dev/null "http://${target}:${BIND_PORT}/healthz"
fi

# An unset database URL fails later with a pydantic traceback that says
# `database_url` and nothing about which file or variable to fix. Say it here.
: "${FOXGUARD_DATABASE_URL:?not set. Point it at PostgreSQL, e.g. postgresql+psycopg://foxguard:...@127.0.0.1:5432/foxguard}"

if [[ ${FOXGUARD_DEV_MODE:-false} == "true" ]]; then
  log "WARNING: FOXGUARD_DEV_MODE=true — CORS is open and any loopback request"
  log "WARNING: is treated as an administrator. Never set this on a gateway."
fi

# --------------------------------------------------------------------------- #
# wait for the database
# --------------------------------------------------------------------------- #
# Through SQLAlchemy rather than pg_isready: the URL is a SQLAlchemy URL, and
# parsing it in shell to feed another tool is one more thing to get wrong. This
# also proves the credentials work, which pg_isready does not.
#
# The last error is kept and reported. "PostgreSQL is not up" and "PostgreSQL is
# up and rejected your password" look identical from here, and telling somebody
# to check whether the database is running when it is running and healthy costs
# them an afternoon.
DB_ERROR=""

probe_db() {
  python - <<'PROBE' 2>&1
import os, sys
from sqlalchemy import create_engine, text
try:
    create_engine(os.environ["FOXGUARD_DATABASE_URL"], pool_pre_ping=True).connect().execute(text("SELECT 1"))
except Exception as exc:
    # The driver's own words, one line, without a traceback nobody reads.
    sys.stderr.write(" ".join(str(exc).split())[:400])
    sys.exit(1)
PROBE
}

wait_for_db() {
  local deadline=$((SECONDS + DB_WAIT))
  while true; do
    if DB_ERROR=$(probe_db); then
      return 0
    fi
    (( SECONDS < deadline )) || return 1
    sleep 2
  done
}

log "waiting up to ${DB_WAIT}s for the database"
if ! wait_for_db; then
  log "the database did not accept a connection within ${DB_WAIT}s."
  log "last error: ${DB_ERROR:-none reported}"
  case $DB_ERROR in
    *"password authentication failed"*|*"role \""*"does not exist"*)
      log ""
      log "That is an authentication failure, not an unreachable server: the"
      log "credentials in FOXGUARD_DATABASE_URL are not the ones this database"
      log "has. POSTGRES_PASSWORD is only read when the data directory is first"
      log "created, so changing it in .env does nothing to a database that"
      log "already exists. Either put the original password back, or start over"
      log "with 'docker compose down -v' -- WHICH DESTROYS EVERY PEER, ACCOUNT"
      log "AND TOTP SECRET, and cannot be undone."
      ;;
  esac
  die "cannot serve without a database."
fi
log "database reachable"

# --------------------------------------------------------------------------- #
# migrate
# --------------------------------------------------------------------------- #
# On by default: a container that starts against an empty database and answers
# 500 to everything is worse than one that takes three seconds longer to boot.
# `alembic upgrade head` is idempotent, so a restart is free.
#
# Turn it OFF (FOXGUARD_AUTO_MIGRATE=false) if you run more than one replica --
# nothing here serialises two processes migrating the same database at once --
# or if you would rather apply migrations as a deliberate step.
if [[ $AUTO_MIGRATE == "true" ]]; then
  log "applying migrations"
  ( cd /opt/foxguard/src/backend && alembic upgrade head ) \
    || die "alembic upgrade head failed. Fix the schema before serving."
  log "schema at head"
else
  log "FOXGUARD_AUTO_MIGRATE is off — assuming the schema is already at head"
fi

# --------------------------------------------------------------------------- #
# wait for the bind address to exist
# --------------------------------------------------------------------------- #
# The portal has to answer on the gateway's *tunnel* address, and that address
# does not exist until the WireGuard interface is up -- which, in a compose
# deployment, happens in another container. Without this the API loses the race
# on a cold boot, dies with EADDRNOTAVAIL, and restarts until it happens to win.
#
# Binding a probe socket is the test rather than parsing `ip addr`, because this
# image ships no iproute2 and the question is exactly "can I bind here".
wait_for_bind() {
  local deadline=$((SECONDS + ${FOXGUARD_BIND_WAIT_SECONDS:-60}))
  while true; do
    if python - "$BIND_HOST" <<'PROBE' 2>/dev/null
import socket, sys
family = socket.AF_INET6 if ":" in sys.argv[1] else socket.AF_INET
probe = socket.socket(family, socket.SOCK_STREAM)
try:
    probe.bind((sys.argv[1], 0))
finally:
    probe.close()
PROBE
    then
      return 0
    fi
    (( SECONDS < deadline )) || return 1
    sleep 2
  done
}

if [[ $BIND_HOST != "0.0.0.0" && $BIND_HOST != "::" ]]; then
  log "waiting for ${BIND_HOST} to exist on this host"
  wait_for_bind || die "${BIND_HOST} never appeared. Is the WireGuard interface up? (the gateway container creates it when FOXGUARD_BOOTSTRAP_WG=true)"
fi

# --------------------------------------------------------------------------- #
# serve
# --------------------------------------------------------------------------- #
# foxguard-serve, never plain uvicorn: uvicorn trusts X-Forwarded-For from
# 127.0.0.1 by default, and the portal identifies peers *by* the source address.
# See backend/foxguard/server.py.
log "starting the API on ${BIND_HOST}:${BIND_PORT}"
exec foxguard-serve --host "$BIND_HOST" --port "$BIND_PORT" "$@"
