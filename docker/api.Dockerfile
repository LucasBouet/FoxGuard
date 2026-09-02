# syntax=docker/dockerfile:1.7
#
# Foxguard control plane: the API, and the captive portal bundle it serves.
#
#   docker build -f docker/api.Dockerfile -t foxguard-api .
#
# The build context is the repository root, because this image needs both
# `backend/` and `frontend/portal/`.
#
# WHY THE PORTAL IS IN THIS IMAGE AND NOT ITS OWN
# The portal identifies a caller by the source address of its TCP connection,
# because inside WireGuard that address is bound to a public key. Put any server
# between the peer and the API -- a second container, an nginx, a Traefik -- and
# the API reads the intermediary's address instead of the peer's, and every
# portal request becomes a 403. So the bundle is static, executed by the
# browser, and served from the same origin as the API. See
# backend/foxguard/api/static.py.

# --------------------------------------------------------------------------- #
# 1. the portal bundle
# --------------------------------------------------------------------------- #
FROM node:22-bookworm-slim AS portal

WORKDIR /src/frontend/portal
# Copied on their own so a dependency install is cached until the lockfile
# actually changes; the source below invalidates only the build.
COPY frontend/portal/package.json frontend/portal/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/portal/ ./
# next.config.mjs sets output: "export" -- this produces out/, a static tree.
RUN npm run build

# --------------------------------------------------------------------------- #
# 2. the runtime
# --------------------------------------------------------------------------- #
FROM python:3.12-slim-bookworm AS runtime

# Matches the native install's layout (deploy/foxguard-install.sh), so a path in
# a log or a traceback means the same thing whichever way Foxguard was
# deployed.
ENV FOXGUARD_PREFIX=/opt/foxguard \
    PATH=/opt/foxguard/venv/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# curl, for the healthcheck, and nothing else. Notably not postgresql-client:
# the entrypoint waits for the database through SQLAlchemy, using the same URL
# the application will, which also proves the credentials work -- pg_isready
# would only prove something is listening. The control plane runs no privileged
# tool at all; that is the agent's job, in another image.
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl \
 && rm -rf /var/lib/apt/lists/*

RUN python -m venv "$FOXGUARD_PREFIX/venv"

WORKDIR /opt/foxguard/src

COPY backend/ backend/

# Editable, deliberately: alembic reads its versions/ from this tree at runtime
# and `foxguard.main` must be the same code that migrated the database. A
# non-editable install would put a second copy under site-packages and let the
# two drift. The pip cache mount keeps the wheel downloads across builds.
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --upgrade pip \
 && pip install -e ./backend

COPY --from=portal /src/frontend/portal/out/ /opt/foxguard/portal/
COPY docker/entrypoint-api.sh /usr/local/bin/foxguard-entrypoint
RUN chmod +x /usr/local/bin/foxguard-entrypoint

# Unprivileged, with a fixed uid so anything mounted in has predictable
# ownership. The control plane holds no capability whatsoever -- if it is
# compromised it can rewrite the database, but it cannot program the network.
#
# Not --system: that flag allocates from the system range, and combining it with
# an explicit uid above SYS_UID_MAX makes useradd warn on every build. The uid
# is what matters here, so the flag goes rather than the number.
RUN useradd --uid 10001 --user-group --no-create-home \
      --home-dir /opt/foxguard --shell /usr/sbin/nologin foxguard \
 && chown -R foxguard:foxguard /opt/foxguard
USER foxguard

# Where the portal bundle landed above. The API serves it from / after every
# router is mounted, so /api and /healthz keep priority.
ENV FOXGUARD_PORTAL_STATIC_DIR=/opt/foxguard/portal \
    FOXGUARD_BIND_HOST=0.0.0.0 \
    FOXGUARD_BIND_PORT=8080 \
    FOXGUARD_DB_WAIT_SECONDS=60 \
    FOXGUARD_BIND_WAIT_SECONDS=60 \
    FOXGUARD_AUTO_MIGRATE=true

EXPOSE 8080

# Through the entrypoint, not a bare curl: this container listens on the tunnel
# address rather than on loopback, and only the entrypoint knows which one that
# is at runtime.
HEALTHCHECK --interval=15s --timeout=5s --start-period=40s --retries=3 \
  CMD ["/usr/local/bin/foxguard-entrypoint", "--healthcheck"]

ENTRYPOINT ["/usr/local/bin/foxguard-entrypoint"]
