# syntax=docker/dockerfile:1.7
#
# Foxguard admin dashboard.
#
#   docker build -f docker/dashboard.Dockerfile -t foxguard-dashboard .
#
# Build context is the repository root, for consistency with the other two
# images; only frontend/admin/ is actually read.
#
# WHAT THIS PROCESS HOLDS
# The dashboard is a Next.js server, not a static SPA, precisely so the admin
# credential stays server-side: every API call runs in a server component,
# reads FOXGUARD_ADMIN_API_TOKEN from this process's environment, and returns
# plain data to the browser (frontend/admin/src/lib/api.ts). Anyone who can
# reach this port is talking to something that can already administer the
# network. Bind it to the tunnel, never to the WAN.

# --------------------------------------------------------------------------- #
# 1. build
# --------------------------------------------------------------------------- #
FROM node:22-bookworm-slim AS build

WORKDIR /app
COPY frontend/admin/package.json frontend/admin/package-lock.json ./
RUN npm ci --no-audit --no-fund

COPY frontend/admin/ ./
# next.config.mjs bakes the /api rewrite target at build time. Every call that
# carries a credential is server-side and reads FOXGUARD_API_URL at *runtime*
# instead, so this value only affects a browser-side /api fetch -- of which the
# dashboard currently makes none. Runtime configuration still wins where it
# matters; see docs/docker.md.
ENV NEXT_STANDALONE=true \
    NEXT_TELEMETRY_DISABLED=1 \
    FOXGUARD_API_URL=http://127.0.0.1:8080
# There is no public/ in this app. Creating it keeps the COPY below honest
# rather than conditional -- an empty directory is cheaper than a build that
# breaks the day somebody adds a favicon.
RUN mkdir -p public && npm run build

# --------------------------------------------------------------------------- #
# 2. runtime
# --------------------------------------------------------------------------- #
FROM node:22-bookworm-slim AS runtime

ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    HOSTNAME=0.0.0.0 \
    PORT=3000

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# The standalone tree carries its own minimal node_modules and server.js; the
# static assets and public/ are the two things it does not include.
COPY --from=build /app/.next/standalone ./
COPY --from=build /app/.next/static ./.next/static
COPY --from=build /app/public ./public

# node:* images already ship an unprivileged `node` user (uid 1000). This
# process needs no capability and writes nothing.
USER node

EXPOSE 3000

# Aimed at HOSTNAME, not 127.0.0.1: compose binds this to the tunnel address,
# and a healthcheck on loopback would fail on a perfectly healthy container.
#
# Deliberately not `curl -f`: this checks that the Next.js server is answering,
# which is all this container is responsible for. A 5xx here usually means the
# API is down, and marking the dashboard unhealthy for that would restart the
# wrong process.
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
  CMD H="$HOSTNAME"; [ "$H" = "0.0.0.0" ] || [ "$H" = "::" ] && H=127.0.0.1; \
      curl -s -o /dev/null --max-time 4 "http://$H:$PORT/login" || exit 1

CMD ["node", "server.js"]
