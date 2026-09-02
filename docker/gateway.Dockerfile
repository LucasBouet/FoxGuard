# syntax=docker/dockerfile:1.7
#
# Foxguard dataplane: the agent, and the daemons it drives.
#
#   docker build -f docker/gateway.Dockerfile -t foxguard-gateway .
#
# THIS IS THE PRIVILEGED HALF, AND IT IS NOT ISOLATED
# The agent's whole job is to program the host's network: nftables rules,
# WireGuard peers, kernel routes. That only works with CAP_NET_ADMIN in the
# host's network namespace, which means this container shares the host's stack
# rather than getting its own. Treat running it as equivalent to running the
# agent on the host, because that is what it is. The isolation this image buys
# you is over the *filesystem* and the dependency tree, not the network.
#
#   docker run --network host --cap-add NET_ADMIN --cap-add NET_RAW ...
#
# The host must have the wireguard module available; nothing here can load it.
#
# Debian 13 because that is the platform the deployment scripts target and the
# versions this project has actually been measured against: haproxy 3.0.x with
# master-worker reloads, dnsmasq 2.9x, nftables 1.1.x.
FROM debian:trixie-slim

ENV FOXGUARD_PREFIX=/opt/foxguard \
    PATH=/opt/foxguard/venv/bin:/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DEBIAN_FRONTEND=noninteractive

# dnsmasq-base rather than dnsmasq: the same binary without the init script and
# the /etc/dnsmasq.d drop-in directory, neither of which means anything here --
# the agent renders one self-contained --conf-file and nothing else may add to
# it. Same principle as owning a single nft table.
#
# iptables is not a typo alongside nftables: WireGuard's wg-quick and some
# hosts' NAT rules still reach for it, and its absence turns a clear error into
# a confusing one.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      python3 python3-venv \
      nftables iptables iproute2 wireguard-tools \
      dnsmasq-base haproxy \
      ca-certificates curl procps \
 && rm -rf /var/lib/apt/lists/*

RUN python3 -m venv "$FOXGUARD_PREFIX/venv"

WORKDIR /opt/foxguard/src

# The agent reuses foxguard.nftables from the control plane -- the generator
# model, the applier, the validation guards -- so the two packages are installed
# together exactly as deploy/foxguard-install.sh does it. Same code, same
# safety checks, whichever way Foxguard is deployed.
COPY backend/ backend/
COPY agent/ agent/
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --upgrade pip \
 && pip install -e ./backend -e ./agent

COPY docker/fg-servicectl.sh /usr/local/bin/fg-servicectl
COPY docker/entrypoint-gateway.sh /usr/local/bin/foxguard-entrypoint
RUN chmod +x /usr/local/bin/fg-servicectl /usr/local/bin/foxguard-entrypoint

# Absolute paths for every external binary. The defaults are bare names, and a
# bare name is one PATH surprise away from "dnsmasq: not found" reported as a
# DNS reconciliation failure.
#
# FOXGUARD_AGENT_SYSTEMCTL_PATH is the substitution that makes this image work:
# there is no systemd in a container, so the agent's start/reload/restart calls
# go to fg-servicectl instead. See docker/fg-servicectl.sh.
ENV FOXGUARD_AGENT_NFT_PATH=/usr/sbin/nft \
    FOXGUARD_AGENT_WG_PATH=/usr/bin/wg \
    FOXGUARD_AGENT_IP_PATH=/usr/sbin/ip \
    FOXGUARD_AGENT_DNSMASQ_PATH=/usr/sbin/dnsmasq \
    FOXGUARD_AGENT_HAPROXY_PATH=/usr/sbin/haproxy \
    FOXGUARD_AGENT_SYSTEMCTL_PATH=/usr/local/bin/fg-servicectl \
    FOXGUARD_AGENT_DNS_DIR=/etc/foxguard/dns \
    FOXGUARD_AGENT_PROXY_DIR=/etc/foxguard/proxy \
    FOXGUARD_AGENT_STATE_DIR=/var/lib/foxguard \
    FOXGUARD_RUN_DIR=/run/foxguard \
    FOXGUARD_GEO_REFRESH_ENABLED=true \
    FOXGUARD_GEO_REFRESH_INTERVAL_SECONDS=604800 \
    FOXGUARD_BOOTSTRAP_WG=false \
    FOXGUARD_API_WAIT_SECONDS=120

# State the agent must keep across restarts: last-good.nft (what it can roll
# back to), routes.json (which routes it installed, so it can withdraw them)
# and the geo dataset. Losing these does not lose the policy -- the control
# plane holds that -- but it does lose the agent's ability to undo its own work.
VOLUME ["/var/lib/foxguard", "/etc/foxguard/dns", "/etc/foxguard/proxy"]

# Reports on the agent's own reconcile loop rather than on a port, because this
# container listens on nothing of its own -- HAProxy and dnsmasq do, and their
# health is a property of the policy, not of this process.
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
  CMD /usr/local/bin/foxguard-entrypoint --healthcheck || exit 1

ENTRYPOINT ["/usr/local/bin/foxguard-entrypoint"]
