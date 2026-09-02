# Foxguard in containers

Three images, one compose file, everything configured by environment variable.

```bash
git clone https://github.com/LucasBouet/Foxguard && cd Foxguard
./docker/gen-env.sh          # secrets + the interface keypair
docker compose up -d
```

That is a working gateway: control plane, dashboard, captive portal, agent,
and — when you turn them on — the internal resolver and the reverse proxy.

---

## Read this before you run it

**The gateway container is not isolated from the host's network, and that is
deliberate.** Two independent reasons, either of which would be enough on its
own:

1. **The portal identifies a caller by the source address of its TCP
   connection**, because inside WireGuard that address is bound to a public key.
   Docker's bridge rewrites source addresses. Behind one, every peer arrives as
   the bridge gateway: the portal answers 403 to everybody, or — worse —
   resolves them all to the same peer.

2. **The agent's job is to program the host's network**: nftables rules, the
   WireGuard interface, kernel routes. In a private network namespace it would
   get a pristine empty stack of its own and configure it perfectly, affecting
   nothing.

So `network_mode: host` plus `CAP_NET_ADMIN`. Running the gateway container is
equivalent to running the agent on the host, because that is what it is. What
containerisation buys you here is a pinned dependency tree and a one-command
deployment — **not** a security boundary at the network layer.

PostgreSQL is the exception. It has no reason to see the host's stack, so it
keeps its own and is published on loopback.

---

## The three images

| Image | Contains | Privilege | Listens on |
|---|---|---|---|
| `foxguard-api` | control plane + the portal bundle it serves | `cap_drop: ALL` | tunnel IP, 8080 |
| `foxguard-dashboard` | the admin UI (Next.js, server-side) | `cap_drop: ALL` | tunnel IP, 3000 |
| `foxguard-gateway` | the agent, dnsmasq, HAProxy | `NET_ADMIN`, `NET_RAW` | whatever the policy says |

The split follows the trust levels the project already had. The control plane
holds no capability at all: compromise it and the database can be rewritten, but
the network cannot be programmed. The dashboard holds the admin credential in
its own process and never hands it to a browser. The gateway holds the
privilege, and nothing else.

The portal is inside the API image rather than its own, for the reason in
point 1 above: any server between the peer and the API destroys the identity the
portal runs on. It is a static bundle the browser executes, served from the same
origin as the API.

---

## Handing it to somebody else

Two ways, and which one applies depends on whether the images are published.

### Once the images are on GHCR

They need no repository, no build, and no Rust-adjacent toolchain surprises —
two files and a script that fetches them:

```bash
curl -fsSLO https://raw.githubusercontent.com/LucasBouet/FoxGuard/main/deploy/foxguard-quickstart.sh
less foxguard-quickstart.sh        # it installs Docker and edits their firewall
bash foxguard-quickstart.sh
```

It installs Docker, loads the wireguard module, turns on forwarding, downloads
`docker-compose.yml` + `.env.example` + `gen-env.sh`, strips the `build:`
sections (there is no source tree to build from), generates the secrets and the
interface keypair, works out their WAN interface and public address, and starts
the stack **with the agent in dry run**. The last two steps — reading what it
would apply, then turning the dry run off — are theirs to take deliberately,
because the agent programs their firewall and they are almost certainly
connected over SSH.

They end up with exactly this:

```
~/foxguard/
├── docker-compose.yml     # pull only, no build sections
├── .env                   # secrets, mode 0600 — this is a credential
├── .env.example           # kept, so they can see what they did not set
├── docker/gen-env.sh
└── certs/                 # bind-mounted into the proxy
```

`curl … | bash` works too, but this project's scripts are meant to be read
before they are run, and this one installs Docker and touches nftables.

### Before the images are published

`ghcr.io/<owner>/foxguard-*` answers `denied` — GHCR returns the same thing for
"does not exist" and "is private", so that anyone cannot enumerate other
people's private package names. Until the workflow has run and the packages are
flipped to public, the handoff is a clone:

```bash
git clone https://github.com/LucasBouet/FoxGuard && cd FoxGuard
./docker/gen-env.sh
docker compose up -d          # builds all three images, a few minutes
```

## Quick start, in full

### 1. The host, once

```bash
modprobe wireguard                       # and add it to /etc/modules-load.d/
sysctl -w net.ipv4.ip_forward=1          # persist in /etc/sysctl.d/99-foxguard.conf
```

Neither can be done from inside a container: `/proc/sys` is mounted read-only,
and loading a module needs `CAP_SYS_MODULE`, which this deployment does not
ask for. The gateway container checks both and tells you which one is missing.

### 2. Secrets

```bash
./docker/gen-env.sh
```

Writes `.env` (mode 0600) from `.env.example`, filling in:

- `POSTGRES_PASSWORD` and the matching `FOXGUARD_DATABASE_URL`
- `FOXGUARD_ADMIN_API_TOKEN` — administers the API until an account exists
- `FOXGUARD_AGENT_API_TOKEN` — the only thing separating the agent from anyone
  else who can reach the control plane
- `FOXGUARD_PROXY_SSO_SECRET` — signs the SSO cookie; the proxy verifies with
  the same value
- `FOXGUARD_WG_PRIVATE_KEY` / `FOXGUARD_WG_PUBLIC_KEY`

The keypair is generated here, not on first boot, because the two halves go to
two different containers. A gateway that mints its own key after the API has
been told a different one produces client configurations that connect to
nothing.

`.env` is a credential. It holds the token that administers this gateway, the
database password, and the WireGuard private key that *is* this gateway's
identity. Back it up somewhere you would be comfortable keeping root.

### 3. The three things only you know

```bash
FOXGUARD_WG_ENDPOINT_HOST=vpn.example.com   # what your router forwards udp/51820 to
FOXGUARD_WAN_INTERFACE=eth0                 # the host's internet-facing interface
FOXGUARD_TUNNEL_IP=10.88.0.1                # change if 10.88.0.0/24 collides
```

If you change `FOXGUARD_TUNNEL_IP`, change `FOXGUARD_WG_ADDRESS` and
`FOXGUARD_WG_POOL_V4` to match.

### 4. Up

```bash
docker compose up -d
docker compose ps          # all four healthy within ~30s
docker compose logs -f gateway
```

### 5. First administrator

Until an account exists, `FOXGUARD_ADMIN_API_TOKEN` is what administers the
gateway — and anything done with it is audited as `admin-token`, with nobody's
name on it. Create a real account, then drop the token:

```bash
source .env
curl -sf -X POST "http://$FOXGUARD_TUNNEL_IP:8080/api/v1/users" \
  -H "Authorization: Bearer $FOXGUARD_ADMIN_API_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"username":"ada","password":"<at least 12 characters>","is_admin":true}'
```

The password is stored as an argon2 hash and never shown again. To set a new one
later, PATCH the account rather than creating a second:

```bash
ID=$(curl -s -H "Authorization: Bearer $FOXGUARD_ADMIN_API_TOKEN" \
     "http://$FOXGUARD_TUNNEL_IP:8080/api/v1/users" | jq -r '.[]|select(.is_admin)|.id' | head -1)
curl -s -X PATCH -H "Authorization: Bearer $FOXGUARD_ADMIN_API_TOKEN" \
     -H 'Content-Type: application/json' -d '{"password":"<a new one>"}' \
     "http://$FOXGUARD_TUNNEL_IP:8080/api/v1/users/$ID"
```

Then blank `FOXGUARD_ADMIN_API_TOKEN` in `.env` and
`docker compose up -d api dashboard`. The dashboard falls back to it only while
no administrator has signed in; once accounts exist it is a spare key you have
left under the mat.

The dashboard is at `http://<tunnel ip>:3000`, from inside the tunnel.

---

## Startup order, and why there is no `depends_on` between api and gateway

The API binds the tunnel address, which does not exist until the gateway
container has created the interface. The gateway waits for the API to answer, so
its first reconcile is not a wall of connection errors.

A compose dependency either way round turns two bounded waits into a deadlock.
So there is none: the API waits up to `FOXGUARD_BIND_WAIT_SECONDS` for its
address to appear, the gateway waits up to `FOXGUARD_API_WAIT_SECONDS` for the
control plane, and neither wait is fatal. They converge, usually in a couple of
seconds.

---

## What replaced what

Under systemd, Foxguard is five units. In containers it is three processes and a
shim:

| systemd | container |
|---|---|
| `foxguard-api.service` | the `api` container |
| `foxguard-dashboard.service` | the `dashboard` container |
| `foxguard-agent.service` | pid 1 of the `gateway` container |
| `foxguard-dns.service` | dnsmasq, started on demand by `fg-servicectl` |
| `foxguard-proxy.service` | HAProxy, started on demand by `fg-servicectl` |
| `foxguard-geo-refresh.timer` | a background loop in the gateway entrypoint |

### `fg-servicectl`

The agent does not start dnsmasq or HAProxy itself. It renders their
configuration, validates it with the daemon's own checker (`dnsmasq --test`,
`haproxy -c`), and then asks an init system to make the daemon serve it —
`is-active`, `reload`, `restart`. There is no init system in a container, so
`docker/fg-servicectl.sh` stands in for one. `FOXGUARD_AGENT_SYSTEMCTL_PATH`
points the agent at it.

It is not named `systemctl`, on purpose: shadowing a well-known binary hides
what is happening from whoever is debugging this at 3am.

The behaviour it reproduces is the units' own:

- **HAProxy reload is `SIGUSR2` to the master**, not a restart. The master keeps
  the listening sockets, hands them to a new worker, and the old worker drains
  instead of dropping connections. Restarting would break every passthrough
  session on every policy change — and a passthrough session is often a shell
  somebody is typing in.
- **dnsmasq reload is `SIGHUP`**, which re-reads the hosts file and flushes the
  cache without dropping the listening socket. Adding a peer is a reload; only a
  change to the configuration itself is a restart.
- **A pid file is checked with `kill -0`**, because a pid file outlives the
  process it named, and a crashed daemon that reads as active for ever is never
  restarted.

Neither daemon is started at container boot. Before the agent has rendered a
configuration there is nothing for either to serve, and a daemon restarting in a
loop over a file that does not exist yet is noise that hides the real first-boot
errors. This is exactly what systemd does, where those units are installed but
not enabled.

---

## Configuration

Everything is an environment variable, and `.env` is the whole configuration.
The tables below are the container-specific ones; `.env.example` is the complete
annotated list, and `backend/.env.example` documents the control plane's
settings in more depth.

### Container behaviour

| Variable | Default | What it does |
|---|---|---|
| `FOXGUARD_REGISTRY` | `ghcr.io/lucasbouet` | Where images are pulled from |
| `FOXGUARD_VERSION` | `latest` | Image tag. Pin it for a real deployment |
| `FOXGUARD_AUTO_MIGRATE` | `true` | `alembic upgrade head` on API start |
| `FOXGUARD_DB_WAIT_SECONDS` | `60` | How long the API waits for PostgreSQL |
| `FOXGUARD_BIND_WAIT_SECONDS` | `60` | How long the API waits for the tunnel address |
| `FOXGUARD_API_WAIT_SECONDS` | `120` | How long the gateway waits for the API |
| `FOXGUARD_BOOTSTRAP_WG` | `true` in `.env.example` | Create the interface if absent |
| `FOXGUARD_WG_ADDRESS` | `10.88.0.1/24` | What the gateway gives the interface |
| `FOXGUARD_GEO_REFRESH_ENABLED` | `true` | Run the dataset refresher loop |
| `FOXGUARD_GEO_REFRESH_INTERVAL_SECONDS` | `604800` | Weekly |
| `FOXGUARD_CERTS_DIR` | `./certs` | Bind-mounted at `/etc/foxguard/proxy/certs` |

`FOXGUARD_AUTO_MIGRATE` is on because a container that starts against an empty
database and answers 500 to everything is worse than one that takes three
seconds longer to boot. `alembic upgrade head` is idempotent, so a restart is
free. Turn it off if you ever run more than one API replica — nothing here
serialises two processes migrating the same database.

### Paths shared between the API and the agent

These four have to agree on both sides: the rendered configuration refers to its
pattern files and its hosts file by **absolute path**, so a mismatch produces a
proxy that will not parse its own map files.

```
FOXGUARD_DNS_HOSTS_PATH=/etc/foxguard/dns/hosts
FOXGUARD_DNS_CONF_PATH=/etc/foxguard/dns/dnsmasq.conf
FOXGUARD_PROXY_CONF_PATH=/etc/foxguard/proxy/haproxy.cfg
FOXGUARD_PROXY_MAPS_DIR=/etc/foxguard/proxy/maps
```

Leave them alone unless you also change the volume mounts in
`docker-compose.yml`.

### The agent's own settings

The agent reads `FOXGUARD_AGENT_*`. The image sets the paths to every external
binary absolutely — a bare `dnsmasq` is one `PATH` surprise away from
"not found" reported as a DNS reconciliation failure. The ones worth changing:

| Variable | Default | |
|---|---|---|
| `FOXGUARD_AGENT_POLL_INTERVAL_SECONDS` | `10` | Reconciliation is level-triggered, so this is latency, never correctness |
| `FOXGUARD_AGENT_DRY_RUN` | `false` | Render and validate, never apply |
| `FOXGUARD_AGENT_MANAGE_DNS` | `true` | Off to run the resolver elsewhere |
| `FOXGUARD_AGENT_MANAGE_PROXY` | `true` | Off to run the proxy elsewhere |
| `FOXGUARD_AGENT_MANAGE_ROUTES` | `true` | Off to manage kernel routes yourself |
| `FOXGUARD_AGENT_MANAGE_WIREGUARD` | `true` | Off if `wg` is managed elsewhere |

**Try `FOXGUARD_AGENT_DRY_RUN=true` first** on a box that already carries
traffic. The agent renders and validates the full ruleset and applies none of
it, and the logs tell you exactly what it would have done.

---

## State, and what a `docker compose down` keeps

Four volumes:

| Volume | Holds | Losing it means |
|---|---|---|
| `foxguard-pgdata` | the database | every device re-registers, every client config changes |
| `foxguard-state` | `last-good.nft`, `routes.json`, the geo dataset, the interface key | the agent cannot undo its own work; a new identity |
| `foxguard-dns` | the rendered zone | nothing — re-rendered next tick |
| `foxguard-proxy` | the rendered HAProxy config and maps | nothing — re-rendered next tick |

The policy lives in the database. The first two volumes are the ones that
matter; the last two are the agent's output and converge on their own.

`docker compose down` keeps all four. `docker compose down -v` destroys them,
including every peer's public key and tunnel address, every account's password
hash and TOTP secret. There is no undo.

### Backups

`deploy/foxguard-backup.sh` is written for a host install. The container
equivalent:

```bash
source .env
docker compose exec -T postgres \
  pg_dump --format=plain --no-owner --no-privileges -U "$POSTGRES_USER" "$POSTGRES_DB" \
  > "foxguard-$(date +%Y%m%d-%H%M%S).sql"
```

That plus `.env` (which carries the tokens and the interface key) is a complete
backup. Both are credentials. Keep them as protected as root on this box.

Check a dump before trusting it — a truncated one restores cleanly and silently
drops rows:

```bash
tail -5 foxguard-*.sql | grep -q 'PostgreSQL database dump complete' && echo usable
```

---

## Certificates

`/etc/foxguard/proxy/certs` is a bind mount (`FOXGUARD_CERTS_DIR`, default
`./certs`) rather than a named volume, because certificates come from somewhere
else — certbot, your CA, a copy from another box — and getting a file into a
named volume is an archaeology exercise.

Foxguard's ACME flow uses DNS-01, so nothing needs to be served on port 80 to
issue a certificate. Run certbot on the host, point its deploy hook at
`./certs`, and the agent's next reconcile picks the file up.

---

## Upgrading

```bash
docker compose pull
docker compose up -d
```

The API migrates the schema on start. Read the release notes for the version
you are jumping to, and take a dump first — a migration is not reversible by
`docker compose down`.

Pin `FOXGUARD_VERSION` for anything you care about. `latest` means the next
`docker compose pull` changes the gateway, at a moment you did not choose.

---

## Building and publishing

### Locally

```bash
docker compose build           # all three
make docker-build              # the same thing
```

Build context is the repository root for all three images: the API image needs
`backend/` and `frontend/portal/`, the gateway image needs `backend/` and
`agent/` — the agent reuses `foxguard.nftables` from the control plane, so the
generator, the applier and the validation guards are literally the same code.

### GitHub Container Registry

`.github/workflows/images.yml` builds and pushes on every push to `main` and on
every `v*` tag. GHCR needs no account beyond the repository's own: `GITHUB_TOKEN`
with `packages: write` is the credential — no secret to create, nothing to
rotate.

Images land at `ghcr.io/<owner>/foxguard-{api,dashboard,gateway}` and are
**private until you make them public**, which is a one-time click per image
under the repository's Packages tab. A public package needs no login to pull,
which is what makes `docker compose up` work on a fresh gateway.

Pull requests build but never push: a fork must not be able to publish an image
under your name.

Images are built for `linux/amd64` and `linux/arm64`. The arm64 half goes
through QEMU and is slow — the Next.js build especially — but it is what puts
these on the small ARM boxes people actually run a home gateway on.

To publish somewhere else, set `FOXGUARD_REGISTRY` and push by hand; nothing in
the compose file assumes GHCR beyond that default.

---

## Troubleshooting

**`cannot read the nftables ruleset`**
The gateway container is missing `CAP_NET_ADMIN` or the host's network
namespace. In compose: `network_mode: host` plus
`cap_add: [NET_ADMIN, NET_RAW]`. Both, not one.

**`could not create wg0. Is the wireguard module loaded on the host?`**
`modprobe wireguard` on the host. Nothing inside the container can load it.

**`net.ipv4.ip_forward is 0 on the host`**
A warning, not a failure: peers complete a handshake and then reach nothing.
`sysctl -w net.ipv4.ip_forward=1`. `/proc/sys` is read-only inside the
container, so this cannot be fixed from in there.

**`10.88.0.1 never appeared`**
The API gave up waiting for the tunnel address. Either the gateway container
did not create the interface (check its logs), or `FOXGUARD_BOOTSTRAP_WG` is
false and nothing else created it.

**The portal answers 403 to every peer**
Something is rewriting source addresses. Check that the API container really is
on `network_mode: host` and that nothing is proxying in front of it. This is
the failure mode the whole host-networking decision exists to prevent.

**`password authentication failed for user "foxguard"`, and PostgreSQL is healthy**
`POSTGRES_PASSWORD` is read only when the data directory is first created.
Changing it in `.env` afterwards changes what the API sends and nothing about
what the database expects, so a working deployment starts refusing itself. Put
the original password back, or `docker compose down -v` and start over — which
destroys every peer, account and TOTP secret, with no undo. The API's entrypoint
says all of this when it happens; it does not make you work it out.

**`wg0 carries a DIFFERENT key from the one the control plane publishes`**
The interface already existed when the gateway container started, so it was left
alone — correct, something else owns it — but it is not the key this deployment
hands out. Every generated client configuration names a gateway that cannot
decrypt for them, and the only symptom is peers that never handshake. Either set
`FOXGUARD_WG_PUBLIC_KEY` to the interface's key, or delete `wg0` and let the
container recreate it from `FOXGUARD_WG_PRIVATE_KEY`.

**The dashboard is healthy but every page shows an error**
The dashboard is up and the API is not. `docker compose logs api`. The
dashboard's healthcheck deliberately does not fail for this — marking it
unhealthy would point at the wrong process.

**Peers connect but resolve nothing, and DNS is enabled**
`docker compose exec gateway fg-servicectl status foxguard-dns`. If it is
inactive, the agent's last apply failed; the reason is in the gateway's log.

**A policy change did not take effect**
Reconciliation is level-triggered: every pass applies the full desired state, so
the next tick converges. If it does not, the agent is logging why once per poll
interval — `docker compose logs -f gateway`.

---

## What this deployment does not do

- **It is not a security boundary at the network layer.** Said three times in
  this document because it is the thing people assume containers give them.
- **It does not run the installer's preflight.** `deploy/foxguard-install.sh
  --preflight` checks things about a host that a container cannot see. Run it on
  the host if you want that report.
- **It does not manage certificates.** See above.
- **One API replica.** The portal login throttle and in-flight OIDC
  transactions are per-process. Session expiry is safe under several workers —
  it takes a PostgreSQL advisory lock — but nothing else is.

For the host install, which is what `deploy/foxguard-install.sh` builds and what
the hardening checklist assumes, see [deployment.md](deployment.md).
