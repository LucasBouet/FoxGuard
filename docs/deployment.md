# Deploying on a Linux gateway

Target: a dedicated LXC or VM behind OPNsense, running WireGuard and nftables.

**The first rule of this document: keep a way in that does not depend on
Foxguard.** A console session through Proxmox, or SSH from a LAN address that
does not transit the tunnel. Every step below is designed so a mistake is
recoverable, but only if you can still reach the box.

---

## 0. The scripted route

`deploy/foxguard-install.sh` does sections 1–5 for you, with the checks written
out. Read it before running it — it is short, and it is installing something
that decides what your network can reach.

### The whole thing, on a fresh box

Copy-paste, change the four values marked below, run it. This is the complete
install: WireGuard interface, control plane, portal, dashboard, agent, internal
DNS, the first administrator and the first device.

```sh
git clone <your-repo> /root/foxguard-src
cd /root/foxguard-src

# 1. Changes nothing. Tells you whether this box can host Foxguard at all,
#    and — with the same flags — exactly what the real run would create.
sudo ./deploy/foxguard-install.sh --check-only \
  --bootstrap-wireguard --pool 10.88.0.0/24 --wan-interface eth0

# 2. The real thing.
sudo ./deploy/foxguard-install.sh \
  --bootstrap-wireguard \
  --listen-port 51820 \
  --pool 10.88.0.0/24 \
  --endpoint vpn.example.com:51820 \
  --wan-interface eth0 \
  --admin-user ada \
  --bootstrap-peer ada-laptop \
  --dns \
  --dns-zone fox.internal \
  --dns-upstream 1.1.1.1 \
  --dns-upstream 9.9.9.9
```

Change these four:

| Flag | What to put there | How to find it |
| --- | --- | --- |
| `--endpoint` | the public address peers dial | whatever your router forwards `udp/51820` to |
| `--wan-interface` | the interface facing the internet | `ip route get 1.1.1.1` |
| `--admin-user` | your own login | anything; the password is generated and shown once |
| `--bootstrap-peer` | the device you are reading this from | a name, ≤ 15 characters of `[a-zA-Z0-9_=+.-]` |

Everything else is a sensible default. `--pool` and `--listen-port` are written
out only because they are the two you are most likely to want different.

**Nothing reaches nftables.** The installer leaves the agent stopped and in dry
run on purpose, and finishes by printing the three commands that take you live —
section 3 below is the same thing with the reasoning.

Three flags are worth understanding rather than copying:

- **`--bootstrap-wireguard`** creates `wg0` and its `wg-quick` unit. Leave it
  off if you brought the interface up yourself, which is the normal case on a
  box you already reach through a tunnel. It refuses rather than overwrite an
  existing config.
- **`--endpoint`** is what makes the dashboard's config generator work: it is
  written to `FOXGUARD_WG_ENDPOINT_HOST`, and without it every generated
  configuration is reported as incomplete rather than handed out unable to
  connect. It is valid on its own — you do not need `--bootstrap-wireguard` to
  use it.
- **`--bootstrap-peer`** solves the first device only. Its private key is
  generated *on the gateway* and shown once, which is a fair trade for the
  laptop you are setting up from and a bad habit for anything after. Every
  device after it comes from **Devices → Config generator** in the dashboard,
  which makes the keypair in your browser and never sends the private half here.
  The *file* is the same either way: the installer asks
  `GET /peers/{id}/config-profile` the same question the dashboard asks, so the
  first device gets the resolver, the search domain, the MTU and every zone
  route — not the pool alone.

### Smaller variants

```sh
# Preflight only, against the interface you already have.
sudo ./deploy/foxguard-install.sh --check-only

# The common case: wg0 is already up (section 1), no internal DNS.
sudo ./deploy/foxguard-install.sh \
  --wan-interface eth0 --endpoint vpn.example.com:51820

# Unattended (CI, a rebuild from a known-good config): --yes skips every prompt.
sudo ./deploy/foxguard-install.sh --yes \
  --wan-interface eth0 --endpoint vpn.example.com:51820 \
  --dns --dns-upstream 1.1.1.1
```

Re-running is safe at any time: existing secrets are reused rather than
rotated, so the agent does not lose its token during an upgrade.

`sudo ./deploy/foxguard-install.sh --help` lists every flag.

### What it actually does

It detects the tunnel address and peer pool from your live WireGuard interface,
generates the secrets, writes `0600` config, applies the migrations, builds both
frontends, installs the systemd units, and creates the first administrator —
printing that password once.

`--bootstrap-wireguard` writes `/etc/wireguard/wg0.conf` with an `[Interface]`
block and **no peers** — those belong to Foxguard — then enables `wg-quick@wg0`.
It is create-if-absent: an interface that already exists is used as it is, and
it **refuses outright** if a config file is already there rather than overwrite
the thing holding your only way in.

`--bootstrap-peer` exists because a device added by hand to `wg0.conf` is
removed on the agent's first sync — the control plane does not know about it. So
instead it registers the device properly, bound to the administrator account,
and prints a ready client config once.

That config is built from `GET /peers/{id}/config-profile`, the same endpoint
the dashboard's generator calls, so it carries everything the dashboard would
put there:

| Line | Comes from |
| --- | --- |
| `Address` | the address IPAM just allocated |
| `DNS` | `--dns`: the resolver's tunnel address, plus the zone as a search domain |
| `MTU` | `FOXGUARD_CLIENT_CONFIG_MTU`, omitted when unset |
| `AllowedIPs` | the pools plus every enabled zone route (`FOXGUARD_CLIENT_CONFIG_ALLOWED_IPS`, default `routed`) |
| `PersistentKeepalive` | `FOXGUARD_CLIENT_CONFIG_KEEPALIVE`, omitted at 0 |

The suggested file name is derived the same way too — `wg-quick` takes the
interface name from the file name and refuses more than 15 characters of
`[a-zA-Z0-9_=+.-]`, so `Ada's MacBook Pro (2019)` is offered as
`Ada-s-MacBook-P.conf`.

One thing to know if you connect immediately: with `--dns`, that `DNS =` line
points at a resolver **the agent has not started yet** — it is still stopped and
in dry run at that point (section 3). A device that connects before you finish
resolves nothing at all. Comment the line out if you need the tunnel working
first, or just do section 3 before connecting.

You still have to forward `udp/51820` to this box on your router — the installer
says so but cannot do it.

### What it does not do

**It leaves the agent stopped and in dry run.** Nothing reaches nftables until
you have read the rules and flipped the flag yourself; the script finishes by
telling you exactly how, and section 3 below is the same thing with the
reasoning. Getting this wrong is how you lose remote access to the machine, so
it is not automated and will not be.

It also does not open the UDP port on your router, and it does not decide your
policy: a fresh install has no groups, no rules, and therefore no traffic
allowed between peers. `docs/usage.md` is the first hour after this one.

### The agent will not start: `Permission denied` on its own executable

```
foxguard-agent[20594]: /opt/foxguard/venv/bin/python3: can't open file
  '/opt/foxguard/venv/bin/foxguard-agent': [Errno 13] Permission denied
```

Running as **root**, which is why this one costs an afternoon.

The unit hardens root by setting `CapabilityBoundingSet=CAP_NET_ADMIN
CAP_NET_RAW`. That drops `CAP_DAC_OVERRIDE` along with everything else, and
`CAP_DAC_OVERRIDE` is precisely the capability that lets root ignore file
permissions. Without it, root facing a file owned by the service user with no
"other" bits is just "other".

```sh
chmod -R a+rX /opt/foxguard
systemctl restart foxguard-agent
```

Ownership is deliberately not touched: the dashboard's `.next` cache has to stay
writable by `foxguard`. Nothing secret lives under the prefix — the credentials
are in `/etc/foxguard` at `0600`.

The installer now does this on every run, so re-running it repairs a box in this
state, and `foxguard-healthcheck.sh` names the cause instead of only reporting
that the agent is down.

**While the agent is down, nothing reaches the dataplane**: no nftables rules,
no WireGuard peers, no DNS zone. A device registered in the dashboard appears in
the database and never on the interface, which looks like the control plane
losing it.

### If you lost the "shown once" output

The installer prints the administrator's password and the bootstrap device's
config exactly once, because neither is stored anywhere it could read them back:
the password is kept as an argon2 hash, and the client's private key is not kept
at all. If the terminal scrolled away, the session dropped, or the script died
after creating them, both are gone — the install itself is fine.

Neither is a reinstall. The shared token in `/etc/foxguard/backend.env` is a
working admin credential, so:

```sh
API=http://10.88.0.1:8080/api/v1
AUTH="Authorization: Bearer $(grep FOXGUARD_ADMIN_API_TOKEN /etc/foxguard/backend.env | cut -d= -f2)"

# 1. The account exists; only the plaintext is lost. Set a new password
#    (12 characters minimum). This also revokes any session issued against
#    the old one.
ID=$(curl -s "$API/users" -H "$AUTH" | jq -r '.[] | select(.username=="ada") | .id')
curl -s -X PATCH "$API/users/$ID" -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"password":"a new long password"}'

# 2. The bootstrap device's private key is unrecoverable, and a peer's public
#    key cannot be swapped in place — its address, name, memberships and audit
#    trail all hang off the key it was registered with. Delete it and make a
#    new one from the dashboard, which generates the keypair in your browser.
curl -s -X DELETE "$API/peers/$(curl -s "$API/peers" -H "$AUTH" \
  | jq -r '.[] | select(.name=="ada-laptop") | .id')" -H "$AUTH"
```

Then sign in at `http://10.88.0.1:3000` and use **Devices → Config generator**
for the device. That path never puts a private key on the gateway, which is why
losing this output stops being possible after the first device.

Afterwards, and any time later:

```sh
sudo ./deploy/foxguard-healthcheck.sh
```

Read-only. It checks the services, that dev mode is off, that the API is started
with `foxguard-serve`, that config files are `0600`, that the live nftables table
still carries the `iifname != "wg0" accept` guard, whether the dataplane has
drifted from the database, that WireGuard's peer list matches the control plane,
and that the portal refuses both forwarded headers and non-peer addresses.

The rest of this document is the manual procedure, and the explanation of what
the script is doing at each step.

## 1. Prepare the box

Debian 12 / Ubuntu 24.04 assumed. In an LXC, the container needs `CAP_NET_ADMIN`
and access to `/dev/net/tun` — an unprivileged container works, but check that
`nft list ruleset` and `wg show` both succeed before going further.

```sh
apt update
apt install -y nftables wireguard-tools python3 python3-venv python3-pip git

systemctl enable --now nftables
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv6.conf.all.forwarding=1
printf 'net.ipv4.ip_forward=1\nnet.ipv6.conf.all.forwarding=1\n' \
  > /etc/sysctl.d/99-foxguard.conf
```

Bring up WireGuard **before** Foxguard and confirm you can reach the gateway
through the tunnel from at least one device. Foxguard manages peers on an
existing interface; it does not create it.

```sh
# /etc/wireguard/wg0.conf — interface section only, Foxguard writes the peers
[Interface]
Address = 10.88.0.1/24
ListenPort = 51820
PrivateKey = <generated with: wg genkey>

systemctl enable --now wg-quick@wg0
wg show wg0
```

## 2. Install

```sh
install -d -m 0750 /opt/foxguard /etc/foxguard /var/lib/foxguard
git clone <your-repo> /opt/foxguard/src

python3 -m venv /opt/foxguard/venv
/opt/foxguard/venv/bin/pip install -e /opt/foxguard/src/backend
/opt/foxguard/venv/bin/pip install -e /opt/foxguard/src/agent
```

The agent depends on the backend package because it reuses
`foxguard.nftables` — the generator model, the validation and the safety guards
are literally the same code as the control plane's, not a reimplementation. If
your gateway is separate from the API box, this installs a few unused libraries
there; that is the price of not having two divergent copies of the code that can
lock you out.

## 3. Database and control plane

PostgreSQL 15+, on this box or another one:

```sh
sudo -u postgres createuser --pwprompt foxguard
sudo -u postgres createdb -O foxguard --template=template0 --encoding=UTF8 \
  --lc-collate=C.UTF-8 --lc-ctype=C.UTF-8 foxguard
```

**Spell the encoding out.** On a minimal LXC with no locale configured, `initdb`
creates the cluster as `SQL_ASCII` and `createdb` inherits it. psycopg then
returns *bytes* where SQLAlchemy expects text, and the very first connection
dies on a regex over the server version string:

```
TypeError: cannot use a string pattern on a bytes-like object
```

which says nothing about encodings. `template0` is the only template that lets
you override it. To check an existing database:

```sh
sudo -u postgres psql -tAc \
  "SELECT datname, pg_encoding_to_char(encoding) FROM pg_database"
```

Generate the two tokens — they are unrelated and should never be the same value:

```sh
python3 -c "import secrets; print('admin:', secrets.token_urlsafe(32))"
python3 -c "import secrets; print('agent:', secrets.token_urlsafe(32))"
```

`/etc/foxguard/backend.env` (mode `0600`):

```ini
FOXGUARD_DEV_MODE=false
FOXGUARD_DATABASE_URL=postgresql+psycopg://foxguard:<password>@127.0.0.1:5432/foxguard
FOXGUARD_ADMIN_API_TOKEN=<admin token>
FOXGUARD_AGENT_API_TOKEN=<agent token>

FOXGUARD_WG_INTERFACE=wg0
FOXGUARD_WG_POOL_V4=10.88.0.0/24
FOXGUARD_WG_GATEWAY_IP=10.88.0.1
# Leave FOXGUARD_WG_STAGING_POOL_V4 unset. It does not mark confinement --
# addresses are permanent -- and outside the prefix wg0 carries it makes peers
# unroutable. See "The staging pool" in docs/architecture.md.

FOXGUARD_WAN_INTERFACE=eth0
FOXGUARD_PORTAL_PORT=8080
FOXGUARD_INTERNAL_CIDRS=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
FOXGUARD_GATEWAY_INPUT_POLICY=open

# For the dashboard's config generator. Without these it reports every
# configuration as incomplete rather than handing out one that cannot connect.
FOXGUARD_WG_PUBLIC_KEY=<wg show wg0 public-key>
FOXGUARD_WG_ENDPOINT_HOST=vpn.example.com:51820
FOXGUARD_CLIENT_CONFIG_ALLOWED_IPS=routed
```

The installer fills both in when it can — it reads the key from the interface it
bootstrapped, and the endpoint from `--endpoint`. The generator itself never
needs a private key: it makes the keypair in the operator's browser and the
gateway is only ever told the public half.

Run the migrations and start the API bound to localhost (or to the tunnel
address — never to the WAN):

```sh
cd /opt/foxguard/src/backend
set -a && . /etc/foxguard/backend.env && set +a
/opt/foxguard/venv/bin/alembic upgrade head
# foxguard-serve, not uvicorn -- see section 5b for why.
/opt/foxguard/venv/bin/foxguard-serve --host 127.0.0.1 --port 8000
```

Once that works, install the unit — it runs the same command with the hardening
already written down:

```sh
useradd --system --home /opt/foxguard --shell /usr/sbin/nologin foxguard
chown -R foxguard:foxguard /opt/foxguard
cp /opt/foxguard/src/backend/systemd/foxguard-api.service /etc/systemd/system/
# Edit --host in the unit to your tunnel address before enabling it.
systemctl daemon-reload && systemctl enable --now foxguard-api
```

The control plane does **not** need `CAP_NET_ADMIN` and the unit drops all
capabilities: it never touches the network. Only the agent does — which is why
they are two processes and not one.

## 4. Dry run the agent — do this before enabling anything

`/etc/foxguard/agent.env` (mode `0600`):

```ini
FOXGUARD_AGENT_API_URL=http://127.0.0.1:8000
FOXGUARD_AGENT_API_TOKEN=<agent token>
FOXGUARD_AGENT_POLL_INTERVAL_SECONDS=10
FOXGUARD_AGENT_STATE_DIR=/var/lib/foxguard
FOXGUARD_AGENT_DRY_RUN=true
FOXGUARD_AGENT_LOG_LEVEL=DEBUG
```

Run it in the foreground:

```sh
set -a && . /etc/foxguard/agent.env && set +a
/opt/foxguard/venv/bin/foxguard-agent
```

In dry-run mode the agent fetches the ruleset and validates it with
`nft -c -f` — it applies nothing and touches no WireGuard peer. You should see
`dry run: ruleset <digest> validated, not applied`.

Read the ruleset yourself before letting anything apply it:

```sh
curl -s -H "Authorization: Bearer <admin token>" \
  localhost:8000/api/v1/ruleset/preview | jq -r .content
```

Check three things:

1. `iifname != "wg0" accept` is the first rule of `chain input`. Your SSH is
   safe.
2. Both base chains say `policy accept`.
3. The only `delete` statement is `delete table inet foxguard`.

## 5. Go live

```sh
sed -i 's/^FOXGUARD_AGENT_DRY_RUN=true/FOXGUARD_AGENT_DRY_RUN=false/' \
  /etc/foxguard/agent.env

cp /opt/foxguard/src/agent/systemd/foxguard-agent.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now foxguard-agent
journalctl -u foxguard-agent -f
```

Verify from the box and from a peer:

```sh
nft list table inet foxguard        # our table, alone
nft list ruleset | grep -c 'table'  # your other tables are still there
wg show wg0
```

## 5b. The portal and the enrollment endpoint

Both are served by the same FastAPI app as the admin API, and both are
unauthenticated by design — they identify their caller by the tunnel address it
sends from. Three deployment rules follow from that, and none of them is
optional.

**Start it with `foxguard-serve`, not plain `uvicorn`.**

```sh
foxguard-serve --host 10.88.0.1 --port 8080
```

This is a security control, not a convenience wrapper. `uvicorn` enables
`ProxyHeadersMiddleware` **by default** and trusts `127.0.0.1`; it rewrites the
client address from `X-Forwarded-For` before Foxguard sees it. Since the portal
identifies peers *by that address*, anything able to connect on loopback could
otherwise impersonate any peer with one header. `foxguard-serve` disables it.

If you must run uvicorn directly, pass `--no-proxy-headers`. The API refuses
peer-identified requests carrying forwarded headers either way, so a mistake
here fails closed — but it fails closed *loudly*, and you would rather not find
out that way.

**Bind where only the tunnel can reach it.** `FOXGUARD_PORTAL_PORT` (default
8080) is what the nftables ruleset opens to quarantined peers.

**Never behind a reverse proxy.** nginx or Traefik in front of the portal makes
every request arrive from the proxy's address, and peer identification stops
working — or, if you "fix" that by trusting the header, anyone can claim to be
any peer. The Phase 5 reverse proxy is meant for internal *web services*, not
for the portal or `/api/v1/enroll`.

### Building and serving the portal UI

The portal is a **static bundle executed by the browser**, served by the API
itself. That is what keeps the peer's own address on the connection the API
reads:

```sh
cd /opt/foxguard/src/frontend/portal
npm ci && npm run build          # produces out/
```

Point the API at it and the portal answers on `/`:

```ini
FOXGUARD_PORTAL_STATIC_DIR=/opt/foxguard/src/frontend/portal/out
```

A missing directory is a warning, not a failure — the API still starts, so peers
can be enrolled and the admin API used while the UI is sorted out.

**One worker.** The login throttle and the in-flight OIDC transactions live in
process memory. With `--workers 4` the login budget is four times what you
configured, and an OIDC callback can land on a worker that never saw the
authorization request.

Check it from a quarantined peer:

```sh
# From the peer, through the tunnel:
curl -s http://10.88.0.1:8080/api/v1/portal/status | jq
# -> peer_id, state "staging"/"quarantined", auth_methods, totp_required

# From the gateway itself (not a peer address) -- must be 403:
curl -s -o /dev/null -w '%{http_code}\n' http://10.88.0.1:8080/api/v1/portal/status
```

### Enrolling a server peer

```sh
# On the gateway: register the key and mint a one-time enrollment key.
curl -s -X POST localhost:8000/api/v1/peers -H "Authorization: Bearer <admin>" \
  -H 'Content-Type: application/json' \
  -d '{"name":"backup-01","peer_type":"server","wg_public_key":"<pubkey>",
       "group_slugs":["backup"]}'
curl -s -X POST localhost:8000/api/v1/peers/<id>/enrollment-key \
  -H "Authorization: Bearer <admin>" -H 'Content-Type: application/json' \
  -d '{"expires_at":"2026-08-01T00:00:00Z"}'      # optional; ideal for a lab box
```

Provision the key onto the machine, then **from inside the tunnel**:

```sh
curl -s -X POST http://10.88.0.1:8080/api/v1/enroll \
  -H 'Content-Type: application/json' \
  -d '{"enrollment_key":"fgk_...","wg_public_key":"<pubkey>"}'
```

`wg_public_key` is an optional cross-check; include it, it catches a
provisioning script that handed this box another machine's key.

### Optional: OIDC

Register a confidential client with Authentik/Keycloak whose redirect URI is the
portal's callback **inside the tunnel**, then set the four `FOXGUARD_OIDC_*`
variables from `.env.example`. Leave them unset and the portal serves local
accounts only — Foxguard never requires an IdP.

Each user needs `external_idp_issuer` + `external_idp_subject` matching the
`iss`/`sub` their IdP issues, and their peer must be bound to that account.

## 5c. Session expiry

Runs inside the API process; nothing extra to install or enable. Every
`FOXGUARD_SESSION_SWEEP_INTERVAL_SECONDS` (default 60) it quarantines user peers
whose session has run out. **Server peers are never touched** — their access
ends when their enrollment key is revoked, not on a timer.

Lifetimes are per group, and a peer in several gets the shortest:

```sh
curl -s -X PATCH localhost:8000/api/v1/groups/<id> \
  -H "Authorization: Bearer <admin>" -H 'Content-Type: application/json' \
  -d '{"session_lifetime_seconds": 14400}'      # pentest-lab: 4h
```

Groups with no override fall back to
`FOXGUARD_DEFAULT_SESSION_LIFETIME_SECONDS`. Tightening a group's lifetime
applies to sessions that are **already running**; loosening it does not extend
them, because that would grant time without anyone re-authenticating.

**See who is logged in and for how much longer:**

```sh
curl -s localhost:8000/api/v1/sessions -H "Authorization: Bearer <admin>" \
  | jq -r '.[] | "\(.peer_name)\t\(.username)\t\(.auth_method)\t\(.seconds_remaining)s left"'
```

**Run the sweep by hand** (safe at any time — it takes the same advisory lock as
the timer, so it cannot collide with it):

```sh
curl -s -X POST localhost:8000/api/v1/sessions/sweep -H "Authorization: Bearer <admin>" | jq
# {"expired": [...], "regenerated": true, "ran": true}
# "ran": false means the background sweeper held the lock -- it is doing the work.
```

### Preferring cron over the built-in timer

```ini
FOXGUARD_SESSION_SWEEP_ENABLED=false
```

then drive it externally. **If you disable it without setting up the cron,
nothing expires** — user peers stay active until they log out or you intervene.
The API logs a warning at startup when it is off, for exactly this reason.

```
*/1 * * * * curl -sf -X POST http://127.0.0.1:8000/api/v1/sessions/sweep \
              -H "Authorization: Bearer <admin>" >/dev/null
```

**Expiry cuts live connections**, not just new ones — the quarantine drop is
evaluated before the `established,related` accept. A user mid-`ssh` when their
session ends loses that connection and has to visit the portal again. That is
deliberate; the alternative is a timeout that only applies to people who happen
to reconnect.

## 5d. Administrator accounts

The static token is for machines. People sign in, which is what makes the audit
log name them.

**Bootstrap the first administrator** with the token, once:

```sh
curl -s -X POST localhost:8000/api/v1/users \
  -H "Authorization: Bearer <admin token>" -H 'Content-Type: application/json' \
  -d '{"username":"ada","password":"<a long one>","is_admin":true}'
```

Then sign in from the dashboard. Give them TOTP while you are there
(`/users` → Manage → Provision TOTP): an administrator account is worth a second
factor.

Actions taken with the static token appear as `admin-token`; actions taken by a
signed-in person appear under their username. If you want *every* action
attributed, remove `FOXGUARD_ADMIN_API_TOKEN` once accounts exist — but keep it
if provisioning scripts or CI call the API, and know that it is then a
credential nobody's name is attached to.

**Single sign-on for administrators** is optional and needs one extra variable
on top of the portal's OIDC settings:

```ini
FOXGUARD_OIDC_ADMIN_REDIRECT_URL=http://10.88.0.1:3000/login/sso
```

It points at the *dashboard*, not the API — the dashboard completes the exchange
server-side so the session token never travels through a URL. Register that URI
with the IdP, and give the account an `external_idp_issuer`/`external_idp_subject`
plus `is_admin`. Foxguard still decides whether they administer it: the account
must exist locally, be active and be an administrator, all re-checked at every
sign-in.

**Seeing and cutting sessions:**

```sh
curl -s localhost:8000/api/v1/admin/sessions -H "Authorization: Bearer <admin>" \
  | jq -r '.[] | "\(.username)\t\(.source_ip)\tlast seen \(.last_seen_at)"'

# Revoke one without touching the account:
curl -s -X DELETE localhost:8000/api/v1/admin/sessions/<id> \
  -H "Authorization: Bearer <admin>"
```

**Cutting someone off entirely** takes effect on their next request, not at
session expiry — deactivate the account, remove its admin rights, or change its
password, any of which revokes what they hold:

```sh
curl -s -X PATCH localhost:8000/api/v1/users/<id> \
  -H "Authorization: Bearer <admin token>" -H 'Content-Type: application/json' \
  -d '{"is_active": false}'
```

## 5e. The admin dashboard

```sh
cd /opt/foxguard/src/frontend/admin
npm ci && npm run build
FOXGUARD_API_URL=http://127.0.0.1:8000 \
FOXGUARD_ADMIN_API_TOKEN=<admin token> \
  npm run start -- -p 3000
```

`FOXGUARD_ADMIN_API_TOKEN` here is the fallback used before anyone has signed
in; once an administrator signs in, their session token is kept in an httpOnly
cookie on the dashboard's origin and used instead. Either way the credential is
read by the **server** side of the dashboard and never sent to the browser, so
the machine running `npm run start` is as trusted as the API box — run it there,
bound to localhost or the tunnel address, never to the WAN.

Then install its unit:

```sh
cp /opt/foxguard/src/frontend/admin/systemd/foxguard-dashboard.service \
   /etc/systemd/system/
# /etc/foxguard/dashboard.env, mode 0600:
#   FOXGUARD_API_URL=http://10.88.0.1:8080
#   FOXGUARD_ADMIN_API_TOKEN=<admin token>   # until an account exists
systemctl daemon-reload && systemctl enable --now foxguard-dashboard
```

It needs no capabilities and no database access of its own — it only talks to
the API.

### The kill switch

`/kill-switch` in the UI, or directly:

```sh
# Everyone re-authenticates. NOTE: a server peer re-enrolls automatically within
# one poll, so this does not hold the fleet down.
curl -s -X POST localhost:8000/api/v1/kill-switch \
  -H "Authorization: Bearer <admin>" -H 'Content-Type: application/json' \
  -d '{"mode":"quarantine","confirm":"QUARANTINE ALL PEERS"}' | jq

# Nothing comes back without an administrator. Use this for a suspected
# compromise.
curl -s -X POST localhost:8000/api/v1/kill-switch \
  -H "Authorization: Bearer <admin>" -H 'Content-Type: application/json' \
  -d '{"mode":"lockdown","confirm":"DISABLE ALL PEERS"}' | jq
```

**There is no undo.** Restore peers deliberately; the previous state of every one
is in the audit entry:

```sh
curl -s "localhost:8000/api/v1/audit-log?action=killswitch.trigger" \
  -H "Authorization: Bearer <admin>" | jq '.[0].detail.peers'
```

Peers already `revoked` — and, in quarantine mode, `disabled` — are deliberately
left alone: both are stricter than the targets, and the kill switch must never
widen anyone's access.

## 5f. Internal DNS and zones (optional)

Both are off until you ask for them, and neither changes anything about how
access is decided — a zone is a *segment*, and DNS is a *name service*. Access
still comes from `peers.state` and the ACL rules.

### DNS

Turn it on with `--dns` at install time, or in `/etc/foxguard/backend.env`:

```sh
FOXGUARD_DNS_ENABLED=true
FOXGUARD_DNS_ZONE=fox.internal
FOXGUARD_DNS_MODE=forward          # or split -- see below
FOXGUARD_DNS_UPSTREAMS=1.1.1.1,9.9.9.9
FOXGUARD_DNS_LISTEN_ADDRESSES=10.88.0.1
```

then `systemctl restart foxguard-api`. The agent renders the zone on its next
poll, writes `/etc/foxguard/dns/{hosts,dnsmasq.conf}` and starts
`foxguard-dns.service`. Every peer gets a name derived from its own
(`laptop.fox.internal`), the gateway answers to `gw.fox.internal`, and
`/api/v1/dns/records` adds aliases and A records for services that live off the
tunnel.

#### The zone resolves nowhere, but forwarding works

One line in the journal, and nothing else wrong:

```
dnsmasq: failed to load names from /etc/foxguard/dns/hosts: Permission denied
```

dnsmasq drops privileges at startup and re-reads `addn-hosts` **as the
unprivileged user**. The hosts file is written 0644 for exactly that reason —
but every directory on the way to it has to be traversable too, and
`/etc/foxguard` holding credentials is a natural place to put 0750.

The daemon starts, binds, forwards upstream, and answers nothing for the zone.

```sh
chmod 0751 /etc/foxguard
systemctl restart foxguard-dns
```

Traversable is not readable: with no `o+r` nothing can list the directory, and
the credentials inside are `0600` root regardless. The installer now creates it
this way; check it with

```sh
runuser -u nobody -- cat /etc/foxguard/dns/hosts >/dev/null && echo ok
```

#### `setting capabilities failed: Operation not permitted`

```
dnsmasq[40852]: setting capabilities failed: Operation not permitted
dnsmasq[40852]: FAILED to start up
foxguard-dns.service: Main process exited, code=exited, status=5/NOTINSTALLED
```

dnsmasq drops to an unprivileged user at startup and calls `capset()` to keep
`CAP_SETUID` across the change. Several of the hardening directives in the unit
— `ProtectKernelTunables=` and `ProtectKernelModules=` among them — make systemd
hand the process a **permitted set narrower than its bounding set**, and
`CAP_SETUID` is one of the ones that goes. `capset()` cannot raise it back, and
dnsmasq treats that as fatal.

Measured on a live Debian 13 container rather than reasoned about:

| | `CapPrm` | `CapBnd` |
| --- | --- | --- |
| without `ProtectKernelTunables=` | `…14c0` | `…14c0` |
| with it | **`…1440`** | `…14c0` |

`0x14c0 − 0x1440 = 0x80`, which is bit 7: `CAP_SETUID`.

The fix is to list it as **ambient**, so it is in the permitted set from the
start. The shipped unit does. If yours predates that:

```sh
systemctl edit foxguard-dns
```

```ini
[Service]
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_SETUID
```

```sh
systemctl daemon-reload && systemctl restart foxguard-dns
```

dnsmasq drops it along with everything else the moment it has changed user, so
the daemon still ends up with an empty effective set. Removing the hardening
directives instead does **not** work — several of them cause the same thing, so
dropping one only moves the failure.

#### You never start `foxguard-dns` yourself

The installer installs the unit and **does not enable it**, which is
deliberate. Its `ExecStartPre` runs `dnsmasq --test` on a configuration file
that does not exist until a zone has been rendered, so a unit enabled at boot on
a fresh install fails, and `Restart=on-failure` turns that into a loop.

The agent owns the daemon instead. It writes the artefacts and then reloads or
restarts the unit, which is also what starts it the first time. Two consequences
worth knowing:

- **Nothing happens while the agent is in dry run.** It validates the zone with
  `dnsmasq --test` and logs `dry run: DNS zone <digest> validated, not applied`.
  No file is written and no daemon is started. Take the agent out of dry run
  (section 5) and the resolver comes up on the next poll.
- **After a reboot the agent starts it again**, even though the rendered files
  on disk are unchanged. That is not free behaviour — the applier checks
  `systemctl is-active` before concluding there is nothing to do, precisely
  because "the files are right" and "the zone is being served" are different
  statements. `make test-dns-applier-live` drives a real dnsmasq through that
  case.

If you would rather systemd owned it, `systemctl enable foxguard-dns` is safe
*once a zone exists* — the agent's behaviour does not change, it simply finds
the unit already active and leaves it alone.

**Clients have to be told.** Add the resolver and a search domain to the peer's
config, or names resolve nowhere:

```ini
[Interface]
PrivateKey = ...
Address = 10.88.0.5/32
DNS = 10.88.0.1, fox.internal
```

`forward` mode resolves everything and sends what is not in the zone upstream,
which is what makes that line work on its own. `split` mode answers for the zone
and REFUSES the rest — better for privacy, but a client that sends *all* its
queries here then gets REFUSED for the internet and needs a second resolver to
fall through to. Use `split` only where clients are configured for it.

Two things worth knowing before you enable it:

- **Do not put a WAN address in `FOXGUARD_DNS_LISTEN_ADDRESSES`.** That is an
  open resolver; `foxguard-healthcheck.sh` fails if it finds one.
- **A quarantined peer can resolve the whole zone**, so device names disclose
  your inventory to a device that has not authenticated yet. If that matters,
  set `FOXGUARD_ALLOW_DNS_IN_QUARANTINE=false`.

### Zones

A zone is a network segment: a peer sits in exactly one, and the zone can own
routes to networks behind its peers — Netbird's "networks", in Foxguard's model.

```sh
# a zone, and a network reachable through one of its peers
curl -sX POST -H "$AUTH" -H 'Content-Type: application/json' \
  http://10.88.0.1:8080/api/v1/zones \
  -d '{"slug":"office","name":"Office network"}'

curl -sX POST -H "$AUTH" -H 'Content-Type: application/json' \
  http://10.88.0.1:8080/api/v1/zones/$ZONE_ID/routes \
  -d '{"cidr":"192.168.10.0/24","via_peer_id":"'"$ROUTER_PEER_ID"'"}'
```

The CIDR then joins the zone's nftables set, so one ACL rule naming `office`
covers the devices *and* the network behind them. On its next poll the agent
puts the CIDR in the routing peer's `AllowedIPs` and installs
`ip route add 192.168.10.0/24 dev wg0`. Both halves are needed; the healthcheck
reports a route with no carrier as a black hole.

Three things it will refuse, and you want it to:

- a **default route** as a zone route — it would replace the gateway's own and
  cut every remote session;
- a **prefix covering an address this gateway already answers on** — a route for
  `192.168.1.0/24` on a box whose LAN address is `192.168.1.10` sends your own
  SSH replies into the tunnel;
- **replacing a route it did not install** — it warns and leaves it alone.

Traffic *inside* a zone is denied until you tick "allow traffic inside the
zone". That is deliberate: everywhere else here, access is denied until
something grants it.

`FOXGUARD_AGENT_MANAGE_ROUTES=false` turns the kernel-route half off entirely if
you would rather manage the routing table yourself. The `AllowedIPs` half still
happens, so an `ip route add <cidr> dev wg0` by hand completes the path.

## 5z. The guided alternative

Everything in sections 5a to 5h is reachable by answering questions instead:

```sh
sudo ./deploy/foxguard-setup.sh
```

It detects what it can (your WireGuard interface and its addresses, the
internet-facing interface, the address peers would dial), explains what each
answer changes, validates as you go rather than failing three screens later, and
shows you the exact `foxguard-install.sh` command it built before running
anything. `--dry-run` stops after printing that command.

It is a front end, not a second installer — there is one implementation of the
install, so the two cannot drift, and the command it prints is something you can
keep for next time.

Two things it does that are easy to get wrong by hand:

* **Naming an interface that does not exist offers to create it.** By flag, that
  is a separate `--bootstrap-wireguard` you have to remember; forgetting it gets
  you a preflight failure several answers later.
* **The Cloudflare token is read without echo** and printed as `<redacted>` in
  the command it shows you, so it never reaches your scrollback or your shell
  history.

## 5g. Reverse proxy (optional)

Publishes services that live behind peers: HTTP terminated, or TCP passed
through untouched. Off by default.

```sh
sudo ./deploy/foxguard-install.sh \
  --proxy --proxy-domain example.com \
  --proxy-external 203.0.113.10 \
  --acme-email you@example.com \
  --acme-cf-token <a Zone:DNS:Edit token for that zone>
```

**The domain is not optional and cannot be `.internal`.** Peer names stay on the
DNS zone (`laptop.fox.internal`); a *service* needs a name a public CA will
sign. Use a domain you own.

**Certificates.** DNS-01 with the Cloudflare plugin, one wildcard for
`example.com` and `*.example.com`. DNS-01 rather than HTTP-01 because HTTP-01
needs every name to resolve publicly to this box, which would force public
records for internal-only services. A wildcard rather than per-service
certificates for two reasons: publishing becomes a database write with no ACME
round trip, and per-name certificates would publish your internal service
inventory to Certificate Transparency logs.

The installer prints the `certbot certonly` command and installs the deploy
hook. Run it once; renewals then load the new certificate over HAProxy's runtime
socket **without a reload**, so a passthrough session is never dropped.

Until you do, the proxy runs on a self-signed bootstrap certificate — it has to,
because HAProxy will not start with an empty `crt` directory. Browsers will
refuse it and the healthcheck says so.

**A service and the way in are one request.** A listener with no authenticator
that applies to it is refused, so there is no valid state where a service exists
and nothing guards it:

```sh
curl -X POST http://<gateway>:8080/api/v1/services \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"slug":"grafana","name":"Grafana","kind":"http","exposure":"both",
       "upstream_peer_id":"<peer uuid>","upstream_host":"10.88.0.6","upstream_port":3000,
       "authenticators":[{"kind":"peer_identity","scope":"internal"},
                         {"kind":"bearer","scope":"external"}],
       "access":[{"kind":"group","group_id":"<devs uuid>","action":"accept"}]}'
```

That publishes `grafana.example.com` on both doors: inside the tunnel the source
address proves who you are and the `devs` group is enough; from the internet a
bearer token is required. **Peer identity scoped to the external listener is
refused** — outside the tunnel a source address belongs to an ISP or a NAT and
is bound to no key.

**Split-horizon is what makes one name work on both doors.** With the internal
resolver on, `grafana.example.com` resolves to the gateway's tunnel address for
a connected peer, so it never leaves the tunnel. Everyone else gets your public
record and arrives on the WAN listener.

One conflict to avoid, and both the installer and the healthcheck refuse it: do
not set `FOXGUARD_DNS_ZONE` to a domain that covers `FOXGUARD_PROXY_DOMAIN`
while `FOXGUARD_DNS_MODE=split`. The resolver would answer NXDOMAIN for
`_acme-challenge` and renewals would stop.

### Country filters

Installing the proxy also installs `foxguard-geo-refresh.timer`, which downloads
a prefix dataset weekly (about 4 MiB, from db-ip.com). It costs nothing until a
service names a country, and having it already there beats discovering it is
missing on the day you add one.

The download is **deliberately not part of a reconciliation**. The agent's loop
installs firewall rules, and a ruleset that fails to apply because someone
else's web server is down is not a trade worth making.

```sh
# Fetch it now instead of waiting for the timer:
systemctl start foxguard-geo-refresh.service
journalctl -u foxguard-geo-refresh -n 20

# Or during the install:
./deploy/foxguard-install.sh --proxy --proxy-domain example.com --geo-now
```

Until it has run once the map is empty, which means **an allow list refuses
everyone and a deny list blocks nobody**. `GET /api/v1/proxy` says so in its
warnings and the map file says so in its own header.

The gateway builds the map from the countries your filters actually name, not
the whole world — measured, the planet costs HAProxy about 367 MiB of resident
memory and three countries about 47. Adding a country you have not used before
rebuilds the map on the agent's next poll, which takes a few seconds.

Geo is noise reduction, not a security control. Anybody who cares defeats it
with a VPN in one click.

**What a passthrough service can and cannot have:**

| | HTTP terminated | TCP passthrough |
| --- | --- | --- |
| Peer identity, IP filters, rate limit | yes | yes |
| Bearer, basic auth | yes | **no** |
| Identity headers to the upstream | yes | **no** |

A plain-TCP service also cannot share a port — no SNI, no Host header — so one
is allocated from `FOXGUARD_PROXY_TCP_PORT_START..END` (20000–20999 by default).

**Publishing a service opens a path your ACLs do not cover.** The proxy connects
*from the gateway*, which no zone or group rule constrains. `GET /api/v1/proxy`
lists those paths under `implicit_paths` and the healthcheck prints them. What
constrains them is that HAProxy can only ever reach the declared `host:port` —
not a firewall rule. Publish accordingly.

**Never put the proxy in front of the Foxguard API or portal.** They identify
their caller by source address and refuse any forwarded header; a proxy destroys
that identity. The control plane refuses such a service at creation.

## 5h. Single sign-on (optional)

Lets a person reach a published service with their Foxguard account instead of a
shared token.

```sh
sudo ./deploy/foxguard-install.sh --proxy --proxy-domain example.com --sso ...
```

The installer generates `FOXGUARD_PROXY_SSO_SECRET` and writes it to
`backend.env`. Foxguard signs the cookie with it and the proxy verifies with the
same value, so **it is rendered into the HAProxy configuration** — which is why
that file is `0640 root:haproxy`. Rotating it signs everybody out.

**The login page lives at `auth.<your domain>`**, covered by the wildcard
certificate you already have. This is the one place the proxy is put in front of
the Foxguard API, and it is bounded by construction: only `/api/v1/sso/` is
routed there, everything else on that host name is refused by HAProxy before it
reaches a backend. The portal and enrollment endpoints in particular must never
be reachable that way — they identify their caller by source address.

**The proxy verifies the cookie itself.** No round trip to the API per request,
so a published service keeps serving while `foxguard-api` restarts. The cost is
that a valid cookie stays valid until it expires, which is why revocation is
explicit: `DELETE /api/v1/proxy/sso-sessions/<id>` puts the session id in a map
the proxy consults, and the agent pushes that map over the runtime socket
without a reload.

**Signing out is two things**, and `GET /api/v1/sso/logout` does both: it clears
the cookie *and* revokes the session behind it. Clearing alone would leave a
token that still verifies.

Two limits to know before you rely on it:

* **An SSO service admits any active Foxguard account.** Groups belong to
  devices, not to people, so there is nothing finer to authorize on yet.
  `is_admin` is the only distinction available.
* **Sessions are not idle-based.** A session ends at a wall-clock deadline
  (`FOXGUARD_PROXY_SSO_LIFETIME_SECONDS`, 8h by default), not after a period of
  inactivity — the same limitation admin sessions have.

## 6. Operating it

**See what is live:**

```sh
nft list table inet foxguard
nft list set inet foxguard g_admin_v4      # who is in a group right now
nft -j list table inet foxguard | jq       # counters, per rule
```

Every generated rule carries a `counter` and a `fg:<ref>:<name>` comment, so you
can map a hit count back to the ACL rule that produced it.

**Detect drift:**

```sh
# What the database says the box should be running:
curl -s -H "Authorization: Bearer <admin token>" \
  localhost:8000/api/v1/ruleset/preview | jq -r .digest

# What the agent last reported applying:
curl -s -H "Authorization: Bearer <admin token>" \
  localhost:8000/api/v1/ruleset/versions | jq -r '.[0] | "\(.status) \(.digest)"'
```

Equal digests with status `applied` means no drift. The agent re-applies the
full state on every change, so drift should only ever come from someone editing
nftables by hand.

**Version your ACLs in git:**

```sh
curl -s -H "Authorization: Bearer <admin token>" \
  localhost:8000/api/v1/policies/export > acls/policies.json
git -C acls commit -am 'acl: allow backup agents to reach postgres'

# After a rebuild — always preview first:
curl -s -X POST localhost:8000/api/v1/policies/import \
  -H "Authorization: Bearer <admin token>" -H 'Content-Type: application/json' \
  -d "{\"dry_run\": true, \"prune\": true, \"document\": $(cat acls/policies.json)}" | jq
```

`prune: true` makes the import a full sync — groups and rules absent from the
document are deleted. Without it, the import only creates and updates.

## Backup and restore

**The policy export is not a backup.** `GET /api/v1/policies/export` covers
groups and ACL rules — the things worth versioning in git. Everything else lives
solely in PostgreSQL: every peer's public key and tunnel address, every
account's password hash and TOTP secret, the enrollment key hashes, the audit
log. Lose the database and every device needs re-registering, which means every
client config changes.

```sh
sudo ./deploy/foxguard-backup.sh                    # -> /var/backups/foxguard
sudo ./deploy/foxguard-backup.sh --dest /mnt/nas/foxguard --keep 30
```

One `0600` tarball per run: a `pg_dump`, the three `/etc/foxguard/*.env` files,
and the WireGuard interface config. It refuses to finish if `pg_dump` produced a
truncated file — a dump that stops halfway restores cleanly and silently drops
rows, which is worse than no dump at all.

Nightly, keeping a month:

```
15 3 * * * /opt/foxguard/src/deploy/foxguard-backup.sh --dest /mnt/nas/foxguard --keep 30 >/dev/null
```

**The archive is a credential.** It holds the admin and agent tokens, the
database password, the WireGuard private key that *is* this gateway's identity,
and TOTP secrets in plaintext — they have to be usable to verify a code. Protect
a backup exactly as you protect root on this box, and encrypt it if it leaves
your network.

Check one without restoring it:

```sh
sudo ./deploy/foxguard-backup.sh --verify /mnt/nas/foxguard/foxguard-20260729-031501.tar.gz
```

### Restoring

```sh
tar -xzf foxguard-20260729-031501.tar.gz -C /tmp
cd /tmp/foxguard-20260729-031501

systemctl stop foxguard-agent foxguard-api foxguard-dashboard

# The database must exist with UTF8 encoding before the dump goes in.
sudo -u postgres dropdb --if-exists foxguard
sudo -u postgres createdb -O foxguard --template=template0 --encoding=UTF8 \
  --lc-collate=C.UTF-8 --lc-ctype=C.UTF-8 foxguard
sudo -u postgres psql -q foxguard < database.sql

install -m 0600 backend.env agent.env dashboard.env /etc/foxguard/
install -m 0600 wg0.conf /etc/wireguard/          # the gateway's identity

systemctl restart wg-quick@wg0
systemctl start foxguard-api foxguard-dashboard
./deploy/foxguard-healthcheck.sh
```

Start the agent last, and consider putting it back in dry run for one cycle if
the restore was onto different hardware.

**Restoring without `wg0.conf` gives you a gateway with a new keypair**: every
existing client config points at a server that can no longer decrypt them, and
you would have to redistribute all of them. That file matters as much as the
database.

## Uninstalling

```sh
sudo ./deploy/foxguard-uninstall.sh --dry-run       # print the plan, change nothing
sudo ./deploy/foxguard-uninstall.sh                 # the default removal
```

The default stops and disables the five units, deletes `inet foxguard` from
nftables, withdraws the kernel routes the agent installed for zone networks, and
removes `/opt/foxguard`, `/etc/foxguard`, `/var/lib/foxguard`, the unit files and
the service user. Certificate private keys are **shredded** before that
directory goes: `rm -rf` unlinks without overwriting, and a wildcard key covers
the whole domain. `/etc/letsencrypt` is deliberately left alone — certbot owns
it, other things may use the same certificate, and re-issuing after an
accidental deletion runs into rate limits. It leaves the database, the WireGuard interface and every apt
package alone, because none of those is unambiguously Foxguard's to delete.

The routes are not opt-in and not left behind either: they point into a tunnel
whose peers nothing manages any more, so leaving them is leaving a black hole in
the routing table. Only the ones recorded in `/var/lib/foxguard/routes.json` are
removed — the same rule the agent follows — so a route you added by hand to the
same network survives.

Three flags go further, each opt-in for its own reason:

| Flag | What it adds | Why it is not the default |
| --- | --- | --- |
| `--remove-database` | drops the `foxguard` database and role | takes the audit log with it; a gzipped `pg_dump` lands in `/root` first, and an empty dump aborts the drop |
| `--remove-wireguard` | `wg-quick@wg0` down, interface deleted, keys removed | if you reached the box through that tunnel, this is the command that ends your session |
| `--remove-packages` | purges the apt packages the installer added, `dnsmasq-base` included | naming ten packages routinely removes several hundred — `nodejs` drags the whole `node-*` tree — and purging `postgresql` destroys **every** database on the machine, not only Foxguard's |

`--remove-packages` simulates with `apt-get -s purge` first, prints the count and
the head of the list, refuses outright if apt reports essential packages, and
asks again before purging. `python3`, `curl` and `iproute2` are never touched
even though the installer pulls them in: apt's own tooling depends on python3
and `iproute2` is how the box configures its networking, so removing either to
tidy up after Foxguard costs more than it cleans.

No step can abort the run. A failure — a `DROP DATABASE` with a session still
attached, a `daemon-reload` on an unreachable systemd — is collected and named in
the summary, and the exit code is 1. Re-running is safe: every step checks
whether its target is still there.

What it deliberately does not do: revoke anything. Client `.conf` files on other
machines keep working as WireGuard configs and become dead keys pointing at a
gateway that no longer answers. If the point is to cut access rather than to
remove the software, use the kill switch first — see [The kill switch](#the-kill-switch).

## Recovering from a mistake

**Locked out through the tunnel.** Get in over the console or from the LAN and:

```sh
systemctl stop foxguard-agent
nft delete table inet foxguard      # your other tables are untouched
```

The tunnel keeps working — WireGuard peers are unaffected by removing the
filtering table. Fix the policies, then start the agent again.

**A bad ruleset.** It cannot be applied: `nft -c -f` runs first on the same
bytes, and `nft -f` is a single transaction. If the table somehow disappears
after a successful apply, the agent re-applies
`/var/lib/foxguard/last-good.nft` on its own.

**`TypeError: cannot use a string pattern on a bytes-like object` on startup or
during migrations.** The database is `SQL_ASCII`, not UTF8 — see section 3. If
it is still empty, recreate it; otherwise dump, recreate and restore.

**The agent exits with `Permission denied` on its own executable, as root.**
Not a paradox: its unit hardens root down to `CAP_NET_ADMIN`/`CAP_NET_RAW`,
which drops `CAP_DAC_OVERRIDE` along with everything else, so root loses its
free pass on file permissions. If `/opt/foxguard` is owned by another user and
not world-readable, the agent cannot reach its own binary.

```sh
chown -R root:root /opt/foxguard /var/lib/foxguard
chmod 0755 /opt/foxguard
chown -R foxguard:foxguard /opt/foxguard/src/frontend/admin/.next   # if built
systemctl restart foxguard-agent
```

Nothing secret lives under `/opt/foxguard` — credentials are in `/etc/foxguard`
at `0600` — so a world-readable prefix costs nothing.

**A peer that must lose access right now.** Set its state to `quarantined` (or
delete it). Because the quarantine drop is evaluated before the
`established,related` accept, its open connections are cut on the next
reconciliation, not whenever it reconnects.

**A peer that must never come back.** Set it to `revoked`. That state is
terminal: no `PATCH`, no valid enrollment key and no correct password will
reactivate it. To undo the decision you delete the peer and register it again,
which forces a new WireGuard key and a new enrollment key.

**A user locked out by TOTP.** `DELETE /api/v1/users/<id>/totp` disables the
factor and destroys the secret; re-provision with `POST .../totp` and confirm
with a fresh code. Note the confirmation code is spent, so their first login
needs the *next* one — up to 30 seconds later.

**A user throttled at the portal.** The budget is per peer and drains on its
own after `FOXGUARD_PORTAL_LOGIN_WINDOW_SECONDS`. There is no unlock command
because there is no lockout; if you need it cleared immediately, restart the API
(the counters are in memory).

## Hardening checklist

- [ ] `FOXGUARD_DEV_MODE` is unset or `false` on the gateway.
- [ ] `backend.env` and `agent.env` are `0600` and owned by root.
- [ ] The admin and agent tokens are different values.
- [ ] At least one administrator account exists and has signed in, so actions
      are attributed to a person rather than to `admin-token`.
- [ ] Administrator accounts have TOTP enabled.
- [ ] The API listens on `127.0.0.1` or the tunnel address, never on the WAN.
- [ ] PostgreSQL is not reachable from outside the box.
- [ ] `FOXGUARD_INTERNAL_CIDRS` lists every internal network, otherwise
      `internet_exit` groups can route to them.
- [ ] If SSO is on: `FOXGUARD_PROXY_SSO_SECRET` is at least 32 characters and
      was generated, not chosen. It sits in two files on the gateway
      (`backend.env` and the rendered HAProxy configuration) and both are
      `0640` or tighter.
- [ ] If SSO is on: `GET /api/v1/proxy/sso-sessions` shows nobody you do not
      recognise, and nothing signed in from an address you do not expect.
- [ ] If the proxy is on: the wildcard private key is `0640 root:haproxy`, and
      the Cloudflare credential is an API **token** scoped to `Zone:DNS:Edit` on
      that one zone, never the global key.
- [ ] If the proxy is on: `/api/v1/proxy` shows no `implicit_paths` you did not
      intend — each one is a gateway-to-upstream path outside the ACL model.
- [ ] If the proxy is on: no service is exposed externally with an authenticator
      list you would not put on the public internet. The control plane refuses
      peer identity there, but a bearer token you pasted into a wiki is yours to
      worry about.
- [ ] Your management SSH does not transit the tunnel — check before switching
      `FOXGUARD_GATEWAY_INPUT_POLICY` to `restricted`.
- [ ] `/var/lib/foxguard/last-good.nft` exists after the first successful apply.
- [ ] The API is started with `foxguard-serve` (or `uvicorn --no-proxy-headers`).
      With uvicorn's default proxy headers, anything on loopback can impersonate
      any peer.
- [ ] The portal is bound to the tunnel address, **not** to the WAN, and has no
      reverse proxy in front of it.
- [ ] The API runs with a single uvicorn worker (login throttle and OIDC state
      are per-process).
- [ ] `curl` to `/api/v1/portal/status` from a non-peer address returns 403.
- [ ] Enrollment keys for temporary machines carry an `expires_at`.
- [ ] Every user peer has an `owner_user_id` — an unbound peer can never log in.
- [ ] `FOXGUARD_SESSION_SWEEP_ENABLED` is true, **or** a cron calls
      `/api/v1/sessions/sweep` — check `journalctl` for the "session expiry is
      DISABLED" warning.
- [ ] Groups that matter carry an explicit `session_lifetime_seconds`; the
      global default applies to everything else.
- [ ] `POST /api/v1/sessions/sweep` returns `ran: true` at least sometimes — a
      permanent `false` means something else is holding the lock.
- [ ] The dashboard is bound to localhost or the tunnel address, never the WAN,
      and its `FOXGUARD_ADMIN_API_TOKEN` is in an `0600` environment file.
- [ ] You have tried the kill switch **once**, on purpose, and know which mode
      you would reach for at 3am.
- [ ] `deploy/foxguard-backup.sh` runs on a schedule, its output leaves this
      box, and you have restored one somewhere to prove it works.
- [ ] The ACL document is exported to a git repository you actually commit to.
- [ ] With DNS enabled: `ss -lun | grep :53` shows only tunnel addresses. A
      `0.0.0.0:53` there is an open resolver on the WAN.
- [ ] With DNS enabled: you accept that a quarantined peer can enumerate your
      device names, or `FOXGUARD_ALLOW_DNS_IN_QUARANTINE` is false.
- [ ] Every zone route in `/var/lib/foxguard/routes.json` still points at the
      tunnel interface and has a peer carrying it — the healthcheck says so.
- [ ] No zone route covers an address this gateway answers on. The agent refuses
      them, but a route added by hand to the same prefix is yours to check.
