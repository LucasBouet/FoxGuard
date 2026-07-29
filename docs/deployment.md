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

```sh
git clone <your-repo> /root/foxguard-src
cd /root/foxguard-src

# Changes nothing. Tells you whether this box can host Foxguard at all.
sudo ./deploy/foxguard-install.sh --check-only

# Bring WireGuard up first (section 1), then:
sudo ./deploy/foxguard-install.sh --wan-interface eth0
```

### Letting it create the interface too

Normally you bring `wg0` up yourself — it carries your remote access, and the
installer would rather not be the thing that breaks it. If you would rather it
did, it is opt-in:

```sh
sudo ./deploy/foxguard-install.sh \
  --bootstrap-wireguard \
  --bootstrap-peer my-laptop \
  --endpoint vpn.example.com:51820 \
  --wan-interface eth0
```

`--bootstrap-wireguard` writes `/etc/wireguard/wg0.conf` with an `[Interface]`
block and **no peers** — those belong to Foxguard — then enables
`wg-quick@wg0`. It is create-if-absent: an interface that already exists is
used as it is, and it **refuses outright** if a config file is already there
rather than overwrite the thing holding your only way in.

`--bootstrap-peer` solves the awkward first step. A device added by hand to
`wg0.conf` is removed on the agent's first sync, because the control plane does
not know about it — so instead this registers the device properly, bound to the
administrator account, and prints a ready client config once.

That client's private key is generated on the gateway. For the laptop you are
setting up from that is a fair trade; for everything after, generate the keypair
on the device and register only the public key. The peer form in the dashboard
says so too.

You still have to forward `udp/51820` to this box on your router — the installer
says so but cannot do it.

It detects the tunnel address and peer pool from your live WireGuard interface,
generates the secrets, writes `0600` config, applies the migrations, builds both
frontends, installs the systemd units, and creates the first administrator —
printing that password once.

**It deliberately leaves the agent stopped and in dry run.** Nothing reaches
nftables until you have read the rules and flipped the flag yourself; the script
finishes by telling you exactly how. Re-running it is safe — existing secrets
are reused rather than rotated, so the agent does not lose its token during an
upgrade.

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
sudo -u postgres createdb -O foxguard foxguard
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
FOXGUARD_WG_STAGING_POOL_V4=10.88.9.0/24
FOXGUARD_WG_GATEWAY_IP=10.88.0.1

FOXGUARD_WAN_INTERFACE=eth0
FOXGUARD_PORTAL_PORT=8080
FOXGUARD_INTERNAL_CIDRS=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
FOXGUARD_GATEWAY_INPUT_POLICY=open
```

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
