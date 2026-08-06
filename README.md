# Foxguard

Self-hosted network access control on top of WireGuard: peers, groups, ACL
policies and an **nftables** dataplane generated from a single source of truth.
No cloud dependency, no feature gating, no vendor control plane.

> **Status: Phases 1–6 complete.** Database schema + migrations, CRUD API, ACL
> import/export, the nftables generator and its test suite, the gateway agent,
> the enrollment endpoint and the captive portal (local accounts with argon2id,
> optional TOTP, OIDC, rate limiting, the peer state machine), session expiry
> with per-group lifetimes, the admin dashboard with its kill switch, network
> zones with routed networks, an internal resolver, and a client-config
> generator that never lets a private key reach the server. What is left is the
> reverse proxy and the bouncer (see [Roadmap](#roadmap)).

---

## What it does

Two kinds of peers, two enrollment flows:

| | **Server peers** | **User peers** |
| --- | --- | --- |
| Who | machines, services, no human behind them | laptops, phones |
| Auth | long random **enrollment key**, provisioned once | portal login (OIDC **or** local account) |
| Landing state | straight into its groups | quarantine until authenticated |
| Session expiry | **never** — access is stable until the key is revoked | re-auth every N hours (shortest lifetime among its groups) |

Both kinds get a fixed tunnel IP. Group membership drives ACL policies
(`source group → dest group/zone/CIDR/port`), which compile into an nftables
ruleset that is validated with `nft -c -f` and applied atomically.

### Groups, zones and names

A **group** is what a device does; a **zone** is where it sits. A peer holds any
number of groups and sits in exactly one zone, and a zone can own routes to
networks behind its peers — so one ACL rule naming `office` covers the devices
*and* the `192.168.10.0/24` behind them. Zone routes are programmed in both
halves that WireGuard needs: the CIDR in the carrying peer's `AllowedIPs`, and a
kernel route into the tunnel.

Optionally, the gateway also runs a **resolver for the tunnel**: every peer gets
a name in a zone you choose (`laptop.fox.internal`), the gateway answers to
`gw.fox.internal`, and hand-authored records name services that live off the
tunnel. Same shape as the firewall rules — rendered from the database, applied by
the agent, checked with `dnsmasq --test` before the daemon ever sees it.

### Client configurations, without a stored private key

The dashboard builds a ready-to-use `.conf` — download, clipboard, or QR code
for a phone — and **the private key never reaches the gateway**. The keypair is
generated in the browser, the file is assembled there, and the API only ever
returns the non-secret half: addresses, endpoint, resolver, `AllowedIPs`. The QR
encoder is in the page for the same reason; every hosted one works by being sent
the thing you want encoded.

`AllowedIPs` is filled in from the control plane, with one rule that is easy to
get wrong by hand: a peer that *carries* a network for a zone never receives that
network back in its own configuration, because routing its own LAN into the
tunnel would cut it off from the network it exists to serve.

### How a peer proves who it is

Enrollment and the portal are the only endpoints with no bearer token, so they
identify their caller by **the tunnel address it sends from**. That is sound
here and nowhere else: WireGuard's cryptokey routing drops any packet whose
source is not in the sending peer's `AllowedIPs`, and Foxguard writes those
itself, one `/32` per peer. Inside `wg0` the source address is as trustworthy as
the peer's private key.

Requests from outside the pool are refused before anything else happens, and any
request carrying `X-Forwarded-For` (or `Forwarded`, or `X-Real-IP`) is refused
outright — a proxy in front of the portal would let anyone claim any peer. Start
the API with **`foxguard-serve`**, which disables uvicorn's proxy headers;
`docs/architecture.md` §5 explains why not parsing those headers yourself is not
enough.

On top of that address check:

| | proves | second factor |
| --- | --- | --- |
| **Server peer** | holds the WireGuard key for its address | its own enrollment key |
| **User peer** | holds the WireGuard key for its address | password (argon2id) + optional TOTP, **or** OIDC |

A user peer is bound to its account (`owner_user_id`) at registration. Logging
in with *some* valid credential is not enough — it must be **that peer's**
account, because ACL groups belong to the peer, not to the user.

## Architecture

```
                    ┌────────────────────────────────┐
   admin/API  ────▶ │  Control plane (FastAPI)       │
                    │  - CRUD, ACL, policy import    │
                    │  - renders the nft ruleset     │──▶ PostgreSQL
                    └───────────────┬────────────────┘
                                    │  GET /api/v1/agent/state   (bearer token)
                                    │  POST /api/v1/agent/report
                    ┌───────────────▼────────────────┐
                    │  Gateway agent (Python)        │
                    │  - nft -c -f  then  nft -f     │
                    │  - wg syncconf (peers only)    │
                    └────────────────────────────────┘
                                 WireGuard box
```

The agent is a **pull client** and never touches the database, so the same
binary works whether it runs on the API box or on a separate gateway. Every
poll applies the *full* desired state — a missed tick, a restart or a
hand-edited ruleset all converge on the next pass.

Design decisions and their rationale are in [`docs/architecture.md`](docs/architecture.md).

## Repository layout

Monorepo — the backend, the agent and the frontend move together and share the
nftables model, so splitting them would only add version-skew problems.

```
Foxguard/
├── backend/            # FastAPI control plane
│   ├── foxguard/
│   │   ├── nftables/   # ← the sensitive part: model, generator, applier
│   │   ├── services/   # ruleset projection, IPAM, policies, enrollment,
│   │   │               #   peer state machine, sessions, expiry + scheduler,
│   │   │               #   passwords, TOTP, OIDC, rate limiting
│   │   ├── api/routes/ # CRUD + agent + enrollment + portal + session endpoints
│   │   ├── models.py   # SQLAlchemy schema
│   │   └── config.py   # environment-driven settings
│   ├── alembic/        # migrations
│   └── tests/          # generator/applier/IPAM tests run with no DB and no root
├── agent/              # gateway agent (nftables + wg syncconf) + systemd unit
├── frontend/
│   ├── admin/          # Next.js dashboard; the admin token stays server-side
│   │   ├── src/lib/    #   wireguard.ts / wg-config.ts / qr.ts run in the
│   │   │               #   browser and import nothing — that is the invariant
│   │   └── tests/      #   run with `node --test` against the real wg + zbar
│   └── portal/         # static bundle; runs in the browser, served by the API
├── deploy/             # installer + health check, both with their own safeguards
├── examples/           # example ACL document for the import endpoint
└── docs/
```

## Quickstart (development)

Requirements: Python 3.11+, Docker (for PostgreSQL). No root, no `nft`, no
WireGuard needed to run the test suite.

```sh
git clone <your-repo> Foxguard && cd Foxguard

make dev-up                       # PostgreSQL on :5432 (+ test DB on :5433)
python -m venv .venv && . .venv/bin/activate
make install                      # backend + agent, editable

cp backend/.env.example backend/.env    # FOXGUARD_DEV_MODE=true is preset
make migrate
make run                          # http://127.0.0.1:8000/docs
```

`FOXGUARD_DEV_MODE=true` is the only thing that lets the API start without
tokens. It also opens CORS for a Next.js dev server on :3000. Never set it on a
gateway.

<details>
<summary>Without Docker (LXC, or any box where nesting is off)</summary>

Docker is only ever used to get a PostgreSQL. A local cluster does just as well:

```sh
apt install -y postgresql
pg_createcluster 17 main --start          # if no cluster exists yet
sudo -u postgres psql -c "CREATE ROLE foxguard LOGIN PASSWORD 'foxguard' SUPERUSER"
for db in foxguard foxguard_test foxguard_apitest; do
  sudo -u postgres createdb -O foxguard $db
done
```

Everything then works unchanged, except that the test database is on :5432
rather than the :5433 the compose file uses, so point the second tier at it:

```sh
make test-all TEST_DB='postgresql+psycopg://foxguard:foxguard@localhost:5432/foxguard_test'
```

`make test-api` needs no override — it already uses :5432.

</details>

### Trying it out

```sh
# In dev mode any bearer token is accepted.
AUTH='Authorization: Bearer dev'

curl -s -X POST localhost:8000/api/v1/policies/import \
  -H "$AUTH" -H 'Content-Type: application/json' \
  -d "{\"dry_run\": true, \"document\": $(cat examples/policies.example.json)}" | jq

# Happy with the diff? Re-run with "dry_run": false, then look at the result:
curl -s localhost:8000/api/v1/ruleset/preview -H "$AUTH" | jq -r .content
```

`GET /api/v1/ruleset/preview` renders exactly what the agent would apply. If you
have nftables locally, `curl ... | nft -c -f -` checks it without applying it.

### Tests

Three tiers, each opting in to more infrastructure:

```sh
make test          # 260+ tests: generator, applier, IPAM, config, WireGuard sync,
                   # state machine, rate limiter, TOTP, OIDC token verification,
                   # session deadlines. No database, no root, no nft binary.
make test-all      # adds the PostgreSQL-backed tests (schema, policy round trip,
                   # expiry sweep, the advisory lock)
make test-api      # adds end-to-end tests against a running API (starts one for you)
make test-frontend # the dashboard's own: X25519 against `wg pubkey`, the config
                   # file against `wg-quick strip`, the QR encoder against
                   # `zbarimg` and `segno`, and the no-storage invariant
```

Two more need privileges or a daemon, and say so when they skip:

```sh
make test-dns-live    # the rendered zone against a real dnsmasq
make test-routes-live # the reconciler against a real kernel routing table
make test-wg-live     # a generated config loaded into a real WireGuard interface
```

Everything above passes on a clean checkout: 393 / 524 / 45 (agent) / 137 (API)
/ 46 (dashboard) at the time of writing. Tiers 2 and 3 skip themselves unless
`FOXGUARD_TEST_DATABASE_URL` / `FOXGUARD_TEST_API_URL` are set, so `make test`
works on any machine.

The API tier is not redundant with the others: it covers failures that only
exist once a real request cycle and a real database driver are involved.
Two live bugs were found there and nowhere else — a transaction committed after
the response was sent (making every write invisible to the next read), and
`INET` columns coming back from psycopg as `ipaddress` objects that a
`str`-annotated response model rejected with a 500.

The frontend tier is there for the same reason. The config generator's claim is
"a configuration that works", and the only things that can settle that are the
tools that have to read it: `wg pubkey` for the key derivation (425 keys a run,
both directions), `wg-quick strip` and a real interface for the file, `zbarimg`
for the QR code. Comparing the QR module matrix against `segno` found an error
in the error-correction tables — version 8 at level H — that every other check
passed straight through, because the symbol still scanned at every other size.

It also tests the two things that cannot be faked convincingly:

- **Source-address identity.** `make test-api` allocates the peer pool inside
  `127.0.0.0/8`, so a test client can *actually bind to* a peer's tunnel address
  and the server sees exactly what it would see through `wg0`. That is how
  "one peer's key cannot enroll another peer" is verified rather than asserted.
- **OIDC.** The tests stand up a throwaway identity provider with real RSA keys,
  a real discovery document and real signed tokens, so discovery, the token
  exchange and the signature check all run for real. A forged token, a token
  from another issuer, an `alg: none` token and an HMAC token signed with the
  public JWKS key are each confirmed to be rejected.

**The nftables generator is the part worth reading first.** Its tests are
written as safety properties before features: never flush the global ruleset,
never use `policy drop` on a base chain, never touch traffic unrelated to the
tunnel, never let a group name become an nft statement. See
`backend/tests/test_nft_generator.py`.

There is also a golden baseline (`backend/tests/golden/full_ruleset.nft`),
created on the first run and committed afterwards, so any change to the rendered
output is a reviewable diff. See `backend/tests/golden/README.md`.

## Deploying on a real Linux gateway

A Debian/Ubuntu LXC or VM, ideally behind your existing router. Everything below
assumes you can still reach the box **without** the tunnel — a console or SSH
from the LAN. Keep that open until the last step.

**If you would rather be asked than remember flags:**

```sh
sudo ./deploy/foxguard-setup.sh
```

It walks through everything below as questions — with a detected default, an
example and a sentence about what each one changes — runs the preflight, shows
you the exact `foxguard-install.sh` command it built, and only then installs.
`--dry-run` stops after printing the command. It is a front end to the same
installer, not a second one, so nothing can drift between them.

The rest of this section is the scripted form, which is what you want for a
rebuild or for CI.

### 1. Check the box can host it — changes nothing

```sh
git clone <your-repo> /root/foxguard-src && cd /root/foxguard-src
sudo ./deploy/foxguard-install.sh --check-only
```

It verifies `CAP_NET_ADMIN`, WireGuard kernel support, that `wg0` exists and
carries an address, that the ports are free and that forwarding is on. It stops
at the first thing that would have bitten you later.

### 2. Install

```sh
sudo ./deploy/foxguard-install.sh \
  --wan-interface eth0 \
  --endpoint vpn.example.com:51820
```

Packages, service user, PostgreSQL (UTF8 — see the note below), secrets in
`0600` config, migrations, both frontends, three systemd units, and the first
administrator whose password is printed once.

`--endpoint` is what your router forwards `udp/51820` to. It is not cosmetic:
without it the dashboard's config generator reports every client configuration
as incomplete rather than handing out one that cannot connect.

<details>
<summary>Everything at once, on a box with nothing on it yet</summary>

Interface included, internal DNS included, first administrator and first device
included. Change the endpoint, the WAN interface, and the two names.

```sh
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

Run it with `--check-only` first and the same flags: it prints exactly what it
would create and changes nothing. `docs/deployment.md` §0 explains each flag.

</details>

<details>
<summary>What the bootstrap flags actually do</summary>

Normally `wg0` is yours — it carries your remote access and the installer would
rather not be what breaks it, so creating it is opt-in.

`--bootstrap-wireguard` writes an `[Interface]`-only config and enables
`wg-quick@wg0`. It is create-if-absent: an existing interface is used as it is,
and it refuses outright rather than overwrite an existing config file.

`--bootstrap-peer` handles the awkward first device. One added by hand to
`wg0.conf` is removed on the agent's first sync — the control plane does not
know it — so this registers it properly and prints a ready client config once.
The file comes from the same `GET /peers/{id}/config-profile` the dashboard
uses, so it has the resolver, the search domain and every zone route in it, not
just the pool. Its private key is generated on the gateway: fair for the laptop
you are setting up from, a bad habit for everything after. Every device after it
comes from **Devices → Config generator** in the dashboard, which makes the
keypair in your browser and never puts a private key on the gateway.

You still have to forward `udp/51820` on your router.
</details>

### 3. Go live — deliberately manual

The installer leaves the agent **stopped and in dry run**. Nothing reaches
nftables until you have read the rules:

```sh
curl -s http://10.88.0.1:8080/api/v1/ruleset/preview \
  -H "Authorization: Bearer $(grep ADMIN_API_TOKEN /etc/foxguard/backend.env | cut -d= -f2)" \
  | jq -r .content
```

Confirm three things: `iifname != "wg0" accept` is the **first** rule of
`chain input` (this is what keeps your SSH alive), both base chains say
`policy accept`, and the only delete statement is `delete table inet foxguard`.

```sh
systemctl start foxguard-agent && journalctl -u foxguard-agent -f
# expect: "dry run: ruleset <digest> validated, not applied"

sed -i 's/^FOXGUARD_AGENT_DRY_RUN=true/FOXGUARD_AGENT_DRY_RUN=false/' /etc/foxguard/agent.env
systemctl restart foxguard-agent
```

If it goes wrong: `systemctl stop foxguard-agent && nft delete table inet foxguard`.
The tunnel survives — removing the filter table does not touch WireGuard.

### 4. Verify, now and later

```sh
sudo ./deploy/foxguard-healthcheck.sh
```

Read-only, safe on a live gateway. It checks the services, that dev mode is off,
that the API runs under `foxguard-serve`, config file modes, that the live table
still guards non-tunnel traffic **first**, drift between database and dataplane,
that WireGuard's peer list matches the control plane, and that the portal refuses
both forwarded headers and non-peer addresses.

Then sign in to the dashboard, enable TOTP on your account, and confirm your SSH
does not depend on the tunnel.

### Two things that will bite you otherwise

**PostgreSQL encoding.** On a minimal LXC with no locale, `initdb` creates the
cluster as `SQL_ASCII`; psycopg then hands SQLAlchemy bytes and the first
connection dies on `TypeError: cannot use a string pattern on a bytes-like
object`, which mentions no encoding at all. The installer creates the database
`--template=template0 --encoding=UTF8` and refuses an existing one that is not.

**No reverse proxy in front of the portal.** It identifies peers by source
address; nginx or Traefik in front makes every request arrive from the proxy.
The API refuses forwarded headers outright, so this fails closed — loudly.

Foxguard only ever owns `table inet foxguard`. Your existing host firewall,
Docker rules and fail2ban chains are never flushed and never modified.

The manual procedure, and the reasoning behind each step, is in
[`docs/deployment.md`](docs/deployment.md).

### 5. Then actually use it

Nothing is enforced until there are groups, devices and a rule — in that order.
[`docs/usage.md`](docs/usage.md) walks through the first working setup, the
tasks you will repeat (onboarding a person, onboarding a machine, cutting
access), what your users see at the portal, and a triage table for when a peer
reaches nothing.

Back it up before you rely on it. The ACL export covers groups and rules only;
peers, accounts and their secrets live solely in the database:

```sh
sudo ./deploy/foxguard-backup.sh --dest /mnt/nas/foxguard --keep 30
```

To remove it again:

```sh
sudo ./deploy/foxguard-uninstall.sh --dry-run   # print the plan, change nothing
sudo ./deploy/foxguard-uninstall.sh             # services, ruleset, files
```

The default leaves the database, the tunnel and every apt package in place;
`--remove-database`, `--remove-wireguard` and `--remove-packages` go further and
each explains what it takes with it before doing so. See
[Uninstalling](docs/deployment.md#uninstalling).

## Safety properties

These are enforced in code and covered by tests, not just documented:

- **Private keys never reach the server.** The backend only stores public keys;
  the agent reads the interface's private key locally via `wg showconf` when it
  rewrites peer sections.
- **Nothing unvalidated is applied.** `nft -c -f` runs first, on the exact same
  bytes; `nft -f` is a single kernel transaction, and the applier verifies the
  table exists afterwards, restoring the last known good ruleset if not.
- **Reloading does not reset connections.** `ct state established,related accept`
  precedes the policy rules, and `wg syncconf` is a no-op when the peer set is
  unchanged — no `wg-quick down/up`.
- **…except for peers being quarantined**, whose drop rules are deliberately
  evaluated *before* the established/related accept. Session expiry and the kill
  switch must cut open flows, not just new ones.
- **Base chains use `policy accept` with an explicit final drop.** A `policy
  drop` on `input` would cut SSH to the gateway on the very first apply. In
  nftables a `drop` in any table wins, so accepting in ours never weakens the
  host firewall.
- **Idempotence.** Regenerating from database state always produces identical
  bytes — no timestamps, no ORM ordering leaks — so drift is detectable by
  comparing digests.
- **No MITM.** Quarantine blocks everything except the portal; there is no
  transparent HTTPS interception and no DNS hijack.
- **A name service cannot break the firewall.** A hand-authored DNS record that
  will not render is logged and skipped; the ruleset in the same agent response
  still reaches the kernel. Access control is never taken down by a typo in a
  CNAME.
- **A zone route can never cut your own access.** Default routes are refused, so
  are prefixes covering an address the gateway already answers on, and a route
  the agent did not install is never replaced. Failing to read the local address
  list refuses every route rather than guessing.
- **No injection.** Group slugs, interface names and rule ids are validated
  against strict regexes and comments are sanitised before reaching the script.
- **Revocation is final.** `revoked` is a terminal state: no admin `PATCH`, no
  valid enrollment key and no correct password brings a peer back. Registering
  it again forces a new WireGuard key and a new enrollment key.
- **Credentials never override an administrator.** Enrollment and portal login
  can only move a peer `staging`/`quarantined` → `active`. A `disabled` peer
  holding a still-valid key stays disabled.
- **Guessing is expensive.** Login and enrollment are throttled per peer, and
  the login path spends the same argon2 time whether or not the account exists,
  so response timing is not a username oracle.
- **A TOTP code works once.** The time step it matched is recorded, so a code
  cannot be replayed during the ±30s skew window (RFC 6238 §5.2).
- **ID tokens are verified, not decoded.** Signature against the provider's
  JWKS, restricted to asymmetric algorithms — a JWKS is public, so allowing
  HMAC would let anyone who can read it sign their own tokens — then `iss`,
  `aud`, `exp`, `sub` and the `nonce` that binds the token to *this* login.
- **Expiry cuts open connections.** The quarantine drop is evaluated before the
  `established,related` accept, so a timed-out session ends the flows it already
  had. An expiry that only applied to new connections would be advisory.
- **Tightening a group takes effect on live sessions.** The deadline is
  recomputed from *current* membership, so moving a peer into a 4h group ends a
  24h session now. The reverse does not hold: a more lenient group never extends
  a session that is already running.
- **`active` on a user peer always means a human authenticated.** Administrators
  can quarantine, disable or revoke, but not declare a user peer active —
  otherwise it would carry no `last_authenticated_at` and the expiry job would
  have nothing to reason about.
- **The kill switch can only ever narrow access.** It skips `revoked` and (in
  quarantine mode) `disabled` peers, because both are *stricter* than its
  targets — "quarantining" a revoked peer would hand it the portal back. A panic
  button that widens anyone's reach is worse than none, since it is pressed
  exactly when nobody has time to check.
- **Administrators are people.** Sign-in — by password + TOTP, or by SSO —
  issues a per-person session against the same accounts the portal uses, so the
  audit log names whoever fired the kill switch. The static token stays for
  machines and is recorded as one. The account is re-checked on every request,
  so deactivating it, demoting it or changing its password cuts live sessions at
  once.
- **A device login cannot become an administrator session.** Portal and admin
  OIDC transactions carry different subjects and each flow refuses the other's,
  so a peer's authorization code is worthless at the admin callback.
- **No admin credential reaches the browser.** The dashboard renders in Next.js
  server components and keeps the session token in an httpOnly cookie; the
  browser gets HTML, never a credential.
- **A forwarded header is refused, not ignored.** Ignoring it is not enough:
  uvicorn's proxy middleware is on by default and rewrites the client address
  before the app runs, which turned a 403 into a 200 carrying another peer's
  identity. Both the server entry point and the request path now close it.

## Roadmap

- **Phase 1 — done.** Schema + migrations, CRUD, enrollment keys, ACL
  import/export with dry-run diff, nftables generator + applier, gateway agent.
- **Phase 2 — done.** `staging → active` enrollment endpoint, captive portal
  (local accounts with argon2id, optional TOTP with replay protection, OIDC with
  PKCE), per-peer login throttling, and the peer state machine.
- **Phase 3 — done.** Session expiry sweep on a timer (guarded by a PostgreSQL
  advisory lock so extra workers cannot duplicate it), per-group lifetimes,
  automatic return to quarantine for user peers only, session listing and a
  manual sweep endpoint for cron-driven deployments.
- **Phase 4 — done.** Admin dashboard (Next.js, admin token never reaches the
  browser): overview with dataplane drift, peers, accounts, groups + policy
  matrix, ACL rules, policy import with dry-run diff, audit log, the kill switch,
  and full create/edit/delete for all of them. Plus the captive portal UI — a
  static bundle served by the API, so peer identification survives.
- **Phase 5 — network zones and internal DNS, done.** Zones as segments with
  their own routed networks and exit nodes, zone-to-zone ACL rules, one zone per
  peer alongside its groups, and a kernel-route reconciler in the agent written
  as four refusals so a zone route can never cut the gateway's own access.
  Plus a dnsmasq instance Foxguard owns end to end: names for every peer, an
  admin-authored record table, forwarding or split DNS, and a reload path that
  adds a device without dropping an in-flight query. The schema absorbed both
  without a rewrite, as Phase 1 intended — zones are `groups.kind = 'zone'` and
  the `zone` ACL endpoint cost one enum value.
- **Phase 6 — client configurations, done.** A generator in the dashboard that
  produces a finished `.conf` — file, clipboard or QR code — with the keypair
  made in the browser and the private key never sent to the gateway. The API
  returns structured data rather than rendered text, precisely so that a later
  change cannot turn it into "POST the key and let the server build the file".
  `AllowedIPs` is filled in from the control plane, minus the networks the
  device itself carries. Verified against `wg pubkey`, `wg-quick strip`, a real
  WireGuard interface, `zbarimg` and `segno`. The admin navigation was regrouped
  into menus at the same time, so the next screen is one entry in `lib/nav.ts`.
- **Phase 7 — reverse proxy, done.** Services that live behind a peer, published
  through a HAProxy instance Foxguard owns end to end: HTTP terminated or TCP
  passed through, an internal door and an external one with *different* policy
  on each. Inside the tunnel a source address is proof of which key sent the
  packet, so peer identity costs nothing and is refused on the external door
  where it would prove nothing. Bearer tokens and generated service accounts
  cover the outside. Never in front of the portal or the API — they identify
  their caller by source address and the control plane refuses such a service at
  creation. Publishing opens a gateway-to-upstream path the ACL model does not
  cover, so that path is derived and shown rather than left invisible.
  Certificates are one DNS-01 wildcard, loaded over HAProxy's runtime socket
  without a reload so a passthrough session survives renewal.
- **Phase 7c — single sign-on, done.** A Foxguard login page, a signed cookie
  every published service accepts, and revocation that takes effect immediately
  rather than whenever the token would have expired. The proxy verifies the
  cookie natively, so a published service keeps working while the API restarts.
  The algorithm is pinned rather than read from the token: measured, the
  idiomatic HAProxy snippet accepts an unsigned `alg:none` forgery.
- **Phase 7d — SSO authorization, done.** Signing in stopped being the same
  thing as being allowed in. People go in the same groups the peers use — a
  group is a set of principals, not a second taxonomy — and membership grants
  **no** network access, which an end-to-end test pins down by asserting the
  rendered ruleset is unchanged. A service asks for any one of a set of groups,
  optionally and an administrator, per door rather than per service. The claim
  is a comma-wrapped string because a JSON array comes back as raw JSON text and
  cannot be matched, and the wrapping is what stops `infra` admitting
  `infrastructure`. Somebody signed in without the right group gets a 403 that
  names what they lack, never a redirect — that would bounce a valid cookie
  round a loop nothing on the client can break. Changing a membership revokes
  the sessions carrying it.
- **Phase 7e — geo restrictions, done.** A service can name the countries it
  admits or refuses. The measurement that shaped it: the whole world is 1.37
  million prefixes and **367 MiB of HAProxy memory** over an empty
  configuration, so the gateway builds a map holding only the countries some
  filter actually names — three countries cost 47 MiB. A partial map is correct
  rather than a compromise, because an address in no listed country matches
  nothing, which an allow list reads as "refuse" and a deny list as "ignore".
  The 27 MiB dataset never crosses the API; only the list of countries does.
  Refreshing it is a systemd timer and never part of a reconciliation — the loop
  that installs firewall rules must not fail because someone else's web server
  is down. Sold as noise reduction, not security: any VPN defeats it.
- **Still open.** CrowdSec — whose AppSec component is a Coraza WAF, so the
  bouncer and the WAF are one integration rather than two. Then mTLS.

## License

Choose one before publishing. AGPL-3.0 is the usual pick for self-hosted
infrastructure you do not want re-hosted as a closed SaaS.
