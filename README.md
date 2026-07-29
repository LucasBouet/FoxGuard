# Foxguard

Self-hosted network access control on top of WireGuard: peers, groups, ACL
policies and an **nftables** dataplane generated from a single source of truth.
No cloud dependency, no feature gating, no vendor control plane.

> **Status: Phases 1–4 complete.** Database schema + migrations, CRUD API, ACL
> import/export, the nftables generator and its test suite, the gateway agent,
> the enrollment endpoint and the captive portal (local accounts with argon2id,
> optional TOTP, OIDC, rate limiting, the peer state machine), session expiry
> with per-group lifetimes, and the admin dashboard with its kill switch. What
> is left is Phase 5's roadmap items and the portal's own UI (see
> [Roadmap](#roadmap)).

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
(`source group → dest group/CIDR/port`), which compile into an nftables ruleset
that is validated with `nft -c -f` and applied atomically.

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
```

Everything above passes on a clean checkout: 269 / 302 / 9 (agent) / 68 (API) at
the time of writing. Tiers 2 and 3 skip themselves unless
`FOXGUARD_TEST_DATABASE_URL` / `FOXGUARD_TEST_API_URL` are set, so `make test`
works on any machine.

The API tier is not redundant with the others: it covers failures that only
exist once a real request cycle and a real database driver are involved.
Two live bugs were found there and nowhere else — a transaction committed after
the response was sent (making every write invisible to the next read), and
`INET` columns coming back from psycopg as `ipaddress` objects that a
`str`-annotated response model rejected with a 500.

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
sudo ./deploy/foxguard-install.sh --wan-interface eth0
```

Packages, service user, PostgreSQL (UTF8 — see the note below), secrets in
`0600` config, migrations, both frontends, three systemd units, and the first
administrator whose password is printed once.

<details>
<summary>Let it create WireGuard too</summary>

Normally `wg0` is yours — it carries your remote access and the installer would
rather not be what breaks it. If you would rather it did:

```sh
sudo ./deploy/foxguard-install.sh \
  --bootstrap-wireguard \
  --bootstrap-peer my-laptop \
  --endpoint vpn.example.com:51820 \
  --wan-interface eth0
```

`--bootstrap-wireguard` writes an `[Interface]`-only config and enables
`wg-quick@wg0`. It is create-if-absent: an existing interface is used as it is,
and it refuses outright rather than overwrite an existing config file.

`--bootstrap-peer` handles the awkward first device. One added by hand to
`wg0.conf` is removed on the agent's first sync — the control plane does not
know it — so this registers it properly and prints a ready client config once.
Its private key is generated on the gateway: fair for the laptop you are setting
up from, a bad habit for everything after.

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
- **Phase 5 (kept unblocked, not built).** Network zones with their own
  routes/exit nodes — `groups.kind` already distinguishes `group` from `zone`
  and `groups.parent_id` allows nesting; an integrated reverse proxy; a CrowdSec
  bouncer. ACL endpoints are modelled as `(kind, group, cidr)`, so adding a
  `zone` endpoint kind is one enum value rather than a rewrite.

## License

Choose one before publishing. AGPL-3.0 is the usual pick for self-hosted
infrastructure you do not want re-hosted as a closed SaaS.
