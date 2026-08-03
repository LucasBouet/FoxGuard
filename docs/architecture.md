# Architecture decisions

Why things are the way they are. Read this before changing anything in
`backend/foxguard/nftables/`.

---

## 1. Agent ↔ control plane: REST pull with a bearer token

The agent calls `GET /api/v1/agent/state`, applies what it gets, and posts the
outcome to `/api/v1/agent/report`. It has no database credentials.

**Why not let the agent read PostgreSQL directly?** It would duplicate the
ruleset-rendering logic (or force the agent to import the ORM), and it would pin
the gateway and the database to the same box forever. The REST client works
identically in both topologies, so you can start with everything in one LXC and
split later without touching the agent.

The response is a **full snapshot**, never a delta. Level-triggered
reconciliation means a missed poll, an agent restart, a gateway rebuild or a
hand-edited ruleset all converge on the next tick. Deltas would require the
agent to be right about its own history, which it cannot be after a reboot.

The agent skips reconciliation when the digest is unchanged, so a 10-second
poll interval costs one cheap request and no `nft` invocation.

## 2. Foxguard owns WireGuard peers and IPAM

Foxguard allocates a fixed tunnel address per peer (lowest free host in the
configured pool) and writes the `[Peer]` sections of the interface.

**Private keys never leave the device.** The peer's keypair is generated on the
device; the backend only ever sees the public key. For the *interface's own*
private key, the agent reads the live configuration with `wg showconf`, keeps
the `[Interface]` block verbatim, and rewrites only the peer sections. The
control plane never sees it.

Peer changes are applied with `wg syncconf`, never `wg-quick down/up`: syncconf
diffs the running interface against a config file, so untouched peers keep their
handshakes. The agent additionally compares normalised peer sections and skips
the call entirely when nothing changed.

**Why own it at all?** Because otherwise revocation is a lie: filtering a peer
you cannot remove from the interface still lets it hold a tunnel. Owning the
peer list makes "revoked" mean revoked.

## 3. Enrollment: staging pool + key presented through the tunnel

You chose enrollment *through* the tunnel rather than an externally exposed
endpoint. There is a constraint that shapes how this can work:

> **WireGuard cannot carry an enrollment secret in-band.** A peer whose public
> key is not already in the interface's configuration cannot complete a
> handshake at all. There is no "unauthenticated connection" to piggyback on.

So the flow is:

1. The public key is registered (admin API / bulk import). The peer is created
   in state `staging` and gets an address — from `FOXGUARD_WG_STAGING_POOL_V4`
   if set, otherwise from the main pool.
2. `staging` peers are in the `fg_quarantine_*` nftables sets: they can reach
   the portal/enrollment port on the gateway and **nothing else**. A registered
   key on its own grants zero access.
3. The device presents its enrollment key to the enrollment endpoint *from
   inside the tunnel*. The hash matches and the key has not expired → the peer
   moves to `active` and joins its groups. The ruleset is regenerated.

### The staging pool does less than it looks like, and can break routing

`FOXGUARD_WG_STAGING_POOL_V4` was introduced on the theory that it would make
confinement visible in `wg show` — quarantined peers in one range, active peers
in another. **It does not do that**, and the claim was wrong:

* A peer's address is allocated **once**, at registration, and never changes.
  There is a single allocation site and every peer is created in `staging`, so
  with a staging pool configured *every* peer gets an address from it —
  permanently, including after it goes active. The main pool ends up unused for
  peer addressing.
* Worse, if the staging pool is not covered by a route into the tunnel, its
  peers are **unroutable**. Foxguard programs peers with `wg syncconf`, which
  sets the crypto configuration and does not touch the routing table (that is
  what lets untouched peers keep their handshakes). Unless routes were added by
  hand, the only route to the tunnel is the connected one implied by the
  interface address, so with `wg0` on `10.13.37.1/24` a peer at `10.13.38.1`
  gets its replies sent out the default route. The handshake succeeds and
  nothing else works — measured, not theorised.

The first failure is inherent: a WireGuard peer needs a stable address, since
the client bakes it into its own config and `AllowedIPs` must match, so
state-dependent addressing is not something this design can offer.

The second is checked in three places, at decreasing strength:

| Where | Check | Severity |
| --- | --- | --- |
| `foxguard-install.sh` preflight | `--staging-pool` ⊆ `--pool` | fatal |
| `foxguard-healthcheck.sh` | `ip route get` into each pool lands on `wg0` | failure |
| `Settings` | staging pool ⊆ main pool | warning only |

The installer can be strict because it creates the interface itself, with the
main pool's prefix — there, "inside the pool" and "reachable" are the same
statement. The healthcheck runs on the gateway and measures the real invariant
directly, which also credits routes an operator added by hand. `Settings` only
warns: the control plane is allowed to run somewhere other than the gateway, so
it cannot see the interface, and subnet arithmetic on the pools alone would
reject a perfectly good deployment — a `wg0` on `10.13.0.1/16` routes two
sibling `/24`s without complaint.

**Recommendation: use one pool.** Set `FOXGUARD_WG_POOL_V4` and leave the
staging pool unset. If you want a separate range anyway, carve it out of the
range the interface's address already covers (`10.88.0.128/25` under a
`10.88.0.1/24` interface) and know that it is simply where peers are allocated,
not a marker of their state. `peers.state` is the marker, and the `fg_quarantine_*`
nftables sets are what enforce it.

Server-peer enrollment keys:

- generated with `secrets.token_urlsafe(32)`, shown **once**;
- stored as a salted SHA-256 (the input is a 256-bit random secret, so argon2
  would buy nothing — unlike human passwords, which do use argon2id);
- verified in constant time, always hashing even for unknown peers so timing
  does not leak which peer ids exist;
- optionally time-limited (`enrollment_key_expires_at`), so a lab/CTF box is
  safe by default without the admin remembering to revoke.

Revoking a key defaults to `quarantine=true`: the peer is pushed back to
quarantine immediately and the ruleset regenerated. Revocation that only takes
effect "next time" is not revocation.

## 4. Internet exit is per group, and cannot bypass ACLs

A group with `internet_exit = true` gets two things: a forward accept toward the
WAN interface, and a masquerade rule in a `nat postrouting` chain (same `inet`
table, so it is still one atomic transaction).

The forward rule is:

```
ip saddr @g_<slug>_v4 ip daddr != @fg_internal_v4 oifname "<wan>" counter accept
```

The `ip daddr != @fg_internal_v4` clause is the important part. Without it,
flipping `internet_exit` on a group would quietly grant it access to every
internal network reachable through the gateway — an ACL bypass hidden behind a
checkbox. `fg_internal_v4/v6` is built from `FOXGUARD_INTERNAL_CIDRS`.

Exit rules are emitted **after** the policy rules, so an explicit `drop` can
still carve out a subset of an exit-enabled group.

`internet_exit` without `FOXGUARD_WAN_INTERFACE` is a validation error, not a
silently ignored flag.

## 5. The portal identifies peers by source address

`POST /api/v1/enroll` and everything under `/api/v1/portal/` carry no bearer
token. They resolve their caller with one query: which peer holds the tunnel
address this request came from?

Treating an IP as an identity is normally a mistake. It is not one here, and the
reason is specific: WireGuard's cryptokey routing drops any packet whose source
is not inside the sending peer's `AllowedIPs`, and Foxguard writes those itself,
one `/32` per peer. A packet from `10.88.0.7` arriving on `wg0` can only have
been sent by whoever holds that address's private key. The address *is* the key.

That guarantee is worth exactly as much as the assumption that the packet came
in on the tunnel, so two things protect it:

- `Settings.is_tunnel_address` rejects any source outside the configured pools
  before the database is touched. An attacker on the LAN who forges a pool
  address cannot complete a TCP handshake either, because the replies are routed
  into the tunnel.
- `client_ip` ignores `X-Forwarded-For` — deliberately, and now doubly so. Behind
  a header-rewriting proxy this scheme would let anyone claim any peer. **Do not
  put the portal behind a reverse proxy that sets forwarded headers.**

Failures are a single opaque 403. Distinguishing "not on the tunnel" from "no
such peer" would turn the endpoint into an address scanner.

### Not parsing forwarded headers is necessary but not sufficient

Foxguard reads no forwarded headers. That was believed to settle it, and it did
not: **uvicorn ships `ProxyHeadersMiddleware` enabled by default**, trusting
`127.0.0.1`, and it rewrites `scope["client"]` from `X-Forwarded-For` *before the
application runs*. By the time `client_ip` reads `request.client.host`, the
address can already be one an attacker chose.

Measured against this codebase before the fix: a request from `127.0.0.1` that
was correctly refused with 403 became a **200 carrying another peer's identity**
simply by adding `X-Forwarded-For: <that peer's tunnel address>`. That is enough
to attempt a portal login or an enrollment as any peer, from any process or
container that can reach the API on loopback.

Two independent defences, because either alone can be defeated by a mistake:

1. **`foxguard-serve`** (`foxguard/server.py`) runs uvicorn with
   `proxy_headers=False`, so `request.client` is the real TCP peer. It is the
   documented way to start the API, and `make run` / `make test-api` use it.
2. **`deps.assert_no_forwarded_headers`** refuses any request to a
   peer-identified endpoint that carries `X-Forwarded-For`, `Forwarded` or
   `X-Real-IP`, whoever started the server. Since no legitimate deployment puts
   a proxy in front of the portal, such a header is either a misconfiguration or
   an attack — and refusing loudly beats trusting quietly.

This is also why Phase 5's integrated reverse proxy must stay in front of
internal *web services* and never in front of the portal or `/api/v1/enroll`.

### Enrollment needs both factors

A device must hold the WireGuard key for its address *and* present that peer's
enrollment key. Neither alone does anything: a registered public key grants
nothing (that is what `staging` means), and a leaked enrollment key is useless
without the tunnel.

The key is checked against the peer that owns the source address, never looked
up across the table. "Find whichever peer this key belongs to" would let anyone
inside the tunnel enroll as any peer whose key they obtained.

### The portal has no session cookie

What authenticating buys is *network access*, held in the nftables ruleset. An
HTTP session on top of that would be a second, weaker copy of the same state, so
every portal endpoint re-derives the peer from the source address, and "log out"
means going back to quarantine. The row in `sessions` records *when a human last
proved they were present* — which is what Phase 3 expires and what the audit log
needs to explain why a peer is active.

### The account must be the one the device is bound to

`owner_user_id` is set when a user peer is registered and never inferred at
request time. Login refuses any other account, local or OIDC.

This matters more than it looks. ACL groups belong to the **peer**, not to the
user. Without the check, an attacker with their own low-privilege account could
log in on a stolen admin laptop and inherit its access.

## 6. The peer state machine

Phase 1 let the admin API write any value into `peers.state`. Two tables now
guard it, keyed on *who* is asking (`services/peer_state.py`):

- **Admin.** Anything except leaving `revoked`. Revocation that can be undone by
  editing a field is not revocation, so a revoked peer must be deleted and
  registered again — which forces a new WireGuard key and a new enrollment key.
- **Self-service** (enrollment key, portal login). Only
  `staging`/`quarantined` → `active`. A `disabled` peer holding a valid key stays
  disabled: no credential overrides an administrator.

Self-transitions are always allowed, so re-authenticating refreshes rather than
409s. A test asserts the self-service table is a strict subset of the admin one,
so a peer can never reach a state its administrator could not.

An admin granting `active` directly is legitimate — a server whose provisioning
is not automated yet — but it bypasses proof of possession, so it is audited as
`peer.state.override` rather than hidden inside `peer.update`.

## 7. Throttling, and why it is not slowapi

A quarantined peer already has network access to the portal, and a staging peer
to the enrollment endpoint. Both are reachable by anyone holding a WireGuard key,
including someone who stole a laptop and is guessing its owner's password.

`services/ratelimit.py` is ~120 lines with no dependency. slowapi and
FastAPI-limiter exist to share counters across processes via Redis; the portal is
one uvicorn process authenticating a handful of humans per hour, so that would
add a moving part to a security control and buy nothing.

Three decisions inside it:

- **Sliding log, not a fixed window.** Fixed windows let an attacker spend the
  whole budget at the end of one window and again at the start of the next,
  doubling the real rate at exactly the wrong moment.
- **Failures only.** A user who re-authenticates several times is not an
  attacker, and throttling them would turn a security control into an outage.
- **Keyed on the peer, not the username.** The peer is the thing an attacker
  cannot forge; keying on the username would let anyone lock out an account
  whose name they merely know.

`check()` runs *before* the argon2 verification. Letting a throttled caller reach
a deliberately slow hash would make the limiter an amplifier rather than a
defence.

> **Scope caveat.** The counters live in the API process. Several uvicorn
> workers multiply the effective budget by the worker count. Run one worker, or
> move this behind a shared store — do not simply raise the limit.

## 8. TOTP: confirmed before enforced, and single-use

Optional, per user, and only for local passwords — an OIDC account's second
factor is the IdP's business.

`POST /users/{id}/totp` stores a secret but leaves `totp_enabled` false. Only a
correct code flips it. Enabling on provisioning is how an admin locks a user out
of their own account with a secret that never made it into an authenticator app.

`users.totp_last_used_step` (migration `0002`) records the highest time step
already spent. Without it a code stays usable for the whole ±30s skew window,
which RFC 6238 §5.2 explicitly forbids. One consequence is worth knowing: the
code used to *confirm* enrolment is spent, so the very next login needs the next
code, up to 30 seconds later.

Disabling TOTP destroys the secret rather than parking it. A disabled factor
whose seed is still in the database is a credential nobody is watching.

## 9. OIDC: PKCE, and tokens that are verified rather than decoded

Entirely optional. `Settings.oidc_enabled` is true only when issuer, client id,
client secret and redirect URL are *all* set; a half-configured IdP is treated as
off rather than as a startup error, so the portal keeps serving local logins on a
box where someone started wiring Authentik and stopped.

- **The ID token is verified.** Signature against the provider's JWKS, then
  `iss`, `aud`, `exp`, `sub` and `nonce`. An unverified `id_token` is an
  attacker-supplied JSON document, and trusting its `sub` is the classic way to
  turn SSO into an open door.
- **Asymmetric algorithms only, listed explicitly.** A JWKS holds *public* keys,
  so allowing an HMAC algorithm would let anyone who can read it sign their own
  tokens with the key we verify against. `alg: none` is excluded for the same
  reason, more obviously.
- **PKCE even though the client is confidential.** The redirect lands on a portal
  inside the tunnel, where another peer could in principle observe the code.
- **`state` binds the flow to a peer.** It is not only CSRF protection: it
  records which peer started, and a callback from a different tunnel address is
  refused. Otherwise a peer could finish someone else's login and inherit the
  session. It is single-use, so a captured callback URL is worthless afterwards.
- **`joserfc`, not `authlib.jose`**, which its own author deprecated in favour of
  it. It also makes the accepted algorithms an explicit argument rather than a
  default.

The transaction store is in-process, like the rate limiter, and carries the same
single-worker caveat.

## 10. Session expiry: what "expired" is computed from

A user peer's deadline is the **stricter** of two answers
(`services/expiry.effective_deadline`):

- `sessions.expires_at`, frozen at login from the lifetime the peer's groups
  implied then;
- `peers.last_authenticated_at` plus the lifetime its groups imply **now**.

Recomputing the second one is the point. Moving a peer into `pentest-lab` (4h)
has to shorten a session that was opened as `admin` (24h) immediately, not at
the next login — otherwise tightening a group is a promise the dataplane does
not keep for hours.

Taking the *minimum* is what stops the same mechanism working backwards. If the
recomputed value simply replaced the stored one, adding a peer to a lenient
group would hand it more time without anyone re-authenticating. So groups can
tighten a live session and never extend one; extending requires a fresh login,
which is the only thing that moves `last_authenticated_at`.

A peer in several groups gets the shortest lifetime among them, for the same
reason (`services/sessions.lifetime_seconds`).

### Server peers are excluded, structurally

The query filters on `peer_type = 'user'`. This is the difference the two peer
types exist for: a backup job must not be logged out at 3am because a timer
said so. Their access ends when their enrollment key is revoked, and only then.

### Why expiry cuts open connections

Because the quarantine drop sits *before* the `established,related` accept in
both base chains. A session that expires while an SSH connection is open ends
that connection on the next reconciliation. Expiry that only applied to new
flows would be advisory, and so would the Phase 4 kill switch built on the same
ordering.

### `active` on a user peer always means someone authenticated

The admin API refuses to set a *user* peer to `active`. Administrators keep
every way of taking access away — quarantine, disable, revoke — but granting it
is the portal's job alone.

Without that rule the sweeper faces a peer with no `last_authenticated_at` and
two bad options: never expire it, which is a permanent hole, or expire it on the
next tick, which makes the override pointless. Server peers are unaffected;
there the override is legitimate and audited as `peer.state.override`.

The sweeper still handles a null `last_authenticated_at` by quarantining, so a
hand-edited row or a future bug fails closed rather than open.

## 11. The scheduler, and the lock that makes it safe

An asyncio task in the FastAPI lifespan, not APScheduler and not a systemd
timer. The job is one query plus a ruleset regeneration, it has to run where the
database is, and a scheduler dependency would be a third moving part in a path
that takes away network access.

Running it in-process raises two problems, both solved rather than documented
away:

**Several workers would each run it.** Unlike the rate limiter, this one needs
no shared store, because PostgreSQL already has the primitive:
`pg_try_advisory_xact_lock`. A worker that cannot take the lock skips the tick.
The **transaction-scoped** variant is deliberate — it is released by the commit
*or the rollback*, so a sweep that dies halfway cannot strand the lock and wedge
expiry until someone restarts the database. The same guard makes an external
cron hitting `POST /api/v1/sessions/sweep` safe to run alongside the timer;
whichever loses reports `ran: false` instead of waiting.

**A database outage must not kill the API.** The loop catches everything, logs
it and retries next tick. A sweeper that dies quietly leaves every peer
authenticated indefinitely, which is exactly the failure this phase exists to
prevent — so it fails loudly and keeps going.

The sweep regenerates the ruleset **once** for the whole batch, and a pass that
finds nothing writes no `ruleset_versions` row at all. That is what keeps
digests stable between ticks and drift detection meaningful.

`FOXGUARD_SESSION_SWEEP_INTERVAL_SECONDS` is the *granularity* of expiry, not
its accuracy: a 4h lifetime ends within one interval of 4h.

## 12. The kill switch, and the hole in "quarantine everything"

`POST /api/v1/kill-switch` cuts the fleet in one call, server peers included, in
deliberate exception to their normal "stable until the key is revoked" rule.

### It can never grant access

Whatever the mode, a peer's reach only narrows:

- `revoked` peers are never touched. The state is terminal *and* stricter than
  either target — "quarantining" a revoked peer would put it back in
  `fg_quarantine` and hand it the portal.
- `disabled` peers are untouched in `quarantine` mode, for the same reason.
- `staging` peers are left alone in `quarantine` mode: they already have exactly
  quarantine's access, and rewriting their state would erase the fact that they
  never enrolled.

This is the property worth protecting. A panic button that widens somebody's
reach is worse than no panic button, because it is pressed at the one moment
nobody has time to audit what it did.

### Why there are two modes

The brief asks for "everything back to quarantine", and that is the default. But
quarantine is the state peers authenticate *out of*:

> A user peer types their password again. A **server peer re-presents its
> enrollment key automatically, within one poll.**

So `quarantine` mode buys seconds against a compromised server, not an
investigation window. It is the right tool for "something looks odd, make
everyone re-authenticate", and an end-to-end test asserts the come-straight-back
behaviour so it cannot change by accident.

`lockdown` mode moves peers to `disabled` instead: no dataplane presence at all,
and `disabled` is outside the self-service transition table (§6), so no
credential brings a peer back — only an administrator. That is the one to reach
for when a compromise is actually suspected.

### No undo

Restoring the fleet is deliberate and peer-by-peer. An undo endpoint would have
to guess which peers *should* come back, at the worst possible moment to guess.
The previous state of every affected peer is written into the audit entry, so the
reconstruction is mechanical rather than remembered.

The confirmation phrase is **per mode** (`QUARANTINE ALL PEERS` /
`DISABLE ALL PEERS`) and enforced by the API, not by the UI: it makes a stray
POST harmless, and makes it impossible to fire a lockdown while meaning to
quarantine.

## 13. Dashboard aggregates are computed server-side

`GET /api/v1/dashboard` and `GET /api/v1/policies/matrix` exist because the
alternatives are worse, not because the browser could not add up numbers.

An overview that fires eight requests disagrees with itself the moment something
changes between them; one endpoint is one transaction and therefore one
consistent picture. And "who can talk to whom" has exactly one correct answer,
which belongs next to the code that compiles those rules into nftables.

The matrix reports the **first matching rule** per pair, in `(priority, ref)`
order — the order nftables evaluates them. A later `accept` behind an earlier
`drop` never fires, and rendering that cell as "allowed" would be a lie an
operator might act on. Every ref targeting the pair is still listed, so a
shadowed rule is discoverable rather than invisible.

`ruleset.in_sync` compares the digest the database implies against the last one
the agent reported applying. It is the only number on the overview that describes
reality rather than intent.

## 14. The dashboard keeps the admin token server-side

The dashboard is a Next.js app rather than a static SPA for one reason: Phase 1's
admin authentication is a single shared bearer token, and a static SPA would have
to hand it to the browser, where it lives in every extension, devtools session
and cached bundle on that machine.

Instead every call runs in a server component or a server action.
`frontend/admin/src/lib/api.ts` imports `server-only`, so importing it from a
`"use client"` module is a build error rather than a silent leak.

Now that admin sessions exist, the same structure holds the *session* token: it
lives in an httpOnly cookie on the dashboard's origin, so an XSS in a dashboard
page cannot read a credential that controls the network. The API takes it as a
plain bearer token and needs no cookie handling of its own.

## 15. Administrators are people, not a shared secret

Phase 1's admin auth was one static bearer token. It worked, and it meant every
audit entry said `admin-api` — including `killswitch.trigger`. "Who took the
fleet down at 03:14" had no answer, which is the one question an audit log
exists to answer.

`POST /api/v1/admin/login` now issues a per-person session against the same
`users` table the portal uses. One account can be both a device owner and an
administrator; `is_admin` is finally an authorisation boundary rather than a
label.

- **Both credentials still work, and they are told apart.** A session names the
  person (`actor_type=admin`, the account's id and username); the static token is
  recorded as `admin-token` with `actor_type=system`. Automation keeps working,
  and its actions are visibly automation.
- **Sessions are tried first**, so a person's identity is never lost to a shared
  secret that happens to also be in the environment.
- **Tokens are hashed, not stored.** A high-entropy random secret, so salted
  SHA-256 for the same reason enrollment keys use it and human passwords do not.
- **The account is re-checked on every request, not only at login.** Deactivating
  an account, removing its admin rights or changing its password cuts live
  sessions immediately rather than whenever they happen to expire. Three
  end-to-end tests hold that line.
- **Login is throttled and its failures are opaque.** Wrong password, unknown
  account and "not an administrator" are indistinguishable from outside, and all
  three cost the same argon2 work — otherwise response timing maps out who the
  administrators are.

`audit_context(request)` is what carries this to the audit log: call sites splat
it instead of passing `source_ip=` separately, so identity travels with the
address rather than being forgotten alongside it.

### Administrator SSO

`GET /api/v1/admin/oidc/start` and `POST /api/v1/admin/oidc/complete` reuse the
portal's PKCE and JWKS machinery. Two things differ, and both matter.

**The flow is split rather than a single callback.** The IdP redirects the
*browser*, and the browser is talking to the dashboard, not to the API — so the
dashboard receives the code and completes the exchange server-side. The session
token therefore goes straight into its httpOnly cookie instead of travelling
back through a URL, where it would land in logs, browser history and `Referer`
headers.

**A transaction carries a subject, and each flow checks its own.** A portal
transaction is bound to the peer that started it; an administrator transaction
has no peer and carries `None`. The portal's callback refuses a subject that is
not its peer, and the admin callback refuses a subject that is not absent — so a
device login can never be redeemed as an administrator session, which would be a
straight privilege escalation. A test asserts exactly that.

The IdP says who someone is; Foxguard decides whether they administer it. The
account must exist locally, be active, and be an administrator — all re-checked
here rather than delegated, so a group change at the IdP cannot silently grant
control of the network.

### Dev mode is no longer a blanket bypass

`FOXGUARD_DEV_MODE=true` with no admin token used to make *any* request an
authenticated administrator, from anywhere. On a gateway accidentally left in
that state, every peer on the tunnel owned the admin API.

The bypass is now confined to loopback callers. Local development is unaffected
— everything is loopback — while a peer at `10.88.0.7` gets a 401 and a logged
error. Verified live: a request from a non-loopback address is refused where a
loopback one succeeds.

## 16. Internal DNS: a rendered artefact, not a service to configure

`FOXGUARD_DNS_ENABLED` puts a resolver on the gateway that answers for a zone of
your choosing: `gw.fox.internal`, `laptop.fox.internal`, whatever you name your
devices. It follows the same shape as the ruleset — the control plane renders
two artefacts from the database, the agent installs them and reloads the daemon,
and there is no incremental path that could drift.

### dnsmasq, and its own instance

dnsmasq rather than CoreDNS or unbound: it is one small Debian package, it reads
a hosts-format file, and `SIGHUP` re-reads that file without dropping the
listening socket. That last property is what makes adding a device cost nothing
— measured, not assumed.

It runs as **`foxguard-dns.service` on its own configuration file**, never as a
drop-in under `/etc/dnsmasq.d`. Same principle as owning a single nftables
table: the host's resolver packaging cannot change what Foxguard serves, and
Foxguard cannot change what the host serves. Uninstalling removes one unit.

### Reload and restart are different, and the difference matters

`SIGHUP` re-reads the hosts files and flushes the cache. It does **not** re-read
the configuration file. So:

| Change | What the agent does |
| --- | --- |
| a peer registered, renamed or revoked | `systemctl reload` → SIGHUP |
| the zone, upstreams or listen address changed | `systemctl restart` |

Treating everything as a restart would drop in-flight queries every time
somebody registers a device. `ExecReload=/bin/kill -HUP $MAINPID` in the unit is
what makes the first row possible.

### `dnsmasq --test` is this component's `nft -c -f`

The agent writes the artefacts, runs `dnsmasq --test` against the new
configuration, and only then reloads. A configuration the daemon rejects never
reaches it, and the previous zone is restored — so a bad zone costs one
reconciliation rather than name resolution for the fleet.

### The hosts file is 0644, and that is not an oversight

dnsmasq drops privileges at startup and re-reads `addn-hosts` **as the
unprivileged user it dropped to**. Every other file Foxguard writes is 0600;
copying that habit here produces a resolver that works until its first reload
and then quietly serves an empty zone. Found by breaking it.

### Names are fully qualified, never bare

`expand-hosts` is deliberately absent. It would make the resolver authoritative
for bare labels globally, so a peer named `wpad` or `mail` would answer for a
name its clients expect to resolve elsewhere. Short names are the search
domain's job — which is why a client config carries `DNS = <gateway>, <zone>`.

### A broken zone must never break the dataplane

DNS records are hand-authored, so an administrator can write a CNAME loop or two
records fighting over a name. If that made `GET /api/v1/agent/state` fail, a
typo in a DNS record would stop *firewall* rules reaching the kernel — access
control taken down by a name service. So:

- `services/dns.render_or_none` swallows the failure, logs it, and the agent
  leaves the resolver exactly as it is;
- the mutation endpoints re-render the whole zone inside the transaction and
  roll back, so the typo is refused at the source rather than discovered later;
- `GET /api/v1/dns` reports the validation errors instead of a 500, because
  "your zone is broken" is the most useful thing it can say.

### An alias whose target is revoked is dropped, not an error

A CNAME points at a name; revoking the peer that held it takes the name away.
Treating that as a broken zone means the **kill switch** — the one action
guaranteed to only ever narrow access — silently stops the whole fleet resolving
anything. Found exactly that way, by running the end-to-end suite twice against
one database.

So the projection drops aliases whose target is gone and the zone still renders;
`GET /api/v1/dns` lists them under `warnings` so it is visible rather than
magic. The *typo* case is still a 409: `POST /api/v1/dns/records` asks whether
the target exists before committing, because an alias to a name that never
existed is a mistake worth catching at the source.

### Which peers have a name

`staging`, `quarantined` and `active` — the same set the agent keeps on the
WireGuard interface. A `disabled` or `revoked` peer keeps its address in the
database and loses its name: a name resolving to a device that cannot be on the
tunnel is a wrong answer, not a stale one.

Labels are **stored**, not derived at render time (`peers.dns_label`, migration
`0004`). Deriving would push every collision — "Laptop" and "laptop" both want
`laptop` — out to the resolver, where the only options are refusing to serve the
whole zone or picking a winner nobody chose. Stored, the clash is a 409 on the
request that caused it. The unique index is on `lower(dns_label)`, because DNS
is case-insensitive and the column would otherwise happily hold both.

### Forward or split, and why forward is the default

`split` answers for the zone and REFUSES everything else, so nothing about the
fleet's browsing reaches the gateway. It is the better posture and it is *not*
the default, for one practical reason: `DNS = 10.88.0.1` in a WireGuard config
replaces the client's resolver entirely, and in split mode that client gets
REFUSED for the whole internet. It only works where clients are configured to
send in-zone queries alone. `forward` is what makes the feature work out of the
box; `split` is the hardening step.

> **Known limitation.** A quarantined peer can resolve the whole zone, so the
> naming reveals your inventory to a device that has not authenticated. There is
> no per-client view here, and adding one would mean a second resolver instance.
> If that matters, set `FOXGUARD_ALLOW_DNS_IN_QUARANTINE=false` — confined peers
> then reach the portal and nothing else.

## 17. Zones: a region of the address space, not another group

Groups answer "what does this device do". Zones answer "where does it sit", and
the difference has consequences:

- **A peer is in exactly one zone** (`peers.zone_id`) and any number of groups.
  A zone owns routes, and "which zone's routes apply" has to have one answer.
- **A zone's nft set is an interval set** (`z_<slug>_v4`), because it holds
  routed prefixes as well as peer addresses. Groups keep the cheaper plain set.
- **Slugs share one namespace.** A group and a zone can never have the same
  slug, so an ACL rule naming `servers` is never ambiguous about which it means.

Zones are `groups` rows with `kind = 'zone'` — the column was reserved for this
in `0001`, so `0005` added the behaviour without a table rewrite. ACL endpoints
reuse `src_group_id`: a zone *is* a groups row, and `src_kind` says how to read
the reference.

### The set holds the devices *and* the networks behind them

"Who may reach the office" has to mean both, or every routed subnet would need
its own ACL rule alongside the zone's. So a zone route joins the zone's set,
and one rule covers the whole segment.

### Intra-zone traffic is denied by default

A zone whose members cannot talk to each other reads as odd, and it is still the
right default: everywhere else in Foxguard access is denied until something
grants it, and making a zone the exception would mean creating one silently
opens paths. It is one checkbox, and the accept it emits sits *after* the ACL
rules — so an explicit drop still carves a subset out of a zone that talks to
itself, exactly as with internet exit.

### A routed network needs two halves, and neither is optional

`wg syncconf` sets cryptokey routing and does not touch the routing table.
A zone route therefore needs:

1. the CIDR in the **carrying peer's `AllowedIPs`**, which decides *which peer*
   a packet for `192.168.10.7` is encrypted to;
2. a **kernel route into the interface**, which decides that the packet reaches
   `wg0` at all.

Measured on a real WireGuard interface: with the route but no `AllowedIPs`, the
kernel refuses the packet with `sendmsg: Required key not available` — the wg
layer has no peer for that destination. With both, it is accepted for
encryption. Two different refusals at two different layers, which is why the
healthcheck tests for both and reports a route with no carrier as a black hole.

A route with no `via_peer_id` is a network the gateway already reaches itself.
It widens the zone's set and **no** kernel route is installed for it — adding one
would break the path that works.

### The route reconciler is written as four refusals

It is the only component that can take away the operator's own access, so:

1. **Never a default route.** `0.0.0.0/0` would replace the gateway's own and
   cut every remote session, including the one that asked for it. Refused in the
   API schema, in the ruleset generator *and* in the agent — three layers,
   because the first two can be bypassed by editing the database.
2. **Never a prefix covering an address this box already answers on.** A route
   for `192.168.1.0/24` on a gateway whose LAN address is `192.168.1.10` sends
   the operator's own SSH replies into the tunnel. The list is read live from
   `ip -json addr show`, and a failure to read it refuses *every* route — not
   knowing what the box answers on is when a route is most dangerous.
   The control plane's own address is protected on top of that, so a zone route
   can never cut the agent off from the API that would tell it to undo the route.
3. **Never touch a route it did not install.** If something is already there it
   belongs to whoever put it there — possibly the operator's own static route to
   that very network. The reconciler says so and moves on.
4. **Never guess on withdrawal.** Only routes recorded in
   `/var/lib/foxguard/routes.json` are removed, so a lost state file removes
   nothing rather than everything.

One route that will not install never stops the others being withdrawn: problems
are collected and reported, because a half-reconciled routing table is worse
than a fully reported one.

A CIDR may be carried by **one** peer across every zone. WireGuard resolves an
address to a peer through `AllowedIPs`, and two peers claiming the same prefix is
not a tie it reports — `wg` gives it to whichever was configured last, so the
route would work until an unrelated change reordered them. The generator refuses
that outright.

### What is deliberately not here

`0.0.0.0/0` as a zone route — an "exit node that is a peer" — needs policy
routing (a separate table plus an `ip rule`), not a route in the main table.
Doing it in the main table is exactly failure mode 1. Internet exit through the
*gateway's* WAN is what `internet_exit` already does, per group and per zone.

---

## 18. Client configurations are assembled in the browser

Foxguard stores no private keys. That is easy to say and hard to keep: the
moment a dashboard can produce a ready-to-use `.conf`, the obvious
implementation is to generate the keypair server-side and hand the file down,
and the private key is then in a request log, a response buffer, and whatever
sat between.

So the split is structural rather than procedural. `GET
/api/v1/peers/{id}/config-profile` returns **structured data, never rendered
text**: addresses, resolver, endpoint, `AllowedIPs`, keepalive, MTU. The browser
generates the keypair (`lib/wireguard.ts`, X25519 in about two hundred lines of
TypeScript), assembles the file (`lib/wg-config.ts`), and draws the QR code
(`lib/qr.ts`) — the last one because every hosted QR service works by being sent
the thing you want encoded, which here is the key itself.

An endpoint that returned finished text would be one code review away from
accepting a private key so the server could "just do it". Returning data makes
that a redesign instead of a parameter.

### The installer is the second caller, not a second design

`--bootstrap-peer` has a private key on the gateway — it generated one there, on
purpose, for the one device that cannot yet reach a dashboard. That is the only
difference. It calls the same `config-profile` endpoint and renders the same
file, so the first device is not the one provisioned with half a configuration:
no `DNS` line on a deployment that runs a resolver, no zone routes in
`AllowedIPs`, a file name no client will import.

Rendering it twice — `lib/wg-config.ts` for the browser, jq for the shell — is
the price of the endpoint returning data instead of text, and it is cheaper than
the alternative. `deploy/tests/test-client-config.sh` renders every case through
both and compares them byte for byte, with comments off, so the two cannot drift
apart quietly. The one deliberate difference is failure: the browser throws on
an incomplete profile because it can offer the button again once the setting is
fixed, while the installer substitutes a visible placeholder because it runs
once, on a terminal that is about to scroll away.

### The three modules cannot reach anything

`wireguard.ts`, `wg-config.ts` and `qr.ts` have **no imports at all** — not
even each other. `tests/no-storage.test.ts` asserts it against the compiled
output, along with the absence of `localStorage`, `fetch`, and any storage or
transport API in the generator page, and that the generator calls exactly two
server actions. Both carry public data only.

This is testable in a way "we were careful" is not, which is the point: the
property has to survive people who did not read this document.

### `AllowedIPs` is a routing table, and one exclusion is not optional

On a gateway `AllowedIPs` is an access-control list. On a client it is a routing
table: every prefix listed is pulled into the tunnel and stops being reachable
locally. The two readings coincide until a peer *carries* a network for a zone.

A site router advertising `192.168.10.0/24` must never receive that prefix back
in its own configuration — it would route its own LAN into the tunnel and lose
the network it exists to serve. The tunnel still comes up, so nothing points at
the config. `clientconfig.compute_allowed_ips` removes it in every mode and
returns what it removed, so the dashboard can say why.

The default route is the exception: `0.0.0.0/0` covers the carried network too,
but dropping it would silently turn full tunnel into no tunnel, so the operator
is warned instead.

### No preshared keys

WireGuard's `PresharedKey` is symmetric, so the gateway would have to store one.
That is the single invariant this whole design exists to keep, so PSKs are not
offered. A deployment that wants the post-quantum hardening has to provision
them out of band, on both ends, by hand.

### What is verified, and against what

The claim "a valid config" is about `wg-quick` and the WireGuard clients, not
about our reading of INI syntax, so nothing here is checked by golden file:

- the X25519 implementation against **`wg pubkey` itself**, over 425 keys per
  run plus the RFC 7748 vectors, in both directions and including unclamped
  input;
- the generated file against **`wg-quick strip`**, and then loaded into a **real
  WireGuard interface** whose `wg show` must report the public key the browser
  derived (`make test-wg-live`, needs `CAP_NET_ADMIN`);
- the QR encoder against **`zbarimg`** for the round trip, and against **segno**
  for the module matrix, entry by entry across all 160 error-correction table
  rows. That comparison found a real error — version 8 at level H had five
  blocks where the standard says six — which every other test passed straight
  through.

The file name is part of validity: `wg-quick` takes the interface name from it,
and refuses anything that is not at most 15 characters of `[a-zA-Z0-9_=+.-]`.

---

## The nftables ruleset

### Own table only

Everything lives in `table inet foxguard`. The script starts with:

```
table inet foxguard
delete table inet foxguard
table inet foxguard { ... }
```

The first line is a no-op if the table exists and creates it if it does not,
which makes the `delete` always safe. The whole file is one `nft -f`
transaction.

`flush ruleset` never appears, and the applier refuses any script containing it
or deleting a table it does not own. That check ignores quoted strings, so a
rule *named* "flush ruleset" is a harmless label rather than a self-inflicted
denial of service.

### Base chains use `policy accept`

Counter-intuitive but deliberate. On a box you administer over SSH, a `policy
drop` on `input` cuts your session the moment the first ruleset is applied.
Instead:

- `input`: `iifname != "wg0" accept` first — traffic that did not come from the
  tunnel is not our business.
- `forward`: `iifname != "wg0" oifname != "wg0" accept` — traffic that neither
  enters nor leaves the tunnel is not our business.
- Default-deny is an **explicit** `counter drop` at the end of the tunnel-facing
  path.

"Accept" in our table means *this table has no opinion*. In nftables, all chains
registered on a hook are evaluated and a `drop` in **any** table wins, so this
never weakens your host firewall, Docker's rules or a CrowdSec bouncer.

### Rule order inside `forward`

```
1. iifname != wg0 && oifname != wg0        → accept   (foreign traffic)
2. ct state invalid                        → drop
3. quarantine saddr/daddr                  → drop     ← before established!
4. ct state established,related            → accept
5. ICMP errors (unreachable, too-big, …)   → accept
6. ACL policy rules, ordered by (priority, ref)
7. internet exit rules
8. rate-limited log + counter drop         → default deny
```

Step 3 before step 4 is the single most consequential ordering choice in the
file. Putting `established,related` first — the usual firewall idiom — would
mean a peer moved to quarantine keeps every connection it already has open.
Session expiry and the kill switch would then be advisory. This way, other
peers' connections survive a reload while a quarantined peer is cut instantly.

ICMP errors are always accepted: dropping `packet-too-big` / `fragmentation
needed` silently black-holes any TCP flow above the path MTU, and that failure
mode is miserable to debug.

### Gateway-local services: `open` (default) or `restricted`

`FOXGUARD_GATEWAY_INPUT_POLICY` controls what active peers may reach *on the
gateway itself*:

- `open` — quarantined peers are confined; active peers' traffic to the gateway
  is left to the host firewall. Safe default: it cannot cut your management
  access.
- `restricted` — active peers may only reach the portal (plus DNS/ICMP when
  enabled); everything else from the tunnel is dropped. Switch to this once you
  are sure your SSH does not transit the tunnel.

### Groups are nftables sets

Each group gets `g_<slug>_v4` and `g_<slug>_v6`, holding the tunnel addresses of
its **active** members. Set lookups are O(1), so a rule stays a single rule no
matter how many peers a group has.

Consequences worth knowing:

- Slugs are limited to `^[a-z0-9][a-z0-9_-]{0,23}$` — they become part of an nft
  identifier, and the length keeps set names inside nft's limits. The database
  enforces the same pattern with a `CHECK` constraint.
- Quarantined *and* staging peers share `fg_quarantine_v4/v6`.
- Disabled and revoked peers appear in no set at all.

### Determinism

Identical database state must render identical bytes: no timestamps, no
hostname, no ORM row-order leaking in. Groups sort by slug, set elements sort
numerically, rules sort by `(priority, ref)`.

This is what makes `regenerate` a genuine no-op when nothing changed — the
digest is unchanged, so no new `ruleset_versions` row and no `nft` call — and
what makes drift detection possible by comparing digests.

### Injection

Every identifier reaching the script is regex-validated; rule comments are
stripped to `[A-Za-z0-9 :._/@=+-]` and truncated. A group named
`foo" ; flush ruleset ; #` is a validation error, and validation reports **all**
problems at once so an ACL import shows everything wrong in one response.

---

## Transactions: routes commit, the dependency does not

`get_db` yields a session and guarantees rollback-on-exception and cleanup. It
deliberately does **not** commit. Every mutating route calls `session.commit()`
itself before returning.

This is a correctness constraint, not a style preference. FastAPI runs the
teardown of a `yield` dependency *after* the response has been sent, so
committing there tells the client "201 Created" before the transaction is
durable. Measured on this codebase: a create followed immediately by a list
missed the new row **40 times out of 40**. It is not a rare race — it is the
normal case. Any provisioning script, CI job or UI that refreshes after a POST
hits it, and it produced a real 500 (a duplicate-key insert) during testing.

If you add a route that writes, it must commit. `tests/test_api_integration.py`
covers this with a write-then-immediately-read assertion.

## Set names: hyphens become underscores

`backup-svc` becomes the nft set `g_backup_svc_v4`. nft's scanner does accept
`-` inside identifiers, but `-` is also its range operator, and the generator is
the one place where an ambiguity that is awkward to test is not worth carrying.

`validate_spec` rejects two slugs that would collapse onto the same set name
(`back-up` and `back_up`), so the mapping stays injective and one group can
never inherit another's members. Slugs keep their hyphens everywhere else — the
database, the API and the exported policy document are unaffected.

## PostgreSQL `INET` columns are not strings

psycopg 3 returns `INET` columns as `ipaddress` objects. A response model
annotated `str` therefore fails validation and the endpoint returns a 500 — this
took out `GET /api/v1/audit-log` until it was fixed. `schemas.IpString` is a
`str` field with a coercing validator; use it for any field backed by `INET`.

## Data model notes

### Why `ref` on ACL rules and `slug` on groups

The policy export references groups by slug and rules by `ref`, never by UUID,
so an exported document survives a gateway rebuild from scratch. Re-importing
what you exported is a no-op — the property that makes a git-versioned ACL
repository trustworthy.

### Atomic imports

`POST /api/v1/policies/import` applies the document, renders the resulting nft
ruleset, and only then commits. A document that would produce an invalid ruleset
is rejected with the database untouched — the same guarantee `nft -c -f` gives
the dataplane.

`dry_run` defaults to **true**, and the preview is produced by running the real
import inside the transaction and rolling it back. Preview and application
cannot disagree, because they are the same code path.

### Kept open for Phase 5

- `groups.kind` (`group` | `zone`) and `groups.parent_id` exist today, so zones
  with their own routes/exit nodes do not need a table rewrite. The generator
  currently ignores `kind`.
- ACL endpoints are `(kind, group_id, cidr)` rather than a bare `src_group_id`,
  so a `zone` endpoint kind is one enum value.
- `groups.extra` / `acl_rules.extra` / `peers.extra` are JSONB escape hatches
  for reverse-proxy hints or CrowdSec metadata that should not shape the core
  schema today.
- `peers.wg_interface` exists so multi-interface setups do not need a migration.
- Because our table only ever *accepts* traffic it has no opinion about, a
  CrowdSec bouncer installing its own table composes with Foxguard rather than
  fighting it.

## Known gaps (after Phase 4)

Stated plainly rather than discovered later:

- **`FOXGUARD_DEV_MODE=true` still weakens admin authentication.** With no admin
  token configured it treats any **loopback** request as an administrator. The
  bypass is confined to loopback rather than granted to everyone (§15), so a
  gateway left in dev mode does not hand its admin API to peers on the tunnel —
  but it is still not a mode to run in production.
- **Nothing warns a user before their portal session ends.** They discover it
  when the connection drops. `GET /api/v1/sessions` exposes `seconds_remaining`,
  so the portal has what a warning would need.
- **Admin session lifetime is fixed, not idle-based.** `last_seen_at` is
  recorded and shown, but a session expires at a wall-clock deadline rather than
  after a period of inactivity.
- **No admin UI for a few corners.** Editing a peer's groups and tags after
  registration, per-rule editing beyond enable/disable, and password resets are
  still `curl`. Everything on the critical path — register, enroll, sign in,
  quarantine, revoke — has a form.
- **The portal has no enrollment screen.** Server peers present their key from a
  provisioning script, which is the intended flow; there is no browser page for
  it, by design rather than omission.
- **Expiry is only as prompt as the sweep interval.** A session ends within one
  interval of its deadline, not at it. Lower
  `FOXGUARD_SESSION_SWEEP_INTERVAL_SECONDS` if that matters; the sweep is one
  indexed query when nothing is due.
- **Nothing warns a user before their session ends.** They discover it when the
  connection drops and have to visit the portal again. `GET /api/v1/sessions`
  exposes `seconds_remaining`, so a Phase 4 notification has what it needs.
- **Rate-limit and OIDC state are per-process.** Both are in-memory. Run the API
  with a single uvicorn worker; with several, the login budget is multiplied and
  an OIDC callback can land on a worker that never saw the `start`. The expiry
  sweep is *not* affected — it takes an advisory lock (§11).
- **No account lockout, only throttling.** A sustained attacker who waits out
  each window keeps getting attempts. Combined with argon2 and a 10-per-5-minutes
  budget that is a very slow channel, but it is not a lockout. The Phase 5
  CrowdSec bouncer is the intended answer.
- **TOTP secrets are stored in plaintext.** They have to be usable for
  verification, so this is inherent to TOTP rather than an oversight — but it
  means a database dump yields working second factors, unlike the password
  hashes next to them. Encrypting them at rest needs a key the API can read,
  which is a key-management problem Phase 2 does not solve.
- **IPAM races are resolved by the unique constraint**, not by a lock: two
  concurrent creations make one insert fail, which the caller retries. Correct,
  but it surfaces as a 409 rather than a transparent retry.
- **The generator ignores `groups.kind`.** Creating a `zone` today behaves
  exactly like a group.
- **Mask selection in the QR encoder is not byte-identical to segno's.** Penalty
  rule 3 is stated as a 1:1:3:1:1 *ratio*; segno matches the literal
  seven-module pattern. Both produce valid codes and occasionally prefer
  different masks. Rules 1, 2 and 4 agree exactly, and every mask pattern is
  checked against a real decoder.

### Closed since Phase 1

- ~~No enrollment endpoint.~~ `POST /api/v1/enroll` (§5).
- ~~`peers.state` transitions are not guarded.~~ Two transition tables (§6).
- ~~Sessions are recorded but never expired.~~ The sweep and its scheduler
  (§10, §11).
- ~~No kill switch.~~ `POST /api/v1/kill-switch`, two modes (§12).
- ~~Admin auth is a static token with no attribution.~~ Per-person sessions
  (§15); the token remains for machines and is recorded as one.
- ~~The dashboard is read-mostly.~~ Every object has a form.
- ~~The generated ruleset has never been run through a real `nft`.~~ The golden
  baseline now validates *and applies* cleanly against nftables v1.1.3 on a
  container with `CAP_NET_ADMIN`, leaving neighbouring tables untouched. Keep
  the agent in `FOXGUARD_AGENT_DRY_RUN=true` for its first run on a new gateway
  anyway — that checks the ruleset your database actually produces, against your
  kernel, without applying it.
