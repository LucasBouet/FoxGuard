# Phase 6 — reverse proxy: implementation spec

Everything needed to build the reverse proxy without re-deriving the design.
Written to be read cold by someone (or some session) with no memory of the
conversation that produced it.

> **Built.** This document is the plan; `docs/architecture.md` §19 is the record
> of what exists and why. Batch 1 shipped in full. Three things changed while
> building it, each because running the code said so:
>
> * **A service and its policy are created in one request.** §5.2's rule refuses
>   a listener with no applicable authenticator — which made a two-step creation
>   impossible, because the first step would always be refused. Found by the e2e
>   suite on its first run. `ServiceCreate` now carries `authenticators`,
>   `filters` and `access`.
> * **sha-512-crypt rounds are pinned at 5000, not passlib's default.** HAProxy
>   re-verifies on every request; measured, 656000 rounds costs 267 ms per
>   request — a 3 req/s ceiling. Python 3.13 also removed the stdlib `crypt`
>   module, so `passlib` is a new dependency.
> * **Bearer tokens are stored unsalted**, which §5.5 did not say. They have to
>   be: HAProxy computes `sha2(256)` over the presented token and looks it up in
>   a map, and there is no way to hand it a salt.
>
> §18's open questions are still open, except the first: TLS-wrapped TCP
> passthrough does not share `:443`. Each passthrough service gets its own port.

Sections marked **DECIDED** are settled and should not be reopened without a
reason; sections marked **OPEN** need an answer before the code that depends on
them is written.

---

## 1. What this feature is

A reverse proxy on the gateway that publishes services living behind peers:
HTTP terminated (auth, WAF, header injection all possible) and TCP passthrough
(encrypted end to end, so none of those are possible). Services are declared in
the database, rendered into a HAProxy configuration, and applied by the agent —
the same shape as `nftables/` and `dns/`.

The Netbird analogue is a network resource plus an access policy, except that
Foxguard already has the access-policy vocabulary (peers, groups, zones) and
this feature must reuse it rather than invent a second one.

---

## 2. Decisions already taken — DECIDED

| Question | Answer |
| --- | --- |
| Service naming | `<slug>.example.com` — apex wildcard, under the domain the operator already owns |
| Certificates | Let's Encrypt, **DNS-01**, wildcard `*.example.com` + `example.com` |
| ACME provider | Cloudflare (`python3-certbot-dns-cloudflare`, packaged in Debian 13) |
| Access semantics | **OR** across identity authenticators, **AND** across filters |
| Policy location | Hybrid — rendered into the config for everything static, forward-auth only for browser SSO |
| Gateway `:443` (WAN) | Free; HAProxy takes `:80` and `:443` |
| Foxguard admin UI behind the proxy | **Never** |
| Bearer token scope | One token belongs to one service |
| HTTP basic auth | Service accounts with a generated high-entropy password, never human passwords |
| First codable batch | Internal **and** external exposure, with certificates |
| Gateway → upstream permission | Created implicitly and displayed (see §10 for where it is actually enforced) |
| Plain-TCP port allocation | Automatic from a reserved range, overridable |
| Upstream TLS verification | Off by default, opt-in per service |
| Access logs | journald for the request stream, `audit_log` for security events only |
| Kill switch | Stops **internal** services, leaves **external** ones serving |
| Who may manage services | Administrators only (`is_admin`) |
| Unreachable upstream | Foxguard 503 page naming the offline device |

### 2.1 Consequences of two of those choices, recorded on purpose

**Apex wildcard.** `*.example.com` plus `example.com` means the private key on
the gateway covers the entire domain — mail, the main site, everything. Two
mitigations are mandatory, not optional:

* the Cloudflare credential must be a scoped **API token** (`Zone:DNS:Edit` on
  that one zone), never the global API key, stored `0600 root:root`;
* the key file is the highest-value secret on the gateway; it belongs in the
  backup exclusion list decisions and in the uninstaller's shred path.

**Kill switch stops internal but not external.** Be aware this is mostly
symbolic in the common case: the kill switch disables *peers*, and an upstream
that lives behind a disabled peer stops answering regardless of what the proxy
does. The setting therefore only changes behaviour for services whose upstream
is the gateway itself. Implement it as chosen, but the 503 page will be what
most external visitors see during a lockdown, and the docs must say so.

---

## 3. Inherited constraints — read these before designing anything

These are facts about the existing codebase that the design must respect. Each
one has bitten, or would bite.

**3.1 The portal identifies callers by source address, and refuses proxies.**
`backend/foxguard/api/deps.py:284` (`calling_peer`) treats the source address as
an identity, which is sound only because WireGuard's cryptokey routing binds it
to a public key. `deps.assert_no_forwarded_headers` (`deps.py:242`) refuses any
request carrying `X-Forwarded-For`, `Forwarded` or `X-Real-IP`, and its docstring
records that a request correctly refused with 403 became a 200 carrying another
peer's identity when the header was trusted.

Therefore:

* the proxy must never front `/api/v1/portal`, `/api/v1/enroll`, `/api/v1/agent`
  or the admin API;
* the control plane must **refuse at creation** a service whose upstream
  resolves to Foxguard's own API or portal listener. This is a validator, not a
  documentation note — it is exactly the kind of misconfiguration that works
  until enrollment silently breaks weeks later.

**3.2 Admin sign-in throttling is keyed on the source address**
(`config.py:77`). Behind a proxy every attacker shares one counter with every
legitimate user. Another reason the admin UI stays off the proxy.

**3.3 Group slugs are nftables set-name components.**
`ck_groups_slug_format` is `^[a-z0-9][a-z0-9_-]{0,23}$`, 24 characters. Service
slugs go into HAProxy identifiers and DNS labels, so they get the same rule, and
they share **one namespace** with `peers.dns_label`, `groups.slug` (which covers
zones, since a zone is a `groups` row with `kind='zone'`) and DNS record names.
A name must never be ambiguous about what it points at.

**3.4 The ACL endpoint vocabulary already exists.** `AclRule` carries
`src_kind`/`dst_kind` of type `endpoint_kind`, with `group` and `zone` sharing
the `group_id` column (`models.py:390`). Service access rules reuse the same
enum and the same column trick. Do not invent a parallel vocabulary.

**3.5 The rendered-artefact pattern, third instance.** nftables and DNS both do:
render everything from the database → validate with the engine's own checker
(`nft -c -f`, `dnsmasq --test`) → hash → agent applies → drift is a digest
comparison. There is no incremental path anywhere and there must not be one
here. `haproxy -c -f` is the third checker.

**3.6 The agent's shape.** `agent/foxguard_agent/main.py` has `run_once` driving
`NftApplier`, `DnsApplier` and `RouteApplier`. Add `ProxyApplier` beside them,
with the same contract: `check()` for dry-run, `apply()` returning
`"unchanged" | "reloaded" | "restarted"`, restore-on-failure.

**3.7 A broken artefact must never break the dataplane.** `services/dns.py`
documents this rule and implements `render_or_none`, which logs and yields
nothing so that a bad DNS record cannot stop firewall rules reaching the kernel.
The proxy needs the identical escape hatch: a service that cannot render must
not stop `GET /api/v1/agent/state` from delivering nftables and DNS.

**3.8 Two SQLAlchemy/Alembic lessons that cost real time in Phase 5.**

* When a relationship collection is already loaded (`lazy="selectin"`), a bare
  foreign-key insert leaves it stale, validation runs against the wrong state,
  and the bad row commits anyway. Append to the relationship. See
  `api/routes/zones.py`.
* `ALTER TYPE ... ADD VALUE` needs a `COMMIT` **before and after** if the new
  value is used by a constraint in the same migration. See
  `alembic/versions/0005_zones.py`.

**3.9 dnsmasq answers only names it has been given.** There is no
`expand-hosts`, and entries are explicit. That is what makes split-horizon
possible: the resolver can answer `app.example.com` from the hosts file while
forwarding `_acme-challenge.example.com` upstream. **But** in `split` resolver
mode dnsmasq refuses everything outside `dns_zone` — so if `dns_zone` were ever
set to the certificate domain, ACME's propagation check would get NXDOMAIN.
Keep `fox.internal` for peer names and put services under the real domain; add a
preflight assertion that `dns_zone` is not a suffix of `proxy_domain` when
`dns_mode = split`.

**3.10 Stale comment to fix in passing.** `models.py:73` says `GroupKind.ZONE`
is "reserved for Phase 5, not yet honoured by the generator". Phase 5 shipped.

---

## 4. Principles

1. **One access-control vocabulary.** Who may use a service is written with the
   same endpoint kinds as who may reach a host. Two systems that can disagree
   about access is a bug factory.
2. **A reverse proxy is an ACL bypass machine.** Every path it opens must be
   visible somewhere a human looks.
3. **Passthrough is not HTTP.** The capability difference (§9) is modelled, not
   documented away.
4. **Nothing implicit that is not displayed.**
5. **Fail closed on authorization, fail soft on rendering.** No applicable
   authenticator means deny. An unrenderable service means the other services —
   and the firewall — carry on.

---

## 5. Data model

New Alembic revision `0006_proxy.py` (0005 is the current head).

### 5.1 `services`

| Column | Type | Notes |
| --- | --- | --- |
| `id` | uuid pk | |
| `slug` | `String(24)` unique | same regex as `groups.slug`; shared namespace |
| `name`, `description` | | |
| `enabled` | bool | |
| `kind` | enum `service_kind` | `http` (terminated) \| `tcp` (passthrough) |
| `upstream_peer_id` | fk `peers` ON DELETE CASCADE, nullable | NULL = the gateway itself hosts it |
| `upstream_host` | `String(255)` | address inside the tunnel or behind a zone route |
| `upstream_port` | int | |
| `upstream_tls` | bool default false | upstream speaks HTTPS |
| `upstream_tls_verify` | bool default false | DECIDED: off by default |
| `exposure` | enum `service_exposure` | `internal` \| `external` \| `both` |
| `external_hostname` | `String(255)` unique nullable | defaults to `<slug>.<proxy_domain>` |
| `internal_hostname` | `String(255)` unique nullable | same value in split-horizon; see §8 |
| `listen_port` | int unique nullable | plain TCP only; auto-allocated |
| `sni_hostname` | `String(255)` nullable | TLS-wrapped TCP sharing `:443` |
| `health_check` | bool default false | see §12 on why this defaults off |
| `extra` | JSONB | |
| `created_at`, `updated_at` | | |

Constraints worth writing explicitly:

* `kind = 'tcp'` ⇒ `listen_port IS NOT NULL OR sni_hostname IS NOT NULL`
* `exposure IN ('external','both') AND kind = 'http'` ⇒ `external_hostname IS NOT NULL`
* `upstream_peer_id IS NULL` ⇒ upstream must be a gateway-local address
* unique partial index on `listen_port WHERE listen_port IS NOT NULL`

### 5.2 `service_auth` — the OR list

`id`, `service_id` (CASCADE), `kind` enum `service_auth_kind`
(`peer_identity` | `bearer` | `basic` | `foxguard_sso` | `mtls`), `scope` enum
`service_scope` (`internal` | `external` | `both`), `config` JSONB, `enabled`,
`priority`.

Validation, and it has teeth:

* `peer_identity` may never have a scope covering `external` — refuse at
  creation, with a message that says why (§7.1).
* For **each** exposure the service actually has, at least one enabled row must
  apply. Otherwise the service is either wide open or wholly unreachable
  depending on how the fallback is written — refuse at creation, and deny at
  runtime.

### 5.3 `service_filters` — the AND list

`id`, `service_id` (CASCADE), `kind` enum `service_filter_kind`
(`ip_allow` | `ip_deny` | `geo_allow` | `geo_deny` | `rate_limit` | `waf` |
`crowdsec`), `scope`, `value` JSONB, `enabled`, `priority`.

Generic on purpose: geo, WAF and CrowdSec arrive in later phases and should not
each need a migration. Batch 1 implements `ip_allow`, `ip_deny` and
`rate_limit`; the others are accepted by the schema and rejected by the
validator with "not implemented yet" until their phase lands.

### 5.4 `service_access` — who may use it

`id`, `service_id` (CASCADE), `kind` (**reuse `endpoint_kind`**), `group_id` fk
`groups` (covers zones), `peer_id` fk `peers`, `cidr`, `action` (reuse
`acl_action`), `priority`.

Empty list means deny — consistent with everything else in Foxguard.

### 5.5 `service_tokens` — bearer

`id`, `service_id` (CASCADE), `name`, `token_hash` unique, `prefix`
(first 8 characters, for display), `created_by_user_id`, `expires_at`,
`last_used_at`, `revoked_at`.

Hashing: salted SHA-256, **not** a KDF — the same reasoning already written in
`services/admin_auth.py` for session tokens and enrollment keys. These are
high-entropy generated secrets, so a KDF buys nothing.

`last_used_at` cannot be updated by HAProxy. Either accept that it is only
updated on the forward-auth path (so: never, in batch 1), or have the agent ship
a periodic digest from the access log. Prefer the second, later; do not fake it.

### 5.6 `service_accounts` — basic auth

`id`, `service_id` (CASCADE), `username`, `password_hash`, `created_at`,
`revoked_at`. Password is generated, displayed once, and hashed with
**sha-512-crypt (`$6$`)** because that is what a HAProxy `userlist` can verify.
Acceptable precisely because the password is generated and high-entropy; this is
why human passwords were excluded (DECIDED).

### 5.7 Settings (`config.py`, `proxy_` prefix)

```
proxy_enabled                 bool = False
proxy_domain                  str | None          # example.com
proxy_external_bind           list[str]           # WAN addresses
proxy_external_http_port      int = 80
proxy_external_https_port     int = 443
proxy_internal_bind           list[str]           # defaults to the gateway tunnel IP
proxy_internal_https_port     int = 443
proxy_tcp_port_range          "20000-20999"
proxy_conf_path               = /etc/foxguard/proxy/haproxy.cfg
proxy_certs_dir               = /etc/foxguard/proxy/certs
proxy_maps_dir                = /etc/foxguard/proxy/maps
proxy_runtime_socket          = /run/foxguard/haproxy.sock
proxy_acme_email              str | None
proxy_acme_dns_provider       = "cloudflare"
proxy_acme_credentials_path   = /etc/foxguard/proxy/cloudflare.ini
proxy_hsts_max_age            int = 31536000
proxy_killswitch_stops_internal  bool = True
proxy_killswitch_stops_external  bool = False
```

Follow the `dns_*` precedent: off by default, `list[str]` fields need
`Annotated[..., NoDecode]` or pydantic-settings raises at import time on the
documented `a,b,c` form.

---

## 6. The rendered artefact

One `haproxy.cfg`, plus map files and userlists in `proxy_maps_dir`. Byte-stable
output, one digest over the whole set.

### 6.1 Config shape

```
global    master-worker, stats socket <runtime_socket> level admin,
          ssl-default-bind-options, log to stdout (journald picks it up)
defaults  timeouts, option httplog

frontend fg_external_http     bind <wan>:80          → redirect scheme https
frontend fg_external_https    bind <wan>:443 ssl crt <certs_dir>
frontend fg_internal_https    bind <tunnel-ip>:443 ssl crt <certs_dir>
frontend fg_tcp_<slug>        mode tcp, bind :<listen_port>       (one per plain-TCP service)
frontend fg_sni               mode tcp, bind <wan>:443 …          (only if SNI passthrough is used — see OPEN below)

backend  be_<slug>            one per service
```

Each frontend sets `var(txn.exposure)` to `internal` or `external`. Every auth
and filter rule is then conditioned on it, which is what makes "peer identity
inside, bearer outside" expressible on one service.

### 6.2 How each mechanism is expressed

* **Peer identity** — one file per group/zone referenced by any
  `service_access` row, containing the tunnel addresses of its members, loaded
  with `acl fg_grp_<slug> src -f <maps_dir>/grp_<slug>.lst`. This mirrors the
  nftables set approach exactly, is byte-stable, and is updatable at runtime.
  Only ever consulted on `fg_internal_https` and on internal TCP frontends.
* **Bearer** — `req.hdr(authorization)`, strip `Bearer `, `sha2(256),hex`,
  match against `tok_<slug>.map`. Storing only hashes means the map is not a
  secret worth much; the lookup is not constant-time, but the input is already a
  SHA-256 of a high-entropy secret so there is nothing to leak by timing.
* **Basic** — `userlist ul_<slug>` with `$6$` hashes, `http-request auth unless
  { http_auth(ul_<slug>) }`.
* **IP filters** — plain ACL files, same mechanism as the group lists.
* **Rate limit** — stick tables, keyed per exposure: source IP externally, peer
  identity internally.
* **Identity headers to the upstream** — set `X-Foxguard-Peer`,
  `X-Foxguard-Groups`, `X-Foxguard-User`, and **unconditionally delete any
  client-supplied copy first**. This is a hole every time it is forgotten.

### 6.3 Applying it — and the part that needs measuring first

HAProxy resolves `-f` map and ACL file references **at parse time**, so
`haproxy -c` fails if the maps are not already on disk. The applier therefore
writes maps first, then the config, then validates, then reloads — and restores
the previous set of files if validation fails. Messier than `DnsApplier`
because it is N files rather than 2; a staged directory plus a swap is the
cleaner shape and should be preferred if it can be made atomic enough.

Three classes of change, which must be **measured, not assumed** — exactly the
mistake avoided in Phase 5 when SIGHUP turned out to reload hosts but not the
config file:

| Change | Expected action |
| --- | --- |
| Service added/removed, frontend or backend changed | `systemctl reload` (HAProxy master-worker `-sf`: existing connections finish) |
| Map/ACL contents (peer joined a group, token issued, IP blocked) | Runtime API, **no reload** |
| Certificate renewed | Runtime API `set ssl cert` + `commit ssl cert`, **no reload** |

**Critical trap to verify:** a Runtime API change is in memory only. If the file
on disk is not updated too, the next reload silently reverts it. The applier
must always write the file *and* push the runtime update; never one or the
other.

---

## 7. Authentication and authorization

### 7.1 Peer identity — what it is and what it is not

Inside the tunnel the source address is cryptographically bound to a public key:
WireGuard drops any packet whose source is not in the sending peer's
`AllowedIPs`, and Foxguard writes those itself, one `/32` per peer. A packet
from `10.13.37.7` on `wg0` can only have been sent by the holder of that peer's
private key. This is the same guarantee `calling_peer` already relies on.

It gives identity for free, and through the peer: its groups, its zone, its
owning user. So "this service is for the `devs` group" needs no new identity
plumbing at all.

Two things it is **not**:

* It is not available on the external frontend, ever. A request arriving from
  the internet has a source address belonging to an ISP or a NAT, bound to
  nothing. Hence the creation-time refusal in §5.2.
* It does not prove "the peer is connected". WireGuard is connectionless; what
  is proved is "this packet came from that key", which is stronger. Last
  handshake is a liveness signal for display, never for auth.

**Do not** attempt to correlate a public source address with a peer's last known
WireGuard endpoint. CGNAT puts thousands of strangers behind one address,
endpoints roam on every network change, and anyone sharing the NAT inherits the
identity.

### 7.2 Pipeline order

Cheapest and least forgeable first:

1. IP and geo — and for pure IP, prefer nftables on the `input` chain, before
   the TCP handshake
2. CrowdSec remediation *(phase E)*
3. TLS termination
4. WAF *(phase E)* — before auth, so the auth endpoint is protected too
5. Peer identity — free, no lookup, no control-plane dependency
6. Bearer / basic / Foxguard SSO
7. Authorization: does this identity match `service_access`
8. Proxy to the upstream, identity headers rewritten

### 7.3 Where policy lives (DECIDED: hybrid)

Rendered into the config: peer identity, IP, geo, group/zone membership, bearer
by hash, basic. Forward-auth to Foxguard: browser SSO only, because it genuinely
needs a login page, a redirect and session state. Fail closed, with a short
positive cache.

The point of the split is that the most important path — peer identity — never
depends on the API being up.

---

## 8. Names, exposure and ports

### 8.1 Split-horizon is the whole reason for the naming choice

A connected peer typing `https://app.example.com` would otherwise resolve the
public A record, leave through the internet, arrive on the external frontend and
lose its identity — while being on the VPN. The fix is the internal resolver
answering that same name with the gateway's tunnel address, which requires the
**same certificate on both frontends**, which is why services live under the
real domain and not under `fox.internal`.

Peer names stay on `fox.internal` (`laptop.fox.internal`); service names go under
`example.com`. Two namespaces that do not collide, one wildcard certificate.

Implementation: internal service names become additional `HostEntry` rows in the
existing `DnsSpec`, pointing at the gateway's tunnel address — an **A record to
the gateway**, not a CNAME to the upstream peer, because the proxy is the
destination. Public records for external names are the operator's job (managing
them through the Cloudflare API is explicitly out of scope).

### 8.2 Port sharing — the rules, which the UI must reflect

| Service | Shares a port? |
| --- | --- |
| HTTP / HTTPS terminated | Yes — `:443`, routed by SNI then Host |
| TCP passthrough **with** TLS | Yes — `:443`, routed by SNI, if the client sends one |
| TCP passthrough **without** TLS | **No** — one dedicated port each |

Hence the auto-allocated range (DECIDED). Allocation is a database concern with
a unique constraint, not a runtime scan.

### 8.3 TLS is not optional on the internal frontend

Two reasons, the second decisive: browsers disable a growing list of APIs on
non-secure origins (service workers, WebCrypto, clipboard); and under
split-horizon the name is the *same*, so one external visit sets HSTS and the
browser will then refuse plain HTTP internally.

---

## 9. Capability matrix — model this, do not just document it

| | HTTP terminated | TCP passthrough |
| --- | --- | --- |
| Peer identity | yes (internal) | yes (internal) |
| IP / geo filters | yes | yes |
| Rate limit | yes | yes |
| Bearer / basic / SSO | yes | **no** |
| WAF | yes | **no** |
| Identity headers to upstream | yes | **no** |
| CrowdSec | full | IP level only |

The API must reject the impossible combinations, and the UI must grey them out
rather than let someone tick a WAF box on an SSH passthrough.

---

## 10. The implicit gateway → upstream path

Publishing a service opens a path that the ACL model does not cover: the proxy
originates its connection **from the gateway**, so neither the `forward` chain
nor the zone/group rules apply. The decision was to create and display it. Two
halves, and they are enforced in different places — this is worth being precise
about rather than pretending it is one thing:

**Enforced in nftables — the input chain.** Peers reaching the internal
frontend traverse `chain input`, which already has a `RESTRICTED` mode
(`generator.py:642`). So the generator must emit accepts for
`proxy_internal_https_port` and for each internal plain-TCP `listen_port`, from
the union of sources allowed by `service_access` on internally-exposed services.
This is real, enforced, and belongs in the ruleset.

**Displayed, not enforced by nftables — gateway to upstream.** Foxguard has no
`output` chain, deliberately: base chains are `policy accept` with explicit
drops so that a bad ruleset can never lock the operator out
(`generator.py:10-16`). Adding an output chain to enforce this would either
change nothing (policy accept) or reintroduce the lockout risk. The actual
enforcement is the proxy configuration itself, which can only ever connect to
the declared `upstream_host:upstream_port`.

So: derive a read-only entry per service, surface it in `GET /api/v1/acl` with
`implicit: true` and the owning service slug, and render it in the ruleset as a
**comment** in the forward chain so that someone reading `nft list ruleset` sees
that the path exists. What must never happen is a published service creating a
path that appears nowhere.

---

## 11. Certificates

* certbot with `python3-certbot-dns-cloudflare`, DNS-01, requesting
  `*.example.com` **and** `example.com` (a wildcard does not cover the apex).
* DNS-01 rather than HTTP-01 because HTTP-01 needs the name to resolve publicly
  to the gateway, which forces public A records for internal-only services.
* Wildcard rather than per-service certificates for two reasons: publishing a
  service becomes a database write with no ACME round trip, and per-name
  certificates would publish the whole internal service inventory to
  Certificate Transparency logs.
* Deploy hook: concatenate `fullchain.pem` + `privkey.pem` into a single PEM in
  `proxy_certs_dir` (HAProxy wants them in one file; certbot writes two), then
  push via the Runtime API. **No reload** — TCP passthrough sessions can live
  for hours.
* The config references the certificate *directory*, so a renewal never changes
  the rendered artefact and never changes the digest.
* Permissions: `0640 root:haproxy`. Note the contrast with DNS — dnsmasq re-reads
  `addn-hosts` *after* dropping privileges, which forced the anomalous `0644`
  there; HAProxy reads its certificates *before*, so the project's normal regime
  applies.
* Healthcheck: assert `not_after` is more than 14 days away, and that the
  certificate on disk actually covers every configured hostname.

---

## 12. Operational behaviour

**Peer states.** A service on a peer that is not in `NAMED_STATES`
(`services/dns.py:66` — staging, quarantined, active) stops being served, and a
revoked peer's identity stops authenticating. Same reasoning as DNS: the kill
switch must remain the one action that only ever narrows.

**Unreachable upstream** (DECIDED): a Foxguard 503 page naming the device, not a
bare HAProxy error. Diagnosable immediately instead of being blamed on the proxy.

**Health checks default off.** An upstream behind a roaming laptop will flap
every time the lid closes. When enabled, prefer a long-interval L4 check or
`observe layer4`; never an aggressive HTTP check against a peer-hosted service.

**Logs** (DECIDED): the per-request stream goes to journald with system
retention. Only security events — auth refused, IP or geo blocked, WAF hit —
are written to `audit_log`, where they are actually consultable. Postgres is not
an access-log store.

---

## 13. API surface

```
GET    /api/v1/services                 list, with computed reachability
POST   /api/v1/services                 admin only
GET    /api/v1/services/{id}
PATCH  /api/v1/services/{id}
DELETE /api/v1/services/{id}

POST   /api/v1/services/{id}/auth       add an authenticator
DELETE /api/v1/services/{id}/auth/{aid}
POST   /api/v1/services/{id}/filters
DELETE /api/v1/services/{id}/filters/{fid}
POST   /api/v1/services/{id}/access
DELETE /api/v1/services/{id}/access/{aid}

POST   /api/v1/services/{id}/tokens     returns the plaintext once
DELETE /api/v1/services/{id}/tokens/{tid}
POST   /api/v1/services/{id}/accounts   returns the password once
DELETE /api/v1/services/{id}/accounts/{aid}

GET    /api/v1/proxy                    rendered config + digest + warnings
GET    /api/v1/proxy/certificates       hostnames, not_after, source
```

Every mutation goes through the shared `deps.regenerate_or_422` so an
unrenderable result is a 422 at the source rather than a 500 later. Every
mutation writes an `audit_log` entry. `require_admin` on all of them (DECIDED).

Validators to write, each of which corresponds to a real failure mode:

1. Upstream must be covered by the target peer's `AllowedIPs` — either its own
   tunnel address, or a `zone_routes` CIDR carried by that peer. Catches "you
   published `192.168.10.5` but nothing routes there" at creation instead of as
   a timeout. **This directly reuses the Phase 5 zone work.**
2. Upstream must not be Foxguard's own API or portal listener (§3.1).
3. Slug must be free across peers, groups, zones and services (§3.3).
4. Per-exposure authenticator coverage (§5.2).
5. `peer_identity` never scoped to `external`.
6. Capability matrix respected (§9).
7. `listen_port` inside `proxy_tcp_port_range` and unused.

---

## 14. Frontend

`frontend/admin/src/app/` already has `peers`, `groups`, `zones`, `rules`,
`dns`, `policies`, `sessions`, `users`, `audit`, `kill-switch`, `config`. Add
`services`.

Screens: list with exposure and reachability badges; a create/edit form where
choosing `tcp` visibly disables the HTTP-only options; a per-service access
panel reusing the existing endpoint picker from the rules page; token and
account creation with a show-once secret; and the implicit path from §10
displayed read-only.

---

## 15. Deployment

* Installer: `--proxy`, `--proxy-domain`, `--proxy-external-bind`,
  `--acme-email`, `--acme-cloudflare-token`. Packages: `haproxy`, `certbot`,
  `python3-certbot-dns-cloudflare`. Preflight: `:80` and `:443` free on the WAN
  address (reuse the `ss` helper — and remember the column is `$4`, not `$5`,
  which was a real bug in the Phase 5 preflight).
* `agent/systemd/foxguard-proxy.service` — its own unit with its own config
  file, never `/etc/haproxy/haproxy.cfg`; `ExecStartPre=haproxy -c -f`;
  `ExecReload` using the seamless path. `ReadWritePaths` must include
  `/etc/foxguard/proxy` and `/run/foxguard` or `ProtectSystem=strict` gives
  EROFS — the same trap the DNS unit hit.
* Uninstaller: stop and disable `foxguard-proxy`, remove the certificates
  (shred the private key), release the certbot lineage, remove the config
  directory. Follow the ordering lesson from Phase 5 — read any state you need
  **before** deleting the state directory.
* Healthcheck: proxy listening on the expected addresses, config digest matches
  the control plane, certificate expiry, per-service upstream reachability, and
  the `dns_zone` / `proxy_domain` / `dns_mode` assertion from §3.9.

---

## 16. Verification plan

What Phase 5 established about this container: `CAP_NET_ADMIN` yes,
`CAP_SYS_ADMIN` no, so the wireguard module and `nft` work but network
namespaces do not. That shapes what can be proved here.

### 16.1 Measured before writing code — RESULTS

All seven were run against real HAProxy 3.0.11 and dnsmasq 2.91 in the dev
container before any code was written. Two extra findings fell out.

| # | Question | Result |
| --- | --- | --- |
| M1 | Does a reload keep an in-flight connection alive? | **Yes.** A 6-second response with the reload fired at t+2s completed with 200, and a new request during the drain also got 200. Master PID unchanged, workers rotated. |
| M2 | Does `haproxy -c` fail on a missing map/ACL file? | **Yes** — `failed to open pattern file`. Maps must be written *before* validation. |
| M3 | Does a Runtime API map update survive a reload? | **No.** `add map` took effect immediately (200) and was gone after reload (403), while the on-disk entry survived. |
| M4 | Does `commit ssl cert` survive a reload? | **No.** Same shape: live immediately, reverts to the on-disk certificate on reload. |
| M5 | Does a `userlist` accept `$6$` sha-512-crypt? | **Yes** — 401 / 200 / 401 for no, good and wrong credentials. |
| M6 | Does dnsmasq answer hosts entries outside `local=/zone/` in `split` mode? | **Yes.** `app.example.com` answered NOERROR from the hosts file while `local=/fox.internal/` was in force; an *unknown* out-of-zone name got REFUSED and an unknown in-zone name got NXDOMAIN. Split-horizon therefore works in both resolver modes. |
| M7 | Is `jwt_verify` present in 3.0.11? | **Yes.** |

**M3 and M4 together give the applier's central rule:** every runtime update must
be accompanied by a write of the same change to disk, or the next reload
silently reverts it. Never one without the other.

**Extra finding 1 — `hex` outputs UPPERCASE.** `req.hdr(authorization),…,sha2(256),hex`
yields `F52FBD…`, while `hashlib.sha256().hexdigest()` and `sha256sum` yield
`f52fbd…`. Without `,lower` appended to the converter chain, no bearer token
would ever have matched, and the failure mode is a silent 403. The rendered map
keeps the project's normal lowercase-hex convention and the config lowercases.

**Extra finding 2 — the stats socket path is capped at 97 characters.**
`socket path '…' too long (max 97)` is a hard parse error.
`/run/foxguard/haproxy.sock` is comfortably inside it; long test paths are not.

### 16.2 Testable here, against real software

* Real HAProxy: config validation, rejection and restore, seamless reload with
  PID comparison, Runtime API map and certificate updates.
* SNI routing for TCP passthrough, with `openssl s_client -servername`.
* **Peer identity end to end**, despite having no second tunnel end: add the
  gateway address *and* a stand-in peer address to a real `wg0`, then use
  `curl --interface 10.13.37.5`. The source address is genuine and the
  source-based ACL path is exercised for real.
* Certificate handling with locally generated certificates: the deploy-hook
  concatenation, the directory load, SNI selection, expiry checks.

### 16.3 Not testable here

* A real ACME issuance (needs the domain and the Cloudflare credential).
* Traffic actually traversing the tunnel to an upstream on another host — the
  same `CAP_SYS_ADMIN` limitation as Phase 5. The Phase 5 workaround applies:
  distinguish `sendmsg: Required key not available` (CIDR absent from
  `AllowedIPs`) from `Destination address required` (present) to prove the
  cryptokey-routing half.

---

## 17. Phasing

* **Batch 1 (DECIDED as the first codable unit)** — service model, HTTP
  termination, TCP passthrough, internal *and* external exposure, certificates
  via certbot/Cloudflare, peer identity, bearer, basic, IP filters, rate limit,
  auto DNS name, implicit path display, 503 page, admin UI.
* **Phase C** — Foxguard SSO by forward-auth. *(Shipped, though not by
  forward-auth: the proxy verifies the signed cookie itself, so a published
  service keeps working while the API restarts. Revocation is bought back with a
  denylist map pushed over the runtime socket.)*
* **Phase C2 — SSO authorization.** *(Shipped.)* Users belong to the existing
  `groups` table; an authenticator requires any one of a set, optionally ANDed
  with an administrator flag, per door. Measured before it was written: an array
  claim comes back as raw JSON text, so the claim is a comma-wrapped string
  matched with `-m sub`, where several patterns are an OR and the wrapping is
  what prevents `infra` matching `infrastructure`. A valid session that fails
  the check must return 403 — a redirect loops forever against its own cookie.
* **Phase D — geo.** *(Shipped.)* DB-IP lite, chosen over GeoLite2 because it
  needs no MaxMind account. The plan said "load as a map through the Runtime
  API, never rendered into the config: hundreds of thousands of prefixes", and
  measurement changed the shape: the whole world is **1,372,328** prefixes,
  26.6 MiB on disk and **367 MiB of HAProxy RSS** over an empty configuration.
  So the map holds only the countries some filter names — three countries cost
  47 MiB, and their IPv4 half alone costs 9. It is a plain `-f` map file rather
  than a runtime push, because a million entries pushed one line at a time is
  not a reload avoided, it is a reload made slower.

  Two further consequences, both measured. A partial map is *correct*: an
  address in no listed country does not match, so an allow list refuses it and a
  deny list ignores it. And the gateway builds the map itself — the 27 MiB
  source never crosses the API, only the list of countries does. Refreshing the
  dataset is a **timer, never a reconcile**: the loop that installs firewall
  rules must not fail because db-ip.com had an outage.
  Sold as noise reduction, not security — any VPN defeats it.
* **Phase E** — CrowdSec and WAF, which are **one project, not two**: CrowdSec's
  AppSec component is a Coraza-based WAF speaking OWASP CRS, and a single SPOE
  integration provides both. Standalone alternative: `coraza-spoa`. Neither is
  packaged in Debian. Ship with three modes per service — `off` / `detect` /
  `block`, defaulting to `detect`, with the audit log recording what *would*
  have been blocked. Anything else and the first file-upload form breaks and the
  feature is disabled forever.
* **Later** — mTLS. Needs a private CA, but only for *clients*: HAProxy loads it
  as `ca-file` and the client certificate ships in the peer's config bundle. No
  OS trust store is involved, so none of the pain that ruled out an internal CA
  for server certificates.

---

## 18. Still OPEN

1. **SNI passthrough on the external `:443`.** It cannot share the port with the
   terminating HTTPS frontend without a first-layer `mode tcp` frontend that
   inspects SNI and either passes through or loops back to the HTTP frontend.
   That loopback costs a hop and complicates the config. Is TLS-wrapped TCP
   passthrough on `:443` needed at all, or is a dedicated port acceptable for
   every passthrough service?
2. **Rate-limit defaults** — thresholds, and what a breach returns (429 with
   `Retry-After`, or a silent tarpit).
3. **`last_used_at` on tokens** — accept that it stays NULL in batch 1, or build
   the access-log digest that fills it.
4. **Certificate inventory** — a `proxy_certificates` table, or have the agent
   report `not_after` in its existing report and store nothing.
5. **Header allowlist to upstreams** — is `X-Foxguard-Groups` sent always, or
   only when a service opts in? Sending it always leaks group names to every
   upstream.
6. **Does an external service require an upstream peer at all**, or may
   `upstream_peer_id` be NULL for something the gateway hosts itself (the 503
   page, a status endpoint)? The schema allows it; the policy should be stated.
