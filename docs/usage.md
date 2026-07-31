# Using Foxguard

Foxguard is installed and the agent is applying rules. This is what to do with
it — the first working setup, then the handful of tasks you will repeat.

Everything here is in the dashboard (`http://10.88.0.1:3000`). The `curl`
equivalents are shown too, because provisioning scripts want them; substitute
your own gateway address throughout.

---

The dashboard's screens are grouped: **Devices** (peers, zones, the config
generator), **Access** (groups, rules, policies), **Identity** (accounts,
sessions), **Network** (DNS), plus Overview, the audit log and the kill switch.
Paths below are written that way — *Devices → Peers* means the Devices menu.

## Reaching the dashboard

The gateway has no desktop, and both the dashboard and the portal are bound to
the **tunnel address** — never the LAN, never the WAN. So there are two ways in,
and you want to know both before you need the second one.

### Through the tunnel — the normal way

```
connect WireGuard  →  you land in quarantine  →  portal on :8080  →  sign in
                   →  you are active          →  dashboard on :3000
```

That ordering is the ruleset, not a convention. A quarantined peer is allowed
exactly one thing:

```
ip saddr @fg_quarantine_v4 tcp dport 8080 counter accept  comment "fg:quarantine-portal"
ip saddr @fg_quarantine_v4                counter drop    comment "fg:quarantine-deny"
```

Port 3000 is not in that list. Once you sign in you are out of the quarantine
set, and with the default `FOXGUARD_GATEWAY_INPUT_POLICY=open` the gateway's own
services — including the dashboard — become reachable.

**The bootstrap:** your laptop has to be a registered peer before any of this
works, and registering it needs the dashboard you cannot reach yet. Break the
loop with `curl` over SSH once (see "Day one" below), or let the installer do it
with `--bootstrap-peer`.

### Over SSH — the way that works when the tunnel does not

```sh
# from your workstation
ssh -L 3000:10.88.0.1:3000 -L 8080:10.88.0.1:8080 root@<gateway LAN address>
```

Then open `http://localhost:3000`. The forward terminates on the gateway, which
reaches its own tunnel address locally, so nothing has to be exposed.

Keep this in your notes. The moment you actually need the dashboard is often the
moment the tunnel is broken, and a management path that depends on the thing you
are trying to fix is not a management path. It is the same reason the ruleset
opens with `iifname != "wg0" accept`.

> Do **not** "solve" this by binding the dashboard to `0.0.0.0` or putting a
> reverse proxy in front of it. It holds a credential that administers your
> network, and a proxy in front of the *portal* breaks peer identification
> outright.

---

## The model, in four sentences

A **peer** is one device with one fixed tunnel address. Peers belong to
**groups**, and **ACL rules** say which group may reach which group, CIDR or
port. Anything no rule allows is dropped — there is no implicit permit.

The one thing to internalise: **there are two kinds of peer, and they
authenticate differently.**

| | **Server peer** | **User peer** |
| --- | --- | --- |
| For | a machine: NAS, backup job, CI runner | a person's laptop or phone |
| Proves itself with | an enrollment key, provisioned once | a portal sign-in |
| Session | none — access is stable until you revoke the key | expires; must sign in again |
| Bound to | nothing | exactly one account |

Pick wrongly and it will annoy you: a NAS registered as a user peer drops off the
network every eight hours waiting for a human who is not there.

---

## Day one

Nothing works until there are groups, devices and a rule. In that order — peers
reference groups, and rules reference groups.

### 1. Groups

Groups are the unit everything else hangs off. Two or three is a good start;
resist modelling your whole network on day one.

Dashboard → **Access → Groups & matrix** → *New group*.

```sh
AUTH='Authorization: Bearer <admin token>'; J='Content-Type: application/json'
API=http://10.88.0.1:8080/api/v1

curl -s -X POST $API/groups -H "$AUTH" -H "$J" \
  -d '{"slug":"staff","name":"Staff laptops","session_lifetime_seconds":28800}'
curl -s -X POST $API/groups -H "$AUTH" -H "$J" \
  -d '{"slug":"services","name":"Internal services"}'
```

`session_lifetime_seconds` only affects **user** peers. A peer in several groups
gets the *shortest* of them, and shortening a group ends sessions that are
already running.

### 2. Your own laptop

An account first — the device is bound to it and only that account can unlock it.

Dashboard → **Identity → Accounts** → *New account*, then
**Devices → Config generator**.

The generator does the whole thing in one screen: it makes the keypair **in your
browser**, registers the device with the public half, and hands you a finished
`.conf` — file, clipboard, or QR code for a phone. The private key never reaches
the gateway, which is what lets Foxguard say it stores none.

Fill in *Register a new one*, pick the owner and the groups, press **Generate
configuration**, and give the operator the file. There is nothing else to do:
the address, the endpoint, the resolver and `AllowedIPs` are all filled in from
the control plane.

<details>
<summary>The same thing by hand, if you would rather</summary>

The keypair is generated **on the device**, and only the public key is sent:

```sh
# on the laptop
wg genkey | tee privatekey | wg pubkey
```

```sh
# on the gateway
curl -s -X POST $API/users -H "$AUTH" -H "$J" \
  -d '{"username":"ada","password":"<a long one>"}'

curl -s -X POST $API/peers -H "$AUTH" -H "$J" \
  -d '{"name":"ada-laptop","peer_type":"user","wg_public_key":"<the public key>",
       "owner_user_id":"<ada id>","group_slugs":["staff"],"tags":["laptop"]}'
```

The response carries `tunnel_ip`. The client config:

```ini
[Interface]
PrivateKey = <the private key, which never left the laptop>
Address = 10.88.0.5/32

[Peer]
PublicKey = <gateway public key: wg show wg0 public-key>
Endpoint = vpn.example.com:51820
AllowedIPs = 10.88.0.0/24, 192.168.10.0/24
PersistentKeepalive = 25
```

**`AllowedIPs` decides what the laptop routes into the tunnel.** The pool alone
gets you to the gateway and other peers; add each internal network you want to
reach through it. Leaving it at the pool is the usual reason "the rule is there
but nothing works".

</details>

### 3. A service

Server peers enroll with a key instead of signing in.

Dashboard → **Devices → Peers** → *Register a peer* (type **server**), then *Manage* →
*Generate key*. The key is shown once.

```sh
curl -s -X POST $API/peers -H "$AUTH" -H "$J" \
  -d '{"name":"nas","peer_type":"server","wg_public_key":"<nas public key>",
       "group_slugs":["services"],"tags":["prod"]}'

curl -s -X POST $API/peers/<peer id>/enrollment-key -H "$AUTH" -H "$J" -d '{}'
# {"enrollment_key":"fgk_...", ...}   <- shown once, only a hash is stored
```

Put the key on the machine, bring its tunnel up, and let it enroll **from inside
the tunnel**:

```sh
curl -s -X POST http://10.88.0.1:8080/api/v1/enroll \
  -H 'Content-Type: application/json' \
  -d '{"enrollment_key":"fgk_...","wg_public_key":"<its own public key>"}'
```

It goes straight to `active` — no portal, no expiry. Put that call in the
machine's provisioning so a rebuild re-enrolls itself.

For a lab box, give the key an `expires_at`: it stops working on its own,
without you remembering to revoke it.

### 4. The rule that connects them

Until now nothing can talk to anything.

Dashboard → **Access → Rules** → *New rule*.

```sh
curl -s -X POST $API/acl-rules -H "$AUTH" -H "$J" -d '{
  "ref":"staff-to-services","name":"Staff reach internal services",
  "action":"accept","priority":100,
  "src":{"kind":"group","group_slug":"staff"},
  "dst":{"kind":"group","group_slug":"services"},
  "protocol":"tcp","dst_port_start":443}'
```

`ref` is a stable name you choose. It survives export/import, so make it
meaningful — it is what you will read in a git diff a year from now.

Rules are evaluated by `(priority, ref)` and **the first match decides**. A
broad `drop` at priority 10 shadows every `accept` below it; the matrix on
**Groups & matrix** shows the rule that actually wins, not the one you hoped for.

### 5. Check it

```sh
curl -s $API/ruleset/preview -H "$AUTH" | jq -r .content | grep staff
```

Then connect the laptop, sign in at the portal, and try reaching the service.
Dashboard → **Overview** should say the dataplane is in sync.

---

## The tasks you will repeat

### Onboarding a person

1. **Identity → Accounts** → create their account. Give it TOTP if it is an admin.
2. **Devices → Peers** → register their device: type *user*, owner = their account, the
   groups they need.
3. **Devices → Config generator** → send them the file it produces. The keypair
   is made in your browser; nothing you send them was ever on the gateway.
4. They connect, open `http://10.88.0.1:8080/`, and sign in.

They land in quarantine first — that is normal, and the portal is the only thing
they can reach until they authenticate.

### Onboarding a machine

Same, but type *server*, no owner, and an enrollment key it presents itself. No
portal and no expiry.

### Giving a device a name

Every peer already has one: **Devices → Peers** → *Manage* shows its DNS name, derived
from the device name at registration and editable there. Turn the resolver on
first (`FOXGUARD_DNS_ENABLED=true`) and add this to the client config:

```ini
DNS = 10.88.0.1, fox.internal
```

`ssh laptop.fox.internal` then works from anywhere on the tunnel. **Network → DNS**
in the
dashboard shows the whole zone as the gateway will serve it, plus a place to add
aliases (`portal` → `gw`) and A records for things that live off the tunnel
(`nas` → `192.168.1.50`).

Two devices cannot take the same name. Foxguard refuses the second rather than
inventing `laptop-2`, because a name nobody can predict from the dashboard is
worse than an error.

### Reaching a network behind a peer

A branch office, a lab subnet, a NAS network — anything that is not the peer
itself. **Devices → Zones** → create a zone, then add a route to it:

| Field | Meaning |
| --- | --- |
| Network | `192.168.10.0/24` — the network you want to reach |
| Carried by | the peer that routes it. Empty means the gateway reaches it itself |

Put the peers that should live in that segment into the zone (**Devices → Peers** →
*Manage* → Zone), and write one ACL rule with a **zone** endpoint. The rule
covers the peers *and* the network behind them — that is the difference from a
group.

Two things to expect:

- **Traffic inside the zone is denied** until you tick "allow traffic inside the
  zone". Everywhere else here access is denied until something grants it, and a
  zone is not the exception.
- **The far side has to route back.** Foxguard puts the network into the routing
  peer's `AllowedIPs` and installs the kernel route on the gateway. The device
  at `192.168.10.7` still needs a way back to `10.88.0.0/24` — usually
  masquerading on the routing peer, which is that machine's job, not the
  gateway's.

If a route stops working, `deploy/foxguard-healthcheck.sh` says which half is
missing: no route at all, a route pointing at the wrong interface, or a route
into the tunnel that no peer carries.

### Handing someone a configuration

**Devices → Config generator**. Pick an existing device or register a new one,
and press *Generate configuration*.

**The private key is made in your browser and stays there.** It goes into the
file directly; the gateway is only ever told the public half, which is all it
needs. Nothing about the key is stored, logged, or recoverable — lose the file
and the device needs a new keypair. If the operator already has a private key,
paste it instead and the public half is derived locally.

Take the file away by download, clipboard, or QR code. The QR is the whole
file, so treat the screen as you would the file.

`AllowedIPs` is the setting worth understanding, because on the client it is a
*routing table*: every prefix listed stops being reachable locally.

| Mode | What the device routes into the tunnel |
| --- | --- |
| Tunnel only | the WireGuard pools. The gateway and other peers, nothing more |
| Its own zone | the pools plus the networks routed inside this device's zone |
| Every routed network | the pools plus every routed network in the fleet (default) |
| Full tunnel | `0.0.0.0/0`. Needs a group with internet exit, or the device has no internet at all |

The gateway's ACLs still decide what actually passes; this only decides what the
device offers to send. **A device that carries a network for a zone never
receives that network back in its own configuration** — routing its own LAN into
the tunnel would cut it off from the network it exists to serve. The generator
says so when it happens.

Two settings have to be filled in before any of this produces a working file:
`FOXGUARD_WG_PUBLIC_KEY` and `FOXGUARD_WG_ENDPOINT_HOST`. The installer writes
both when it can. If it could not, the generator refuses to hand out a file and
names the variable that is missing.

### Cutting access

| Situation | What to do |
| --- | --- |
| Make them sign in again | **Quarantine** the peer |
| Temporarily off the network | **Disable** the peer — no dataplane presence, no credential brings it back |
| Laptop stolen, key leaked | **Revoke**. Terminal: register it again with a new keypair if it ever returns |
| Person is leaving | Deactivate the account — their devices can no longer sign in |
| Suspected compromise, everything | **Kill switch**, `lockdown` mode |

Quarantine and disable both cut connections that are already open, not just new
ones.

### Seeing who is on

**Identity → Sessions** shows administrators signed in to the dashboard and devices
currently authenticated, with time remaining. Server peers never appear — they
hold no session.

---

## What your users see

One page, at the portal address. It tells them which device this is, and offers
a password field (plus an authenticator code if their account has one) or an SSO
button if you configured an IdP.

Things worth telling them once:

- **The session ends.** They will be dropped and have to sign in again; the page
  shows roughly how long they have left.
- **Only their own account works on their own device.** Credentials that are
  valid elsewhere will be refused, and that is deliberate.
- **Signing out cuts the connection immediately**, including transfers in
  progress.

---

## Keep your ACLs in git

The reason `ref` and `slug` exist. The export references nothing by UUID, so it
survives a rebuild from scratch:

```sh
curl -s $API/policies/export -H "$AUTH" > acls/policies.json
git -C acls commit -am 'acl: staff reach the NAS over https'
```

Re-importing what you exported is a no-op — that is the property that makes the
repository trustworthy. Always preview first:

```sh
curl -s -X POST $API/policies/import -H "$AUTH" -H "$J" \
  -d "{\"dry_run\":true,\"prune\":true,\"document\":$(cat acls/policies.json)}" | jq
```

`prune: true` makes it a full sync — groups and rules absent from the document
are deleted. Without it, import only creates and updates.

The dashboard does the same thing under **Access → Policies**, and refuses to apply
anything you have not previewed.

**This is not a backup.** It covers groups and rules only; peers, accounts and
their secrets live solely in the database. See "Backup and restore" in
`deployment.md`.

---

## When something does not work

| Symptom | Look at |
| --- | --- |
| Peer connects, reaches nothing | Is it `active`? User peers must sign in. Then: is there a rule? |
| Rule exists, still blocked | `AllowedIPs` on the client — does it route that network into the tunnel? |
| Rule exists, still blocked | The matrix: a higher-priority `drop` may shadow it |
| Dropped off after a while | Session expired. Normal for user peers; check the group's lifetime |
| A machine keeps dropping off | It is registered as a *user* peer. It should be a *server* peer |
| Changes have no effect | **Overview** — is the dataplane in sync? Is the agent running? |
| Nobody can reach anything | `nft list table inet foxguard`, then `journalctl -u foxguard-agent` |
| Names do not resolve | Is `DNS = <gateway>, <zone>` in the client config? Then `systemctl status foxguard-dns` |
| One name stopped resolving | **Network → DNS** → "Not currently served". An alias is dropped when its target is revoked |
| A zone's network is unreachable | `deploy/foxguard-healthcheck.sh` → **Zone routes**: it says which half is missing |
| A zone route will not save | It is refused for a reason — a default route, or one covering an address the gateway already answers on |
| The generator says "incomplete" | `FOXGUARD_WG_PUBLIC_KEY` or `FOXGUARD_WG_ENDPOINT_HOST` is unset in `/etc/foxguard/backend.env` |
| A generated config will not import | The file name is the interface name: at most 15 characters of `[a-zA-Z0-9_=+.-]`. The generator already trims it — check nothing renamed the file |
| The routing peer lost its own LAN | Its `AllowedIPs` contains the network it carries. Regenerate its config; the generator excludes it |

Every allowed and denied decision carries a counter and a `fg:<ref>:<name>`
comment in the live ruleset, so you can map a hit count back to the rule that
produced it:

```sh
nft -j list table inet foxguard | jq '.nftables[] | select(.rule.comment)'
```

And every state change is in **Audit log**, attributed to whoever made it.
