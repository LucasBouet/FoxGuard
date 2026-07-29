# Using Foxguard

Foxguard is installed and the agent is applying rules. This is what to do with
it — the first working setup, then the handful of tasks you will repeat.

Everything here is in the dashboard (`http://10.88.0.1:3000`). The `curl`
equivalents are shown too, because provisioning scripts want them; substitute
your own gateway address throughout.

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

Dashboard → **Groups & matrix** → *New group*.

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

Dashboard → **Accounts** → *New account*, then **Peers** → *Register a peer*.

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

### 3. A service

Server peers enroll with a key instead of signing in.

Dashboard → **Peers** → *Register a peer* (type **server**), then *Manage* →
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

Dashboard → **Rules** → *New rule*.

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

1. **Accounts** → create their account. Give it TOTP if it is an admin.
2. **Peers** → register their device: type *user*, owner = their account, the
   groups they need.
3. Send them the client config. Generate the keypair on their device.
4. They connect, open `http://10.88.0.1:8080/`, and sign in.

They land in quarantine first — that is normal, and the portal is the only thing
they can reach until they authenticate.

### Onboarding a machine

Same, but type *server*, no owner, and an enrollment key it presents itself. No
portal and no expiry.

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

**Sessions** shows administrators signed in to the dashboard and devices
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

The dashboard does the same thing under **Policies**, and refuses to apply
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

Every allowed and denied decision carries a counter and a `fg:<ref>:<name>`
comment in the live ruleset, so you can map a hit count back to the rule that
produced it:

```sh
nft -j list table inet foxguard | jq '.nftables[] | select(.rule.comment)'
```

And every state change is in **Audit log**, attributed to whoever made it.
