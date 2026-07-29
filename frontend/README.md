# Foxguard frontend

```
frontend/
├── admin/          # admin dashboard — server-rendered, holds the admin token
└── portal/         # captive portal — static bundle, runs in the browser
```

The two apps have **opposite architectures**, and both are forced by the same
constraint rather than chosen by taste. See each section below.

## Why two apps rather than one

The portal is reachable by **quarantined** peers — that is its whole purpose — so
it is the most exposed surface Foxguard has. The dashboard is reachable only from
inside the tunnel by an operator. Keeping them as separate deployables means a
bug in the portal bundle cannot expose an admin route, and they can be served on
different ports with different nftables treatment.

---

# portal/ — the captive portal

Next.js **static export**. There is no portal server, and that is not an
optimisation.

The portal identifies its caller by the source address of the TCP connection,
because inside WireGuard that address is bound to a peer's public key. If this
app had a server that called the API on the browser's behalf, the API would see
*that server's* address and refuse every request. So the browser executes the
bundle and calls `/api/v1/portal/*` itself, over the peer's own connection, and
the API serves those files from the same origin — no CORS exemption on the one
surface a quarantined peer can already reach.

```sh
cd frontend/portal
npm install
npm run build            # -> out/
```

Then point the API at it:

```ini
FOXGUARD_PORTAL_STATIC_DIR=/path/to/frontend/portal/out
```

and start it with **`foxguard-serve`**, which disables uvicorn's proxy headers.
With them on (uvicorn's default) anything able to connect on loopback can
impersonate any peer with an `X-Forwarded-For` header — see
`docs/architecture.md` §5.

`npm run dev` is of limited use: on its own port the browser's calls are
cross-origin and no peer owns the dev server's address. Build and serve through
the API to exercise it for real.

## What it shows

One screen, three states — no routing and **no session token**. What
authenticating buys is network access held in the gateway's nftables ruleset, so
"am I signed in?" is answered by asking the gateway, never by reading something
the page stored.

- **not connected** — password (plus authenticator code when the account
  requires one), and an SSO button when OIDC is configured *and* the account is
  bound to an IdP subject;
- **connected** — who you are signed in as, roughly how long the session has
  left, and sign out;
- **cannot sign in** — a server peer (it enrolls with a key instead), or a
  device an administrator has disabled.

The username is prefilled from `/portal/status`: the device is bound to one
account and the API refuses any other, so guessing it helps nobody. It is not a
disclosure either — reaching the page already proved possession of the peer's
key.

Failures are kept distinct because the right next step differs: a `403` means
the tunnel is not carrying this request, a `401` means the credentials were
wrong *for this device*, and a `429` reports how long the throttle lasts.

---

# admin/ — the dashboard

Next.js (App Router) + React + TypeScript + Tailwind.

```sh
cd frontend/admin
npm install
FOXGUARD_API_URL=http://127.0.0.1:8000 \
FOXGUARD_ADMIN_API_TOKEN=<admin token> \
  npm run dev            # http://127.0.0.1:3000
```

`npm run build` for production, `npm run typecheck` for types alone.

## No admin credential reaches the browser

This is the reason the dashboard is a Next.js **server** app — the exact opposite
of the portal, for the exact opposite reason. The portal must not put a server
in the path because the source address is the identity; the dashboard must put
one there because it holds a credential the browser should never see.

Signing in at `/login` calls the API and puts the resulting session token in an
**httpOnly cookie on the dashboard's own origin** (`src/lib/session.ts`). The
browser cannot read it, so an XSS in a dashboard page cannot walk off with a
credential that controls the network; the server attaches it to API calls.

`src/lib/api.ts` prefers that session over `FOXGUARD_ADMIN_API_TOKEN`, because
only the session names a person — an audit entry saying `ada` is worth more than
one saying `admin-token`. The static token remains as a fallback so a gateway
with no administrator account yet can still reach its own dashboard, and the
header says plainly when that is what is happening.

Every call to the control plane happens in a **server component** or a **server
action** (`src/lib/api.ts`, `src/lib/actions.ts`), which read
`FOXGUARD_ADMIN_API_TOKEN` from the process environment and return plain data.
The browser receives rendered HTML and never sees a credential or an API URL.

A static SPA would have to ship the admin bearer token to the browser, where it
lives in every extension, devtools session and cached bundle on that machine.
`src/lib/api.ts` imports `server-only`, so a stray import from a `"use client"`
module is a build error rather than a leak.

## Screens

| Route | What it answers |
| --- | --- |
| `/` | Is the dataplane running what the database says? Then peer counts, sessions, recent activity. |
| `/peers` | Which peers exist, in what state, with what tags — filtered by the API, not in the browser. Register peers, manage enrollment keys, quarantine / disable / revoke. |
| `/users` | Accounts, their sign-in methods and 2FA. Create accounts, provision TOTP. |
| `/groups` | Group settings, the policy matrix, and group create/edit/delete. |
| `/rules` | ACL rules in the order nftables evaluates them; create, enable/disable, delete. |
| `/policies` | Export the ACL document for git; import it back with a dry-run diff. |
| `/sessions` | Who is signed in to the dashboard, and which devices are on the network. Revoke either. |
| `/audit` | Who did what, with one-click filters for the actions that matter when something is wrong. |
| `/kill-switch` | Cut the fleet. Deliberately awkward. |

### Things the forms are opinionated about

**Private keys are never asked for.** The peer form says so and shows the
`wg genkey | wg pubkey` incantation, because the cheapest way to stop someone
pasting a private key is to tell them not to before they do.

**Secrets shown once look like it.** Enrollment keys and TOTP seeds render in a
highlighted panel with a copy button and an explicit "this is the only time"
note, rather than as another field in a table.

**`active` is not offered on a user peer.** The API returns 409 for it — a user
peer becomes active by authenticating — so the form does not present a button
that would fail.

**Destructive actions arm before they fire.** A second click, with the
consequence spelled out next to it: revoking is terminal, deleting a group takes
its ACL rules with it. Not `window.confirm`, which cannot carry that sentence.

### Three details worth knowing

**The sync banner leads the overview.** Every other number on that page describes
*intent*; `ruleset.in_sync` is the only one describing reality — whether the
agent has confirmed applying the ruleset the database currently implies.

**The policy matrix shows the rule that actually decides.** Cells carry the first
matching rule's action in `(priority, ref)` order — the order nftables evaluates
them. A later `accept` sitting behind an earlier `drop` never fires, and painting
that cell green would be a lie an operator might act on. The other refs targeting
the pair are in the cell's tooltip, so a shadowed rule stays discoverable.

**Import is a two-step flow.** *Apply* stays disabled until a dry run has
succeeded for the exact text in the box; editing it clears the preview. The dry
run is not a client-side guess — the API runs the real import inside a
transaction and rolls it back, so preview and application cannot disagree.

## Colour

Peer states and ACL actions use the reserved **status** palette, not the
categorical one: they are states, not series. Two rules follow, and both are load
bearing:

- a status colour never carries meaning alone — every badge is a coloured dot
  **plus** a written label;
- the label is drawn in normal ink, never in the status colour. The warning step
  is deliberately below 3:1 on the light surface, and the label is the mitigation.

Values live as CSS custom properties in `src/app/globals.css`. Dark mode is a
*selected* set of steps for the dark surface, not an automatic inversion, and it
follows both the OS setting and an explicit `data-theme` stamp.

## Dependency pins

`overrides` in `package.json` pins `sharp` and `postcss` above their advisory
ranges. Both arrive through Next; `npm audit fix --force` "resolves" them by
downgrading Next to 9.3.3, which is not a fix. `npm audit` reports zero
vulnerabilities with the overrides in place.

## Types

`src/lib/types.ts` is hand-written and deliberately partial — the dashboard reads
a subset of each response. If that stops paying off, generate a full client from
the live schema instead of widening it by hand:

```sh
curl -s http://127.0.0.1:8000/openapi.json > openapi.json
```
