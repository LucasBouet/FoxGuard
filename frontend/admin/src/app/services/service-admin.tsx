"use client";

import { useState, useTransition } from "react";

import {
  Button,
  Check,
  ConfirmButton,
  Disclosure,
  Field,
  Input,
  Notice,
  ResultNotice,
  SecretOnce,
  Select,
  SlugChips,
  parseList,
  toggleSlug,
} from "@/components/forms";
import { Card, Cell, Row, Table } from "@/components/ui";
import {
  addServiceAccess,
  addServiceAuth,
  addServiceFilter,
  createService,
  createServiceAccount,
  createServiceToken,
  deleteService,
  removeServiceAccess,
  removeServiceAuth,
  removeServiceFilter,
  revokeSsoSession,
} from "@/lib/actions";
import type { Result } from "@/lib/actions";
import type {
  Group,
  Peer,
  Service,
  ServiceAccountCreated,
  ServiceAuth,
  ServiceAuthKind,
  ServiceExposure,
  ServiceFilter,
  ServiceFilterKind,
  ServiceKind,
  ServiceScope,
  ServiceTokenCreated,
  SsoSession,
  Zone,
} from "@/lib/types";

const SLUG_PATTERN = "^[a-z0-9][a-z0-9_-]{0,23}$";

/**
 * Which authenticators a service of this kind can actually carry.
 *
 * A TCP passthrough service never sees the plaintext, so bearer and basic auth
 * cannot apply to it. The control plane refuses them; greying them out here
 * means nobody ticks a box believing the service is protected when it is not.
 */
function availableAuth(kind: ServiceKind): ServiceAuthKind[] {
  return kind === "tcp"
    ? ["peer_identity"]
    : ["peer_identity", "bearer", "basic", "foxguard_sso"];
}

/** How each way in reads in a form, rather than as an enum value. */
const AUTH_LABEL: Record<string, string> = {
  peer_identity: "peer identity (the tunnel proves it)",
  bearer: "API token",
  basic: "service account (basic auth)",
  foxguard_sso: "Foxguard sign-in",
};

/**
 * Who this way in actually admits, in one phrase.
 *
 * Worth spelling out rather than showing a realm nobody reads: an SSO
 * authenticator with no groups admits every account in Foxguard, and that is
 * the fact an operator most needs to see without opening anything.
 */
function describeAudience(auth: ServiceAuth): string {
  if (auth.kind !== "foxguard_sso") {
    return auth.realm ? `realm ${auth.realm}` : "anyone holding the credential";
  }
  const parts: string[] = [];
  if (auth.require_admin) parts.push("administrators");
  if (auth.group_slugs.length > 0) parts.push(auth.group_slugs.join(" or "));
  return parts.length > 0 ? parts.join(" and in ") : "any Foxguard account";
}

/**
 * Filters this kind of service can carry.
 *
 * A TCP passthrough service never sees the plaintext, so a rate limit — which
 * counts *requests* — has nothing to count. The WAF and CrowdSec are absent
 * entirely: the control plane refuses them until they exist, and offering a
 * control that always errors is worse than not offering it.
 */
function availableFilters(kind: ServiceKind): ServiceFilterKind[] {
  const shared: ServiceFilterKind[] = ["ip_allow", "ip_deny", "geo_allow", "geo_deny"];
  return kind === "tcp" ? shared : [...shared, "rate_limit"];
}

const FILTER_LABEL: Record<string, string> = {
  ip_allow: "only these addresses",
  ip_deny: "never these addresses",
  geo_allow: "only these countries",
  geo_deny: "never these countries",
  rate_limit: "rate limit",
};

/** What a filter actually narrows to, in one phrase. */
function describeFilter(item: ServiceFilter): string {
  if (item.kind === "rate_limit") {
    return `${item.rate} requests / ${item.period_seconds}s`;
  }
  return item.values.join(", ") || "—";
}

/** Scopes an authenticator may have, given the exposure it is being added to. */
function availableScopes(kind: ServiceAuthKind): ServiceScope[] {
  // Outside the tunnel a source address belongs to an ISP or a NAT and is bound
  // to no key, so peer identity is internal-only and the API refuses anything
  // else. Offering the choice would just produce a 422.
  return kind === "peer_identity" ? ["internal"] : ["internal", "external", "both"];
}

export function CreateService({
  peers,
  groups,
  zones,
  domain,
  hasExternal,
}: {
  peers: Peer[];
  groups: Group[];
  zones: Zone[];
  domain: string | null;
  hasExternal: boolean;
}) {
  const [slug, setSlug] = useState("");
  const [name, setName] = useState("");
  const [kind, setKind] = useState<ServiceKind>("http");
  const [exposure, setExposure] = useState<ServiceExposure>("internal");
  const [peerId, setPeerId] = useState("");
  const [host, setHost] = useState("");
  const [port, setPort] = useState("");
  const [tls, setTls] = useState(false);
  const [tlsVerify, setTlsVerify] = useState(false);
  const [internalAuth, setInternalAuth] = useState<ServiceAuthKind>("peer_identity");
  const [externalAuth, setExternalAuth] = useState<ServiceAuthKind>("bearer");
  const [accessTarget, setAccessTarget] = useState("");
  const [result, setResult] = useState<Result<unknown> | null>(null);
  const [ssoGroups, setSsoGroups] = useState<string[]>([]);
  const [ssoAdmin, setSsoAdmin] = useState(false);
  const [pending, start] = useTransition();

  const wantsExternal = exposure === "external" || exposure === "both";
  const wantsInternal = exposure === "internal" || exposure === "both";
  const targets = [
    ...groups.map((group) => ({ id: group.id, label: `group ${group.slug}`, kind: "group" })),
    ...zones.map((zone) => ({ id: zone.id, label: `zone ${zone.slug}`, kind: "zone" })),
  ];

  function submit(event: React.FormEvent) {
    event.preventDefault();
    // The policy travels with the service: a listener with no authenticator
    // that applies to it is refused, so creating them separately can never work.
    const authenticators: {
      kind: ServiceAuthKind;
      scope: ServiceScope;
      group_slugs?: string[];
      require_admin?: boolean;
    }[] = [];
    // The group requirement rides on whichever door chose sign-in. Both doors
    // get the same one here; making them differ is the Policy panel's job.
    const sso = (kind: ServiceAuthKind) =>
      kind === "foxguard_sso"
        ? { group_slugs: ssoGroups, require_admin: ssoAdmin }
        : {};
    if (wantsInternal)
      authenticators.push({ kind: internalAuth, scope: "internal", ...sso(internalAuth) });
    if (wantsExternal)
      authenticators.push({ kind: externalAuth, scope: "external", ...sso(externalAuth) });

    const chosen = targets.find((target) => target.id === accessTarget);
    start(async () => {
      setResult(
        await createService({
          slug,
          name: name || slug,
          kind,
          exposure,
          upstream_peer_id: peerId || null,
          upstream_host: host,
          upstream_port: Number(port),
          upstream_tls: tls,
          upstream_tls_verify: tlsVerify,
          authenticators,
          access: chosen
            ? [{ kind: chosen.kind, group_id: chosen.id, action: "accept" }]
            : [{ kind: "any", action: "accept" }],
        }),
      );
    });
  }

  return (
    <Disclosure label="Publish a service">
      <form onSubmit={submit} className="grid gap-4 sm:grid-cols-2">
        <Field label="Slug" hint="Shares one namespace with peers, groups and zones.">
          <Input
            required
            pattern={SLUG_PATTERN}
            value={slug}
            onChange={(event) => setSlug(event.target.value)}
          />
        </Field>
        <Field label="Name">
          <Input value={name} onChange={(event) => setName(event.target.value)} />
        </Field>

        <Field
          label="Kind"
          hint={
            kind === "tcp"
              ? "Passthrough: the proxy cannot see inside, so no token or password check is possible."
              : "Terminated: the proxy can check a token and tell the upstream who is calling."
          }
        >
          <Select value={kind} onChange={(event) => setKind(event.target.value as ServiceKind)}>
            <option value="http">HTTP (terminated)</option>
            <option value="tcp">TCP (passthrough)</option>
          </Select>
        </Field>
        <Field
          label="Exposure"
          hint={
            !hasExternal
              ? "No WAN address is configured, so only the tunnel-side door exists."
              : "Both means one name, two doors, different policy on each."
          }
        >
          <Select
            value={exposure}
            onChange={(event) => setExposure(event.target.value as ServiceExposure)}
          >
            <option value="internal">Internal (tunnel only)</option>
            <option value="external" disabled={!hasExternal}>
              External (WAN only)
            </option>
            <option value="both" disabled={!hasExternal}>
              Both
            </option>
          </Select>
        </Field>

        <Field label="Behind which peer" hint="Leave empty if the gateway hosts it itself.">
          <Select value={peerId} onChange={(event) => setPeerId(event.target.value)}>
            <option value="">— the gateway —</option>
            {peers.map((peer) => (
              <option key={peer.id} value={peer.id}>
                {peer.name} ({peer.tunnel_ip})
              </option>
            ))}
          </Select>
        </Field>
        <div className="grid grid-cols-2 gap-3">
          <Field
            label="Upstream address"
            hint="Must be an address that peer carries or routes for."
          >
            <Input
              required
              value={host}
              onChange={(event) => setHost(event.target.value)}
              placeholder="10.88.0.6"
            />
          </Field>
          <Field label="Port">
            <Input
              required
              type="number"
              min={1}
              max={65535}
              value={port}
              onChange={(event) => setPort(event.target.value)}
            />
          </Field>
        </div>

        {kind === "http" && (
          <>
            <Check
              label="The upstream speaks HTTPS"
              checked={tls}
              onChange={setTls}
            />
            <Check
              label="Verify the upstream's certificate"
              hint="Off by default: these are usually appliances with self-signed certificates, and the hop already runs inside WireGuard."
              checked={tlsVerify}
              onChange={setTlsVerify}
            />
          </>
        )}

        {wantsInternal && (
          <Field
            label="Way in from the tunnel"
            hint="Inside the tunnel the source address proves which device sent the packet."
          >
            <Select
              value={internalAuth}
              onChange={(event) => setInternalAuth(event.target.value as ServiceAuthKind)}
            >
              {availableAuth(kind).map((option) => (
                <option key={option} value={option}>
                  {AUTH_LABEL[option] ?? option}
                </option>
              ))}
            </Select>
          </Field>
        )}
        {wantsExternal && (
          <Field
            label="Way in from the internet"
            hint="Peer identity is not offered here: outside the tunnel a source address proves nothing."
          >
            <Select
              value={externalAuth}
              onChange={(event) => setExternalAuth(event.target.value as ServiceAuthKind)}
            >
              {availableAuth(kind)
                .filter((option) => option !== "peer_identity")
                .map((option) => (
                  <option key={option} value={option}>
                    {AUTH_LABEL[option] ?? option}
                  </option>
                ))}
            </Select>
          </Field>
        )}

        {(internalAuth === "foxguard_sso" || externalAuth === "foxguard_sso") && (
          <div className="space-y-2 sm:col-span-2">
            <span className="text-sm text-ink-secondary">
              Which accounts may sign in
            </span>
            <p className="text-xs text-ink-muted">
              Leave this empty and every Foxguard account reaches the service.
              Pick groups and membership of any one of them is required.
            </p>
            <SlugChips
              options={groups}
              selected={ssoGroups}
              onToggle={(slug) => setSsoGroups((current) => toggleSlug(current, slug))}
            />
            <Check
              label="Administrators only"
              hint="ANDed with the groups above."
              checked={ssoAdmin}
              onChange={setSsoAdmin}
            />
          </div>
        )}

        <Field
          label="Who may use it"
          hint="Evaluated on the tunnel-side door only — a public address cannot be a peer."
        >
          <Select
            value={accessTarget}
            onChange={(event) => setAccessTarget(event.target.value)}
          >
            <option value="">Anyone who authenticates</option>
            {targets.map((target) => (
              <option key={target.id} value={target.id}>
                {target.label}
              </option>
            ))}
          </Select>
        </Field>

        <div className="sm:col-span-2">
          {domain && (
            <p className="mb-3 text-xs text-ink-muted">
              It will answer to <code>{slug || "<slug>"}.{domain}</code>
              {exposure === "both" && " on both doors — the same name, resolved differently inside and outside."}
            </p>
          )}
          {wantsExternal && externalAuth === "bearer" && (
            <Notice kind="warning">
              Issue a token after creating it, or nothing will be able to
              authenticate from outside.
            </Notice>
          )}
          <ResultNotice result={result} />
          <Button type="submit" disabled={pending} className="mt-3">
            {pending ? "Publishing…" : "Publish"}
          </Button>
        </div>
      </form>
    </Disclosure>
  );
}

export function ServiceDetail({
  service,
  groups,
  zones,
}: {
  service: Service;
  groups: Group[];
  zones: Zone[];
}) {
  const [result, setResult] = useState<Result<unknown> | null>(null);
  const [pending, start] = useTransition();
  const [authKind, setAuthKind] = useState<ServiceAuthKind>("peer_identity");
  const [authScope, setAuthScope] = useState<ServiceScope>("internal");
  const [authGroups, setAuthGroups] = useState<string[]>([]);
  const [authAdmin, setAuthAdmin] = useState(false);
  const [filterKind, setFilterKind] = useState<ServiceFilterKind>("ip_deny");
  const [filterScope, setFilterScope] = useState<ServiceScope>("both");
  const [filterValues, setFilterValues] = useState("");
  const [rate, setRate] = useState("60");
  const [period, setPeriod] = useState("60");
  const [accessTarget, setAccessTarget] = useState("");

  const filterReady =
    filterKind === "rate_limit"
      ? Number(rate) > 0 && Number(period) > 0
      : parseList(filterValues).length > 0;

  const targets = [
    ...groups.map((group) => ({ id: group.id, label: `group ${group.slug}`, kind: "group" })),
    ...zones.map((zone) => ({ id: zone.id, label: `zone ${zone.slug}`, kind: "zone" })),
  ];

  return (
    <div className="flex justify-end gap-2">
      <Disclosure label="Policy">
        <div className="space-y-5">
          <div>
            <p className="mb-2 text-sm font-semibold">Ways in</p>
            <Table
              headers={["Kind", "Door", "Who is allowed", ""]}
              empty="None — the service is not served."
            >
              {service.authenticators.map((auth) => (
                <Row key={auth.id}>
                  <Cell>{AUTH_LABEL[auth.kind] ?? auth.kind}</Cell>
                  <Cell className="text-ink-secondary">{auth.scope}</Cell>
                  <Cell className="text-ink-secondary">{describeAudience(auth)}</Cell>
                  <Cell className="text-right">
                    <ConfirmButton
                      label="Remove"
                      confirmLabel="Remove it"
                      warning="Removing the last way in on a door makes the whole configuration invalid, and the change will be refused."
                      onConfirm={() =>
                        start(async () => {
                          setResult(await removeServiceAuth(service.id, auth.id));
                        })
                      }
                    />
                  </Cell>
                </Row>
              ))}
            </Table>
            <div className="mt-3 flex flex-wrap items-end gap-3">
              <Field label="Add">
                <Select
                  value={authKind}
                  onChange={(event) => {
                    const next = event.target.value as ServiceAuthKind;
                    setAuthKind(next);
                    if (next === "peer_identity") setAuthScope("internal");
                  }}
                >
                  {availableAuth(service.kind).map((option) => (
                    <option key={option} value={option}>
                      {AUTH_LABEL[option] ?? option}
                    </option>
                  ))}
                </Select>
              </Field>
              <Field label="Door">
                <Select
                  value={authScope}
                  onChange={(event) => setAuthScope(event.target.value as ServiceScope)}
                >
                  {availableScopes(authKind).map((option) => (
                    <option key={option} value={option}>
                      {option}
                    </option>
                  ))}
                </Select>
              </Field>
              <Button
                disabled={pending}
                onClick={() =>
                  start(async () => {
                    setResult(
                      await addServiceAuth(service.id, {
                        kind: authKind,
                        scope: authScope,
                        group_slugs: authKind === "foxguard_sso" ? authGroups : [],
                        require_admin: authKind === "foxguard_sso" && authAdmin,
                      }),
                    );
                    if (authKind === "foxguard_sso") {
                      setAuthGroups([]);
                      setAuthAdmin(false);
                    }
                  })
                }
              >
                Add
              </Button>
            </div>
            {authKind === "foxguard_sso" && (
              <div className="mt-3 space-y-2 rounded-md border border-hairline bg-page p-3">
                <p className="text-xs text-ink-secondary">
                  Signing in is not the same as being allowed in. Pick no group
                  and <em>every</em> Foxguard account reaches this service. Pick
                  some and membership of any one of them is required — someone
                  signed in without it gets a refusal that says so, not the login
                  page again.
                </p>
                <SlugChips
                  options={groups}
                  selected={authGroups}
                  on="surface"
                  onToggle={(slug) => setAuthGroups((current) => toggleSlug(current, slug))}
                />
                <Check
                  label="Administrators only"
                  hint="Combined with the groups above by AND, not OR."
                  checked={authAdmin}
                  onChange={setAuthAdmin}
                />
              </div>
            )}
          </div>

          <div>
            <p className="mb-2 text-sm font-semibold">Restrictions</p>
            <p className="mb-2 text-xs text-ink-secondary">
              Narrowing, not admitting: these are ANDed with each other and with
              whatever way in the caller used.
            </p>
            <Table headers={["Kind", "Door", "What", ""]} empty="None.">
              {service.filters.map((item) => (
                <Row key={item.id}>
                  <Cell>{FILTER_LABEL[item.kind] ?? item.kind}</Cell>
                  <Cell className="text-ink-secondary">{item.scope}</Cell>
                  <Cell className="text-ink-secondary">{describeFilter(item)}</Cell>
                  <Cell className="text-right">
                    <ConfirmButton
                      label="Remove"
                      confirmLabel="Remove it"
                      warning="The service stops narrowing on this immediately."
                      onConfirm={() =>
                        start(async () => {
                          setResult(await removeServiceFilter(service.id, item.id));
                        })
                      }
                    />
                  </Cell>
                </Row>
              ))}
            </Table>
            <div className="mt-3 flex flex-wrap items-end gap-3">
              <Field label="Add">
                <Select
                  value={filterKind}
                  onChange={(event) =>
                    setFilterKind(event.target.value as ServiceFilterKind)
                  }
                >
                  {availableFilters(service.kind).map((option) => (
                    <option key={option} value={option}>
                      {FILTER_LABEL[option] ?? option}
                    </option>
                  ))}
                </Select>
              </Field>
              <Field label="Door">
                <Select
                  value={filterScope}
                  onChange={(event) => setFilterScope(event.target.value as ServiceScope)}
                >
                  {(["both", "internal", "external"] as ServiceScope[]).map((option) => (
                    <option key={option} value={option}>
                      {option}
                    </option>
                  ))}
                </Select>
              </Field>
              {filterKind === "rate_limit" ? (
                <>
                  <Field label="Requests">
                    <Input
                      type="number"
                      min={1}
                      value={rate}
                      onChange={(event) => setRate(event.target.value)}
                      className="w-24"
                    />
                  </Field>
                  <Field label="Per (seconds)" hint="Also what Retry-After will say.">
                    <Input
                      type="number"
                      min={1}
                      value={period}
                      onChange={(event) => setPeriod(event.target.value)}
                      className="w-24"
                    />
                  </Field>
                </>
              ) : (
                <Field
                  label={filterKind.startsWith("geo") ? "Countries" : "Addresses"}
                  hint={
                    filterKind.startsWith("geo")
                      ? "Two-letter codes, comma separated: FR, CH"
                      : "Addresses or prefixes, comma separated"
                  }
                >
                  <Input
                    value={filterValues}
                    onChange={(event) => setFilterValues(event.target.value)}
                    placeholder={filterKind.startsWith("geo") ? "FR, CH" : "203.0.113.0/24"}
                  />
                </Field>
              )}
              <Button
                disabled={pending || !filterReady}
                onClick={() =>
                  start(async () => {
                    const outcome = await addServiceFilter(service.id, {
                      kind: filterKind,
                      scope: filterScope,
                      values:
                        filterKind === "rate_limit"
                          ? undefined
                          : parseList(filterValues).map((value) =>
                              filterKind.startsWith("geo") ? value.toUpperCase() : value,
                            ),
                      rate: filterKind === "rate_limit" ? Number(rate) : undefined,
                      period_seconds:
                        filterKind === "rate_limit" ? Number(period) : undefined,
                    });
                    setResult(outcome);
                    if (outcome.ok) setFilterValues("");
                  })
                }
              >
                Add
              </Button>
            </div>
            {filterKind.startsWith("geo") && (
              <Notice kind="warning">
                Geo is noise reduction, not a security control — any VPN defeats
                it in one click. The gateway builds its own prefix map, and until{" "}
                <code>foxguard-geo-refresh</code> has run there, an allow list
                refuses everyone and a deny list blocks nobody.
              </Notice>
            )}
          </div>

          <div>
            <p className="mb-2 text-sm font-semibold">Who may use it</p>
            <Table headers={["Action", "Source", ""]} empty="Anyone who authenticates.">
              {service.access.map((rule) => (
                <Row key={rule.id}>
                  <Cell>{rule.action === "accept" ? "allow" : "deny"}</Cell>
                  <Cell className="text-ink-secondary">
                    {rule.group_slug ?? rule.cidr ?? "any"}
                  </Cell>
                  <Cell className="text-right">
                    <ConfirmButton
                      label="Remove"
                      confirmLabel="Remove it"
                      warning="With no allow rule left, anyone who authenticates gets in."
                      onConfirm={() =>
                        start(async () => {
                          setResult(await removeServiceAccess(service.id, rule.id));
                        })
                      }
                    />
                  </Cell>
                </Row>
              ))}
            </Table>
            <div className="mt-3 flex flex-wrap items-end gap-3">
              <Field
                label="Allow"
                hint="Group and zone rules are evaluated on the tunnel-side door only."
              >
                <Select
                  value={accessTarget}
                  onChange={(event) => setAccessTarget(event.target.value)}
                >
                  <option value="">— pick one —</option>
                  {targets.map((target) => (
                    <option key={target.id} value={target.id}>
                      {target.label}
                    </option>
                  ))}
                </Select>
              </Field>
              <Button
                disabled={pending || !accessTarget}
                onClick={() => {
                  const chosen = targets.find((target) => target.id === accessTarget);
                  if (!chosen) return;
                  start(async () => {
                    setResult(
                      await addServiceAccess(service.id, {
                        kind: chosen.kind,
                        group_id: chosen.id,
                        action: "accept",
                      }),
                    );
                  });
                }}
              >
                Add
              </Button>
            </div>
          </div>

          <ResultNotice result={result} />
          <ConfirmButton
            label="Delete this service"
            confirmLabel="Delete it"
            warning="The listener goes away on the agent's next poll. Tokens and accounts go with it."
            onConfirm={() =>
              start(async () => {
                setResult(await deleteService(service.id));
              })
            }
          />
        </div>
      </Disclosure>
    </div>
  );
}

export function ServiceCredentials({ service }: { service: Service }) {
  const [tokenName, setTokenName] = useState("");
  const [username, setUsername] = useState("");
  const [token, setToken] = useState<ServiceTokenCreated | null>(null);
  const [account, setAccount] = useState<ServiceAccountCreated | null>(null);
  const [result, setResult] = useState<Result<unknown> | null>(null);
  const [pending, start] = useTransition();

  const wantsBearer = service.authenticators.some((auth) => auth.kind === "bearer");
  const wantsBasic = service.authenticators.some((auth) => auth.kind === "basic");
  if (!wantsBearer && !wantsBasic) return null;

  return (
    <Card
      title={`Credentials — ${service.slug}`}
      description="Shown once. Foxguard stores a hash and cannot show you the value again; revoke and issue a new one instead."
    >
      <div className="space-y-4">
        {wantsBearer && (
          <div className="flex flex-wrap items-end gap-3">
            <Field label="New API token" hint="A 256-bit secret, hashed unsalted because HAProxy verifies it itself.">
              <Input
                value={tokenName}
                onChange={(event) => setTokenName(event.target.value)}
                placeholder="ci"
              />
            </Field>
            <Button
              disabled={pending || !tokenName}
              onClick={() =>
                start(async () => {
                  const outcome = await createServiceToken(service.id, { name: tokenName });
                  setResult(outcome);
                  if (outcome.ok) {
                    setToken(outcome.data);
                    setTokenName("");
                  }
                })
              }
            >
              Issue
            </Button>
          </div>
        )}
        {token && (
          <SecretOnce
            title={`Token "${token.name}"`}
            value={token.token}
            note="Send it as `Authorization: Bearer <token>`. This is the only time it exists outside your clipboard."
          />
        )}

        {wantsBasic && (
          <div className="flex flex-wrap items-end gap-3">
            <Field
              label="New service account"
              hint="The password is generated, not chosen — that is what lets the hash on the gateway be crypt(3) rather than argon2."
            >
              <Input
                value={username}
                onChange={(event) => setUsername(event.target.value)}
                placeholder="svc"
              />
            </Field>
            <Button
              disabled={pending || !username}
              onClick={() =>
                start(async () => {
                  const outcome = await createServiceAccount(service.id, { username });
                  setResult(outcome);
                  if (outcome.ok) {
                    setAccount(outcome.data);
                    setUsername("");
                  }
                })
              }
            >
              Create
            </Button>
          </div>
        )}
        {account && (
          <SecretOnce
            title={`Account "${account.username}"`}
            value={account.password}
            note="Basic auth over HTTPS only. Shown once."
          />
        )}

        <ResultNotice result={result} />
      </div>
    </Card>
  );
}



export function SsoSessions({ sessions }: { sessions: SsoSession[] }) {
  const [result, setResult] = useState<Result<unknown> | null>(null);
  const [pending, start] = useTransition();

  return (
    <Card
      title="Signed in"
      description={
        "People currently holding a Foxguard sign-in cookie. Revoking one takes " +
        "effect on the agent's next poll — the cookie itself stays valid-looking, " +
        "which is what makes the proxy fast, so the revocation list is what stops it."
      }
    >
      <Table headers={["Account", "From", "Signed in", "Expires", ""]} empty="Nobody.">
        {sessions.map((row) => (
          <Row key={row.id}>
            <Cell className="font-medium">{row.username ?? "—"}</Cell>
            <Cell className="text-ink-secondary">{row.source_ip ?? "—"}</Cell>
            <Cell className="text-ink-secondary">
              {new Date(row.created_at).toLocaleString()}
            </Cell>
            <Cell className="text-ink-secondary">
              {new Date(row.expires_at).toLocaleString()}
            </Cell>
            <Cell className="text-right">
              <ConfirmButton
                label="Sign out"
                confirmLabel="Sign them out"
                warning="They will have to sign in again on their next request."
                disabled={pending}
                onConfirm={() =>
                  start(async () => {
                    setResult(await revokeSsoSession(row.id));
                  })
                }
              />
            </Cell>
          </Row>
        ))}
      </Table>
      <ResultNotice result={result} />
    </Card>
  );
}
