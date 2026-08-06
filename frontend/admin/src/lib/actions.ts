"use server";

/**
 * Mutations. These run on the server, so the admin token stays there — a client
 * component calls them like functions and never sees a URL or a credential.
 *
 * Each one returns a plain result object instead of throwing: these are
 * operator actions and "why did that fail" has to end up on screen.
 */

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";

import { ApiError, api } from "./api";
import { clearSessionToken, setSessionToken } from "./session";
import type {
  AclAction,
  AllowedIpsMode,
  AclEndpoint,
  AclRule,
  ClientConfigProfile,
  DnsRecord,
  DnsRecordKind,
  EnrollmentKey,
  Group,
  KillSwitchResult,
  Peer,
  PeerState,
  PolicyDiff,
  Protocol,
  TotpProvision,
  User,
  Zone,
  ZoneRoute,
  Service,
  ServiceAccountCreated,
  ServiceAuthKind,
  ServiceExposure,
  ServiceKind,
  ServiceScope,
  ServiceTokenCreated,
} from "./types";
import type { AdminLoginResponse, AdminWhoAmI } from "./types";

export type Result<T> = { ok: true; data: T } | { ok: false; error: string };

async function run<T>(fn: () => Promise<T>): Promise<Result<T>> {
  try {
    return { ok: true, data: await fn() };
  } catch (error) {
    return {
      ok: false,
      error:
        error instanceof ApiError
          ? `${error.status}: ${error.detail}`
          : error instanceof Error
            ? error.message
            : "unexpected error",
    };
  }
}

/**
 * Preview or apply a policy document.
 *
 * `dry_run` is honoured by the API by running the *real* import inside a
 * transaction and rolling it back, so the preview and the application cannot
 * disagree. The UI therefore never has to compute a diff itself.
 */
export async function importPolicies(
  document: string,
  dryRun: boolean,
  prune: boolean,
): Promise<Result<PolicyDiff>> {
  return run(async () => {
    let parsed: unknown;
    try {
      parsed = JSON.parse(document);
    } catch (error) {
      throw new Error(
        `not valid JSON: ${error instanceof Error ? error.message : "parse error"}`,
      );
    }
    const diff = await api.post<PolicyDiff>("/api/v1/policies/import", {
      document: parsed,
      dry_run: dryRun,
      prune,
    });
    if (!dryRun) {
      revalidatePath("/groups");
      revalidatePath("/");
    }
    return diff;
  });
}

export async function exportPolicies(): Promise<Result<unknown>> {
  return run(() => api.get<unknown>("/api/v1/policies/export"));
}

/**
 * The kill switch. The confirmation phrase is typed by the operator and passed
 * through verbatim — the API rejects anything else, so the guard does not
 * depend on this form being the only caller.
 */
export async function triggerKillSwitch(
  mode: "quarantine" | "lockdown",
  confirm: string,
): Promise<Result<KillSwitchResult>> {
  const result = await run(() =>
    api.post<KillSwitchResult>("/api/v1/kill-switch", { mode, confirm }),
  );
  if (result.ok) {
    revalidatePath("/");
    revalidatePath("/peers");
  }
  return result;
}

// --------------------------------------------------------------------------- //
// administrator sign-in
// --------------------------------------------------------------------------- //

export async function signIn(
  username: string,
  password: string,
  totpCode: string,
): Promise<Result<AdminWhoAmI>> {
  const result = await run(() =>
    api.post<AdminLoginResponse>("/api/v1/admin/login", {
      username,
      password,
      totp_code: totpCode.trim() || null,
    }),
  );
  if (!result.ok) return result;

  // Straight into an httpOnly cookie: the token never becomes a value any
  // client-side script can read.
  await setSessionToken(result.data.token, result.data.expires_at);
  revalidatePath("/", "layout");
  return { ok: true, data: result.data.user };
}

/** Ask the API for an authorization URL, then send the browser to the IdP. */
export async function startAdminSso(): Promise<Result<{ authorization_url: string }>> {
  return run(() =>
    api.get<{ authorization_url: string; state: string }>("/api/v1/admin/oidc/start"),
  );
}

/**
 * Finish an SSO sign-in.
 *
 * The IdP redirects the *browser* here, so the code arrives at the dashboard
 * and the exchange happens server-side — which is what lets the session token
 * go straight into an httpOnly cookie instead of travelling through a URL,
 * where it would end up in logs, history and `Referer` headers.
 */
export async function completeAdminSso(
  state: string,
  code: string,
): Promise<Result<AdminWhoAmI>> {
  const result = await run(() =>
    api.post<AdminLoginResponse>("/api/v1/admin/oidc/complete", { state, code }),
  );
  if (!result.ok) return result;
  await setSessionToken(result.data.token, result.data.expires_at);
  revalidatePath("/", "layout");
  return { ok: true, data: result.data.user };
}

export async function revokeAdminSession(id: string): Promise<Result<void>> {
  const result = await run(() => api.delete<void>(`/api/v1/admin/sessions/${id}`));
  if (result.ok) revalidatePath("/sessions");
  return result;
}

export async function signOut(): Promise<void> {
  // Revoke server-side first: dropping only the cookie would leave a live
  // session behind that anyone holding the token could keep using.
  try {
    await api.post("/api/v1/admin/logout");
  } catch {
    /* the cookie goes either way -- a session we cannot reach is still one we
       are done with locally */
  }
  await clearSessionToken();
  revalidatePath("/", "layout");
  redirect("/login");
}

export async function sweepSessions(): Promise<Result<unknown>> {
  const result = await run(() => api.post<unknown>("/api/v1/sessions/sweep"));
  if (result.ok) revalidatePath("/");
  return result;
}

// --------------------------------------------------------------------------- //
// groups
// --------------------------------------------------------------------------- //

function refreshEverything() {
  // A group, zone or rule change re-renders the ruleset, so the overview's sync
  // banner and the matrix are both stale afterwards. Zones additionally change
  // what /dns would serve, since a peer's name follows it around.
  revalidatePath("/");
  revalidatePath("/groups");
  revalidatePath("/zones");
  revalidatePath("/peers");
  revalidatePath("/rules");
  revalidatePath("/dns");
}

export async function createGroup(input: {
  slug: string;
  name: string;
  description?: string;
  internet_exit: boolean;
  session_lifetime_seconds: number | null;
}): Promise<Result<Group>> {
  const result = await run(() => api.post<Group>("/api/v1/groups", input));
  if (result.ok) refreshEverything();
  return result;
}

export async function updateGroup(
  id: string,
  patch: Partial<{
    name: string;
    description: string;
    internet_exit: boolean;
    session_lifetime_seconds: number | null;
  }>,
): Promise<Result<Group>> {
  const result = await run(() => api.patch<Group>(`/api/v1/groups/${id}`, patch));
  if (result.ok) refreshEverything();
  return result;
}

export async function deleteGroup(id: string): Promise<Result<void>> {
  const result = await run(() => api.delete<void>(`/api/v1/groups/${id}`));
  if (result.ok) refreshEverything();
  return result;
}

// --------------------------------------------------------------------------- //
// zones
// --------------------------------------------------------------------------- //

export async function createZone(input: {
  slug: string;
  name: string;
  description?: string;
  internet_exit: boolean;
  intra_zone: boolean;
  session_lifetime_seconds: number | null;
}): Promise<Result<Zone>> {
  const result = await run(() => api.post<Zone>("/api/v1/zones", input));
  if (result.ok) refreshEverything();
  return result;
}

export async function updateZone(
  id: string,
  patch: Partial<{
    name: string;
    description: string;
    internet_exit: boolean;
    intra_zone: boolean;
    session_lifetime_seconds: number | null;
  }>,
): Promise<Result<Zone>> {
  const result = await run(() => api.patch<Zone>(`/api/v1/zones/${id}`, patch));
  if (result.ok) refreshEverything();
  return result;
}

export async function deleteZone(id: string): Promise<Result<void>> {
  const result = await run(() => api.delete<void>(`/api/v1/zones/${id}`));
  if (result.ok) refreshEverything();
  return result;
}

/**
 * Add a network to a zone.
 *
 * With `via_peer_id`, the gateway also installs a kernel route into the tunnel
 * on the agent's next poll. Without it, the CIDR only widens the zone's address
 * set -- which is what you want for a LAN the gateway already reaches itself.
 */
export async function createZoneRoute(
  zoneId: string,
  input: { cidr: string; via_peer_id: string | null; description?: string },
): Promise<Result<ZoneRoute>> {
  const result = await run(() =>
    api.post<ZoneRoute>(`/api/v1/zones/${zoneId}/routes`, {
      ...input,
      via_peer_id: input.via_peer_id || null,
    }),
  );
  if (result.ok) refreshEverything();
  return result;
}

export async function updateZoneRoute(
  zoneId: string,
  routeId: string,
  patch: Partial<{ via_peer_id: string | null; description: string; enabled: boolean }>,
): Promise<Result<ZoneRoute>> {
  const result = await run(() =>
    api.patch<ZoneRoute>(`/api/v1/zones/${zoneId}/routes/${routeId}`, patch),
  );
  if (result.ok) refreshEverything();
  return result;
}

export async function deleteZoneRoute(
  zoneId: string,
  routeId: string,
): Promise<Result<void>> {
  const result = await run(() =>
    api.delete<void>(`/api/v1/zones/${zoneId}/routes/${routeId}`),
  );
  if (result.ok) refreshEverything();
  return result;
}

// --------------------------------------------------------------------------- //
// DNS records
// --------------------------------------------------------------------------- //

export async function createDnsRecord(input: {
  name: string;
  kind: DnsRecordKind;
  value: string;
  description?: string;
}): Promise<Result<DnsRecord>> {
  const result = await run(() => api.post<DnsRecord>("/api/v1/dns/records", input));
  if (result.ok) revalidatePath("/dns");
  return result;
}

export async function updateDnsRecord(
  id: string,
  patch: Partial<{ name: string; value: string; description: string; enabled: boolean }>,
): Promise<Result<DnsRecord>> {
  const result = await run(() =>
    api.patch<DnsRecord>(`/api/v1/dns/records/${id}`, patch),
  );
  if (result.ok) revalidatePath("/dns");
  return result;
}

export async function deleteDnsRecord(id: string): Promise<Result<void>> {
  const result = await run(() => api.delete<void>(`/api/v1/dns/records/${id}`));
  if (result.ok) revalidatePath("/dns");
  return result;
}

// --------------------------------------------------------------------------- //
// peers
// --------------------------------------------------------------------------- //

export async function createPeer(input: {
  name: string;
  description?: string;
  peer_type: "server" | "user";
  wg_public_key: string;
  owner_user_id?: string | null;
  dns_label?: string | null;
  zone_slug?: string | null;
  group_slugs: string[];
  tags: string[];
}): Promise<Result<Peer>> {
  const result = await run(() =>
    api.post<Peer>("/api/v1/peers", {
      ...input,
      owner_user_id: input.owner_user_id || null,
      dns_label: input.dns_label || null,
      zone_slug: input.zone_slug || null,
    }),
  );
  if (result.ok) refreshEverything();
  return result;
}

export async function updatePeer(
  id: string,
  patch: Partial<{
    name: string;
    description: string;
    state: PeerState;
    dns_label: string | null;
    zone_slug: string | null;
    group_slugs: string[];
    tags: string[];
  }>,
): Promise<Result<Peer>> {
  const result = await run(() => api.patch<Peer>(`/api/v1/peers/${id}`, patch));
  if (result.ok) refreshEverything();
  return result;
}

export async function deletePeer(id: string): Promise<Result<void>> {
  const result = await run(() => api.delete<void>(`/api/v1/peers/${id}`));
  if (result.ok) refreshEverything();
  return result;
}

/**
 * Generate an enrollment key. The plaintext comes back **once** — only its hash
 * is stored — so the caller has to show it before navigating away. Generating a
 * new one invalidates the previous key for that peer.
 */
export async function createEnrollmentKey(
  peerId: string,
  expiresAt: string | null,
): Promise<Result<EnrollmentKey>> {
  const result = await run(() =>
    api.post<EnrollmentKey>(`/api/v1/peers/${peerId}/enrollment-key`, {
      expires_at: expiresAt || null,
    }),
  );
  if (result.ok) refreshEverything();
  return result;
}

export async function revokeEnrollmentKey(peerId: string): Promise<Result<Peer>> {
  const result = await run(() =>
    api.delete<Peer>(`/api/v1/peers/${peerId}/enrollment-key`),
  );
  if (result.ok) refreshEverything();
  return result;
}

// --------------------------------------------------------------------------- //
// users
// --------------------------------------------------------------------------- //

export async function createUser(input: {
  username: string;
  password?: string;
  email?: string;
  display_name?: string;
  is_admin: boolean;
  group_slugs?: string[];
  external_idp_issuer?: string;
  external_idp_subject?: string;
}): Promise<Result<User>> {
  const result = await run(() =>
    api.post<User>("/api/v1/users", {
      username: input.username,
      password: input.password || null,
      email: input.email || null,
      display_name: input.display_name || null,
      is_admin: input.is_admin,
      group_slugs: input.group_slugs ?? [],
      external_idp_issuer: input.external_idp_issuer || null,
      external_idp_subject: input.external_idp_subject || null,
    }),
  );
  if (result.ok) revalidatePath("/users");
  return result;
}

export async function updateUser(
  id: string,
  patch: Partial<{
    is_active: boolean;
    is_admin: boolean;
    password: string;
    /** Replaces the whole membership, and signs the person out of every
     *  published service — their groups live inside the session cookie. */
    group_slugs: string[];
  }>,
): Promise<Result<User>> {
  const result = await run(() => api.patch<User>(`/api/v1/users/${id}`, patch));
  if (result.ok) {
    revalidatePath("/users");
    revalidatePath("/services");
  }
  return result;
}

export async function deleteUser(id: string): Promise<Result<void>> {
  const result = await run(() => api.delete<void>(`/api/v1/users/${id}`));
  if (result.ok) {
    revalidatePath("/users");
    revalidatePath("/peers");
  }
  return result;
}

/** Stores a secret but leaves TOTP off until `confirmTotp` succeeds. */
export async function provisionTotp(userId: string): Promise<Result<TotpProvision>> {
  return run(() => api.post<TotpProvision>(`/api/v1/users/${userId}/totp`, {}));
}

export async function confirmTotp(userId: string, code: string): Promise<Result<User>> {
  const result = await run(() =>
    api.post<User>(`/api/v1/users/${userId}/totp/confirm`, { code }),
  );
  if (result.ok) revalidatePath("/users");
  return result;
}

export async function disableTotp(userId: string): Promise<Result<User>> {
  const result = await run(() => api.delete<User>(`/api/v1/users/${userId}/totp`));
  if (result.ok) revalidatePath("/users");
  return result;
}

// --------------------------------------------------------------------------- //
// ACL rules
// --------------------------------------------------------------------------- //

export interface RuleInput {
  ref: string;
  name: string;
  priority: number;
  enabled: boolean;
  action: AclAction;
  src: AclEndpoint;
  dst: AclEndpoint;
  protocol: Protocol;
  dst_port_start: number | null;
  dst_port_end: number | null;
}

export async function createRule(input: RuleInput): Promise<Result<AclRule>> {
  const result = await run(() => api.post<AclRule>("/api/v1/acl-rules", input));
  if (result.ok) refreshEverything();
  return result;
}

export async function updateRule(
  id: string,
  patch: Partial<RuleInput>,
): Promise<Result<AclRule>> {
  const result = await run(() => api.patch<AclRule>(`/api/v1/acl-rules/${id}`, patch));
  if (result.ok) refreshEverything();
  return result;
}

export async function deleteRule(id: string): Promise<Result<void>> {
  const result = await run(() => api.delete<void>(`/api/v1/acl-rules/${id}`));
  if (result.ok) refreshEverything();
  return result;
}

/**
 * The non-secret half of a client configuration.
 *
 * **This is the only server call the generator makes, and it carries no key
 * material in either direction.** The private key is created in the browser by
 * `lib/wireguard.ts`, the file is assembled in the browser by `lib/wg-config.ts`,
 * and neither ever crosses this boundary. Adding a parameter here that took one
 * would undo the entire feature, so: don't.
 */
export async function getConfigProfile(
  peerId: string,
  options: { allowedIps?: AllowedIpsMode; dns?: boolean } = {},
): Promise<Result<ClientConfigProfile>> {
  const query = new URLSearchParams();
  if (options.allowedIps) query.set("allowed_ips", options.allowedIps);
  if (options.dns === false) query.set("dns", "false");
  const suffix = query.size > 0 ? `?${query}` : "";
  return run(() =>
    api.get<ClientConfigProfile>(`/api/v1/peers/${peerId}/config-profile${suffix}`),
  );
}

// --------------------------------------------------------------------------- //
// published services (Phase 7)
// --------------------------------------------------------------------------- //

/**
 * Create a service *and* the way in, in one request.
 *
 * Not a convenience: a listener with no authenticator that applies to it is
 * refused by the control plane, so a two-step creation could never succeed --
 * the first step would always come back 422.
 */
export async function createService(input: {
  slug: string;
  name: string;
  description?: string;
  kind: ServiceKind;
  exposure: ServiceExposure;
  upstream_peer_id: string | null;
  upstream_host: string;
  upstream_port: number;
  upstream_tls: boolean;
  upstream_tls_verify: boolean;
  authenticators: { kind: ServiceAuthKind; scope: ServiceScope; realm?: string }[];
  access: { kind: string; group_id?: string | null; cidr?: string | null; action: string }[];
}): Promise<Result<Service>> {
  const result = await run(() => api.post<Service>("/api/v1/services", input));
  if (result.ok) refreshEverything();
  return result;
}

export async function updateService(
  id: string,
  patch: Partial<{ name: string; description: string; enabled: boolean }>,
): Promise<Result<Service>> {
  const result = await run(() => api.patch<Service>(`/api/v1/services/${id}`, patch));
  if (result.ok) refreshEverything();
  return result;
}

export async function deleteService(id: string): Promise<Result<void>> {
  const result = await run(() => api.delete<void>(`/api/v1/services/${id}`));
  if (result.ok) refreshEverything();
  return result;
}

export async function addServiceAuth(
  serviceId: string,
  input: {
    kind: ServiceAuthKind;
    scope: ServiceScope;
    realm?: string;
    /** `foxguard_sso` only: membership of any one is required. */
    group_slugs?: string[];
    /** `foxguard_sso` only, ANDed with `group_slugs`. */
    require_admin?: boolean;
  },
): Promise<Result<Service>> {
  const result = await run(() =>
    api.post<Service>(`/api/v1/services/${serviceId}/auth`, input),
  );
  if (result.ok) refreshEverything();
  return result;
}

export async function removeServiceAuth(
  serviceId: string,
  authId: string,
): Promise<Result<Service>> {
  const result = await run(() =>
    api.delete<Service>(`/api/v1/services/${serviceId}/auth/${authId}`),
  );
  if (result.ok) refreshEverything();
  return result;
}

export async function addServiceAccess(
  serviceId: string,
  input: { kind: string; group_id?: string | null; cidr?: string | null; action: string },
): Promise<Result<Service>> {
  const result = await run(() =>
    api.post<Service>(`/api/v1/services/${serviceId}/access`, input),
  );
  if (result.ok) refreshEverything();
  return result;
}

export async function removeServiceAccess(
  serviceId: string,
  ruleId: string,
): Promise<Result<Service>> {
  const result = await run(() =>
    api.delete<Service>(`/api/v1/services/${serviceId}/access/${ruleId}`),
  );
  if (result.ok) refreshEverything();
  return result;
}

/** The plaintext comes back once and is never retrievable again. */
export async function createServiceToken(
  serviceId: string,
  input: { name: string },
): Promise<Result<ServiceTokenCreated>> {
  const result = await run(() =>
    api.post<ServiceTokenCreated>(`/api/v1/services/${serviceId}/tokens`, input),
  );
  if (result.ok) refreshEverything();
  return result;
}

export async function revokeServiceToken(
  serviceId: string,
  tokenId: string,
): Promise<Result<void>> {
  const result = await run(() =>
    api.delete<void>(`/api/v1/services/${serviceId}/tokens/${tokenId}`),
  );
  if (result.ok) refreshEverything();
  return result;
}

/** The password is generated, not chosen, and shown once. */
export async function createServiceAccount(
  serviceId: string,
  input: { username: string },
): Promise<Result<ServiceAccountCreated>> {
  const result = await run(() =>
    api.post<ServiceAccountCreated>(`/api/v1/services/${serviceId}/accounts`, input),
  );
  if (result.ok) refreshEverything();
  return result;
}

export async function deleteServiceAccount(
  serviceId: string,
  accountId: string,
): Promise<Result<void>> {
  const result = await run(() =>
    api.delete<void>(`/api/v1/services/${serviceId}/accounts/${accountId}`),
  );
  if (result.ok) refreshEverything();
  return result;
}

/**
 * End one browser session now.
 *
 * The cookie itself stays perfectly valid-looking -- its signature is fine and
 * it has not expired, which is exactly what makes the proxy fast. What stops it
 * is the session id landing in a map the proxy consults, pushed on the agent's
 * next poll without a reload.
 */
export async function revokeSsoSession(id: string): Promise<Result<void>> {
  const result = await run(() => api.delete<void>(`/api/v1/proxy/sso-sessions/${id}`));
  if (result.ok) refreshEverything();
  return result;
}
