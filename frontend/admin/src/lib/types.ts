/**
 * Shapes returned by the control plane.
 *
 * Hand-written rather than generated, and deliberately partial: the dashboard
 * reads a subset of each response, and a generated client would couple every
 * screen to every field. `frontend/README.md` explains how to generate a full
 * client from `/openapi.json` if that trade stops paying off.
 */

export type PeerState =
  | "staging"
  | "quarantined"
  | "active"
  | "disabled"
  | "revoked";
export type PeerType = "server" | "user";
export type DnsRecordKind = "A" | "AAAA" | "CNAME";
export type ResolverMode = "forward" | "split";
export type AclAction = "accept" | "drop" | "reject";
export type AuthMethod = "local" | "oidc";

export interface Peer {
  id: string;
  name: string;
  description: string | null;
  peer_type: PeerType;
  state: PeerState;
  wg_public_key: string;
  tunnel_ip: string | null;
  tunnel_ip6: string | null;
  owner_user_id: string | null;
  dns_label: string | null;
  zone_slug: string | null;
  group_slugs: string[];
  tags: string[];
  enrolled_at: string | null;
  last_handshake_at: string | null;
  last_authenticated_at: string | null;
  created_at: string;
}

export interface Group {
  id: string;
  slug: string;
  name: string;
  description: string | null;
  kind: "group" | "zone";
  internet_exit: boolean;
  session_lifetime_seconds: number | null;
}

/**
 * A network zone: the peers assigned to it plus the networks routed inside it.
 *
 * Distinct from `Group` in the UI as well as in the API, because the two answer
 * different questions -- a group is a set of devices, a zone is a region of the
 * address space, and a peer sits in exactly one of them.
 */
export interface Zone {
  id: string;
  slug: string;
  name: string;
  description: string | null;
  internet_exit: boolean;
  intra_zone: boolean;
  session_lifetime_seconds: number | null;
  routes: ZoneRoute[];
  peer_count: number;
  created_at: string;
  updated_at: string;
}

export interface ZoneRoute {
  id: string;
  zone_id: string;
  cidr: string;
  /** The peer that carries it. Null means the gateway reaches it directly. */
  via_peer_id: string | null;
  description: string | null;
  enabled: boolean;
}

export interface DnsRecord {
  id: string;
  name: string;
  kind: DnsRecordKind;
  value: string;
  description: string | null;
  enabled: boolean;
}

export interface DnsZone {
  enabled: boolean;
  zone: string;
  mode: ResolverMode;
  listen_addresses: string[];
  upstreams: string[];
  digest: string | null;
  hosts: string | null;
  conf: string | null;
  /** Populated instead of the artefacts when the state cannot be rendered. */
  errors: string[];
  /** Served-nothing but harmless: an alias whose target was revoked. */
  warnings: string[];
}

export interface Tag {
  id: string;
  name: string;
  color: string | null;
}

export interface AuditEntry {
  id: string;
  created_at: string;
  actor_type: string;
  actor_label: string | null;
  action: string;
  object_type: string | null;
  object_id: string | null;
  source_ip: string | null;
  detail: Record<string, unknown>;
}

export interface RulesetHealth {
  digest: string;
  applied_digest: string | null;
  status: string | null;
  applied_at: string | null;
  in_sync: boolean;
}

export interface Dashboard {
  peers_total: number;
  peers_by_state: Partial<Record<PeerState, number>>;
  peers_by_type: Partial<Record<PeerType, number>>;
  active_sessions: number;
  groups: number;
  acl_rules: number;
  acl_rules_disabled: number;
  users: number;
  ruleset: RulesetHealth;
  recent_audit: AuditEntry[];
}

export interface MatrixCell {
  src: string;
  dst: string;
  action: AclAction;
  rule_refs: string[];
}

export interface PolicyMatrix {
  sources: string[];
  destinations: string[];
  cells: MatrixCell[];
}

export interface PeerSession {
  id: string;
  peer_id: string;
  peer_name: string;
  user_id: string;
  username: string;
  auth_method: AuthMethod;
  authenticated_at: string;
  last_authenticated_at: string;
  expires_at: string | null;
  seconds_remaining: number | null;
  source_ip: string | null;
}

export interface PolicyDiff {
  dry_run: boolean;
  applied: boolean;
  summary: string;
  groups_created: string[];
  groups_updated: Record<string, unknown>[];
  groups_deleted: string[];
  rules_created: string[];
  rules_updated: Record<string, unknown>[];
  rules_deleted: string[];
  ruleset_digest: string | null;
}

export interface AffectedPeer {
  peer_id: string;
  name: string;
  peer_type: PeerType;
  previous_state: PeerState;
  state: PeerState;
}

export interface KillSwitchResult {
  mode: "quarantine" | "lockdown";
  affected: AffectedPeer[];
  sessions_revoked: number;
  regenerated: boolean;
}

export interface AdminWhoAmI {
  user_id: string | null;
  username: string;
  display_name: string | null;
  totp_enabled: boolean;
  /** "session" for a signed-in person, "token" for the shared machine credential. */
  via: "session" | "token";
}

export interface AdminLoginResponse {
  token: string;
  expires_at: string;
  user: AdminWhoAmI;
}

export interface AdminSession {
  id: string;
  user_id: string;
  username: string;
  created_at: string;
  last_seen_at: string;
  expires_at: string;
  source_ip: string | null;
  user_agent: string | null;
  /** The session making the request, so the UI can warn before self-revoking. */
  current: boolean;
}

export interface User {
  id: string;
  username: string;
  email: string | null;
  display_name: string | null;
  is_admin: boolean;
  is_active: boolean;
  totp_enabled: boolean;
  last_login_at: string | null;
  created_at: string;
  auth_methods: AuthMethod[];
  /**
   * Read by SSO on published services and nothing else. A person's group grants
   * no network access — that comes from their devices' own membership.
   */
  group_slugs: string[];
}

export type EndpointKind = "any" | "group" | "zone" | "cidr";
export type Protocol = "any" | "tcp" | "udp" | "icmp";

export interface AclEndpoint {
  kind: EndpointKind;
  group_slug: string | null;
  zone_slug: string | null;
  cidr: string | null;
}

export interface AclRule {
  id: string;
  ref: string;
  name: string;
  description: string | null;
  priority: number;
  enabled: boolean;
  action: AclAction;
  src: AclEndpoint;
  dst: AclEndpoint;
  protocol: Protocol;
  dst_port_start: number | null;
  dst_port_end: number | null;
}

/** Returned once, at generation. Only its hash is stored. */
export interface EnrollmentKey {
  peer_id: string;
  enrollment_key: string;
  expires_at: string | null;
}

/** Also returned once. `enabled` stays false until a code is confirmed. */
export interface TotpProvision {
  secret: string;
  provisioning_uri: string;
  enabled: boolean;
}

/**
 * The non-secret half of a WireGuard client configuration.
 *
 * `complete` is false when the deployment has not been told its own public key
 * or endpoint. The generator refuses to produce a file in that state, and shows
 * the warnings instead — they name the environment variable to set.
 */
export type AllowedIpsMode = "tunnel" | "zone" | "routed" | "full";

export interface ClientConfigProfile {
  peer_id: string;
  peer_name: string;
  peer_state: PeerState;
  fqdn: string | null;
  addresses: string[];
  dns: string[];
  mtu: number | null;
  server_public_key: string | null;
  endpoint: string | null;
  allowed_ips: string[];
  persistent_keepalive: number;
  allowed_ips_mode: AllowedIpsMode;
  excluded_routes: string[];
  warnings: string[];
  complete: boolean;
}

// --------------------------------------------------------------------------- //
// published services (Phase 7)
// --------------------------------------------------------------------------- //

export type ServiceKind = "http" | "tcp";
export type ServiceExposure = "internal" | "external" | "both";
export type ServiceScope = "internal" | "external" | "both";
export type ServiceAuthKind =
  | "peer_identity"
  | "bearer"
  | "basic"
  | "foxguard_sso"
  | "mtls";
export type ServiceFilterKind =
  | "ip_allow"
  | "ip_deny"
  | "geo_allow"
  | "geo_deny"
  | "rate_limit"
  | "waf"
  | "crowdsec";

export interface ServiceAuth {
  id: string;
  kind: ServiceAuthKind;
  scope: ServiceScope;
  enabled: boolean;
  priority: number;
  realm: string | null;
  /** `foxguard_sso` only: membership of any one of these is required. Empty
   *  means any account that can sign in. */
  group_slugs: string[];
  /** `foxguard_sso` only, and ANDed with `group_slugs`. */
  require_admin: boolean;
  created_at: string;
}

export interface ServiceFilter {
  id: string;
  kind: ServiceFilterKind;
  scope: ServiceScope;
  enabled: boolean;
  priority: number;
  values: string[];
  rate: number | null;
  period_seconds: number | null;
  created_at: string;
}

export interface ServiceAccess {
  id: string;
  action: "accept" | "drop" | "reject";
  kind: "any" | "group" | "cidr" | "zone";
  group_id: string | null;
  group_slug: string | null;
  cidr: string | null;
  priority: number;
  created_at: string;
}

export interface Service {
  id: string;
  slug: string;
  name: string;
  description: string | null;
  enabled: boolean;
  kind: ServiceKind;
  exposure: ServiceExposure;
  upstream_peer_id: string | null;
  upstream_peer_name: string | null;
  upstream_host: string;
  upstream_port: number;
  upstream_tls: boolean;
  upstream_tls_verify: boolean;
  internal_hostname: string | null;
  external_hostname: string | null;
  listen_port: number | null;
  sni_hostname: string | null;
  health_check: boolean;
  health_check_interval: number;
  /**
   * Which listeners the service currently has. Differs from `exposure` when the
   * upstream peer is not active -- a peer going down takes the internal door
   * with it and leaves the external one answering the 503 page.
   */
  active_doors: ServiceExposure | null;
  authenticators: ServiceAuth[];
  filters: ServiceFilter[];
  access: ServiceAccess[];
  token_count: number;
  account_count: number;
  created_at: string;
  updated_at: string;
}

export interface ImplicitPath {
  service: string;
  source: string;
  destination: string;
  peer: string | null;
  protocol: string;
  port: number;
  enforced_by: string;
}

export interface ProxyStatus {
  enabled: boolean;
  domain: string | null;
  internal_binds: string[];
  external_binds: string[];
  service_count: number;
  digest: string | null;
  config: string | null;
  files: Record<string, string>;
  implicit_paths: ImplicitPath[];
  warnings: string[];
}

export interface ServiceToken {
  id: string;
  name: string;
  prefix: string;
  expires_at: string | null;
  revoked_at: string | null;
  created_at: string;
}

/** Only ever returned once, by the creating request. */
export interface ServiceTokenCreated extends ServiceToken {
  token: string;
}

export interface ServiceAccount {
  id: string;
  username: string;
  revoked_at: string | null;
  created_at: string;
}

export interface ServiceAccountCreated extends ServiceAccount {
  password: string;
}

export interface SsoSession {
  id: string;
  username: string | null;
  source_ip: string | null;
  user_agent: string | null;
  expires_at: string;
  created_at: string;
}
