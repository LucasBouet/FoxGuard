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
