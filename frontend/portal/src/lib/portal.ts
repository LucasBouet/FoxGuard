/**
 * The portal's API surface, called **from the browser**.
 *
 * Every request here travels the peer's own connection to the gateway, which is
 * the entire point: the API reads the source address off that connection and
 * resolves it to a peer. Relative URLs keep it same-origin, so there is no CORS
 * exemption on the one surface a quarantined peer can already reach — and no
 * opportunity for an intermediary to replace the address.
 */

export type PeerState =
  | "staging"
  | "quarantined"
  | "active"
  | "disabled"
  | "revoked";

export interface PortalStatus {
  peer_id: string;
  peer_name: string;
  peer_type: "server" | "user";
  state: PeerState;
  authenticated: boolean;
  username: string | null;
  auth_methods: ("local" | "oidc")[];
  totp_required: boolean;
  oidc_available: boolean;
  session_expires_at: string | null;
}

export interface LoginResult {
  peer_id: string;
  state: PeerState;
  username: string;
  auth_method: "local" | "oidc";
  group_slugs: string[];
  session_expires_at: string | null;
}

/**
 * Failures the portal must tell apart, because the right thing for the user to
 * do next differs in every case.
 */
export type PortalError =
  | { kind: "off-tunnel" }
  | { kind: "unknown-peer" }
  | { kind: "credentials" }
  | { kind: "throttled"; retryAfter: number }
  | { kind: "server"; detail: string }
  | { kind: "offline" };

export class PortalFailure extends Error {
  constructor(readonly info: PortalError) {
    super(info.kind);
  }
}

async function call<T>(path: string, init: RequestInit = {}): Promise<T> {
  let response: Response;
  try {
    response = await fetch(path, {
      ...init,
      headers: { "Content-Type": "application/json", ...init.headers },
      // The portal is reached over a tunnel whose reachability is the very
      // thing in question; a cached answer would be actively misleading.
      cache: "no-store",
    });
  } catch {
    throw new PortalFailure({ kind: "offline" });
  }

  if (response.ok) {
    return response.status === 204 ? (undefined as T) : ((await response.json()) as T);
  }

  if (response.status === 403) {
    // The API answers 403 identically for "not a tunnel address" and "no peer
    // holds this address" -- deliberately, so the endpoint cannot be used to
    // scan for live peers. The portal cannot tell them apart either, so it
    // explains both.
    throw new PortalFailure({ kind: "off-tunnel" });
  }
  if (response.status === 401) throw new PortalFailure({ kind: "credentials" });
  if (response.status === 429) {
    const header = response.headers.get("Retry-After");
    const retryAfter = header ? Number.parseInt(header, 10) : 60;
    throw new PortalFailure({
      kind: "throttled",
      retryAfter: Number.isFinite(retryAfter) ? retryAfter : 60,
    });
  }

  let detail = response.statusText;
  try {
    const body = await response.json();
    if (typeof body.detail === "string") detail = body.detail;
  } catch {
    /* a non-JSON error body is not worth a second failure */
  }
  throw new PortalFailure({ kind: "server", detail });
}

export const portal = {
  status: () => call<PortalStatus>("/api/v1/portal/status"),
  login: (username: string, password: string, totpCode?: string) =>
    call<LoginResult>("/api/v1/portal/login", {
      method: "POST",
      body: JSON.stringify({
        username,
        password,
        totp_code: totpCode?.trim() ? totpCode.trim() : null,
      }),
    }),
  logout: () => call<{ peer_id: string; state: PeerState }>("/api/v1/portal/logout", {
    method: "POST",
  }),
  oidcStart: () =>
    call<{ authorization_url: string; state: string }>("/api/v1/portal/oidc/start"),
};

export function describe(error: PortalError): { title: string; body: string } {
  switch (error.kind) {
    case "off-tunnel":
      return {
        title: "This device is not recognised",
        body:
          "The portal only answers connections coming through the WireGuard tunnel, from an address it has issued. Check that the tunnel is up, then reload.",
      };
    case "unknown-peer":
      return {
        title: "This device is not registered",
        body: "Ask an administrator to register this device before signing in.",
      };
    case "credentials":
      return {
        title: "Sign-in failed",
        body:
          "That username, password or code was not accepted for this device. Note the account must be the one this device is registered to.",
      };
    case "throttled":
      return {
        title: "Too many attempts",
        body: `Sign-in is paused on this device. Try again in about ${
          error.retryAfter < 60
            ? `${error.retryAfter} seconds`
            : `${Math.ceil(error.retryAfter / 60)} minutes`
        }.`,
      };
    case "offline":
      return {
        title: "Cannot reach the gateway",
        body: "The portal is not answering. Check that the WireGuard tunnel is connected.",
      };
    case "server":
      return { title: "Something went wrong", body: error.detail };
  }
}

export function formatExpiry(iso: string | null): string | null {
  if (!iso) return null;
  const seconds = Math.round((new Date(iso).getTime() - Date.now()) / 1000);
  if (seconds <= 0) return "expired";
  if (seconds < 3600) return `${Math.max(1, Math.round(seconds / 60))} minutes`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)} hours`;
  return `${Math.round(seconds / 86400)} days`;
}
