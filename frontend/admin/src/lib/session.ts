import "server-only";

import { cookies } from "next/headers";

/**
 * Where the administrator's session token lives.
 *
 * In an **httpOnly cookie on the dashboard's own origin**, never in client-side
 * JavaScript and never in `localStorage`. The browser cannot read it, so an XSS
 * in a dashboard page cannot walk off with a credential that controls the
 * network; it is attached to API calls by the server, in `src/lib/api.ts`.
 *
 * The API itself takes the token as a plain `Authorization: Bearer`, so it needs
 * no cookie handling at all — the cookie is purely how *this* app remembers it
 * between requests.
 */

export const SESSION_COOKIE = "foxguard_admin";

export async function getSessionToken(): Promise<string | null> {
  return (await cookies()).get(SESSION_COOKIE)?.value ?? null;
}

export async function setSessionToken(token: string, expiresAt: string): Promise<void> {
  (await cookies()).set(SESSION_COOKIE, token, {
    httpOnly: true,
    sameSite: "lax",
    path: "/",
    // Set only over HTTPS in production. The dashboard is reached over the
    // tunnel, so plain HTTP is a deliberate, documented option for a homelab.
    secure: process.env.NODE_ENV === "production" && process.env.FOXGUARD_INSECURE_COOKIE !== "true",
    expires: new Date(expiresAt),
  });
}

export async function clearSessionToken(): Promise<void> {
  (await cookies()).delete(SESSION_COOKIE);
}

/**
 * True when the deployment still relies on the shared static token.
 *
 * Kept as an escape hatch so a gateway with no administrator account yet is not
 * locked out of its own dashboard — see the bootstrap note in
 * `docs/deployment.md`. It is reported in the UI, because "every action is
 * attributed to a shared secret" is a state an operator should be able to see.
 */
export function staticTokenConfigured(): boolean {
  return Boolean(process.env.FOXGUARD_ADMIN_API_TOKEN);
}
