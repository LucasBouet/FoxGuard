/**
 * Server-side API client.
 *
 * **The admin token never reaches the browser.** Every call here runs in a
 * server component or a server action, reads `FOXGUARD_ADMIN_API_TOKEN` from the
 * process environment, and returns plain data to the client. That is the whole
 * reason the dashboard is a Next.js app rather than a static SPA: a shared
 * bearer token handed to a browser is a shared bearer token in every extension,
 * devtools session and cached bundle on that machine.
 *
 * Nothing in `src/components` or any `"use client"` module may import this.
 */

import "server-only";

import { getSessionToken } from "./session";

const API_URL = process.env.FOXGUARD_API_URL ?? "http://127.0.0.1:8000";
const STATIC_TOKEN = process.env.FOXGUARD_ADMIN_API_TOKEN ?? "";

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly detail: string,
  ) {
    super(`${status}: ${detail}`);
  }
}

/**
 * Prefer the signed-in administrator's session over the shared token.
 *
 * Both are bearer credentials to the API, but only the session names a person,
 * and an audit entry that says "ada" is worth more than one that says
 * "admin-token". The static token stays as a fallback so a gateway without an
 * administrator account yet can still reach its own dashboard.
 */
async function credential(): Promise<string | null> {
  return (await getSessionToken()) ?? (STATIC_TOKEN || null);
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const token = await credential();
  const response = await fetch(`${API_URL}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...init.headers,
    },
    // Every screen shows live control-plane state; a cached peer list that says
    // a revoked laptop is still active is worse than a slow page.
    cache: "no-store",
  });

  if (!response.ok) {
    let detail = response.statusText;
    try {
      const body = await response.json();
      detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
    } catch {
      /* a non-JSON error body is not worth a second failure */
    }
    throw new ApiError(response.status, detail);
  }
  return response.status === 204 ? (undefined as T) : ((await response.json()) as T);
}

export const api = {
  get: <T>(path: string) => request<T>(path),
  post: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: "POST", body: body ? JSON.stringify(body) : undefined }),
  patch: <T>(path: string, body: unknown) =>
    request<T>(path, { method: "PATCH", body: JSON.stringify(body) }),
  delete: <T>(path: string) => request<T>(path, { method: "DELETE" }),
};

/** Fetch that renders an error panel instead of collapsing the whole page. */
export async function tryGet<T>(path: string): Promise<{ data: T | null; error: string | null }> {
  try {
    return { data: await api.get<T>(path), error: null };
  } catch (error) {
    const message =
      error instanceof ApiError
        ? `${error.status}: ${error.detail}`
        : `cannot reach the control plane at ${API_URL}`;
    return { data: null, error: message };
  }
}
