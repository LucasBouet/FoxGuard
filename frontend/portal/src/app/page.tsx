"use client";

import { useCallback, useEffect, useState } from "react";

import {
  PortalFailure,
  type LoginResult,
  type PortalError,
  type PortalStatus,
  describe,
  formatExpiry,
  portal,
} from "@/lib/portal";

/**
 * The whole portal is one screen with three states: still loading, signed in,
 * or a sign-in form. There is no routing and no session token — what
 * authenticating buys is *network access*, held in the gateway's nftables
 * ruleset, so "am I signed in" is answered by asking the gateway, never by
 * reading something this page stored.
 */
export default function PortalPage() {
  const [status, setStatus] = useState<PortalStatus | null>(null);
  const [fatal, setFatal] = useState<PortalError | null>(null);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      setStatus(await portal.status());
      setFatal(null);
    } catch (error) {
      setFatal(error instanceof PortalFailure ? error.info : { kind: "offline" });
      setStatus(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  return (
    <main>
      <header className="mb-6">
        <h1 className="text-xl font-semibold">Network access</h1>
        {status && (
          <p className="mt-1 text-sm text-ink-secondary">
            This device is registered as{" "}
            <span className="font-medium text-ink">{status.peer_name}</span>.
          </p>
        )}
      </header>

      {loading && <Panel>Checking this device…</Panel>}

      {!loading && fatal && <Problem error={fatal} onRetry={refresh} />}

      {!loading && !fatal && status && (
        <SignedState status={status} onChange={refresh} />
      )}

      <footer className="mt-8 text-xs text-ink-muted">
        Foxguard · you are seeing this page because it is the only thing this
        device can reach until it signs in.
      </footer>
    </main>
  );
}

function Panel({ children }: { children: React.ReactNode }) {
  return (
    <div className="rounded-lg border border-hairline bg-surface p-5 text-sm text-ink-secondary">
      {children}
    </div>
  );
}

function Dot({ className }: { className: string }) {
  return <span className={`inline-block h-2 w-2 shrink-0 rounded-full ${className}`} />;
}

function Problem({
  error,
  onRetry,
}: {
  error: PortalError;
  onRetry: () => void;
}) {
  const { title, body } = describe(error);
  return (
    <div className="rounded-lg border border-hairline bg-surface p-5">
      <p className="flex items-center gap-2 font-medium">
        <Dot className="bg-status-critical" />
        {title}
      </p>
      <p className="mt-2 text-sm text-ink-secondary">{body}</p>
      <button
        type="button"
        onClick={onRetry}
        className="mt-4 rounded-md border border-hairline px-3 py-1.5 text-sm font-medium hover:bg-page"
      >
        Try again
      </button>
    </div>
  );
}

function SignedState({
  status,
  onChange,
}: {
  status: PortalStatus;
  onChange: () => void;
}) {
  if (status.peer_type === "server") {
    // Server peers present an enrollment key from their provisioning script;
    // there is no human flow to offer them.
    return (
      <Panel>
        This device is registered as a service, not a person. It authenticates
        with its enrollment key, so there is nothing to sign in to here.
      </Panel>
    );
  }

  if (status.authenticated) {
    return <SignedIn status={status} onChange={onChange} />;
  }

  if (status.state === "disabled" || status.state === "revoked") {
    // Deliberately vague about which: the portal tells whoever holds the device
    // what to do, not what an administrator decided.
    return (
      <Panel>
        This device cannot sign in. Ask an administrator to restore its access.
      </Panel>
    );
  }

  return <SignInForm status={status} onSignedIn={onChange} />;
}

function SignedIn({
  status,
  onChange,
}: {
  status: PortalStatus;
  onChange: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<PortalError | null>(null);
  const remaining = formatExpiry(status.session_expires_at);

  async function signOut() {
    setBusy(true);
    setError(null);
    try {
      await portal.logout();
      onChange();
    } catch (caught) {
      setError(caught instanceof PortalFailure ? caught.info : { kind: "offline" });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="rounded-lg border border-hairline bg-surface p-5">
      <p className="flex items-center gap-2 font-medium">
        <Dot className="bg-status-good" />
        Connected
      </p>
      <p className="mt-2 text-sm text-ink-secondary">
        Signed in as <span className="font-medium text-ink">{status.username}</span>.
        {remaining && (
          <>
            {" "}
            This session ends in about{" "}
            <span className="font-medium text-ink">{remaining}</span>, after which
            you will need to sign in again.
          </>
        )}
      </p>

      {error && (
        <p className="mt-3 flex items-start gap-2 text-sm">
          <Dot className="mt-1.5 bg-status-critical" />
          <span>{describe(error).body}</span>
        </p>
      )}

      <button
        type="button"
        onClick={signOut}
        disabled={busy}
        className="mt-4 rounded-md border border-hairline px-3 py-1.5 text-sm font-medium hover:bg-page disabled:opacity-50"
      >
        {busy ? "Signing out…" : "Sign out"}
      </button>
      <p className="mt-2 text-xs text-ink-muted">
        Signing out cuts this device&rsquo;s access immediately, including
        connections that are already open.
      </p>
    </div>
  );
}

function SignInForm({
  status,
  onSignedIn,
}: {
  status: PortalStatus;
  onSignedIn: () => void;
}) {
  // The device is bound to one account, and the API refuses any other. Showing
  // it saves the user guessing; it is not a disclosure, since the peer already
  // proved possession of its key just by reaching this page.
  const [username, setUsername] = useState(status.username ?? "");
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  const [error, setError] = useState<PortalError | null>(null);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<LoginResult | null>(null);

  const localAvailable = status.auth_methods.includes("local");

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      setResult(await portal.login(username, password, totp));
      setPassword("");
      setTotp("");
      onSignedIn();
    } catch (caught) {
      setError(caught instanceof PortalFailure ? caught.info : { kind: "offline" });
      setPassword("");
      setTotp("");
    } finally {
      setBusy(false);
    }
  }

  async function startSso() {
    setBusy(true);
    setError(null);
    try {
      const { authorization_url } = await portal.oidcStart();
      window.location.href = authorization_url;
    } catch (caught) {
      setError(caught instanceof PortalFailure ? caught.info : { kind: "offline" });
      setBusy(false);
    }
  }

  if (result) return null; // onSignedIn re-renders the parent into SignedIn

  return (
    <div className="rounded-lg border border-hairline bg-surface p-5">
      <p className="flex items-center gap-2 font-medium">
        <Dot className="bg-status-warning" />
        Not connected
      </p>
      <p className="mt-2 text-sm text-ink-secondary">
        Sign in to reach the network. Until then this device can only see this
        page.
      </p>

      {status.oidc_available && (
        <>
          <button
            type="button"
            onClick={startSso}
            disabled={busy}
            className="mt-4 w-full rounded-md border border-hairline bg-page px-3 py-2 text-sm font-medium hover:opacity-90 disabled:opacity-50"
          >
            Continue with single sign-on
          </button>
          {localAvailable && (
            <p className="my-4 text-center text-xs text-ink-muted">
              or sign in with your password
            </p>
          )}
        </>
      )}

      {localAvailable && (
        <form onSubmit={submit} className="mt-4 space-y-3">
          <label className="block text-sm">
            <span className="text-ink-secondary">Username</span>
            <input
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              autoComplete="username"
              required
              className="mt-1 w-full rounded-md border border-hairline bg-page px-3 py-2 text-ink"
            />
          </label>

          <label className="block text-sm">
            <span className="text-ink-secondary">Password</span>
            <input
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              autoComplete="current-password"
              required
              autoFocus
              className="mt-1 w-full rounded-md border border-hairline bg-page px-3 py-2 text-ink"
            />
          </label>

          {status.totp_required && (
            <label className="block text-sm">
              <span className="text-ink-secondary">Authenticator code</span>
              <input
                value={totp}
                onChange={(event) => setTotp(event.target.value)}
                inputMode="numeric"
                autoComplete="one-time-code"
                maxLength={10}
                required
                placeholder="123456"
                className="mt-1 w-full rounded-md border border-hairline bg-page px-3 py-2 font-mono tracking-widest text-ink"
              />
              <span className="mt-1 block text-xs text-ink-muted">
                Each code works once. If it is rejected, wait for the next one.
              </span>
            </label>
          )}

          {error && (
            <p className="flex items-start gap-2 text-sm">
              <Dot className="mt-1.5 bg-status-critical" />
              <span>
                <span className="font-medium">{describe(error).title}. </span>
                <span className="text-ink-secondary">{describe(error).body}</span>
              </span>
            </p>
          )}

          <button
            type="submit"
            disabled={busy || error?.kind === "throttled"}
            className="w-full rounded-md border border-hairline bg-page px-3 py-2 text-sm font-semibold disabled:opacity-50"
          >
            {busy ? "Signing in…" : "Sign in"}
          </button>
        </form>
      )}

      {!localAvailable && !status.oidc_available && (
        <p className="mt-4 text-sm text-ink-secondary">
          No sign-in method is configured for this device&rsquo;s account. Ask an
          administrator.
        </p>
      )}
    </div>
  );
}
