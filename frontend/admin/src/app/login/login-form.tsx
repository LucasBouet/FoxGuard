"use client";

import { useRouter } from "next/navigation";
import { useState, useTransition } from "react";

import { Button, Field, Input, Notice } from "@/components/forms";
import { signIn, startAdminSso } from "@/lib/actions";

export function LoginForm({
  staticTokenConfigured,
  ssoAvailable,
}: {
  staticTokenConfigured: boolean;
  ssoAvailable: boolean;
}) {
  const router = useRouter();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [pending, start] = useTransition();

  function submit(event: React.FormEvent) {
    event.preventDefault();
    setError(null);
    start(async () => {
      const result = await signIn(username, password, totp);
      if (result.ok) {
        router.push("/");
        router.refresh();
      } else {
        setError(result.error);
        setPassword("");
        setTotp("");
      }
    });
  }

  function sso() {
    setError(null);
    start(async () => {
      const result = await startAdminSso();
      if (result.ok) {
        window.location.href = result.data.authorization_url;
      } else {
        setError(result.error);
      }
    });
  }

  return (
    <form onSubmit={submit} className="space-y-3">
      {ssoAvailable && (
        <>
          <Button
            type="button"
            onClick={sso}
            disabled={pending}
            className="w-full"
          >
            Continue with single sign-on
          </Button>
          <p className="text-center text-xs text-ink-muted">
            or sign in with your password
          </p>
        </>
      )}
      <Field label="Username">
        <Input
          value={username}
          onChange={(event) => setUsername(event.target.value)}
          autoComplete="username"
          required
          autoFocus
        />
      </Field>
      <Field label="Password">
        <Input
          type="password"
          value={password}
          onChange={(event) => setPassword(event.target.value)}
          autoComplete="current-password"
          required
        />
      </Field>
      <Field
        label="Authenticator code"
        hint="Only if this account has two-factor authentication enabled."
      >
        <Input
          value={totp}
          onChange={(event) => setTotp(event.target.value)}
          inputMode="numeric"
          autoComplete="one-time-code"
          maxLength={10}
          className="font-mono tracking-widest"
          placeholder="123456"
        />
      </Field>

      {error && (
        <Notice kind="error">
          {/* The API answers every failure identically -- wrong password, no such
              account, not an administrator -- so there is nothing more specific
              to show, and that is deliberate. */}
          Sign-in failed. Check the username, password and code.
        </Notice>
      )}

      <Button type="submit" variant="primary" disabled={pending} className="w-full">
        {pending ? "Signing in…" : "Sign in"}
      </Button>

      {staticTokenConfigured && (
        <p className="pt-2 text-xs text-ink-muted">
          A shared admin token is configured, so the dashboard still works without
          signing in — but every action it takes is recorded as{" "}
          <code className="font-mono">admin-token</code> rather than as a person.
        </p>
      )}
    </form>
  );
}
