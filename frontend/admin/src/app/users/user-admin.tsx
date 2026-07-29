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
} from "@/components/forms";
import {
  confirmTotp,
  createUser,
  deleteUser,
  disableTotp,
  provisionTotp,
  updateUser,
} from "@/lib/actions";
import type { Result } from "@/lib/actions";
import type { TotpProvision, User } from "@/lib/types";

export function CreateUser() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [email, setEmail] = useState("");
  const [isAdmin, setIsAdmin] = useState(false);
  const [useOidc, setUseOidc] = useState(false);
  const [issuer, setIssuer] = useState("");
  const [subject, setSubject] = useState("");
  const [result, setResult] = useState<Result<User> | null>(null);
  const [pending, start] = useTransition();

  function submit(event: React.FormEvent) {
    event.preventDefault();
    start(async () => {
      const response = await createUser({
        username,
        password: password || undefined,
        email: email || undefined,
        is_admin: isAdmin,
        external_idp_issuer: useOidc ? issuer : undefined,
        external_idp_subject: useOidc ? subject : undefined,
      });
      setResult(response);
      if (response.ok) {
        setUsername("");
        setPassword("");
        setEmail("");
        setSubject("");
      }
    });
  }

  return (
    <Disclosure label="New account">
      <form onSubmit={submit} className="space-y-3">
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="Username">
            <Input
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              required
              maxLength={64}
              pattern="^[A-Za-z0-9._@-]{1,64}$"
              placeholder="ada"
            />
          </Field>
          <Field label="Email (optional)">
            <Input
              type="email"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
            />
          </Field>
        </div>

        <Field
          label="Password"
          hint="At least 12 characters. Hashed with argon2id; leave blank for an OIDC-only account."
        >
          <Input
            type="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            minLength={12}
            maxLength={256}
            autoComplete="new-password"
          />
        </Field>

        <Check
          label="Link to an identity provider"
          hint="An account may have a password, an IdP binding, or both — but it needs at least one."
          checked={useOidc}
          onChange={setUseOidc}
        />

        {useOidc && (
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="Issuer" hint="The `iss` claim your IdP sends.">
              <Input
                value={issuer}
                onChange={(event) => setIssuer(event.target.value)}
                required
                placeholder="https://authentik.example.lan/application/o/foxguard"
              />
            </Field>
            <Field label="Subject" hint="The `sub` claim for this person.">
              <Input
                value={subject}
                onChange={(event) => setSubject(event.target.value)}
                required
              />
            </Field>
          </div>
        )}

        <Check
          label="Administrator"
          hint="Recorded on the account. Admin API access is a shared token today, so this is not yet an authorisation boundary."
          checked={isAdmin}
          onChange={setIsAdmin}
        />

        <ResultNotice result={result} />
        {result?.ok && <Notice kind="good">Account created.</Notice>}

        <Button type="submit" variant="primary" disabled={pending}>
          {pending ? "Creating…" : "Create account"}
        </Button>
      </form>
    </Disclosure>
  );
}

export function UserActions({ user }: { user: User }) {
  const [result, setResult] = useState<Result<unknown> | null>(null);
  const [provisioned, setProvisioned] = useState<TotpProvision | null>(null);
  const [code, setCode] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [open, setOpen] = useState(false);
  const [pending, start] = useTransition();

  const canTotp = user.auth_methods.includes("local");

  return (
    <div className="space-y-2">
      <div className="flex justify-end">
        <Button variant="quiet" onClick={() => setOpen(!open)}>
          {open ? "Hide" : "Manage"}
        </Button>
      </div>

      {open && (
        <div className="space-y-3 rounded-md border border-hairline bg-page p-3 text-left">
          <div className="flex flex-wrap gap-1">
            <Button
              disabled={pending}
              onClick={() =>
                start(async () =>
                  setResult(await updateUser(user.id, { is_active: !user.is_active })),
                )
              }
            >
              {user.is_active ? "Deactivate" : "Reactivate"}
            </Button>
            <Button
              disabled={pending}
              onClick={() =>
                start(async () =>
                  setResult(await updateUser(user.id, { is_admin: !user.is_admin })),
                )
              }
            >
              {user.is_admin ? "Remove admin" : "Make admin"}
            </Button>
          </div>

          {canTotp && (
            <div className="space-y-2 border-t border-hairline pt-3">
              <p className="text-xs text-ink-secondary">
                Reset the password. Any admin session this account holds is
                revoked, and their devices need the new password at the portal.
              </p>
              <div className="flex flex-wrap items-end gap-2">
                <Field label="New password" hint="At least 12 characters.">
                  <Input
                    type="password"
                    value={newPassword}
                    onChange={(event) => setNewPassword(event.target.value)}
                    minLength={12}
                    maxLength={256}
                    autoComplete="new-password"
                  />
                </Field>
                <Button
                  disabled={pending || newPassword.length < 12}
                  onClick={() =>
                    start(async () => {
                      const response = await updateUser(user.id, {
                        password: newPassword,
                      });
                      setResult(response);
                      if (response.ok) setNewPassword("");
                    })
                  }
                >
                  Set password
                </Button>
              </div>
            </div>
          )}

          <div className="space-y-2 border-t border-hairline pt-3">
            <p className="text-xs text-ink-secondary">
              Two-factor authentication{" "}
              {canTotp
                ? "— protects this account's password."
                : "— unavailable: this account has no password, so its second factor is the IdP's job."}
            </p>

            {canTotp && !user.totp_enabled && (
              <Button
                disabled={pending}
                onClick={() =>
                  start(async () => {
                    const response = await provisionTotp(user.id);
                    setResult(response);
                    if (response.ok) setProvisioned(response.data);
                  })
                }
              >
                Provision TOTP
              </Button>
            )}

            {provisioned && !user.totp_enabled && (
              <SecretOnce
                title="Copy this secret now"
                value={provisioned.secret}
                note="Shown once. Add it to the authenticator app, then confirm with a code below — TOTP is not enforced until you do, so a failed scan cannot lock anyone out."
              >
                <div className="mt-3 flex flex-wrap items-end gap-2">
                  <Field label="Code from the app">
                    <Input
                      value={code}
                      onChange={(event) => setCode(event.target.value)}
                      inputMode="numeric"
                      maxLength={10}
                      className="font-mono"
                      placeholder="123456"
                    />
                  </Field>
                  <Button
                    disabled={pending || code.length < 6}
                    onClick={() =>
                      start(async () => {
                        const response = await confirmTotp(user.id, code);
                        setResult(response);
                        if (response.ok) {
                          setProvisioned(null);
                          setCode("");
                        }
                      })
                    }
                  >
                    Confirm and enable
                  </Button>
                </div>
                <p className="mt-2 text-xs text-ink-secondary">
                  The confirming code is spent, so their first sign-in needs the
                  next one — up to 30 seconds later.
                </p>
              </SecretOnce>
            )}

            {user.totp_enabled && (
              <ConfirmButton
                label="Disable TOTP"
                confirmLabel="Disable and destroy the secret"
                warning="They will need to re-scan a new secret to turn it back on."
                onConfirm={async () => setResult(await disableTotp(user.id))}
              />
            )}
          </div>

          <div className="border-t border-hairline pt-3">
            <ConfirmButton
              label="Delete account"
              confirmLabel="Delete"
              warning="Peers owned by this account lose their binding and can no longer sign in."
              onConfirm={async () => setResult(await deleteUser(user.id))}
            />
          </div>

          <ResultNotice result={result} />
        </div>
      )}
    </div>
  );
}
