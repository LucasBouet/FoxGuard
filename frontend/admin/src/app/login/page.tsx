import { tryGet } from "@/lib/api";
import { staticTokenConfigured } from "@/lib/session";

import { LoginForm } from "./login-form";

export const dynamic = "force-dynamic";

export default async function LoginPage() {
  // A 501 here means admin SSO is not configured, which is the common case and
  // not an error worth showing — the password form covers it.
  const { data } = await tryGet<{ authorization_url: string }>("/api/v1/admin/oidc/start");

  return (
    <div className="mx-auto max-w-sm">
      <h1 className="text-lg font-semibold">Sign in</h1>
      <p className="mb-6 mt-1 text-sm text-ink-secondary">
        Administrator accounts are the same accounts device owners use — being an
        administrator is a flag on one, not a separate directory.
      </p>
      <div className="rounded-lg border border-hairline bg-surface p-5">
        <LoginForm
          staticTokenConfigured={staticTokenConfigured()}
          ssoAvailable={data !== null}
        />
      </div>
    </div>
  );
}
