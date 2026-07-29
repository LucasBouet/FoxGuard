import { KillSwitchForm } from "./kill-switch-form";

export const dynamic = "force-dynamic";

export default function KillSwitchPage() {
  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-lg font-semibold">Kill switch</h1>
        <p className="mt-1 max-w-3xl text-sm text-ink-secondary">
          Cuts every peer at once, server peers included, in deliberate exception
          to their normal &ldquo;stable until the key is revoked&rdquo; rule.
          Because the quarantine drop is evaluated before the
          established/related accept, connections that are already open are cut
          too — not just new ones.
        </p>
        <p className="mt-2 max-w-3xl text-sm text-ink-secondary">
          Peers that are already <code className="font-mono">revoked</code> or{" "}
          <code className="font-mono">disabled</code> are left untouched: both
          are stricter than the targets here, and a kill switch must never widen
          anyone&rsquo;s access.
        </p>
      </div>
      <KillSwitchForm />
    </div>
  );
}
