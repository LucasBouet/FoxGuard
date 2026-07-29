import { PolicyForm } from "./policy-form";

export const dynamic = "force-dynamic";

export default function PoliciesPage() {
  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-lg font-semibold">Policies</h1>
        <p className="mt-1 text-sm text-ink-secondary">
          Version your ACLs in git and reapply them after a rebuild. An import
          that would produce an invalid nftables ruleset is rejected with the
          database untouched.
        </p>
      </div>
      <PolicyForm />
    </div>
  );
}
