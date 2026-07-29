"use client";

import { useState, useTransition } from "react";

import { Card, Dot } from "@/components/ui";
import { exportPolicies, importPolicies } from "@/lib/actions";
import type { PolicyDiff } from "@/lib/types";

/**
 * Import is a two-step flow on purpose: you cannot apply a document you have
 * not previewed. `applied` is only enabled once a dry run has succeeded for the
 * exact text currently in the box — editing it clears the preview, so the diff
 * on screen always describes what the button would do.
 */
export function PolicyForm() {
  const [document, setDocument] = useState("");
  const [prune, setPrune] = useState(false);
  const [diff, setDiff] = useState<PolicyDiff | null>(null);
  const [previewed, setPreviewed] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();

  const canApply = previewed !== null && previewed === document && diff !== null;

  function preview() {
    setError(null);
    startTransition(async () => {
      const result = await importPolicies(document, true, prune);
      if (result.ok) {
        setDiff(result.data);
        setPreviewed(document);
      } else {
        setError(result.error);
        setDiff(null);
        setPreviewed(null);
      }
    });
  }

  function apply() {
    setError(null);
    startTransition(async () => {
      const result = await importPolicies(document, false, prune);
      if (result.ok) {
        setDiff(result.data);
        setPreviewed(null);
      } else {
        setError(result.error);
      }
    });
  }

  function download() {
    startTransition(async () => {
      const result = await exportPolicies();
      if (!result.ok) {
        setError(result.error);
        return;
      }
      const text = JSON.stringify(result.data, null, 2);
      const url = URL.createObjectURL(new Blob([text], { type: "application/json" }));
      const anchor = window.document.createElement("a");
      anchor.href = url;
      anchor.download = "policies.json";
      anchor.click();
      URL.revokeObjectURL(url);
    });
  }

  return (
    <div className="space-y-4">
      <Card
        title="Export"
        description="The document references groups by slug and rules by ref, never by UUID, so it survives a gateway rebuild. Keep it in git."
      >
        <button
          type="button"
          onClick={download}
          disabled={pending}
          className="rounded-md border border-hairline px-3 py-1.5 text-sm font-medium hover:bg-page disabled:opacity-50"
        >
          Download policies.json
        </button>
      </Card>

      <Card
        title="Import"
        description="Preview first. The dry run executes the real import inside a transaction and rolls it back, so what you see is what applying would do."
      >
        <textarea
          value={document}
          onChange={(event) => {
            setDocument(event.target.value);
            setDiff(null);
            setPreviewed(null);
          }}
          rows={12}
          spellCheck={false}
          placeholder='{"version": 1, "groups": [], "acl_rules": []}'
          className="w-full rounded-md border border-hairline bg-page p-3 font-mono text-xs text-ink"
        />

        <label className="mt-3 flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={prune}
            onChange={(event) => {
              setPrune(event.target.checked);
              setDiff(null);
              setPreviewed(null);
            }}
          />
          <span>
            Prune — delete groups and rules absent from the document
            <span className="text-ink-secondary"> (full sync, not just create/update)</span>
          </span>
        </label>

        <div className="mt-4 flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={preview}
            disabled={pending || document.trim() === ""}
            className="rounded-md border border-hairline px-3 py-1.5 text-sm font-medium hover:bg-page disabled:opacity-50"
          >
            {pending ? "Working…" : "Preview diff"}
          </button>
          <button
            type="button"
            onClick={apply}
            disabled={pending || !canApply}
            className="rounded-md border border-hairline bg-page px-3 py-1.5 text-sm font-medium disabled:opacity-40"
            title={canApply ? undefined : "Preview the document first"}
          >
            Apply
          </button>
          {previewed !== null && previewed !== document && (
            <span className="text-sm text-ink-secondary">
              Document changed — preview again.
            </span>
          )}
        </div>

        {error && (
          <p className="mt-3 flex items-start gap-2 text-sm">
            <Dot className="mt-1.5 bg-status-critical" />
            <span>{error}</span>
          </p>
        )}

        {diff && (
          <div className="mt-4 rounded-md border border-hairline bg-page p-3 text-sm">
            <p className="flex items-center gap-1.5 font-medium">
              <Dot className={diff.applied ? "bg-status-good" : "bg-status-info"} />
              {diff.applied ? "Applied" : "Preview only — nothing changed"}
            </p>
            <p className="mt-1 tabular text-ink-secondary">{diff.summary}</p>
            <dl className="mt-3 grid grid-cols-2 gap-x-6 gap-y-1 sm:grid-cols-3">
              <DiffList label="Groups created" items={diff.groups_created} />
              <DiffList label="Groups deleted" items={diff.groups_deleted} />
              <DiffList label="Rules created" items={diff.rules_created} />
              <DiffList label="Rules deleted" items={diff.rules_deleted} />
            </dl>
          </div>
        )}
      </Card>
    </div>
  );
}

function DiffList({ label, items }: { label: string; items: string[] }) {
  if (items.length === 0) return null;
  return (
    <div>
      <dt className="text-ink-secondary">{label}</dt>
      <dd className="font-mono text-xs">{items.join(", ")}</dd>
    </div>
  );
}
