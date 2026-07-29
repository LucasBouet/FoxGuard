import Link from "next/link";

import { Card, Cell, ErrorPanel, Row, Table, relative } from "@/components/ui";
import { tryGet } from "@/lib/api";
import type { AuditEntry } from "@/lib/types";

export const dynamic = "force-dynamic";

/** Actions worth reaching in one click when something has gone wrong. */
const SHORTCUTS = [
  "killswitch.trigger",
  "portal.login",
  "portal.login.denied",
  "peer.enroll",
  "peer.enroll.denied",
  "session.expired",
  "ruleset.apply",
];

export default async function AuditPage({
  searchParams,
}: {
  searchParams: Promise<{ action?: string }>;
}) {
  const { action } = await searchParams;
  const query = action ? `?action=${encodeURIComponent(action)}&limit=200` : "?limit=200";
  const { data, error } = await tryGet<AuditEntry[]>(`/api/v1/audit-log${query}`);

  if (error || !data) return <ErrorPanel message={error ?? "no data"} />;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2 rounded-lg border border-hairline bg-surface p-4">
        <span className="text-sm text-ink-secondary">Action</span>
        <Link
          href="/audit"
          className={`rounded-md border px-2.5 py-1 text-sm ${
            action
              ? "border-transparent text-ink-secondary hover:bg-page"
              : "border-hairline bg-page font-medium"
          }`}
        >
          all
        </Link>
        {SHORTCUTS.map((name) => (
          <Link
            key={name}
            href={`/audit?action=${encodeURIComponent(name)}`}
            className={`rounded-md border px-2.5 py-1 text-sm ${
              action === name
                ? "border-hairline bg-page font-medium"
                : "border-transparent text-ink-secondary hover:bg-page"
            }`}
          >
            {name}
          </Link>
        ))}
      </div>

      <Card>
        <Table
          headers={["When", "Actor", "Action", "Object", "Source", "Detail"]}
          empty="No entries match."
        >
          {data.map((entry) => (
            <Row key={entry.id}>
              <Cell className="whitespace-nowrap text-ink-secondary">
                {relative(entry.created_at)}
              </Cell>
              <Cell>
                {entry.actor_label ?? "—"}
                <span className="ml-1 text-xs text-ink-muted">{entry.actor_type}</span>
              </Cell>
              <Cell className="font-medium">{entry.action}</Cell>
              <Cell className="text-ink-secondary">{entry.object_type ?? "—"}</Cell>
              <Cell className="text-ink-secondary">{entry.source_ip ?? "—"}</Cell>
              <Cell>
                {Object.keys(entry.detail).length > 0 ? (
                  <code className="text-xs text-ink-secondary">
                    {JSON.stringify(entry.detail).slice(0, 120)}
                  </code>
                ) : (
                  <span className="text-ink-muted">—</span>
                )}
              </Cell>
            </Row>
          ))}
        </Table>
      </Card>
    </div>
  );
}
