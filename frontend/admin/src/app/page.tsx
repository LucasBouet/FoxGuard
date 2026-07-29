import Link from "next/link";

import {
  Card,
  Cell,
  Dot,
  ErrorPanel,
  Row,
  StatTile,
  Table,
  relative,
} from "@/components/ui";
import { tryGet } from "@/lib/api";
import type { Dashboard, PeerState } from "@/lib/types";

export const dynamic = "force-dynamic";

const STATE_ACCENT: Record<PeerState, string> = {
  active: "bg-status-good",
  quarantined: "bg-status-warning",
  staging: "bg-status-info",
  disabled: "bg-status-neutral",
  revoked: "bg-status-critical",
};

const STATE_ORDER: PeerState[] = [
  "active",
  "quarantined",
  "staging",
  "disabled",
  "revoked",
];

export default async function OverviewPage() {
  const { data, error } = await tryGet<Dashboard>("/api/v1/dashboard?audit_limit=8");
  if (error || !data) return <ErrorPanel message={error ?? "no data"} />;

  const { ruleset } = data;

  return (
    <div className="space-y-6">
      {/*
        The one thing on this page that is not inventory: whether the gateway is
        running what the database describes. It leads because every other number
        here is describing intent, and this is the only one describing reality.
      */}
      <Card>
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-start gap-2">
            <Dot
              className={`mt-1.5 ${ruleset.in_sync ? "bg-status-good" : "bg-status-warning"}`}
            />
            <div>
              <p className="font-medium">
                {ruleset.in_sync
                  ? "Dataplane is in sync"
                  : "Dataplane has not confirmed the current ruleset"}
              </p>
              <p className="mt-1 text-sm text-ink-secondary">
                {ruleset.in_sync
                  ? `The agent reported applying this ruleset ${relative(ruleset.applied_at)}.`
                  : "The database describes a ruleset the agent has not reported applying. Check that foxguard-agent is running."}
              </p>
            </div>
          </div>
          <dl className="text-sm">
            <div className="flex gap-2">
              <dt className="text-ink-secondary">desired</dt>
              <dd className="tabular">{ruleset.digest.slice(0, 12)}</dd>
            </div>
            <div className="flex gap-2">
              <dt className="text-ink-secondary">applied</dt>
              <dd className="tabular">
                {ruleset.applied_digest ? ruleset.applied_digest.slice(0, 12) : "—"}
              </dd>
            </div>
          </dl>
        </div>
      </Card>

      <section>
        <h2 className="mb-3 text-sm font-semibold">Peers</h2>
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
          <StatTile label="Total" value={data.peers_total} />
          {STATE_ORDER.map((state) => (
            <StatTile
              key={state}
              label={state}
              value={data.peers_by_state[state] ?? 0}
              accent={STATE_ACCENT[state]}
            />
          ))}
        </div>
      </section>

      <section>
        <h2 className="mb-3 text-sm font-semibold">Control plane</h2>
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
          <StatTile
            label="Live sessions"
            value={data.active_sessions}
            hint="user peers only"
          />
          <StatTile label="Groups" value={data.groups} />
          <StatTile
            label="ACL rules"
            value={data.acl_rules}
            hint={
              data.acl_rules_disabled
                ? `${data.acl_rules_disabled} disabled`
                : undefined
            }
          />
          <StatTile label="Users" value={data.users} />
          <StatTile
            label="Server peers"
            value={data.peers_by_type.server ?? 0}
            hint="never expire"
          />
        </div>
      </section>

      <Card title="Recent activity">
        <Table headers={["When", "Actor", "Action", "Object"]} empty="Nothing yet.">
          {data.recent_audit.map((entry) => (
            <Row key={entry.id}>
              <Cell className="whitespace-nowrap text-ink-secondary">
                {relative(entry.created_at)}
              </Cell>
              <Cell>{entry.actor_label ?? entry.actor_type}</Cell>
              <Cell className="font-medium">{entry.action}</Cell>
              <Cell className="text-ink-secondary">{entry.object_type ?? "—"}</Cell>
            </Row>
          ))}
        </Table>
        <p className="mt-3 text-sm">
          <Link href="/audit" className="underline underline-offset-2">
            Full audit log
          </Link>
        </p>
      </Card>
    </div>
  );
}
