import { Card, Cell, Dot, ErrorPanel, Row, StatTile, Table } from "@/components/ui";
import { tryGet } from "@/lib/api";
import type { DnsRecord, DnsZone, Peer } from "@/lib/types";

import { CreateDnsRecord, DnsRecordActions } from "./dns-admin";

export const dynamic = "force-dynamic";

export default async function DnsPage() {
  const [zone, records, peers] = await Promise.all([
    tryGet<DnsZone>("/api/v1/dns"),
    tryGet<DnsRecord[]>("/api/v1/dns/records"),
    tryGet<Peer[]>("/api/v1/peers"),
  ]);

  if (zone.error || !zone.data) {
    return <ErrorPanel message={zone.error ?? "no data"} />;
  }

  const named = (peers.data ?? []).filter((peer) => peer.dns_label);

  return (
    <div className="space-y-6">
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatTile label="Zone" value={zone.data.zone} />
        <StatTile
          label="Resolver"
          value={zone.data.enabled ? "running" : "disabled"}
          hint={
            zone.data.enabled
              ? undefined
              : "FOXGUARD_DNS_ENABLED is off, so the agent leaves the resolver alone."
          }
        />
        <StatTile
          label="Mode"
          value={zone.data.mode === "forward" ? "forwarding" : "split DNS"}
          hint={
            zone.data.mode === "forward"
              ? "Queries outside the zone go upstream."
              : "Queries outside the zone are REFUSED; the client needs a second resolver."
          }
        />
        <StatTile label="Named devices" value={String(named.length)} />
      </div>

      {zone.data.errors.length > 0 && (
        <ErrorPanel
          message={
            "This zone will not render, so the agent is leaving the resolver " +
            "untouched: " +
            zone.data.errors.join("; ")
          }
        />
      )}

      {zone.data.warnings.length > 0 && (
        <div className="rounded-lg border border-hairline bg-surface p-4 text-sm">
          <p className="font-medium">Not currently served</p>
          <ul className="mt-2 space-y-1 text-ink-secondary">
            {zone.data.warnings.map((warning) => (
              <li key={warning}>{warning}</li>
            ))}
          </ul>
          <p className="mt-2 text-ink-muted">
            An alias is dropped when its target disappears — revoking a device
            must never take the whole zone down. Delete the record, or point it
            somewhere that exists.
          </p>
        </div>
      )}

      <CreateDnsRecord />

      <Card
        title="Records"
        description="Everything that is not a device's own name: aliases, and services that live off the tunnel."
      >
        <Table headers={["Name", "Type", "Value", "Description", "State", ""]} empty="No records.">
          {(records.data ?? []).map((record) => (
            <Row key={record.id}>
              <Cell className="font-mono">
                {record.name}.{zone.data!.zone}
              </Cell>
              <Cell>{record.kind}</Cell>
              <Cell className="font-mono">{record.value}</Cell>
              <Cell className="text-ink-secondary">{record.description ?? "—"}</Cell>
              <Cell>
                {record.enabled ? (
                  <span className="inline-flex items-center gap-1.5 text-sm">
                    <Dot className="bg-status-good" />
                    served
                  </span>
                ) : (
                  <span className="text-ink-muted">disabled</span>
                )}
              </Cell>
              <Cell className="text-right">
                <DnsRecordActions record={record} />
              </Cell>
            </Row>
          ))}
        </Table>
      </Card>

      <Card
        title="Device names"
        description={
          "Derived from each peer's name at registration and editable on the peer. " +
          "Only peers that can be on the tunnel have one — a name resolving to a " +
          "disabled or revoked device would be a wrong answer, not a stale one."
        }
      >
        <Table headers={["Name", "Device", "Address", "State"]} empty="No named devices yet.">
          {named.map((peer) => (
            <Row key={peer.id}>
              <Cell className="font-mono">
                {peer.dns_label}.{zone.data!.zone}
              </Cell>
              <Cell>{peer.name}</Cell>
              <Cell className="font-mono">{peer.tunnel_ip ?? "—"}</Cell>
              <Cell className="text-ink-secondary">{peer.state}</Cell>
            </Row>
          ))}
        </Table>
      </Card>

      <Card
        title="What the gateway serves"
        description={
          "Rendered from the database exactly as the agent receives it. " +
          `Listening on ${zone.data.listen_addresses.join(", ") || "nothing"}` +
          (zone.data.upstreams.length
            ? `, forwarding to ${zone.data.upstreams.join(", ")}.`
            : ".")
        }
      >
        {zone.data.hosts ? (
          <div className="space-y-4">
            <pre className="overflow-x-auto rounded-md border border-hairline bg-surface-sunken p-3 font-mono text-xs">
              {zone.data.hosts}
            </pre>
            <pre className="overflow-x-auto rounded-md border border-hairline bg-surface-sunken p-3 font-mono text-xs">
              {zone.data.conf}
            </pre>
            <p className="text-sm text-ink-muted">
              digest <span className="font-mono">{zone.data.digest?.slice(0, 12)}</span>
            </p>
          </div>
        ) : (
          <ErrorPanel message="Nothing to show: the zone did not render." />
        )}
      </Card>
    </div>
  );
}
