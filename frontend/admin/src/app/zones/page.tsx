import { Card, Cell, Dot, ErrorPanel, Row, Table, duration } from "@/components/ui";
import { tryGet } from "@/lib/api";
import type { Peer, Zone } from "@/lib/types";

import { CreateZone, ZoneActions, ZoneRoutes } from "./zone-admin";

export const dynamic = "force-dynamic";

export default async function ZonesPage() {
  const [zones, peers] = await Promise.all([
    tryGet<Zone[]>("/api/v1/zones"),
    tryGet<Peer[]>("/api/v1/peers"),
  ]);

  if (zones.error || !zones.data) {
    return <ErrorPanel message={zones.error ?? "no data"} />;
  }

  return (
    <div className="space-y-6">
      <CreateZone />

      <Card
        title="Zones"
        description={
          "A zone is a region of the address space: the peers assigned to it plus " +
          "the networks routed inside it. A peer sits in exactly one zone and can " +
          "hold any number of groups."
        }
      >
        <Table
          headers={["Slug", "Name", "Peers", "Routes", "Intra-zone", "Internet exit", "Session lifetime", ""]}
          empty="No zones yet."
        >
          {zones.data.map((zone) => (
            <Row key={zone.id}>
              <Cell className="font-medium">{zone.slug}</Cell>
              <Cell className="text-ink-secondary">{zone.name}</Cell>
              <Cell>{zone.peer_count}</Cell>
              <Cell>{zone.routes.filter((route) => route.enabled).length}</Cell>
              <Cell>
                {zone.intra_zone ? (
                  <span className="inline-flex items-center gap-1.5 text-sm">
                    <Dot className="bg-status-warning" />
                    allowed
                  </span>
                ) : (
                  <span className="text-ink-muted">denied</span>
                )}
              </Cell>
              <Cell>
                {zone.internet_exit ? (
                  <span className="inline-flex items-center gap-1.5 text-sm">
                    <Dot className="bg-status-warning" />
                    enabled
                  </span>
                ) : (
                  <span className="text-ink-muted">—</span>
                )}
              </Cell>
              <Cell>
                {zone.session_lifetime_seconds ? (
                  duration(zone.session_lifetime_seconds)
                ) : (
                  <span className="text-ink-muted">default</span>
                )}
              </Cell>
              <Cell className="text-right">
                <ZoneActions zone={zone} />
              </Cell>
            </Row>
          ))}
        </Table>
      </Card>

      {zones.data.map((zone) => (
        <ZoneRoutes key={zone.id} zone={zone} peers={peers.data ?? []} />
      ))}
    </div>
  );
}
