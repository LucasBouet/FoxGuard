import { Card, ErrorPanel } from "@/components/ui";
import { tryGet } from "@/lib/api";
import type { Group, Peer, User, Zone } from "@/lib/types";

import { ConfigGenerator } from "./config-generator";

export const dynamic = "force-dynamic";

export default async function ConfigPage() {
  const [peers, groups, zones, users] = await Promise.all([
    tryGet<Peer[]>("/api/v1/peers"),
    tryGet<Group[]>("/api/v1/groups"),
    tryGet<Zone[]>("/api/v1/zones"),
    tryGet<User[]>("/api/v1/users"),
  ]);

  if (peers.error || !peers.data) {
    return <ErrorPanel message={peers.error ?? "no data"} />;
  }

  return (
    <div className="space-y-6">
      <Card
        title="Config generator"
        description={
          "A finished WireGuard configuration, assembled in this browser. The " +
          "private key is generated on this machine, goes straight into the file, " +
          "and is never sent to the gateway — Foxguard only ever learns the public " +
          "half, which is all it needs."
        }
      >
        <ConfigGenerator
          peers={peers.data}
          groups={groups.data ?? []}
          zones={zones.data ?? []}
          users={users.data ?? []}
        />
      </Card>
    </div>
  );
}
