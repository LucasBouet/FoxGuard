import { Card, Cell, Dot, ErrorPanel, Row, Table, relative } from "@/components/ui";
import { tryGet } from "@/lib/api";
import type { AdminSession, PeerSession } from "@/lib/types";

import { RevokeSession } from "./session-actions";

export const dynamic = "force-dynamic";

export default async function SessionsPage() {
  const [admins, peers] = await Promise.all([
    tryGet<AdminSession[]>("/api/v1/admin/sessions"),
    tryGet<PeerSession[]>("/api/v1/sessions"),
  ]);

  if (admins.error || !admins.data) {
    return <ErrorPanel message={admins.error ?? "no data"} />;
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-lg font-semibold">Sessions</h1>
        <p className="mt-1 max-w-3xl text-sm text-ink-secondary">
          Two different things sharing a word. An <em>administrator</em> session
          is a person signed in to this dashboard; a <em>peer</em> session is a
          device that authenticated at the portal and is therefore on the
          network.
        </p>
      </div>

      <Card
        title="Administrators"
        description="Revoking one cuts that sign-in without touching the account — the lighter tool next to deactivating someone."
      >
        <Table
          headers={["Who", "Signed in", "Last seen", "Expires", "From", "Client", ""]}
          empty="Nobody is signed in — the dashboard is running on the shared token."
        >
          {admins.data.map((row) => (
            <Row key={row.id}>
              <Cell className="font-medium">
                <span className="inline-flex items-center gap-1.5">
                  {row.current && <Dot className="bg-status-good" />}
                  {row.username}
                  {row.current && (
                    <span className="text-xs text-ink-muted">this session</span>
                  )}
                </span>
              </Cell>
              <Cell className="whitespace-nowrap text-ink-secondary">
                {relative(row.created_at)}
              </Cell>
              <Cell className="whitespace-nowrap text-ink-secondary">
                {relative(row.last_seen_at)}
              </Cell>
              <Cell className="whitespace-nowrap text-ink-secondary">
                {new Date(row.expires_at).toISOString().slice(0, 16).replace("T", " ")}
              </Cell>
              <Cell className="text-ink-secondary">{row.source_ip ?? "—"}</Cell>
              <Cell className="max-w-xs truncate text-xs text-ink-muted">
                {row.user_agent ?? "—"}
              </Cell>
              <Cell className="text-right">
                <RevokeSession id={row.id} current={row.current} />
              </Cell>
            </Row>
          ))}
        </Table>
      </Card>

      <Card
        title="Peers on the network"
        description="User peers only. Server peers hold no session — their access ends when their enrollment key is revoked."
      >
        <Table
          headers={["Device", "Account", "Method", "Signed in", "Time left"]}
          empty="No device is currently authenticated."
        >
          {(peers.data ?? []).map((row) => (
            <Row key={row.id}>
              <Cell className="font-medium">{row.peer_name}</Cell>
              <Cell className="text-ink-secondary">{row.username}</Cell>
              <Cell className="text-ink-secondary">{row.auth_method}</Cell>
              <Cell className="whitespace-nowrap text-ink-secondary">
                {relative(row.last_authenticated_at)}
              </Cell>
              <Cell className="whitespace-nowrap">
                {row.seconds_remaining === null
                  ? "—"
                  : row.seconds_remaining < 3600
                    ? `${Math.ceil(row.seconds_remaining / 60)} min`
                    : `${Math.floor(row.seconds_remaining / 3600)} h`}
              </Cell>
            </Row>
          ))}
        </Table>
      </Card>
    </div>
  );
}
