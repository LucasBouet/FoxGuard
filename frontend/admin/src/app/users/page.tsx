import { Card, Cell, Dot, ErrorPanel, Row, Table, relative } from "@/components/ui";
import { tryGet } from "@/lib/api";
import type { User } from "@/lib/types";

import { CreateUser, UserActions } from "./user-admin";

export const dynamic = "force-dynamic";

export default async function UsersPage() {
  const { data, error } = await tryGet<User[]>("/api/v1/users");
  if (error || !data) return <ErrorPanel message={error ?? "no data"} />;

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-lg font-semibold">Accounts</h1>
        <p className="mt-1 max-w-3xl text-sm text-ink-secondary">
          A user peer is bound to exactly one account when it is registered, and
          only that account can unlock it — ACL groups belong to the device, so
          any-credential-unlocks-any-device would let a low-privilege account
          inherit a stolen laptop&rsquo;s access.
        </p>
      </div>

      <CreateUser />

      <Card>
        <Table
          headers={["Username", "Sign-in", "2FA", "Admin", "Active", "Last login", ""]}
          empty="No accounts yet."
        >
          {data.map((user) => (
            <Row key={user.id}>
              <Cell className="font-medium">{user.username}</Cell>
              <Cell className="text-ink-secondary">
                {user.auth_methods.join(", ") || "—"}
              </Cell>
              <Cell>
                {user.totp_enabled ? (
                  <span className="inline-flex items-center gap-1.5 text-sm">
                    <Dot className="bg-status-good" />
                    on
                  </span>
                ) : (
                  <span className="text-ink-muted">off</span>
                )}
              </Cell>
              <Cell className="text-ink-secondary">{user.is_admin ? "yes" : "—"}</Cell>
              <Cell>
                {user.is_active ? (
                  <span className="text-ink-secondary">yes</span>
                ) : (
                  <span className="inline-flex items-center gap-1.5 text-sm">
                    <Dot className="bg-status-neutral" />
                    no
                  </span>
                )}
              </Cell>
              <Cell className="whitespace-nowrap text-ink-secondary">
                {relative(user.last_login_at)}
              </Cell>
              <Cell className="text-right">
                <UserActions user={user} />
              </Cell>
            </Row>
          ))}
        </Table>
      </Card>
    </div>
  );
}
