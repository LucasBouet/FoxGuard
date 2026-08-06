import { Card, Cell, Dot, ErrorPanel, Row, Table, relative } from "@/components/ui";
import { tryGet } from "@/lib/api";
import type { Group, User } from "@/lib/types";

import { CreateUser, UserActions } from "./user-admin";

export const dynamic = "force-dynamic";

export default async function UsersPage() {
  const [{ data, error }, groups] = await Promise.all([
    tryGet<User[]>("/api/v1/users"),
    tryGet<Group[]>("/api/v1/groups"),
  ]);
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
        <p className="mt-2 max-w-3xl text-sm text-ink-secondary">
          An account&rsquo;s own groups are read by single sign-on on published
          services, and by nothing else. They open no port and rewrite no
          ruleset — what a device may reach still comes from the groups that
          device is in.
        </p>
      </div>

      <CreateUser groups={groups.data ?? []} />

      <Card>
        <Table
          headers={[
            "Username",
            "Sign-in",
            "2FA",
            "Admin",
            "Groups",
            "Active",
            "Last login",
            "",
          ]}
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
              <Cell className="text-ink-secondary">
                {user.group_slugs.join(", ") || <span className="text-ink-muted">—</span>}
              </Cell>
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
                <UserActions user={user} groups={groups.data ?? []} />
              </Cell>
            </Row>
          ))}
        </Table>
      </Card>
    </div>
  );
}
