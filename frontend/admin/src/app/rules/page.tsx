import { ActionBadge, Card, Cell, Dot, ErrorPanel, Row, Table } from "@/components/ui";
import { tryGet } from "@/lib/api";
import type { AclEndpoint, AclRule, Group, Zone } from "@/lib/types";

import { CreateRule, RuleActions } from "./rule-admin";

export const dynamic = "force-dynamic";

function describe(endpoint: AclEndpoint): string {
  if (endpoint.kind === "group") return endpoint.group_slug ?? "?";
  // Prefixed, because a zone and a group can never share a slug but a reader
  // still has to know which kind of thing the rule is about.
  if (endpoint.kind === "zone") return `zone:${endpoint.zone_slug ?? "?"}`;
  if (endpoint.kind === "cidr") return endpoint.cidr ?? "?";
  return "any";
}

function ports(rule: AclRule): string {
  if (rule.dst_port_start === null) return rule.protocol === "any" ? "—" : rule.protocol;
  const range =
    rule.dst_port_end && rule.dst_port_end !== rule.dst_port_start
      ? `${rule.dst_port_start}–${rule.dst_port_end}`
      : String(rule.dst_port_start);
  return `${rule.protocol}/${range}`;
}

export default async function RulesPage() {
  const [rules, groups, zones] = await Promise.all([
    tryGet<AclRule[]>("/api/v1/acl-rules"),
    tryGet<Group[]>("/api/v1/groups"),
    tryGet<Zone[]>("/api/v1/zones"),
  ]);
  if (rules.error || !rules.data) return <ErrorPanel message={rules.error ?? "no data"} />;

  const ordered = [...rules.data].sort(
    (a, b) => a.priority - b.priority || a.ref.localeCompare(b.ref),
  );

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-lg font-semibold">ACL rules</h1>
        <p className="mt-1 max-w-3xl text-sm text-ink-secondary">
          Listed in the order nftables evaluates them: by priority, then ref. The
          first match decides, so a rule below a broader <code>drop</code> never
          fires. Anything not matched at all is dropped by the default deny.
        </p>
      </div>

      <CreateRule groups={groups.data ?? []} zones={zones.data ?? []} />

      <Card>
        <Table
          headers={["#", "Ref", "From", "To", "Proto/port", "Action", "", ""]}
          empty="No rules yet — everything is denied by default."
        >
          {ordered.map((rule) => (
            <Row key={rule.id}>
              <Cell className="text-ink-muted">{rule.priority}</Cell>
              <Cell>
                <span className="font-medium">{rule.ref}</span>
                {rule.name && rule.name !== rule.ref && (
                  <span className="block text-xs text-ink-secondary">{rule.name}</span>
                )}
              </Cell>
              <Cell className="font-mono text-xs">{describe(rule.src)}</Cell>
              <Cell className="font-mono text-xs">{describe(rule.dst)}</Cell>
              <Cell className="text-ink-secondary">{ports(rule)}</Cell>
              <Cell>
                <ActionBadge action={rule.action} />
              </Cell>
              <Cell>
                {rule.enabled ? (
                  <span className="text-ink-secondary">on</span>
                ) : (
                  <span className="inline-flex items-center gap-1.5 text-sm">
                    <Dot className="bg-status-neutral" />
                    off
                  </span>
                )}
              </Cell>
              <Cell className="text-right">
                <RuleActions
                  rule={rule}
                  groups={groups.data ?? []}
                  zones={zones.data ?? []}
                />
              </Cell>
            </Row>
          ))}
        </Table>
      </Card>
    </div>
  );
}
