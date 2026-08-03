import { Card, Cell, Dot, ErrorPanel, Row, Table } from "@/components/ui";
import { tryGet } from "@/lib/api";
import type { Group, Peer, ProxyStatus, Service, SsoSession, Zone } from "@/lib/types";

import { CreateService, ServiceCredentials, ServiceDetail, SsoSessions } from "./service-admin";

export const dynamic = "force-dynamic";

/** Which doors a service really has, given its upstream peer's state. */
function doors(service: Service): { label: string; tone: string } {
  if (!service.active_doors) {
    return { label: "not served", tone: "text-status-danger" };
  }
  if (service.active_doors !== service.exposure) {
    return { label: `${service.active_doors} only`, tone: "text-status-warning" };
  }
  return { label: service.active_doors, tone: "text-ink-secondary" };
}

export default async function ServicesPage() {
  const [services, peers, groups, zones, proxy, sessions] = await Promise.all([
    tryGet<Service[]>("/api/v1/services"),
    tryGet<Peer[]>("/api/v1/peers"),
    tryGet<Group[]>("/api/v1/groups"),
    tryGet<Zone[]>("/api/v1/zones"),
    tryGet<ProxyStatus>("/api/v1/proxy"),
    tryGet<SsoSession[]>("/api/v1/proxy/sso-sessions"),
  ]);

  if (services.error || !services.data) {
    return <ErrorPanel message={services.error ?? "no data"} />;
  }

  const status = proxy.data;

  return (
    <div className="space-y-6">
      {status && !status.enabled && (
        <Card title="The reverse proxy is off">
          <p className="text-sm text-ink-secondary">
            Set <code>FOXGUARD_PROXY_ENABLED=true</code> and{" "}
            <code>FOXGUARD_PROXY_DOMAIN</code> in <code>/etc/foxguard/backend.env</code>,
            then restart <code>foxguard-api</code>. Services need a name a public
            certificate authority will sign, which is why the domain is required
            and cannot be the internal DNS zone.
          </p>
        </Card>
      )}

      {status && status.warnings.length > 0 && (
        <Card title="Warnings">
          <ul className="space-y-1 text-sm text-status-warning">
            {status.warnings.map((warning) => (
              <li key={warning}>{warning}</li>
            ))}
          </ul>
        </Card>
      )}

      {status?.enabled && (
        <CreateService
          peers={peers.data ?? []}
          groups={groups.data ?? []}
          zones={zones.data ?? []}
          domain={status.domain}
          hasExternal={status.external_binds.length > 0}
        />
      )}

      <Card
        title="Published services"
        description={
          "Each service lives behind a peer and the gateway fronts it. An HTTP " +
          "service is terminated, so the proxy can check a token and say who the " +
          "caller is; a TCP service is passed through untouched, so it cannot."
        }
      >
        <Table
          headers={["Slug", "Kind", "Upstream", "Name", "Doors", "Ways in", "Credentials", ""]}
          empty="Nothing published yet."
        >
          {services.data.map((service) => {
            const door = doors(service);
            return (
              <Row key={service.id}>
                <Cell className="font-medium">{service.slug}</Cell>
                <Cell className="text-ink-secondary">
                  {service.kind === "tcp" ? "TCP passthrough" : "HTTP"}
                </Cell>
                <Cell className="text-ink-secondary">
                  {service.upstream_host}:{service.upstream_port}
                  {service.upstream_peer_name && (
                    <span className="text-ink-muted"> via {service.upstream_peer_name}</span>
                  )}
                </Cell>
                <Cell className="text-ink-secondary">
                  {service.internal_hostname ?? service.external_hostname ?? (
                    <span className="text-ink-muted">port {service.listen_port}</span>
                  )}
                </Cell>
                <Cell>
                  <span className={`inline-flex items-center gap-1.5 text-sm ${door.tone}`}>
                    {service.active_doors !== service.exposure && (
                      <Dot className="bg-status-warning" />
                    )}
                    {door.label}
                  </span>
                </Cell>
                <Cell className="text-ink-secondary">
                  {service.authenticators.length === 0 ? (
                    <span className="text-status-danger">none</span>
                  ) : (
                    service.authenticators
                      .map((auth) => `${auth.kind} (${auth.scope})`)
                      .join(", ")
                  )}
                </Cell>
                <Cell className="text-ink-secondary">
                  {service.token_count > 0 && `${service.token_count} token(s)`}
                  {service.token_count > 0 && service.account_count > 0 && ", "}
                  {service.account_count > 0 && `${service.account_count} account(s)`}
                  {service.token_count === 0 && service.account_count === 0 && (
                    <span className="text-ink-muted">—</span>
                  )}
                </Cell>
                <Cell className="text-right">
                  <ServiceDetail
                    service={service}
                    groups={groups.data ?? []}
                    zones={zones.data ?? []}
                  />
                </Cell>
              </Row>
            );
          })}
        </Table>
      </Card>

      {services.data.map((service) => (
        <ServiceCredentials key={service.id} service={service} />
      ))}

      {(sessions.data?.length ?? 0) > 0 && (
        <SsoSessions sessions={sessions.data ?? []} />
      )}

      {status && status.implicit_paths.length > 0 && (
        <Card
          title="Paths outside the ACL model"
          description={
            "The proxy connects from the gateway, which no zone or group rule " +
            "constrains — Foxguard creates no output chain on purpose, so a bad " +
            "ruleset can never lock you out. What constrains these is that " +
            "HAProxy can only ever reach the address and port declared here."
          }
        >
          <Table headers={["Service", "From", "To", "Via peer", "Enforced by"]} empty="">
            {status.implicit_paths.map((path) => (
              <Row key={`${path.service}-${path.destination}-${path.port}`}>
                <Cell className="font-medium">{path.service}</Cell>
                <Cell className="text-ink-secondary">{path.source}</Cell>
                <Cell className="text-ink-secondary">
                  {path.destination}:{path.port}
                </Cell>
                <Cell className="text-ink-secondary">
                  {path.peer ?? <span className="text-ink-muted">—</span>}
                </Cell>
                <Cell className="text-ink-muted">{path.enforced_by}</Cell>
              </Row>
            ))}
          </Table>
        </Card>
      )}
    </div>
  );
}
