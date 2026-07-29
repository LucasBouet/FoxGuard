import Link from "next/link";

import {
  Card,
  Cell,
  ErrorPanel,
  Row,
  StateBadge,
  Table,
  relative,
} from "@/components/ui";
import { tryGet } from "@/lib/api";
import type { Group, Peer, PeerState, Tag, User } from "@/lib/types";

import { CreatePeer, PeerActions } from "./peer-admin";

export const dynamic = "force-dynamic";

const STATES: PeerState[] = [
  "staging",
  "quarantined",
  "active",
  "disabled",
  "revoked",
];

/**
 * Filtering is done by the API, not in the browser: `state`, `group` and `tag`
 * are query parameters it already supports, and tag filtering has AND semantics
 * there. Re-implementing that client-side would be a second, subtly different
 * answer to "which peers match".
 */
function buildQuery(params: Record<string, string | undefined>): string {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value) query.set(key, value);
  }
  const encoded = query.toString();
  return encoded ? `?${encoded}` : "";
}

function FilterLink({
  href,
  active,
  children,
}: {
  href: string;
  active: boolean;
  children: React.ReactNode;
}) {
  return (
    <Link
      href={href}
      className={`rounded-md border px-2.5 py-1 text-sm ${
        active
          ? "border-hairline bg-page font-medium text-ink"
          : "border-transparent text-ink-secondary hover:bg-page"
      }`}
    >
      {children}
    </Link>
  );
}

export default async function PeersPage({
  searchParams,
}: {
  searchParams: Promise<{ state?: string; group?: string; tag?: string }>;
}) {
  const filters = await searchParams;
  const query = buildQuery(filters);

  const [peers, groups, tags, users] = await Promise.all([
    tryGet<Peer[]>(`/api/v1/peers${query}`),
    tryGet<Group[]>("/api/v1/groups"),
    tryGet<Tag[]>("/api/v1/tags"),
    tryGet<User[]>("/api/v1/users"),
  ]);

  if (peers.error || !peers.data) {
    return <ErrorPanel message={peers.error ?? "no data"} />;
  }

  const linkWith = (patch: Record<string, string | undefined>) =>
    `/peers${buildQuery({ ...filters, ...patch })}`;

  return (
    <div className="space-y-4">
      <CreatePeer groups={groups.data ?? []} users={users.data ?? []} />

      {/* Filters sit in one row above the table, never inside it. */}
      <div className="space-y-2 rounded-lg border border-hairline bg-surface p-4">
        <div className="flex flex-wrap items-center gap-2">
          <span className="w-16 text-sm text-ink-secondary">State</span>
          <FilterLink href={linkWith({ state: undefined })} active={!filters.state}>
            all
          </FilterLink>
          {STATES.map((state) => (
            <FilterLink
              key={state}
              href={linkWith({ state })}
              active={filters.state === state}
            >
              {state}
            </FilterLink>
          ))}
        </div>

        {groups.data && groups.data.length > 0 && (
          <div className="flex flex-wrap items-center gap-2">
            <span className="w-16 text-sm text-ink-secondary">Group</span>
            <FilterLink href={linkWith({ group: undefined })} active={!filters.group}>
              all
            </FilterLink>
            {groups.data.map((group) => (
              <FilterLink
                key={group.id}
                href={linkWith({ group: group.slug })}
                active={filters.group === group.slug}
              >
                {group.slug}
              </FilterLink>
            ))}
          </div>
        )}

        {tags.data && tags.data.length > 0 && (
          <div className="flex flex-wrap items-center gap-2">
            <span className="w-16 text-sm text-ink-secondary">Tag</span>
            <FilterLink href={linkWith({ tag: undefined })} active={!filters.tag}>
              all
            </FilterLink>
            {tags.data.map((tag) => (
              <FilterLink
                key={tag.id}
                href={linkWith({ tag: tag.name })}
                active={filters.tag === tag.name}
              >
                {tag.name}
              </FilterLink>
            ))}
          </div>
        )}
      </div>

      <Card>
        <Table
          headers={[
            "Name",
            "Type",
            "State",
            "Tunnel IP",
            "Groups",
            "Tags",
            "Last login",
            "",
          ]}
          empty="No peer matches these filters."
        >
          {peers.data.map((peer) => (
            <Row key={peer.id}>
              <Cell className="font-medium">{peer.name}</Cell>
              <Cell className="text-ink-secondary">{peer.peer_type}</Cell>
              <Cell>
                <StateBadge state={peer.state} />
              </Cell>
              <Cell>{peer.tunnel_ip ?? "—"}</Cell>
              <Cell className="text-ink-secondary">
                {peer.group_slugs.join(", ") || "—"}
              </Cell>
              <Cell className="text-ink-secondary">{peer.tags.join(", ") || "—"}</Cell>
              <Cell className="whitespace-nowrap text-ink-secondary">
                {/* Server peers enroll rather than log in, so "last login" is
                    the wrong question for them. */}
                {peer.peer_type === "server"
                  ? relative(peer.enrolled_at)
                  : relative(peer.last_authenticated_at)}
              </Cell>
              <Cell className="text-right">
                <PeerActions peer={peer} groups={groups.data ?? []} />
              </Cell>
            </Row>
          ))}
        </Table>
      </Card>
    </div>
  );
}
