"use client";

import { useState, useTransition } from "react";

import {
  Button,
  Check,
  ConfirmButton,
  Disclosure,
  Field,
  Input,
  Notice,
  ResultNotice,
  Select,
} from "@/components/forms";
import { Card, Cell, Dot, Row, Table } from "@/components/ui";
import {
  createZone,
  createZoneRoute,
  deleteZone,
  deleteZoneRoute,
  updateZone,
  updateZoneRoute,
} from "@/lib/actions";
import type { Result } from "@/lib/actions";
import type { Peer, Zone } from "@/lib/types";

const SLUG_PATTERN = "^[a-z0-9][a-z0-9_-]{0,23}$";

export function CreateZone() {
  const [slug, setSlug] = useState("");
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [internetExit, setInternetExit] = useState(false);
  const [intraZone, setIntraZone] = useState(false);
  const [lifetime, setLifetime] = useState("");
  const [result, setResult] = useState<Result<unknown> | null>(null);
  const [pending, start] = useTransition();

  function submit(event: React.FormEvent) {
    event.preventDefault();
    start(async () => {
      const response = await createZone({
        slug,
        name: name || slug,
        description: description || undefined,
        internet_exit: internetExit,
        intra_zone: intraZone,
        session_lifetime_seconds: lifetime ? Number(lifetime) * 3600 : null,
      });
      setResult(response);
      if (response.ok) {
        setSlug("");
        setName("");
        setDescription("");
        setInternetExit(false);
        setIntraZone(false);
        setLifetime("");
      }
    });
  }

  return (
    <Disclosure label="New zone">
      <form onSubmit={submit} className="space-y-3">
        <div className="grid gap-3 sm:grid-cols-2">
          <Field
            label="Slug"
            hint="Becomes part of an nftables set name, and shares one namespace with groups so an ACL rule naming it is never ambiguous."
          >
            <Input
              value={slug}
              onChange={(event) => setSlug(event.target.value)}
              pattern={SLUG_PATTERN}
              maxLength={24}
              required
              placeholder="office"
            />
          </Field>
          <Field label="Name" hint="Free text, shown in the UI.">
            <Input
              value={name}
              onChange={(event) => setName(event.target.value)}
              maxLength={128}
              placeholder="Office network"
            />
          </Field>
        </div>

        <Field label="Description">
          <Input
            value={description}
            onChange={(event) => setDescription(event.target.value)}
          />
        </Field>

        <Field
          label="Session lifetime (hours)"
          hint="Blank uses the global default."
        >
          <Input
            type="number"
            min={1}
            step={1}
            value={lifetime}
            onChange={(event) => setLifetime(event.target.value)}
            placeholder="8"
          />
        </Field>

        <Check
          label="Allow traffic inside the zone"
          hint="Off by default. Foxguard denies until something grants, and a zone is not the exception — leave this off and write an explicit rule if you want a subset. An explicit drop still overrides it."
          checked={intraZone}
          onChange={setIntraZone}
        />

        <Check
          label="Internet exit"
          hint="Members reach the internet through the gateway. They still cannot reach FOXGUARD_INTERNAL_CIDRS without an explicit rule, and this needs FOXGUARD_WAN_INTERFACE set."
          checked={internetExit}
          onChange={setInternetExit}
        />

        <ResultNotice result={result} />
        {result?.ok && <Notice kind="good">Zone created.</Notice>}

        <Button type="submit" variant="primary" disabled={pending || !slug}>
          {pending ? "Creating…" : "Create zone"}
        </Button>
      </form>
    </Disclosure>
  );
}

export function ZoneActions({ zone }: { zone: Zone }) {
  const [editing, setEditing] = useState(false);
  const [name, setName] = useState(zone.name);
  const [internetExit, setInternetExit] = useState(zone.internet_exit);
  const [intraZone, setIntraZone] = useState(zone.intra_zone);
  const [lifetime, setLifetime] = useState(
    zone.session_lifetime_seconds ? String(zone.session_lifetime_seconds / 3600) : "",
  );
  const [result, setResult] = useState<Result<unknown> | null>(null);
  const [pending, start] = useTransition();

  function save() {
    start(async () => {
      const response = await updateZone(zone.id, {
        name,
        internet_exit: internetExit,
        intra_zone: intraZone,
        session_lifetime_seconds: lifetime ? Number(lifetime) * 3600 : null,
      });
      setResult(response);
      if (response.ok) setEditing(false);
    });
  }

  if (!editing) {
    return (
      <span className="inline-flex items-center gap-1">
        <Button variant="quiet" onClick={() => setEditing(true)}>
          Edit
        </Button>
        <ConfirmButton
          label="Delete"
          confirmLabel="Delete zone"
          warning={
            `Its ${zone.routes.length} route(s) go with it and its ${zone.peer_count} ` +
            "peer(s) become unassigned. Both narrow access; nothing is widened."
          }
          onConfirm={async () => setResult(await deleteZone(zone.id))}
        />
        <ResultNotice result={result} />
      </span>
    );
  }

  return (
    <div className="space-y-2 py-2">
      <Input value={name} onChange={(event) => setName(event.target.value)} />
      <Input
        type="number"
        min={1}
        value={lifetime}
        onChange={(event) => setLifetime(event.target.value)}
        placeholder="lifetime (hours), blank = default"
      />
      <Check label="Allow traffic inside the zone" checked={intraZone} onChange={setIntraZone} />
      <Check label="Internet exit" checked={internetExit} onChange={setInternetExit} />
      <ResultNotice result={result} />
      <div className="flex gap-2">
        <Button variant="primary" onClick={save} disabled={pending}>
          {pending ? "Saving…" : "Save"}
        </Button>
        <Button variant="quiet" onClick={() => setEditing(false)}>
          Cancel
        </Button>
      </div>
    </div>
  );
}

export function ZoneRoutes({ zone, peers }: { zone: Zone; peers: Peer[] }) {
  const [cidr, setCidr] = useState("");
  const [via, setVia] = useState("");
  const [description, setDescription] = useState("");
  const [result, setResult] = useState<Result<unknown> | null>(null);
  const [pending, start] = useTransition();

  const byId = new Map(peers.map((peer) => [peer.id, peer]));

  function add(event: React.FormEvent) {
    event.preventDefault();
    start(async () => {
      const response = await createZoneRoute(zone.id, {
        cidr,
        via_peer_id: via || null,
        description: description || undefined,
      });
      setResult(response);
      if (response.ok) {
        setCidr("");
        setVia("");
        setDescription("");
      }
    });
  }

  return (
    <Card
      title={`Routes — ${zone.slug}`}
      description={
        "Networks reachable inside this zone. They join the zone's address set, " +
        "so an ACL rule naming the zone covers them without a second rule."
      }
    >
      <Table headers={["Network", "Carried by", "Description", "State", ""]} empty="No routes.">
        {zone.routes.map((route) => (
          <Row key={route.id}>
            <Cell className="font-mono">{route.cidr}</Cell>
            <Cell>
              {route.via_peer_id ? (
                byId.get(route.via_peer_id)?.name ?? (
                  <span className="font-mono text-xs">{route.via_peer_id}</span>
                )
              ) : (
                <span className="text-ink-muted">the gateway itself</span>
              )}
            </Cell>
            <Cell className="text-ink-secondary">{route.description ?? "—"}</Cell>
            <Cell>
              {route.enabled ? (
                <span className="inline-flex items-center gap-1.5 text-sm">
                  <Dot className="bg-status-good" />
                  enabled
                </span>
              ) : (
                <span className="text-ink-muted">disabled</span>
              )}
            </Cell>
            <Cell className="text-right">
              <span className="inline-flex items-center gap-1">
                <Button
                  variant="quiet"
                  onClick={() =>
                    start(async () =>
                      setResult(
                        await updateZoneRoute(zone.id, route.id, {
                          enabled: !route.enabled,
                        }),
                      ),
                    )
                  }
                >
                  {route.enabled ? "Disable" : "Enable"}
                </Button>
                <ConfirmButton
                  label="Delete"
                  confirmLabel="Delete route"
                  warning="The gateway withdraws the kernel route on the agent's next poll."
                  onConfirm={async () =>
                    setResult(await deleteZoneRoute(zone.id, route.id))
                  }
                />
              </span>
            </Cell>
          </Row>
        ))}
      </Table>

      <form onSubmit={add} className="mt-4 space-y-3 border-t border-hairline pt-4">
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="Network" hint="A default route is refused: it would replace the gateway's own and cut every remote session.">
            <Input
              value={cidr}
              onChange={(event) => setCidr(event.target.value)}
              required
              className="font-mono"
              placeholder="192.168.10.0/24"
            />
          </Field>
          <Field
            label="Carried by"
            hint="The peer that routes it. Leave empty for a network the gateway already reaches itself — no tunnel route is installed then."
          >
            <Select value={via} onChange={(event) => setVia(event.target.value)}>
              <option value="">the gateway itself</option>
              {peers.map((peer) => (
                <option key={peer.id} value={peer.id}>
                  {peer.name} ({peer.tunnel_ip ?? "no address"})
                </option>
              ))}
            </Select>
          </Field>
        </div>
        <Field label="Description">
          <Input
            value={description}
            onChange={(event) => setDescription(event.target.value)}
          />
        </Field>
        <ResultNotice result={result} />
        <Button type="submit" variant="primary" disabled={pending || !cidr}>
          {pending ? "Adding…" : "Add route"}
        </Button>
      </form>
    </Card>
  );
}
