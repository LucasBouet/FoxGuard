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
import { createRule, deleteRule, updateRule } from "@/lib/actions";
import type { Result, RuleInput } from "@/lib/actions";
import type {
  AclEndpoint,
  AclRule,
  EndpointKind,
  Group,
  Protocol,
  Zone,
} from "@/lib/types";

/**
 * One side of a rule: any, a group, a zone, or a literal CIDR.
 *
 * A zone endpoint covers its member peers *and* the networks routed inside it,
 * which is the reason it exists as a separate kind rather than being a group
 * with extra fields.
 */
function EndpointFields({
  side,
  groups,
  zones,
  value,
  onChange,
}: {
  side: "Source" | "Destination";
  groups: Group[];
  zones: Zone[];
  value: AclEndpoint;
  onChange: (next: AclEndpoint) => void;
}) {
  return (
    <div className="space-y-2 rounded-md border border-hairline p-3">
      <p className="text-sm font-medium">{side}</p>
      <Select
        value={value.kind}
        onChange={(event) =>
          onChange({
            kind: event.target.value as EndpointKind,
            group_slug: null,
            zone_slug: null,
            cidr: null,
          })
        }
      >
        <option value="any">any</option>
        <option value="group">group</option>
        <option value="zone">zone</option>
        <option value="cidr">CIDR</option>
      </Select>

      {value.kind === "group" && (
        <Select
          value={value.group_slug ?? ""}
          onChange={(event) => onChange({ ...value, group_slug: event.target.value })}
          required
        >
          <option value="">Select a group…</option>
          {groups.map((group) => (
            <option key={group.id} value={group.slug}>
              {group.slug}
            </option>
          ))}
        </Select>
      )}

      {value.kind === "zone" && (
        <Select
          value={value.zone_slug ?? ""}
          onChange={(event) => onChange({ ...value, zone_slug: event.target.value })}
          required
        >
          <option value="">Select a zone…</option>
          {zones.map((zone) => (
            <option key={zone.id} value={zone.slug}>
              {zone.slug}
              {zone.routes.length > 0 && ` (+${zone.routes.length} network)`}
            </option>
          ))}
        </Select>
      )}

      {value.kind === "cidr" && (
        <Input
          value={value.cidr ?? ""}
          onChange={(event) => onChange({ ...value, cidr: event.target.value })}
          required
          className="font-mono"
          placeholder="192.168.10.0/24"
        />
      )}
    </div>
  );
}

const ANY: AclEndpoint = { kind: "any", group_slug: null, zone_slug: null, cidr: null };

export function CreateRule({ groups, zones }: { groups: Group[]; zones: Zone[] }) {
  const [ref, setRef] = useState("");
  const [name, setName] = useState("");
  const [action, setAction] = useState<"accept" | "drop" | "reject">("accept");
  const [priority, setPriority] = useState("100");
  const [src, setSrc] = useState<AclEndpoint>(ANY);
  const [dst, setDst] = useState<AclEndpoint>(ANY);
  const [protocol, setProtocol] = useState<Protocol>("any");
  const [portStart, setPortStart] = useState("");
  const [portEnd, setPortEnd] = useState("");
  const [result, setResult] = useState<Result<AclRule> | null>(null);
  const [pending, start] = useTransition();

  const portsAllowed = protocol === "tcp" || protocol === "udp";

  function submit(event: React.FormEvent) {
    event.preventDefault();
    const input: RuleInput = {
      ref,
      name: name || ref,
      priority: Number(priority),
      enabled: true,
      action,
      src,
      dst,
      protocol,
      dst_port_start: portsAllowed && portStart ? Number(portStart) : null,
      dst_port_end: portsAllowed && portEnd ? Number(portEnd) : null,
    };
    start(async () => {
      const response = await createRule(input);
      setResult(response);
      if (response.ok) {
        setRef("");
        setName("");
        setPortStart("");
        setPortEnd("");
      }
    });
  }

  return (
    <Disclosure label="New rule">
      <form onSubmit={submit} className="space-y-3">
        <div className="grid gap-3 sm:grid-cols-2">
          <Field
            label="Ref"
            hint="Stable identifier used by the exported policy document — keep it meaningful, it survives rebuilds."
          >
            <Input
              value={ref}
              onChange={(event) => setRef(event.target.value)}
              required
              maxLength={64}
              pattern="^[A-Za-z0-9_.:-]{1,64}$"
              placeholder="admin-to-backup-ssh"
            />
          </Field>
          <Field label="Name">
            <Input
              value={name}
              onChange={(event) => setName(event.target.value)}
              maxLength={128}
              placeholder="Admins reach backups over SSH"
            />
          </Field>
        </div>

        <div className="grid gap-3 sm:grid-cols-2">
          <EndpointFields
            side="Source"
            groups={groups}
            zones={zones}
            value={src}
            onChange={setSrc}
          />
          <EndpointFields
            side="Destination"
            groups={groups}
            zones={zones}
            value={dst}
            onChange={setDst}
          />
        </div>

        <div className="grid gap-3 sm:grid-cols-4">
          <Field label="Action">
            <Select
              value={action}
              onChange={(event) =>
                setAction(event.target.value as "accept" | "drop" | "reject")
              }
            >
              <option value="accept">accept</option>
              <option value="drop">drop</option>
              <option value="reject">reject</option>
            </Select>
          </Field>
          <Field label="Priority" hint="Lower runs first.">
            <Input
              type="number"
              min={0}
              max={100000}
              value={priority}
              onChange={(event) => setPriority(event.target.value)}
              required
            />
          </Field>
          <Field label="Protocol">
            <Select
              value={protocol}
              onChange={(event) => setProtocol(event.target.value as Protocol)}
            >
              <option value="any">any</option>
              <option value="tcp">tcp</option>
              <option value="udp">udp</option>
              <option value="icmp">icmp</option>
            </Select>
          </Field>
          <Field
            label="Ports"
            hint={portsAllowed ? "From – to (blank = all)." : "TCP or UDP only."}
          >
            <div className="flex gap-1">
              <Input
                type="number"
                min={1}
                max={65535}
                value={portStart}
                onChange={(event) => setPortStart(event.target.value)}
                disabled={!portsAllowed}
                placeholder="22"
              />
              <Input
                type="number"
                min={1}
                max={65535}
                value={portEnd}
                onChange={(event) => setPortEnd(event.target.value)}
                disabled={!portsAllowed || !portStart}
                placeholder="—"
              />
            </div>
          </Field>
        </div>

        <ResultNotice result={result} />
        {result?.ok && (
          <Notice kind="good">
            Rule created and the ruleset regenerated. A rule that could not be
            expressed in nftables would have been rejected instead.
          </Notice>
        )}

        <Button type="submit" variant="primary" disabled={pending}>
          {pending ? "Creating…" : "Create rule"}
        </Button>
      </form>
    </Disclosure>
  );
}

export function RuleActions({ rule, groups, zones }: { rule: AclRule; groups: Group[]; zones: Zone[] }) {
  const [result, setResult] = useState<Result<unknown> | null>(null);
  const [editing, setEditing] = useState(false);
  const [name, setName] = useState(rule.name);
  const [action, setAction] = useState(rule.action);
  const [priority, setPriority] = useState(String(rule.priority));
  const [src, setSrc] = useState<AclEndpoint>(rule.src);
  const [dst, setDst] = useState<AclEndpoint>(rule.dst);
  const [protocol, setProtocol] = useState<Protocol>(rule.protocol);
  const [portStart, setPortStart] = useState(
    rule.dst_port_start ? String(rule.dst_port_start) : "",
  );
  const [portEnd, setPortEnd] = useState(
    rule.dst_port_end ? String(rule.dst_port_end) : "",
  );
  const [pending, start] = useTransition();

  const portsAllowed = protocol === "tcp" || protocol === "udp";

  function save() {
    start(async () => {
      const response = await updateRule(rule.id, {
        name,
        action,
        priority: Number(priority),
        src,
        dst,
        protocol,
        dst_port_start: portsAllowed && portStart ? Number(portStart) : null,
        dst_port_end: portsAllowed && portEnd ? Number(portEnd) : null,
      });
      setResult(response);
      if (response.ok) setEditing(false);
    });
  }

  if (editing) {
    return (
      <div className="space-y-2 py-2 text-left">
        <Input value={name} onChange={(event) => setName(event.target.value)} />
        <div className="grid gap-2 sm:grid-cols-2">
          <EndpointFields
            side="Source"
            groups={groups}
            zones={zones}
            value={src}
            onChange={setSrc}
          />
          <EndpointFields
            side="Destination"
            groups={groups}
            zones={zones}
            value={dst}
            onChange={setDst}
          />
        </div>
        <div className="grid gap-2 sm:grid-cols-4">
          <Select
            value={action}
            onChange={(event) => setAction(event.target.value as typeof action)}
          >
            <option value="accept">accept</option>
            <option value="drop">drop</option>
            <option value="reject">reject</option>
          </Select>
          <Input
            type="number"
            value={priority}
            onChange={(event) => setPriority(event.target.value)}
          />
          <Select
            value={protocol}
            onChange={(event) => setProtocol(event.target.value as Protocol)}
          >
            <option value="any">any</option>
            <option value="tcp">tcp</option>
            <option value="udp">udp</option>
            <option value="icmp">icmp</option>
          </Select>
          <div className="flex gap-1">
            <Input
              type="number"
              value={portStart}
              onChange={(event) => setPortStart(event.target.value)}
              disabled={!portsAllowed}
              placeholder="from"
            />
            <Input
              type="number"
              value={portEnd}
              onChange={(event) => setPortEnd(event.target.value)}
              disabled={!portsAllowed || !portStart}
              placeholder="to"
            />
          </div>
        </div>
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

  return (
    <span className="inline-flex flex-wrap items-center justify-end gap-1">
      <Button variant="quiet" onClick={() => setEditing(true)}>
        Edit
      </Button>
      <Button
        variant="quiet"
        disabled={pending}
        onClick={() =>
          start(async () =>
            setResult(await updateRule(rule.id, { enabled: !rule.enabled })),
          )
        }
      >
        {rule.enabled ? "Disable" : "Enable"}
      </Button>
      <ConfirmButton
        label="Delete"
        confirmLabel="Delete rule"
        onConfirm={async () => setResult(await deleteRule(rule.id))}
      />
      <ResultNotice result={result} />
    </span>
  );
}
