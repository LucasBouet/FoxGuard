"use client";

import { useState, useTransition } from "react";

import {
  Button,
  ConfirmButton,
  Disclosure,
  Field,
  Input,
  Notice,
  ResultNotice,
  Select,
} from "@/components/forms";
import { createDnsRecord, deleteDnsRecord, updateDnsRecord } from "@/lib/actions";
import type { Result } from "@/lib/actions";
import type { DnsRecord, DnsRecordKind } from "@/lib/types";

//: A zone-relative name, which may carry dots: "git.services".
const NAME_PATTERN = "^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$";

const VALUE_HINT: Record<DnsRecordKind, string> = {
  A: "An IPv4 address. It may be off the tunnel — this is how a service on the LAN behind the gateway gets a name.",
  AAAA: "An IPv6 address.",
  CNAME: "Another name in this zone, written relative to it. It must already exist, or the record would be a silently dead alias.",
};

export function CreateDnsRecord() {
  const [name, setName] = useState("");
  const [kind, setKind] = useState<DnsRecordKind>("A");
  const [value, setValue] = useState("");
  const [description, setDescription] = useState("");
  const [result, setResult] = useState<Result<unknown> | null>(null);
  const [pending, start] = useTransition();

  function submit(event: React.FormEvent) {
    event.preventDefault();
    start(async () => {
      const response = await createDnsRecord({
        name,
        kind,
        value,
        description: description || undefined,
      });
      setResult(response);
      if (response.ok) {
        setName("");
        setValue("");
        setDescription("");
      }
    });
  }

  return (
    <Disclosure label="New DNS record">
      <form onSubmit={submit} className="space-y-3">
        <div className="grid gap-3 sm:grid-cols-3">
          <Field
            label="Name"
            hint="Relative to the zone, so renaming the zone does not orphan it."
          >
            <Input
              value={name}
              onChange={(event) => setName(event.target.value)}
              pattern={NAME_PATTERN}
              maxLength={253}
              required
              className="font-mono"
              placeholder="portal"
            />
          </Field>
          <Field label="Type">
            <Select
              value={kind}
              onChange={(event) => setKind(event.target.value as DnsRecordKind)}
            >
              <option value="A">A</option>
              <option value="AAAA">AAAA</option>
              <option value="CNAME">CNAME</option>
            </Select>
          </Field>
          <Field label="Value" hint={VALUE_HINT[kind]}>
            <Input
              value={value}
              onChange={(event) => setValue(event.target.value)}
              required
              className="font-mono"
              placeholder={kind === "CNAME" ? "gw" : "192.168.1.50"}
            />
          </Field>
        </div>

        <Field label="Description">
          <Input
            value={description}
            onChange={(event) => setDescription(event.target.value)}
          />
        </Field>

        <ResultNotice result={result} />
        {result?.ok && <Notice kind="good">Record created.</Notice>}

        <Button type="submit" variant="primary" disabled={pending || !name || !value}>
          {pending ? "Creating…" : "Create record"}
        </Button>
      </form>
    </Disclosure>
  );
}

export function DnsRecordActions({ record }: { record: DnsRecord }) {
  const [editing, setEditing] = useState(false);
  const [value, setValue] = useState(record.value);
  const [description, setDescription] = useState(record.description ?? "");
  const [result, setResult] = useState<Result<unknown> | null>(null);
  const [pending, start] = useTransition();

  function save() {
    start(async () => {
      const response = await updateDnsRecord(record.id, { value, description });
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
        <Button
          variant="quiet"
          disabled={pending}
          onClick={() =>
            start(async () =>
              setResult(
                await updateDnsRecord(record.id, { enabled: !record.enabled }),
              ),
            )
          }
        >
          {record.enabled ? "Disable" : "Enable"}
        </Button>
        <ConfirmButton
          label="Delete"
          confirmLabel="Delete record"
          warning="An alias pointing at it stops resolving too, and the API refuses the change if that would break the zone."
          onConfirm={async () => setResult(await deleteDnsRecord(record.id))}
        />
        <ResultNotice result={result} />
      </span>
    );
  }

  return (
    <div className="space-y-2 py-2">
      <Input
        value={value}
        onChange={(event) => setValue(event.target.value)}
        className="font-mono"
      />
      <Input
        value={description}
        onChange={(event) => setDescription(event.target.value)}
        placeholder="description"
      />
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
