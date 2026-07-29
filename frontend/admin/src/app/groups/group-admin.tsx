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
} from "@/components/forms";
import { createGroup, deleteGroup, updateGroup } from "@/lib/actions";
import type { Result } from "@/lib/actions";
import type { Group } from "@/lib/types";

const SLUG_PATTERN = "^[a-z0-9][a-z0-9_-]{0,23}$";

export function CreateGroup() {
  const [slug, setSlug] = useState("");
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [internetExit, setInternetExit] = useState(false);
  const [lifetime, setLifetime] = useState("");
  const [result, setResult] = useState<Result<unknown> | null>(null);
  const [pending, start] = useTransition();

  function submit(event: React.FormEvent) {
    event.preventDefault();
    start(async () => {
      const response = await createGroup({
        slug,
        name: name || slug,
        description: description || undefined,
        internet_exit: internetExit,
        session_lifetime_seconds: lifetime ? Number(lifetime) * 3600 : null,
      });
      setResult(response);
      if (response.ok) {
        setSlug("");
        setName("");
        setDescription("");
        setInternetExit(false);
        setLifetime("");
      }
    });
  }

  return (
    <Disclosure label="New group">
      <form onSubmit={submit} className="space-y-3">
        <div className="grid gap-3 sm:grid-cols-2">
          <Field
            label="Slug"
            hint="Becomes part of an nftables set name: lowercase, digits, - and _, max 24."
          >
            <Input
              value={slug}
              onChange={(event) => setSlug(event.target.value)}
              pattern={SLUG_PATTERN}
              maxLength={24}
              required
              placeholder="pentest-lab"
            />
          </Field>
          <Field label="Name" hint="Free text, shown in the UI.">
            <Input
              value={name}
              onChange={(event) => setName(event.target.value)}
              maxLength={128}
              placeholder="Pentest lab"
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
          hint="Blank uses the global default. A peer in several groups gets the shortest of them, and shortening this ends sessions that are already running."
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
          label="Internet exit"
          hint="Members may reach the internet through the gateway. They still cannot reach FOXGUARD_INTERNAL_CIDRS without an explicit rule, and this needs FOXGUARD_WAN_INTERFACE set."
          checked={internetExit}
          onChange={setInternetExit}
        />

        <ResultNotice result={result} />
        {result?.ok && <Notice kind="good">Group created.</Notice>}

        <Button type="submit" variant="primary" disabled={pending || !slug}>
          {pending ? "Creating…" : "Create group"}
        </Button>
      </form>
    </Disclosure>
  );
}

export function GroupActions({ group }: { group: Group }) {
  const [editing, setEditing] = useState(false);
  const [name, setName] = useState(group.name);
  const [internetExit, setInternetExit] = useState(group.internet_exit);
  const [lifetime, setLifetime] = useState(
    group.session_lifetime_seconds ? String(group.session_lifetime_seconds / 3600) : "",
  );
  const [result, setResult] = useState<Result<unknown> | null>(null);
  const [pending, start] = useTransition();

  function save() {
    start(async () => {
      const response = await updateGroup(group.id, {
        name,
        internet_exit: internetExit,
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
          confirmLabel="Delete group"
          warning="ACL rules referencing it are deleted too."
          onConfirm={async () => setResult(await deleteGroup(group.id))}
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
