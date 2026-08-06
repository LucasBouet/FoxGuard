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
  SecretOnce,
  Select,
  SlugChips,
  parseList,
  toggleSlug,
} from "@/components/forms";
import {
  createEnrollmentKey,
  createPeer,
  deletePeer,
  revokeEnrollmentKey,
  updatePeer,
} from "@/lib/actions";
import type { Result } from "@/lib/actions";
import type { EnrollmentKey, Group, Peer, User, Zone } from "@/lib/types";

export function CreatePeer({
  groups,
  zones,
  users,
}: {
  groups: Group[];
  zones: Zone[];
  users: User[];
}) {
  const [name, setName] = useState("");
  const [peerType, setPeerType] = useState<"server" | "user">("server");
  const [publicKey, setPublicKey] = useState("");
  const [owner, setOwner] = useState("");
  const [groupSlugs, setGroupSlugs] = useState<string[]>([]);
  const [zoneSlug, setZoneSlug] = useState("");
  const [dnsLabel, setDnsLabel] = useState("");
  const [tags, setTags] = useState("");
  const [result, setResult] = useState<Result<Peer> | null>(null);
  const [created, setCreated] = useState<Peer | null>(null);
  const [pending, start] = useTransition();

  function toggleGroup(slug: string) {
    setGroupSlugs((current) =>
      current.includes(slug) ? current.filter((s) => s !== slug) : [...current, slug],
    );
  }

  function submit(event: React.FormEvent) {
    event.preventDefault();
    start(async () => {
      const response = await createPeer({
        name,
        peer_type: peerType,
        wg_public_key: publicKey.trim(),
        owner_user_id: peerType === "user" ? owner : null,
        dns_label: dnsLabel || null,
        zone_slug: zoneSlug || null,
        group_slugs: groupSlugs,
        tags: parseList(tags),
      });
      setResult(response);
      if (response.ok) {
        setCreated(response.data);
        setName("");
        setPublicKey("");
        setDnsLabel("");
        setTags("");
      }
    });
  }

  return (
    <Disclosure label="Register a peer">
      <form onSubmit={submit} className="space-y-3">
        {/*
          The private key is generated on the device and never sent here. Saying
          so on the form is the cheapest way to stop someone pasting one.
        */}
        <Notice kind="warning">
          Generate the keypair <strong>on the device</strong> and paste only the
          public key: <code className="font-mono">wg genkey | tee private.key | wg pubkey</code>.
          Foxguard never stores private keys.
        </Notice>

        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="Name">
            <Input
              value={name}
              onChange={(event) => setName(event.target.value)}
              required
              maxLength={128}
              placeholder="backup-01"
            />
          </Field>
          <Field
            label="Type"
            hint={
              peerType === "server"
                ? "Enrolls with a key, never expires, no portal."
                : "Logs in on the portal, session expires, must be bound to an account."
            }
          >
            <Select
              value={peerType}
              onChange={(event) =>
                setPeerType(event.target.value as "server" | "user")
              }
            >
              <option value="server">server — a machine</option>
              <option value="user">user — a person&rsquo;s device</option>
            </Select>
          </Field>
        </div>

        <Field label="WireGuard public key" hint="44 base64 characters.">
          <Input
            value={publicKey}
            onChange={(event) => setPublicKey(event.target.value)}
            required
            className="font-mono"
            placeholder="xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="
          />
        </Field>

        {peerType === "user" && (
          <Field
            label="Owner"
            hint="Bound at registration, never inferred later. Only this account can unlock this device."
          >
            <Select
              value={owner}
              onChange={(event) => setOwner(event.target.value)}
              required
            >
              <option value="">Select an account…</option>
              {users.map((user) => (
                <option key={user.id} value={user.id}>
                  {user.username}
                </option>
              ))}
            </Select>
          </Field>
        )}

        <div>
          <span className="text-sm text-ink-secondary">Groups</span>
          <div className="mt-1">
            <SlugChips
              options={groups}
              selected={groupSlugs}
              onToggle={toggleGroup}
              empty="No groups yet."
            />
          </div>
        </div>

        <div className="grid gap-3 sm:grid-cols-2">
          <Field
            label="Zone"
            hint="Where the device sits. At most one, and its routes come with it. Groups above are what the device does, and it can hold several."
          >
            <Select value={zoneSlug} onChange={(event) => setZoneSlug(event.target.value)}>
              <option value="">no zone</option>
              {zones.map((zone) => (
                <option key={zone.id} value={zone.slug}>
                  {zone.slug}
                </option>
              ))}
            </Select>
          </Field>
          <Field
            label="DNS name"
            hint="Left empty, one is derived from the device name. A name that is already taken is refused rather than silently numbered."
          >
            <Input
              value={dnsLabel}
              onChange={(event) => setDnsLabel(event.target.value)}
              maxLength={63}
              className="font-mono"
              placeholder="derived from the name"
            />
          </Field>
        </div>

        <Field label="Tags" hint="Comma separated. Dashboard filtering only — no effect on ACLs.">
          <Input value={tags} onChange={(event) => setTags(event.target.value)} />
        </Field>

        <ResultNotice result={result} />
        {created && (
          <Notice kind="good">
            <strong>{created.name}</strong> registered at{" "}
            <code className="font-mono">{created.tunnel_ip}</code> in state{" "}
            <code className="font-mono">staging</code> — it has no access until it
            enrolls or signs in.
          </Notice>
        )}

        <Button type="submit" variant="primary" disabled={pending}>
          {pending ? "Registering…" : "Register peer"}
        </Button>
      </form>
    </Disclosure>
  );
}

export function PeerActions({
  peer,
  groups,
  zones,
}: {
  peer: Peer;
  groups: Group[];
  zones: Zone[];
}) {
  const [result, setResult] = useState<Result<unknown> | null>(null);
  const [key, setKey] = useState<EnrollmentKey | null>(null);
  const [expiry, setExpiry] = useState("");
  const [open, setOpen] = useState(false);
  const [memberOf, setMemberOf] = useState<string[]>(peer.group_slugs);
  const [zoneSlug, setZoneSlug] = useState(peer.zone_slug ?? "");
  const [tags, setTags] = useState(peer.tags.join(", "));
  const [pending, start] = useTransition();

  function act(fn: () => Promise<Result<unknown>>) {
    start(async () => setResult(await fn()));
  }

  const membershipChanged =
    memberOf.slice().sort().join() !== peer.group_slugs.slice().sort().join() ||
    zoneSlug !== (peer.zone_slug ?? "") ||
    parseList(tags).join() !== peer.tags.join();

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center justify-end gap-1">
        <Button variant="quiet" onClick={() => setOpen(!open)}>
          {open ? "Hide" : "Manage"}
        </Button>
      </div>

      {open && (
        <div className="space-y-3 rounded-md border border-hairline bg-page p-3 text-left">
          <div className="space-y-2">
            <p className="text-xs text-ink-secondary">
              Groups — changing these rewrites the ruleset immediately, and
              moving a peer into a stricter group shortens a session it already
              has.
            </p>
            <SlugChips
              options={groups}
              selected={memberOf}
              on="surface"
              onToggle={(slug) =>
                setMemberOf((current) => toggleSlug(current, slug))
              }
            />
            <Field label="Zone">
              <Select
                value={zoneSlug}
                onChange={(event) => setZoneSlug(event.target.value)}
              >
                <option value="">no zone</option>
                {zones.map((zone) => (
                  <option key={zone.id} value={zone.slug}>
                    {zone.slug}
                  </option>
                ))}
              </Select>
            </Field>
            <Field label="Tags">
              <Input value={tags} onChange={(event) => setTags(event.target.value)} />
            </Field>
            <Button
              disabled={pending || !membershipChanged}
              onClick={() =>
                act(() =>
                  updatePeer(peer.id, {
                    group_slugs: memberOf,
                    zone_slug: zoneSlug || null,
                    tags: parseList(tags),
                  }),
                )
              }
            >
              {membershipChanged ? "Save membership" : "No changes"}
            </Button>
          </div>

          <div className="border-t border-hairline pt-3" />
          <div className="flex flex-wrap gap-1">
            {peer.state !== "quarantined" && peer.state !== "revoked" && (
              <Button
                disabled={pending}
                onClick={() => act(() => updatePeer(peer.id, { state: "quarantined" }))}
              >
                Quarantine
              </Button>
            )}
            {peer.state !== "disabled" && peer.state !== "revoked" && (
              <Button
                disabled={pending}
                onClick={() => act(() => updatePeer(peer.id, { state: "disabled" }))}
              >
                Disable
              </Button>
            )}
            {peer.state === "disabled" && (
              <Button
                disabled={pending}
                onClick={() => act(() => updatePeer(peer.id, { state: "staging" }))}
              >
                Re-enable (to staging)
              </Button>
            )}
          </div>

          {peer.state !== "revoked" && (
            <ConfirmButton
              label="Revoke"
              confirmLabel="Revoke permanently"
              warning="Terminal: no key and no password brings it back. You would have to register it again with a new keypair."
              onConfirm={async () =>
                setResult(await updatePeer(peer.id, { state: "revoked" }))
              }
            />
          )}

          {peer.peer_type === "server" && (
            <div className="space-y-2 border-t border-hairline pt-3">
              <p className="text-xs text-ink-secondary">
                Enrollment key — generating a new one invalidates the previous.
              </p>
              <div className="flex flex-wrap items-end gap-2">
                <Field label="Expires (optional)">
                  <Input
                    type="datetime-local"
                    value={expiry}
                    onChange={(event) => setExpiry(event.target.value)}
                  />
                </Field>
                <Button
                  disabled={pending}
                  onClick={() =>
                    start(async () => {
                      const response = await createEnrollmentKey(
                        peer.id,
                        expiry ? new Date(expiry).toISOString() : null,
                      );
                      setResult(response);
                      if (response.ok) setKey(response.data);
                    })
                  }
                >
                  Generate key
                </Button>
                <ConfirmButton
                  label="Revoke key"
                  confirmLabel="Revoke key"
                  warning="Also quarantines the peer immediately."
                  onConfirm={async () =>
                    setResult(await revokeEnrollmentKey(peer.id))
                  }
                />
              </div>

              {key && (
                <SecretOnce
                  title="Copy this enrollment key now"
                  value={key.enrollment_key}
                  note="Only its hash is stored — this is the one time it is shown. Provision it onto the device, which presents it from inside the tunnel."
                >
                  <p className="mt-2 text-xs text-ink-secondary">
                    On the device:{" "}
                    <code className="font-mono">
                      curl -X POST http://&lt;gateway&gt;:8080/api/v1/enroll -H
                      &apos;Content-Type: application/json&apos; -d
                      &apos;&#123;&quot;enrollment_key&quot;:&quot;…&quot;&#125;&apos;
                    </code>
                  </p>
                </SecretOnce>
              )}
            </div>
          )}

          <div className="border-t border-hairline pt-3">
            <ConfirmButton
              label="Delete peer"
              confirmLabel="Delete"
              warning="Removes it from WireGuard and the ruleset entirely."
              onConfirm={async () => setResult(await deletePeer(peer.id))}
            />
          </div>

          <ResultNotice result={result} />
        </div>
      )}
    </div>
  );
}
