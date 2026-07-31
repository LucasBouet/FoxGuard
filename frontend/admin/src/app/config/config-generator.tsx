"use client";

import { useEffect, useRef, useState, useTransition } from "react";

import {
  Button,
  Check,
  Field,
  Input,
  Notice,
  ResultNotice,
  Select,
  parseList,
} from "@/components/forms";
import { createPeer, getConfigProfile } from "@/lib/actions";
import type { Result } from "@/lib/actions";
import type {
  AllowedIpsMode,
  ClientConfigProfile,
  Group,
  Peer,
  User,
  Zone,
} from "@/lib/types";
import { configFileName, renderClientConfig } from "@/lib/wg-config";
import { generateKeypair, keyProblem, publicFromPrivate } from "@/lib/wireguard";

import { QrCode } from "./qr-code";

/**
 * A finished client configuration, without the server ever holding a secret.
 *
 * The shape of this component *is* the security property. There are exactly two
 * server calls in it -- register a peer with its public key, and read that
 * peer's profile -- and the private key is a parameter to neither. It lives in
 * React state, goes into a string, and reaches the operator through the
 * clipboard, a Blob, or a QR code drawn from a local encoder. It is never
 * written to `localStorage`, never put in a URL, and dropped from state as soon
 * as the operator says they are done with it.
 */

const MODES: Array<{ value: AllowedIpsMode; label: string; hint: string }> = [
  {
    value: "tunnel",
    label: "Tunnel only",
    hint: "The WireGuard pools. Reaches the gateway and other peers, nothing else.",
  },
  {
    value: "zone",
    label: "Its own zone",
    hint: "The pools plus the networks routed inside this device's zone.",
  },
  {
    value: "routed",
    label: "Every routed network",
    hint: "The pools plus every network any zone routes. ACLs still decide what passes.",
  },
  {
    value: "full",
    label: "Full tunnel",
    hint: "Everything, including internet. Needs a group with internet exit.",
  },
];

type KeySource = "generate" | "paste";

export function ConfigGenerator({
  peers,
  groups,
  zones,
  users,
}: {
  peers: Peer[];
  groups: Group[];
  zones: Zone[];
  users: User[];
}) {
  const [target, setTarget] = useState<"existing" | "new">(
    peers.length > 0 ? "existing" : "new",
  );
  const [peerId, setPeerId] = useState("");
  const [keySource, setKeySource] = useState<KeySource>("generate");
  const [privateKey, setPrivateKey] = useState("");
  const [revealed, setRevealed] = useState(false);

  const [mode, setMode] = useState<AllowedIpsMode>("routed");
  const [includeDns, setIncludeDns] = useState(true);
  const [keepalive, setKeepalive] = useState("");
  const [mtu, setMtu] = useState("");
  const [comments, setComments] = useState(true);

  const [profile, setProfile] = useState<ClientConfigProfile | null>(null);
  const [result, setResult] = useState<Result<unknown> | null>(null);
  const [showQr, setShowQr] = useState(false);
  const [copied, setCopied] = useState(false);
  const [pending, start] = useTransition();

  // New-device fields.
  const [name, setName] = useState("");
  const [peerType, setPeerType] = useState<"server" | "user">("user");
  const [owner, setOwner] = useState("");
  const [groupSlugs, setGroupSlugs] = useState<string[]>([]);
  const [zoneSlug, setZoneSlug] = useState("");
  const [tags, setTags] = useState("");

  const publicKey = keySource === "paste" ? publicFromPrivate(privateKey) : null;
  const pasteProblem = keySource === "paste" && privateKey ? keyProblem(privateKey) : null;

  /**
   * Changing what the config would contain drops the one on screen.
   *
   * Called from the handlers rather than from an effect on the same state:
   * registering a new device sets `peerId` itself, and an effect watching it
   * would fire mid-flight and clear the profile the generate step had just
   * fetched. A stale profile beside fresh settings is how someone hands out a
   * file that does not match what the page says it does -- and a profile that
   * vanishes a moment after appearing is how they stop trusting the page.
   */
  function invalidate() {
    setProfile(null);
    setShowQr(false);
  }

  function reset() {
    setPrivateKey("");
    setProfile(null);
    setShowQr(false);
    setRevealed(false);
    setResult(null);
    setCopied(false);
  }

  function build() {
    start(async () => {
      setResult(null);
      let key = privateKey;
      if (keySource === "generate") {
        const pair = generateKeypair();
        key = pair.privateKey;
        setPrivateKey(pair.privateKey);
      } else {
        const problem = keyProblem(key);
        if (problem) {
          setResult({ ok: false, error: `that private key is ${problem}` });
          return;
        }
      }

      const derived = publicFromPrivate(key);
      if (!derived) {
        setResult({ ok: false, error: "could not derive a public key from that value" });
        return;
      }

      let id = peerId;
      if (target === "new") {
        // Only the public half crosses this call.
        const created = await createPeer({
          name,
          peer_type: peerType,
          wg_public_key: derived,
          owner_user_id: peerType === "user" ? owner : null,
          zone_slug: zoneSlug || null,
          group_slugs: groupSlugs,
          tags: parseList(tags),
        });
        setResult(created);
        if (!created.ok) return;
        id = created.data.id;
        setPeerId(created.data.id);
      }
      if (!id) {
        setResult({ ok: false, error: "choose a device first" });
        return;
      }

      const fetched = await getConfigProfile(id, { allowedIps: mode, dns: includeDns });
      setResult(fetched);
      if (fetched.ok) setProfile(fetched.data);
    });
  }

  const overrides = {
    includeDns,
    comments,
    keepalive: keepalive === "" ? undefined : Number(keepalive),
    mtu: mtu === "" ? undefined : Number(mtu) || null,
  };

  let configText = "";
  let renderError: string | null = null;
  if (profile && privateKey) {
    try {
      configText = renderClientConfig(profile, privateKey, overrides);
    } catch (error) {
      renderError = error instanceof Error ? error.message : "could not render the config";
    }
  }

  return (
    <div className="space-y-5">
      <Notice kind="good">
        Everything below happens in this browser. The private key is generated
        here, written into the file here, and never sent to the gateway — which
        is why Foxguard can promise it stores none.
      </Notice>

      {/* ---------------------------------------------------------------- */}
      <section className="space-y-3">
        <h3 className="text-sm font-semibold">1. The device</h3>
        <div className="flex flex-wrap gap-1">
          <Choice
            active={target === "existing"}
            disabled={peers.length === 0}
            onClick={() => {
              setTarget("existing");
              invalidate();
            }}
          >
            An existing device
          </Choice>
          <Choice
            active={target === "new"}
            onClick={() => {
              setTarget("new");
              invalidate();
            }}
          >
            Register a new one
          </Choice>
        </div>

        {target === "existing" ? (
          <Field label="Device" hint="Its address, zone and routes come from the control plane.">
            <Select
              value={peerId}
              onChange={(event) => {
                setPeerId(event.target.value);
                invalidate();
              }}
            >
              <option value="">Select a device…</option>
              {peers.map((peer) => (
                <option key={peer.id} value={peer.id}>
                  {peer.name} — {peer.tunnel_ip ?? "no address"} ({peer.state})
                </option>
              ))}
            </Select>
          </Field>
        ) : (
          <NewDeviceFields
            {...{
              name,
              setName,
              peerType,
              setPeerType,
              owner,
              setOwner,
              users,
              groups,
              groupSlugs,
              setGroupSlugs,
              zones,
              zoneSlug,
              setZoneSlug,
              tags,
              setTags,
            }}
          />
        )}
      </section>

      {/* ---------------------------------------------------------------- */}
      <section className="space-y-3 border-t border-hairline pt-5">
        <h3 className="text-sm font-semibold">2. The key</h3>
        <div className="flex flex-wrap gap-1">
          <Choice active={keySource === "generate"} onClick={() => setKeySource("generate")}>
            Generate one here
          </Choice>
          <Choice active={keySource === "paste"} onClick={() => setKeySource("paste")}>
            I already have a private key
          </Choice>
        </div>

        {keySource === "paste" && (
          <Field
            label="Private key"
            hint="Stays in this browser. The public half is derived here and is the only part that reaches the gateway."
          >
            <Input
              value={privateKey}
              onChange={(event) => setPrivateKey(event.target.value)}
              type={revealed ? "text" : "password"}
              autoComplete="off"
              spellCheck={false}
              className="font-mono"
              placeholder="wg genkey"
            />
          </Field>
        )}
        {pasteProblem && <Notice kind="error">That private key is {pasteProblem}.</Notice>}
        {publicKey && (
          <p className="text-xs text-ink-secondary">
            Public key: <code className="font-mono">{publicKey}</code>
          </p>
        )}
      </section>

      {/* ---------------------------------------------------------------- */}
      <section className="space-y-3 border-t border-hairline pt-5">
        <h3 className="text-sm font-semibold">3. Settings</h3>
        <Field
          label="AllowedIPs"
          hint={MODES.find((option) => option.value === mode)?.hint}
        >
          <Select
            value={mode}
            onChange={(event) => {
              setMode(event.target.value as AllowedIpsMode);
              invalidate();
            }}
          >
            {MODES.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </Select>
        </Field>
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="PersistentKeepalive" hint="Empty uses the gateway default. 0 omits the line.">
            <Input
              value={keepalive}
              onChange={(event) => setKeepalive(event.target.value)}
              type="number"
              min={0}
              max={65535}
              placeholder="default"
            />
          </Field>
          <Field label="MTU" hint="Empty lets wg-quick work it out. 1420 is the usual fix over Ethernet.">
            <Input
              value={mtu}
              onChange={(event) => setMtu(event.target.value)}
              type="number"
              min={576}
              max={9000}
              placeholder="automatic"
            />
          </Field>
        </div>
        <Check
          label="Point the device at the internal resolver"
          hint="Adds the DNS line. Off if the device has resolvers it must keep."
          checked={includeDns}
          onChange={(value) => {
            setIncludeDns(value);
            invalidate();
          }}
        />
        <Check
          label="Include the comment header"
          hint="A line naming the device. Turn it off for the smallest QR code."
          checked={comments}
          onChange={setComments}
        />
      </section>

      {/* ---------------------------------------------------------------- */}
      <div className="flex flex-wrap items-center gap-2 border-t border-hairline pt-5">
        <Button variant="primary" onClick={build} disabled={pending}>
          {pending ? "Working…" : "Generate configuration"}
        </Button>
        {(profile || privateKey) && (
          <Button onClick={reset} disabled={pending}>
            Clear
          </Button>
        )}
      </div>

      <ResultNotice result={result} />

      {profile && (
        <Output
          profile={profile}
          configText={configText}
          renderError={renderError}
          revealed={revealed}
          setRevealed={setRevealed}
          showQr={showQr}
          setShowQr={setShowQr}
          copied={copied}
          setCopied={setCopied}
        />
      )}
    </div>
  );
}

// --------------------------------------------------------------------------- //

function Choice({
  active,
  disabled,
  onClick,
  children,
}: {
  active: boolean;
  disabled?: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      disabled={disabled}
      onClick={onClick}
      className={`rounded-md border px-2.5 py-1 text-sm disabled:opacity-40 ${
        active
          ? "border-hairline bg-page font-medium"
          : "border-transparent text-ink-secondary hover:bg-page"
      }`}
    >
      {children}
    </button>
  );
}

function NewDeviceFields(props: {
  name: string;
  setName: (value: string) => void;
  peerType: "server" | "user";
  setPeerType: (value: "server" | "user") => void;
  owner: string;
  setOwner: (value: string) => void;
  users: User[];
  groups: Group[];
  groupSlugs: string[];
  setGroupSlugs: (value: string[]) => void;
  zones: Zone[];
  zoneSlug: string;
  setZoneSlug: (value: string) => void;
  tags: string;
  setTags: (value: string) => void;
}) {
  return (
    <div className="space-y-3">
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Name">
          <Input
            value={props.name}
            onChange={(event) => props.setName(event.target.value)}
            maxLength={128}
            placeholder="ada-laptop"
          />
        </Field>
        <Field label="Type">
          <Select
            value={props.peerType}
            onChange={(event) => props.setPeerType(event.target.value as "server" | "user")}
          >
            <option value="user">user — a person&rsquo;s device</option>
            <option value="server">server — a machine</option>
          </Select>
        </Field>
      </div>
      {props.peerType === "user" && (
        <Field label="Owner" hint="Only this account can unlock this device on the portal.">
          <Select value={props.owner} onChange={(event) => props.setOwner(event.target.value)}>
            <option value="">Select an account…</option>
            {props.users.map((user) => (
              <option key={user.id} value={user.id}>
                {user.username}
              </option>
            ))}
          </Select>
        </Field>
      )}
      <div>
        <span className="text-sm text-ink-secondary">Groups</span>
        <div className="mt-1 flex flex-wrap gap-2">
          {props.groups.length === 0 && (
            <span className="text-sm text-ink-muted">No groups yet.</span>
          )}
          {props.groups.map((group) => (
            <button
              key={group.id}
              type="button"
              onClick={() =>
                props.setGroupSlugs(
                  props.groupSlugs.includes(group.slug)
                    ? props.groupSlugs.filter((slug) => slug !== group.slug)
                    : [...props.groupSlugs, group.slug],
                )
              }
              className={`rounded-md border px-2.5 py-1 text-sm ${
                props.groupSlugs.includes(group.slug)
                  ? "border-hairline bg-page font-medium"
                  : "border-transparent text-ink-secondary hover:bg-page"
              }`}
            >
              {group.slug}
            </button>
          ))}
        </div>
      </div>
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Zone" hint="At most one. Its routes come with it.">
          <Select
            value={props.zoneSlug}
            onChange={(event) => props.setZoneSlug(event.target.value)}
          >
            <option value="">no zone</option>
            {props.zones.map((zone) => (
              <option key={zone.id} value={zone.slug}>
                {zone.slug}
              </option>
            ))}
          </Select>
        </Field>
        <Field label="Tags" hint="Comma separated. Dashboard filtering only.">
          <Input value={props.tags} onChange={(event) => props.setTags(event.target.value)} />
        </Field>
      </div>
    </div>
  );
}

function Output({
  profile,
  configText,
  renderError,
  revealed,
  setRevealed,
  showQr,
  setShowQr,
  copied,
  setCopied,
}: {
  profile: ClientConfigProfile;
  configText: string;
  renderError: string | null;
  revealed: boolean;
  setRevealed: (value: boolean) => void;
  showQr: boolean;
  setShowQr: (value: boolean) => void;
  copied: boolean;
  setCopied: (value: boolean) => void;
}) {
  const objectUrl = useRef<string | null>(null);

  // Object URLs keep the Blob -- and therefore the private key -- alive in the
  // page for as long as they exist. Revoked as soon as the download is handed
  // to the browser, and again on unmount.
  useEffect(() => {
    return () => {
      if (objectUrl.current) URL.revokeObjectURL(objectUrl.current);
    };
  }, []);

  function download() {
    const blob = new Blob([configText], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    objectUrl.current = url;
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = configFileName(profile);
    anchor.click();
    URL.revokeObjectURL(url);
    objectUrl.current = null;
  }

  return (
    <div className="space-y-3 border-t border-hairline pt-5">
      <h3 className="text-sm font-semibold">The configuration</h3>

      {profile.warnings.map((warning) => (
        <Notice key={warning} kind="warning">
          {warning}
        </Notice>
      ))}

      {!profile.complete && (
        <Notice kind="error">
          This deployment has not been told its own public key or endpoint, so no
          valid configuration can be produced yet. The warnings above name the
          settings to fill in.
        </Notice>
      )}
      {renderError && <Notice kind="error">{renderError}</Notice>}

      {configText && (
        <>
          <div className="rounded-md border border-hairline bg-page p-3">
            <pre className="overflow-x-auto font-mono text-xs leading-relaxed">
              {revealed
                ? configText
                : configText.replace(
                    /^(PrivateKey = ).*$/m,
                    "$1············································",
                  )}
            </pre>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <Button
              variant="primary"
              onClick={() => {
                void navigator.clipboard?.writeText(configText);
                setCopied(true);
              }}
            >
              {copied ? "Copied" : "Copy"}
            </Button>
            <Button onClick={download}>Download {configFileName(profile)}</Button>
            <Button onClick={() => setShowQr(!showQr)}>
              {showQr ? "Hide QR code" : "Show QR code"}
            </Button>
            <Button variant="quiet" onClick={() => setRevealed(!revealed)}>
              {revealed ? "Hide the private key" : "Reveal the private key"}
            </Button>
          </div>

          {showQr && (
            <div className="space-y-2">
              <QrCode text={configText} />
              <p className="text-xs text-ink-secondary">
                Scan it with the WireGuard app. This is the whole file, private
                key and all — treat the screen as you would the file.
              </p>
            </div>
          )}

          <p className="text-xs text-ink-muted">
            Foxguard cannot show you this key again: it is not stored anywhere.
            Lose it and the device needs a new one.
          </p>
        </>
      )}
    </div>
  );
}
