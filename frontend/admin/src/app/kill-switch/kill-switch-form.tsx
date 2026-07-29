"use client";

import { useState, useTransition } from "react";

import { Card, Cell, Dot, Row, Table } from "@/components/ui";
import { triggerKillSwitch } from "@/lib/actions";
import type { KillSwitchResult } from "@/lib/types";

/**
 * Two deliberate obstacles between an operator and a fleet-wide cut:
 *
 *  1. the mode has to be chosen explicitly — there is no default selection;
 *  2. the confirmation phrase has to be typed, not clicked. It is passed to the
 *     API verbatim, which rejects anything else, so the guard does not depend on
 *     this form being the only caller.
 *
 * There is no undo, and the page says so before the button, not after.
 */

const MODES = {
  quarantine: {
    phrase: "QUARANTINE ALL PEERS",
    title: "Quarantine everything",
    summary:
      "Every active peer goes back to quarantine and loses its open connections. Users can log in again immediately.",
    caveat:
      "A server peer re-presents its enrollment key automatically, so it can be back within one poll. This forces re-authentication; it does not hold the fleet down.",
    accent: "bg-status-warning",
  },
  lockdown: {
    phrase: "DISABLE ALL PEERS",
    title: "Lock down everything",
    summary:
      "Every peer is disabled: no dataplane presence at all, and no credential brings one back.",
    caveat:
      "Only an administrator can restore access, peer by peer. This is the one to use if you actually suspect a compromise.",
    accent: "bg-status-critical",
  },
} as const;

type Mode = keyof typeof MODES;

export function KillSwitchForm() {
  const [mode, setMode] = useState<Mode | null>(null);
  const [confirm, setConfirm] = useState("");
  const [result, setResult] = useState<KillSwitchResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();

  const selected = mode ? MODES[mode] : null;
  const armed = selected !== null && confirm === selected.phrase;

  function fire() {
    if (!mode || !armed) return;
    setError(null);
    startTransition(async () => {
      const response = await triggerKillSwitch(mode, confirm);
      if (response.ok) {
        setResult(response.data);
        setConfirm("");
        setMode(null);
      } else {
        setError(response.error);
      }
    });
  }

  return (
    <div className="space-y-4">
      <div className="grid gap-3 sm:grid-cols-2">
        {(Object.keys(MODES) as Mode[]).map((key) => {
          const option = MODES[key];
          const active = mode === key;
          return (
            <button
              key={key}
              type="button"
              onClick={() => {
                setMode(active ? null : key);
                setConfirm("");
                setError(null);
              }}
              className={`rounded-lg border p-4 text-left ${
                active ? "border-ink bg-page" : "border-hairline bg-surface hover:bg-page"
              }`}
            >
              <span className="flex items-center gap-1.5 font-medium">
                <Dot className={option.accent} />
                {option.title}
              </span>
              <span className="mt-2 block text-sm text-ink-secondary">
                {option.summary}
              </span>
              <span className="mt-2 block text-sm text-ink-secondary">
                {option.caveat}
              </span>
            </button>
          );
        })}
      </div>

      {selected && (
        <Card>
          <p className="text-sm">
            This cannot be undone. Restoring the fleet is a deliberate,
            peer-by-peer act; the previous state of every peer is written to the
            audit log so it can be reconstructed.
          </p>
          <label className="mt-4 block text-sm">
            <span className="text-ink-secondary">
              Type <code className="font-mono font-medium text-ink">{selected.phrase}</code> to
              confirm
            </span>
            <input
              value={confirm}
              onChange={(event) => setConfirm(event.target.value)}
              autoComplete="off"
              spellCheck={false}
              className="mt-1 w-full max-w-md rounded-md border border-hairline bg-page px-3 py-2 font-mono text-sm text-ink"
            />
          </label>
          <button
            type="button"
            onClick={fire}
            disabled={!armed || pending}
            className="mt-4 rounded-md border border-hairline bg-page px-4 py-2 text-sm font-semibold disabled:opacity-40"
          >
            {pending ? "Cutting…" : selected.title}
          </button>
        </Card>
      )}

      {error && (
        <Card>
          <p className="flex items-start gap-2 text-sm">
            <Dot className="mt-1.5 bg-status-critical" />
            <span>{error}</span>
          </p>
        </Card>
      )}

      {result && (
        <Card
          title={`Fired: ${result.mode}`}
          description={`${result.affected.length} peer(s) cut, ${result.sessions_revoked} session(s) revoked.`}
        >
          <Table headers={["Peer", "Type", "Was", "Now"]} empty="Nothing was active.">
            {result.affected.map((peer) => (
              <Row key={peer.peer_id}>
                <Cell className="font-medium">{peer.name}</Cell>
                <Cell className="text-ink-secondary">{peer.peer_type}</Cell>
                <Cell className="text-ink-secondary">{peer.previous_state}</Cell>
                <Cell>{peer.state}</Cell>
              </Row>
            ))}
          </Table>
        </Card>
      )}
    </div>
  );
}
