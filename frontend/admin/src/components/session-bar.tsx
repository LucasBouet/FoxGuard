"use client";

import { useTransition } from "react";

import { signOut } from "@/lib/actions";
import type { AdminWhoAmI } from "@/lib/types";

import { Dot } from "./forms";

/**
 * Who the dashboard is acting as.
 *
 * Shown always, not only when signed in: a deployment running on the shared
 * token attributes every action to `admin-token`, and that is a state the
 * operator should be able to see rather than discover in the audit log later.
 */
export function SessionBar({ who }: { who: AdminWhoAmI | null }) {
  const [pending, start] = useTransition();

  if (!who) {
    return (
      <a href="/login" className="text-sm text-ink-secondary underline underline-offset-2">
        Sign in
      </a>
    );
  }

  if (who.via === "token") {
    return (
      <span className="flex items-center gap-1.5 text-sm text-ink-secondary">
        <Dot className="bg-status-warning" />
        shared token
        <a href="/login" className="underline underline-offset-2">
          sign in
        </a>
      </span>
    );
  }

  return (
    <span className="flex items-center gap-2 text-sm text-ink-secondary">
      <span className="flex items-center gap-1.5">
        <Dot className="bg-status-good" />
        {who.display_name || who.username}
      </span>
      <button
        type="button"
        disabled={pending}
        onClick={() => start(async () => void (await signOut()))}
        className="underline underline-offset-2 disabled:opacity-50"
      >
        {pending ? "…" : "sign out"}
      </button>
    </span>
  );
}
