"use client";

import { useState } from "react";

import { ConfirmButton, ResultNotice } from "@/components/forms";
import { revokeAdminSession } from "@/lib/actions";
import type { Result } from "@/lib/actions";

export function RevokeSession({ id, current }: { id: string; current: boolean }) {
  const [result, setResult] = useState<Result<unknown> | null>(null);

  return (
    <span className="inline-flex items-center gap-2">
      <ConfirmButton
        label="Revoke"
        confirmLabel="Revoke session"
        warning={
          current
            ? "This is the session you are using — you will be signed out."
            : undefined
        }
        onConfirm={async () => setResult(await revokeAdminSession(id))}
      />
      <ResultNotice result={result} />
    </span>
  );
}
