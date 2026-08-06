"use client";

import { useState } from "react";

import type { Result } from "@/lib/actions";

/** Shared form vocabulary, so twelve forms do not invent twelve layouts. */

export function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: React.ReactNode;
}) {
  return (
    <label className="block text-sm">
      <span className="text-ink-secondary">{label}</span>
      {children}
      {hint && <span className="mt-1 block text-xs text-ink-muted">{hint}</span>}
    </label>
  );
}

const CONTROL =
  "mt-1 w-full rounded-md border border-hairline bg-page px-3 py-2 text-sm text-ink";

export function Input(props: React.InputHTMLAttributes<HTMLInputElement>) {
  return <input {...props} className={`${CONTROL} ${props.className ?? ""}`} />;
}

export function Select(props: React.SelectHTMLAttributes<HTMLSelectElement>) {
  return <select {...props} className={`${CONTROL} ${props.className ?? ""}`} />;
}

export function Check({
  label,
  hint,
  checked,
  onChange,
}: {
  label: string;
  hint?: string;
  checked: boolean;
  onChange: (value: boolean) => void;
}) {
  return (
    <label className="flex items-start gap-2 text-sm">
      <input
        type="checkbox"
        checked={checked}
        onChange={(event) => onChange(event.target.checked)}
        className="mt-1"
      />
      <span>
        {label}
        {hint && <span className="block text-xs text-ink-muted">{hint}</span>}
      </span>
    </label>
  );
}

/**
 * A set of slugs, toggled as chips. Used wherever membership is edited — a
 * peer's groups, a person's groups, and the groups an SSO service demands — so
 * that the same thing always looks and behaves the same way.
 */
export function SlugChips({
  options,
  selected,
  onToggle,
  empty = "No groups defined yet.",
  // Which way the chip lifts off its background: "surface" for a chip sitting
  // on the page, "page" for one already inside a raised panel.
  on = "page",
}: {
  options: { id: string; slug: string }[];
  selected: string[];
  onToggle: (slug: string) => void;
  empty?: string;
  on?: "page" | "surface";
}) {
  if (options.length === 0) {
    return <p className="text-xs text-ink-muted">{empty}</p>;
  }
  const lift = on === "page" ? "bg-page" : "bg-surface";
  const hover = on === "page" ? "hover:bg-page" : "hover:bg-surface";
  return (
    <div className="flex flex-wrap gap-1">
      {options.map((option) => (
        <button
          key={option.id}
          type="button"
          onClick={() => onToggle(option.slug)}
          aria-pressed={selected.includes(option.slug)}
          className={`rounded-md border px-2.5 py-1 text-sm ${
            selected.includes(option.slug)
              ? `border-hairline ${lift} font-medium`
              : `border-transparent text-ink-secondary ${hover}`
          }`}
        >
          {option.slug}
        </button>
      ))}
    </div>
  );
}

/** Add or remove one slug — the state update every {@link SlugChips} wants. */
export function toggleSlug(current: string[], slug: string): string[] {
  return current.includes(slug)
    ? current.filter((item) => item !== slug)
    : [...current, slug];
}

export function Button({
  children,
  variant = "default",
  ...props
}: React.ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "default" | "primary" | "quiet";
}) {
  const styles = {
    default: "border-hairline hover:bg-page",
    primary: "border-hairline bg-page font-semibold",
    quiet: "border-transparent text-ink-secondary hover:bg-page",
  }[variant];
  return (
    <button
      {...props}
      className={`rounded-md border px-3 py-1.5 text-sm font-medium disabled:opacity-40 ${styles} ${props.className ?? ""}`}
    >
      {children}
    </button>
  );
}

export function Dot({ className }: { className: string }) {
  return <span className={`inline-block h-2 w-2 shrink-0 rounded-full ${className}`} />;
}

export function Notice({
  kind,
  children,
}: {
  kind: "error" | "good" | "warning";
  children: React.ReactNode;
}) {
  const accent = {
    error: "bg-status-critical",
    good: "bg-status-good",
    warning: "bg-status-warning",
  }[kind];
  return (
    <p className="flex items-start gap-2 text-sm">
      <Dot className={`mt-1.5 ${accent}`} />
      <span>{children}</span>
    </p>
  );
}

/** A collapsed panel, so a create form does not sit open above every list. */
export function Disclosure({
  label,
  children,
  open: initiallyOpen = false,
}: {
  label: string;
  children: React.ReactNode;
  open?: boolean;
}) {
  const [open, setOpen] = useState(initiallyOpen);
  return (
    <div className="rounded-lg border border-hairline bg-surface">
      <button
        type="button"
        onClick={() => setOpen(!open)}
        className="flex w-full items-center justify-between px-5 py-3 text-left text-sm font-semibold"
      >
        {label}
        <span className="text-ink-muted">{open ? "−" : "+"}</span>
      </button>
      {open && <div className="border-t border-hairline p-5">{children}</div>}
    </div>
  );
}

/**
 * A destructive action behind a second click.
 *
 * Deliberately *not* `window.confirm`: the extra text explains what is about to
 * be irreversible, which a native dialog cannot carry.
 */
export function ConfirmButton({
  label,
  confirmLabel,
  warning,
  onConfirm,
  disabled,
}: {
  label: string;
  confirmLabel: string;
  warning?: string;
  onConfirm: () => void | Promise<void>;
  disabled?: boolean;
}) {
  const [armed, setArmed] = useState(false);
  const [busy, setBusy] = useState(false);

  if (!armed) {
    return (
      <Button variant="quiet" disabled={disabled} onClick={() => setArmed(true)}>
        {label}
      </Button>
    );
  }
  return (
    <span className="inline-flex flex-wrap items-center gap-2">
      {warning && <span className="text-xs text-ink-secondary">{warning}</span>}
      <Button
        disabled={busy}
        onClick={async () => {
          setBusy(true);
          try {
            await onConfirm();
          } finally {
            setBusy(false);
            setArmed(false);
          }
        }}
      >
        {busy ? "Working…" : confirmLabel}
      </Button>
      <Button variant="quiet" onClick={() => setArmed(false)}>
        Cancel
      </Button>
    </span>
  );
}

/**
 * A value the server will never show again — an enrollment key, a TOTP secret.
 *
 * It is rendered selectable with a copy button and an explicit warning, because
 * "shown once" is only a good property if the UI makes that obvious *before*
 * the operator navigates away.
 */
export function SecretOnce({
  title,
  value,
  note,
  children,
}: {
  title: string;
  value: string;
  note: string;
  children?: React.ReactNode;
}) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="rounded-md border border-hairline bg-page p-4">
      <p className="flex items-center gap-1.5 text-sm font-semibold">
        <Dot className="bg-status-warning" />
        {title}
      </p>
      <p className="mt-1 text-xs text-ink-secondary">{note}</p>
      <code className="mt-3 block break-all rounded border border-hairline bg-surface p-2 font-mono text-xs">
        {value}
      </code>
      <Button
        className="mt-3"
        onClick={() => {
          void navigator.clipboard?.writeText(value);
          setCopied(true);
        }}
      >
        {copied ? "Copied" : "Copy"}
      </Button>
      {children}
    </div>
  );
}

/** Turns a `Result` into either an error notice or nothing. */
export function ResultNotice({ result }: { result: Result<unknown> | null }) {
  if (!result || result.ok) return null;
  return <Notice kind="error">{result.error}</Notice>;
}

/** Comma-separated text <-> string[], used for tags and group slugs. */
export function parseList(value: string): string[] {
  return value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}
