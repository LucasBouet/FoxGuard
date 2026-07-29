import type { AclAction, PeerState } from "@/lib/types";

/**
 * The shared vocabulary of the dashboard.
 *
 * Every status here is drawn as a coloured dot **plus a written label**, and the
 * label is in normal ink rather than the status colour. Two reasons: colour
 * alone is not an accessible encoding, and the warning step is deliberately
 * below 3:1 on the light surface — the label is what makes it legible.
 */

const STATE_COLOR: Record<PeerState, string> = {
  active: "bg-status-good",
  quarantined: "bg-status-warning",
  staging: "bg-status-info",
  disabled: "bg-status-neutral",
  revoked: "bg-status-critical",
};

const ACTION_COLOR: Record<AclAction, string> = {
  accept: "bg-status-good",
  drop: "bg-status-critical",
  reject: "bg-status-serious",
};

export function Dot({ className }: { className: string }) {
  return <span className={`inline-block h-2 w-2 shrink-0 rounded-full ${className}`} />;
}

export function StateBadge({ state }: { state: PeerState }) {
  return (
    <span className="inline-flex items-center gap-1.5 whitespace-nowrap text-sm">
      <Dot className={STATE_COLOR[state]} />
      {state}
    </span>
  );
}

export function ActionBadge({ action }: { action: AclAction }) {
  return (
    <span className="inline-flex items-center gap-1.5 whitespace-nowrap text-sm">
      <Dot className={ACTION_COLOR[action]} />
      {action}
    </span>
  );
}

export function Card({
  title,
  description,
  children,
  className = "",
}: {
  title?: string;
  description?: string;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <section
      className={`rounded-lg border border-hairline bg-surface p-5 ${className}`}
    >
      {title && <h2 className="text-sm font-semibold">{title}</h2>}
      {description && <p className="mt-1 text-sm text-ink-secondary">{description}</p>}
      <div className={title || description ? "mt-4" : ""}>{children}</div>
    </section>
  );
}

/**
 * A single number and its label. Not a chart: one value with no comparison has
 * nothing to plot, and a tile reads faster than a one-bar bar chart.
 */
export function StatTile({
  label,
  value,
  hint,
  accent,
}: {
  label: string;
  value: number | string;
  hint?: string;
  accent?: string;
}) {
  return (
    <div className="rounded-lg border border-hairline bg-surface p-4">
      <div className="flex items-center gap-1.5 text-sm text-ink-secondary">
        {accent && <Dot className={accent} />}
        {label}
      </div>
      <div className="mt-1 text-3xl font-semibold">{value}</div>
      {hint && <div className="mt-1 text-xs text-ink-muted">{hint}</div>}
    </div>
  );
}

export function Table({
  headers,
  children,
  empty,
}: {
  headers: string[];
  children: React.ReactNode;
  empty?: string;
}) {
  const hasRows = Array.isArray(children) ? children.length > 0 : Boolean(children);
  if (!hasRows && empty) {
    return <p className="py-6 text-center text-sm text-ink-muted">{empty}</p>;
  }
  return (
    // Wide tables scroll inside their own container; the page body never does.
    <div className="overflow-x-auto">
      <table className="w-full border-collapse text-sm">
        <thead>
          <tr className="border-b border-hairline text-left">
            {headers.map((header) => (
              <th key={header} className="px-3 py-2 font-medium text-ink-secondary">
                {header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="tabular">{children}</tbody>
      </table>
    </div>
  );
}

export function Row({ children }: { children: React.ReactNode }) {
  return <tr className="border-b border-hairline last:border-0">{children}</tr>;
}

export function Cell({
  children,
  className = "",
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return <td className={`px-3 py-2 align-middle ${className}`}>{children}</td>;
}

export function ErrorPanel({ message }: { message: string }) {
  return (
    <div className="flex items-start gap-2 rounded-lg border border-hairline bg-surface p-4 text-sm">
      <Dot className="mt-1.5 bg-status-critical" />
      <div>
        <p className="font-medium">Cannot read the control plane</p>
        <p className="mt-1 text-ink-secondary">{message}</p>
      </div>
    </div>
  );
}

export function Empty({ children }: { children: React.ReactNode }) {
  return <p className="py-6 text-center text-sm text-ink-muted">{children}</p>;
}

export function relative(iso: string | null): string {
  if (!iso) return "—";
  const seconds = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
  if (seconds < 60) return "just now";
  const units: [number, string][] = [
    [60, "min"],
    [3600, "h"],
    [86400, "d"],
  ];
  for (const [size, unit] of units) {
    const next = size * (unit === "min" ? 60 : unit === "h" ? 24 : 365);
    if (seconds < next) return `${Math.floor(seconds / size)}${unit} ago`;
  }
  return new Date(iso).toISOString().slice(0, 10);
}

export function duration(seconds: number | null): string {
  if (seconds === null) return "—";
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}min`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h`;
  return `${Math.floor(seconds / 86400)}d`;
}
