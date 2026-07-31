"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useRef, useState } from "react";

import { KILL_SWITCH, NAV_ENTRIES, currentEntry, isCurrent, moveFocus } from "@/lib/nav";

/**
 * The dashboard's navigation.
 *
 * Everything that can be decided without a DOM lives in `lib/nav.ts` and is
 * tested there. What is left here is the interaction: opening a menu, closing
 * it on Escape or on a click elsewhere, and moving focus with the arrow keys.
 *
 * The menus are real menus rather than hover panels. A hover panel is
 * unreachable from a keyboard, unusable on a touch screen, and opens by
 * accident when the pointer crosses the header on the way somewhere else.
 */
export function NavBar() {
  const pathname = usePathname() ?? "/";
  const [open, setOpen] = useState<number | null>(null);
  const [focused, setFocused] = useState(0);
  const container = useRef<HTMLElement | null>(null);
  const itemRefs = useRef<(HTMLAnchorElement | null)[]>([]);
  const current = currentEntry(pathname);

  // Any navigation closes the menu. Without this the panel stays open over the
  // page it just navigated to, because the header is not remounted.
  useEffect(() => setOpen(null), [pathname]);

  useEffect(() => {
    if (open === null) return;
    const onPointer = (event: MouseEvent) => {
      if (!container.current?.contains(event.target as Node)) setOpen(null);
    };
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") setOpen(null);
    };
    document.addEventListener("mousedown", onPointer);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onPointer);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  useEffect(() => {
    if (open !== null) itemRefs.current[focused]?.focus();
  }, [open, focused]);

  function toggle(index: number) {
    setFocused(0);
    setOpen((previous) => (previous === index ? null : index));
  }

  return (
    <nav ref={container} className="flex w-full flex-wrap items-center gap-1">
      {NAV_ENTRIES.map((entry, index) => {
        const active = index === current;

        if (entry.kind === "link") {
          return (
            <Link
              key={entry.href}
              href={entry.href}
              aria-current={active ? "page" : undefined}
              className={`rounded-md px-3 py-1.5 text-sm ${
                active
                  ? "bg-page font-medium text-ink"
                  : "text-ink-secondary hover:bg-page hover:text-ink"
              }`}
            >
              {entry.label}
            </Link>
          );
        }

        const expanded = open === index;
        return (
          <div key={entry.label} className="relative">
            <button
              type="button"
              aria-expanded={expanded}
              aria-haspopup="menu"
              onClick={() => toggle(index)}
              onKeyDown={(event) => {
                if (event.key === "ArrowDown" && !expanded) {
                  event.preventDefault();
                  toggle(index);
                }
              }}
              className={`flex items-center gap-1 rounded-md px-3 py-1.5 text-sm ${
                active || expanded
                  ? "bg-page font-medium text-ink"
                  : "text-ink-secondary hover:bg-page hover:text-ink"
              }`}
            >
              {entry.label}
              <svg
                aria-hidden="true"
                viewBox="0 0 10 6"
                className={`h-1.5 w-2.5 fill-current transition-transform ${
                  expanded ? "rotate-180" : ""
                }`}
              >
                <path d="M0 0h10L5 6z" />
              </svg>
            </button>

            {expanded && (
              <div
                role="menu"
                aria-label={entry.label}
                onKeyDown={(event) => {
                  const next = moveFocus(focused, event.key, entry.items.length);
                  if (next !== focused) {
                    event.preventDefault();
                    setFocused(next);
                  }
                }}
                className="absolute left-0 top-full z-20 mt-1 w-64 max-w-[calc(100vw-2rem)] rounded-lg border border-hairline bg-surface p-1 shadow-lg"
              >
                {entry.items.map((item, position) => (
                  <Link
                    key={item.href}
                    href={item.href}
                    role="menuitem"
                    ref={(node) => {
                      itemRefs.current[position] = node;
                    }}
                    tabIndex={position === focused ? 0 : -1}
                    aria-current={isCurrent(pathname, item.href) ? "page" : undefined}
                    onClick={() => setOpen(null)}
                    className={`block rounded-md px-3 py-2 hover:bg-page ${
                      isCurrent(pathname, item.href) ? "bg-page" : ""
                    }`}
                  >
                    <span className="block text-sm font-medium text-ink">{item.label}</span>
                    <span className="mt-0.5 block text-xs text-ink-secondary">
                      {item.hint}
                    </span>
                  </Link>
                ))}
              </div>
            )}
          </div>
        );
      })}

      {/* Kept visually apart from ordinary navigation: it is the one action
          that can take the whole fleet off the network. */}
      <Link
        href={KILL_SWITCH.href}
        aria-current={isCurrent(pathname, KILL_SWITCH.href) ? "page" : undefined}
        className="ml-2 rounded-md border border-hairline px-3 py-1.5 text-sm font-medium text-ink hover:bg-page"
      >
        {KILL_SWITCH.label}
      </Link>
    </nav>
  );
}
