/**
 * The shape of the admin navigation, and the logic that goes with it.
 *
 * Kept apart from the component on purpose. Which group is open, which entry is
 * current, and where an arrow key lands are all decisions with edge cases --
 * `/` matching everything, a group being current because a page inside it is,
 * wrapping at the ends of a menu -- and none of them need a DOM to be wrong.
 * `tests/nav.test.ts` covers them; the component is left as a thin shell over
 * this, which is the part that has no test runner.
 *
 * Adding a screen later means one entry in `NAV_GROUPS` and nothing else. That
 * is the whole reason for the grouping: a flat row of eleven links had no room
 * left, and every new feature made the next one harder to find.
 */

export interface NavItem {
  href: string;
  label: string;
  /** One line, shown under the label inside the menu. */
  hint: string;
}

export type NavEntry =
  | { kind: "link"; href: string; label: string }
  | { kind: "group"; label: string; items: NavItem[] };

export const NAV_ENTRIES: NavEntry[] = [
  { kind: "link", href: "/", label: "Overview" },
  {
    kind: "group",
    label: "Devices",
    items: [
      { href: "/peers", label: "Peers", hint: "Every device the gateway knows" },
      { href: "/zones", label: "Zones", hint: "Where devices sit, and the networks they carry" },
      {
        href: "/config",
        label: "Config generator",
        hint: "A ready client config, keys made in your browser",
      },
    ],
  },
  {
    kind: "group",
    label: "Access",
    items: [
      { href: "/groups", label: "Groups & matrix", hint: "What a device is allowed to be" },
      { href: "/rules", label: "Rules", hint: "The ACL the dataplane renders from" },
      { href: "/policies", label: "Policies", hint: "Import and export the whole policy" },
    ],
  },
  {
    kind: "group",
    label: "Identity",
    items: [
      { href: "/users", label: "Accounts", hint: "People, passwords and TOTP" },
      { href: "/sessions", label: "Sessions", hint: "Who is authenticated right now" },
    ],
  },
  {
    kind: "group",
    label: "Network",
    items: [
      { href: "/dns", label: "DNS", hint: "The internal zone and its records" },
      {
        href: "/services",
        label: "Services",
        hint: "What the gateway publishes, and who gets in",
      },
    ],
  },
  { kind: "link", href: "/audit", label: "Audit log" },
];

/** Kept out of `NAV_ENTRIES`: it is the one action that can take the fleet off the network. */
export const KILL_SWITCH: NavItem = {
  href: "/kill-switch",
  label: "Kill switch",
  hint: "Cut every peer at once",
};

/**
 * Is `href` the page being shown?
 *
 * `/` is special-cased. Treating it like the others would make the overview
 * link current on every page, since every path starts with a slash.
 */
export function isCurrent(pathname: string, href: string): boolean {
  const path = pathname.split("?")[0].replace(/\/+$/, "") || "/";
  if (href === "/") return path === "/";
  return path === href || path.startsWith(`${href}/`);
}

/** The index in `NAV_ENTRIES` containing the current page, or -1. */
export function currentEntry(pathname: string): number {
  return NAV_ENTRIES.findIndex((entry) =>
    entry.kind === "link"
      ? isCurrent(pathname, entry.href)
      : entry.items.some((item) => isCurrent(pathname, item.href)),
  );
}

/**
 * Where an arrow key moves inside an open menu.
 *
 * Wraps at both ends, which is what a roving-focus menu is expected to do:
 * pressing Down on the last item should reach the first, not stick. Returns
 * the current index unchanged for keys that do not move focus, so the caller
 * can compare and decide whether to call `preventDefault`.
 */
export function moveFocus(current: number, key: string, length: number): number {
  if (length === 0) return -1;
  switch (key) {
    case "ArrowDown":
      return (current + 1) % length;
    case "ArrowUp":
      return (current - 1 + length) % length;
    case "Home":
      return 0;
    case "End":
      return length - 1;
    default:
      return current;
  }
}
