import type { Metadata } from "next";
import Link from "next/link";

import { SessionBar } from "@/components/session-bar";
import { tryGet } from "@/lib/api";
import type { AdminWhoAmI } from "@/lib/types";

import "./globals.css";

export const dynamic = "force-dynamic";

export const metadata: Metadata = {
  title: "Foxguard admin",
  description: "Peers, groups, policies and the state of the dataplane.",
};

const NAV = [
  { href: "/", label: "Overview" },
  { href: "/peers", label: "Peers" },
  { href: "/users", label: "Accounts" },
  { href: "/groups", label: "Groups & matrix" },
  { href: "/rules", label: "Rules" },
  { href: "/sessions", label: "Sessions" },
  { href: "/policies", label: "Policies" },
  { href: "/audit", label: "Audit log" },
];

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  // Resolved here rather than per page so the header can always say who the
  // dashboard is acting as. A failure means "not signed in", not a broken page.
  const { data: who } = await tryGet<AdminWhoAmI>("/api/v1/admin/me");

  return (
    <html lang="en">
      <body className="min-h-screen font-sans antialiased">
        <div className="mx-auto max-w-7xl px-4 py-6">
          <header className="flex flex-wrap items-center justify-between gap-4 border-b border-hairline pb-4">
            <div>
              <Link href="/" className="text-lg font-semibold">
                Foxguard
              </Link>
              <p className="text-sm text-ink-secondary">WireGuard access control</p>
            </div>
            <div className="flex flex-wrap items-center gap-4">
              <SessionBar who={who} />
            </div>
            <nav className="flex w-full flex-wrap items-center gap-1">
              {NAV.map((item) => (
                <Link
                  key={item.href}
                  href={item.href}
                  className="rounded-md px-3 py-1.5 text-sm text-ink-secondary hover:bg-page hover:text-ink"
                >
                  {item.label}
                </Link>
              ))}
              {/* Kept visually apart from ordinary navigation: it is the one
                  action that can take the whole fleet off the network. */}
              <Link
                href="/kill-switch"
                className="ml-2 rounded-md border border-hairline px-3 py-1.5 text-sm font-medium text-ink hover:bg-page"
              >
                Kill switch
              </Link>
            </nav>
          </header>
          <main className="py-6">{children}</main>
        </div>
      </body>
    </html>
  );
}
