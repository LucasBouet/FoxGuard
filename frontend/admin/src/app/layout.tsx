import type { Metadata } from "next";
import Link from "next/link";

import { NavBar } from "@/components/nav-bar";
import { SessionBar } from "@/components/session-bar";
import { tryGet } from "@/lib/api";
import type { AdminWhoAmI } from "@/lib/types";

import "./globals.css";

export const dynamic = "force-dynamic";

export const metadata: Metadata = {
  title: "Foxguard admin",
  description: "Peers, groups, policies and the state of the dataplane.",
};

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
            <NavBar />
          </header>
          <main className="py-6">{children}</main>
        </div>
      </body>
    </html>
  );
}
