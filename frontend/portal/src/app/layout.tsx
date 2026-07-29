import type { Metadata } from "next";

import "./globals.css";

export const metadata: Metadata = {
  title: "Network access",
  description: "Sign in to reach the network.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="min-h-screen font-sans antialiased">
        <div className="mx-auto flex min-h-screen max-w-md flex-col justify-center px-4 py-10">
          {children}
        </div>
      </body>
    </html>
  );
}
