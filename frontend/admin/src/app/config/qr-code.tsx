"use client";

import { useMemo } from "react";

import { encodeQr, toSvgPath } from "@/lib/qr";

/**
 * The configuration as something a phone can scan.
 *
 * Encoded here rather than by a service, because the payload contains a private
 * key: every hosted QR generator works by being sent the thing you want
 * encoded, which for this payload is the one thing that must not leave the
 * machine.
 *
 * Drawn as a single SVG path. `currentColor` on the fill and a plain white
 * rectangle behind it, because scanners want the dark modules dark and the
 * quiet zone light regardless of which theme the operator is using — a code
 * inverted by dark mode does not scan.
 */
export function QrCode({ text, size = 260 }: { text: string; size?: number }) {
  const code = useMemo(() => encodeQr(text, "M"), [text]);

  if (code === null) {
    return (
      <p className="text-sm text-ink-secondary">
        This configuration is too long to fit in a QR code. Download the file
        instead.
      </p>
    );
  }

  const border = 4;
  const extent = code.size + border * 2;

  return (
    <div className="inline-block rounded-md border border-hairline bg-white p-2">
      <svg
        width={size}
        height={size}
        viewBox={`0 0 ${extent} ${extent}`}
        role="img"
        aria-label="WireGuard configuration as a QR code"
        shapeRendering="crispEdges"
      >
        <rect width={extent} height={extent} fill="#ffffff" />
        <path d={toSvgPath(code, border)} fill="#000000" />
      </svg>
    </div>
  );
}
