/**
 * The dashboard talks to the control plane through a same-origin `/api` path so
 * the browser never needs CORS and the admin token never has to reach it.
 *
 * In development, `next dev` proxies to the local API. In production the
 * dashboard is served behind the same origin as the API (see
 * docs/deployment.md), so the rewrite is a no-op there.
 */
const API_URL = process.env.FOXGUARD_API_URL ?? "http://127.0.0.1:8000";

/**
 * `NEXT_STANDALONE=true` makes `next build` also emit `.next/standalone`, a
 * self-contained server with only the modules it actually imports. That is what
 * the container image ships (docker/dashboard.Dockerfile) -- it drops the image
 * from the size of a full node_modules tree to tens of megabytes.
 *
 * Gated on the variable rather than always on, because the systemd deployment
 * runs `next start` from this directory and there is no reason to change what
 * that produces.
 */
const STANDALONE = process.env.NEXT_STANDALONE === "true";

/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  ...(STANDALONE ? { output: "standalone" } : {}),
  async rewrites() {
    return [{ source: "/api/:path*", destination: `${API_URL}/api/:path*` }];
  },
};

export default nextConfig;
