/**
 * The dashboard talks to the control plane through a same-origin `/api` path so
 * the browser never needs CORS and the admin token never has to reach it.
 *
 * In development, `next dev` proxies to the local API. In production the
 * dashboard is served behind the same origin as the API (see
 * docs/deployment.md), so the rewrite is a no-op there.
 */
const API_URL = process.env.FOXGUARD_API_URL ?? "http://127.0.0.1:8000";

/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  async rewrites() {
    return [{ source: "/api/:path*", destination: `${API_URL}/api/:path*` }];
  },
};

export default nextConfig;
