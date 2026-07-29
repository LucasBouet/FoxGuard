/**
 * A **static export**, and that is not a preference.
 *
 * The portal identifies its caller by the source address of the TCP connection,
 * because inside WireGuard that address is cryptographically bound to a peer's
 * key. If this app had a server that fetched the API on the browser's behalf,
 * the API would see *that server's* address and refuse every request with 403.
 *
 * So there is no server: the browser executes the bundle and calls
 * `/api/v1/portal/*` itself, same-origin, over its own connection from inside
 * the tunnel. The API serves these files (see backend/foxguard/api/static.py).
 */

/** @type {import('next').NextConfig} */
const nextConfig = {
  output: "export",
  reactStrictMode: true,
  // The bundle is served from a plain static mount with html=true, which
  // resolves `/foo/` to `/foo/index.html`.
  trailingSlash: true,
  images: { unoptimized: true },
};

export default nextConfig;
