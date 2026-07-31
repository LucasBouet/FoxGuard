/**
 * Turn a profile plus a private key into a `.conf` file.
 *
 * This runs in the browser and nowhere else. The private key is an argument,
 * the return value is a string, and there is no import that could send either
 * anywhere -- `tests/no-storage.test.ts` asserts the compiled module makes no
 * `require` call at all, because "the private key never leaves the browser" is
 * a property of the code, not of good intentions, and properties can be tested.
 *
 * The output targets `wg-quick` and the official clients: `Address`, `DNS` and
 * `MTU` are wg-quick directives rather than kernel ones, which is why a config
 * has to be passed through `wg-quick strip` before `wg setconf` will look at it.
 */

import type { ClientConfigProfile } from "./types";

export interface ConfigOverrides {
  /** Omit the DNS line even when the deployment offers one. */
  includeDns?: boolean;
  /** 0 omits the line entirely. */
  keepalive?: number;
  /** null omits the line and lets wg-quick work the MTU out. */
  mtu?: number | null;
  /** The leading comment naming the device. Off for the smallest QR. */
  comments?: boolean;
}

function line(key: string, value: string): string {
  return `${key} = ${value}`;
}

/**
 * Render the file.
 *
 * Throws on an incomplete profile rather than emitting a config with a missing
 * `PublicKey`. A file that fails at connect time is worse than no file: it
 * fails on someone else's machine, hours later, with an error that names
 * nothing the operator can act on.
 */
export function renderClientConfig(
  profile: ClientConfigProfile,
  privateKey: string,
  overrides: ConfigOverrides = {},
): string {
  if (!profile.server_public_key || !profile.endpoint || profile.addresses.length === 0) {
    throw new Error(
      "this profile is missing the gateway's public key, its endpoint or an address",
    );
  }
  if (!privateKey.trim()) {
    throw new Error("no private key");
  }

  const keepalive = overrides.keepalive ?? profile.persistent_keepalive;
  const mtu = overrides.mtu === undefined ? profile.mtu : overrides.mtu;
  const dns = overrides.includeDns === false ? [] : profile.dns;

  const out: string[] = [];
  if (overrides.comments !== false) {
    out.push(`# ${profile.peer_name}${profile.fqdn ? ` (${profile.fqdn})` : ""}`);
    out.push("# Generated in your browser by Foxguard. The private key below was");
    out.push("# never sent to the gateway and is not stored anywhere else.");
  }
  out.push("[Interface]");
  out.push(line("PrivateKey", privateKey.trim()));
  out.push(line("Address", profile.addresses.join(", ")));
  if (dns.length > 0) out.push(line("DNS", dns.join(", ")));
  if (mtu) out.push(line("MTU", String(mtu)));
  out.push("");
  out.push("[Peer]");
  out.push(line("PublicKey", profile.server_public_key));
  out.push(line("Endpoint", profile.endpoint));
  out.push(line("AllowedIPs", profile.allowed_ips.join(", ")));
  if (keepalive > 0) out.push(line("PersistentKeepalive", String(keepalive)));

  return `${out.join("\n")}\n`;
}

/**
 * A file name the WireGuard clients will accept.
 *
 * `wg-quick` takes the interface name from the file name, and an interface name
 * is at most 15 characters of `[a-zA-Z0-9_=+.-]`. The Android and iOS apps
 * enforce the same rule on import. So "Ada's MacBook Pro (2019).conf" is
 * refused by every client, and the operator is left thinking the config is
 * broken -- it is the name that is.
 */
export function configFileName(profile: ClientConfigProfile): string {
  const source = profile.fqdn?.split(".")[0] || profile.peer_name;
  const cleaned = source
    .normalize("NFKD")
    // Escaped rather than written literally: a literal combining-mark range is
    // invisible in a diff and does not survive a re-encoding of this file.
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/[^a-zA-Z0-9_=+.-]/g, "-")
    .replace(/-+/g, "-")
    .replace(/^[-.]+/, "")
    .slice(0, 15)
    .replace(/[-.]+$/, "");
  return `${cleaned || "foxguard"}.conf`;
}
