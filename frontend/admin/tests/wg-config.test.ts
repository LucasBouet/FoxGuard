/**
 * The generated file, checked by the software that has to read it.
 *
 * "100% valid" is a claim about `wg-quick` and the WireGuard clients, not about
 * our own opinion of INI syntax, so the tests that matter here run the real
 * `wg-quick strip` over the output and -- with `FOXGUARD_LIVE_WG=1` and
 * CAP_NET_ADMIN -- load it into a real WireGuard interface and read the state
 * back out of the kernel.
 *
 * One deliberate difference from a real deployment: the endpoint is an IP
 * literal. `wg setconf` resolves hostnames at parse time, and a build container
 * with no DNS would fail on `vpn.example.com` for reasons that have nothing to
 * do with the config being right.
 */

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import type { ClientConfigProfile } from "../src/lib/types";
import { configFileName, renderClientConfig } from "../src/lib/wg-config";
import { generateKeypair } from "../src/lib/wireguard";

function profile(overrides: Partial<ClientConfigProfile> = {}): ClientConfigProfile {
  return {
    peer_id: "6f1b7c1e-0000-4000-8000-000000000001",
    peer_name: "ada-laptop",
    peer_state: "active",
    fqdn: "ada-laptop.fox.internal",
    addresses: ["10.88.0.5/32"],
    dns: ["10.88.0.1", "fox.internal"],
    mtu: null,
    server_public_key: "ox3iCjdNGr7iHRvp1E+jSVNIUNt/5iaw86e15HOo0Vw=",
    endpoint: "203.0.113.4:51820",
    allowed_ips: ["10.88.0.0/24", "192.168.10.0/24"],
    persistent_keepalive: 25,
    allowed_ips_mode: "routed",
    excluded_routes: [],
    warnings: [],
    complete: true,
    ...overrides,
  };
}

function has(binary: string, args: string[]): boolean {
  try {
    execFileSync(binary, args, { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

const HAS_WG = has("wg", ["--version"]) && has("sh", ["-c", "command -v wg-quick"]);
const LIVE = process.env.FOXGUARD_LIVE_WG === "1";

/**
 * Write the config under a given name.
 *
 * The name is not incidental: `wg-quick` refuses outright unless the file is
 * "a valid interface name, followed by .conf". Passing `configFileName`'s
 * output through here is what proves that function earns its existence.
 */
function withTempConfig<T>(text: string, name: string, fn: (path: string) => T): T {
  const dir = mkdtempSync(join(tmpdir(), "fgconf-"));
  const path = join(dir, name);
  writeFileSync(path, text, { mode: 0o600 });
  try {
    return fn(path);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// --------------------------------------------------------------------------- //
// shape
// --------------------------------------------------------------------------- //

test("a full profile renders every line", () => {
  const config = renderClientConfig(profile({ mtu: 1420 }), "PRIVATEKEYPLACEHOLDER=");
  assert.match(config, /^\[Interface\]$/m);
  assert.match(config, /^PrivateKey = PRIVATEKEYPLACEHOLDER=$/m);
  assert.match(config, /^Address = 10\.88\.0\.5\/32$/m);
  assert.match(config, /^DNS = 10\.88\.0\.1, fox\.internal$/m);
  assert.match(config, /^MTU = 1420$/m);
  assert.match(config, /^\[Peer\]$/m);
  assert.match(config, /^Endpoint = 203\.0\.113\.4:51820$/m);
  assert.match(config, /^AllowedIPs = 10\.88\.0\.0\/24, 192\.168\.10\.0\/24$/m);
  assert.match(config, /^PersistentKeepalive = 25$/m);
  assert.ok(config.endsWith("\n"), "a config file ends with a newline");
});

test("optional lines are omitted rather than emitted empty", () => {
  const config = renderClientConfig(
    profile({ dns: [], mtu: null, persistent_keepalive: 0 }),
    "k=",
  );
  assert.doesNotMatch(config, /DNS/);
  assert.doesNotMatch(config, /MTU/);
  assert.doesNotMatch(config, /PersistentKeepalive/);
});

test("overrides beat the profile without a round trip to the server", () => {
  const config = renderClientConfig(profile({ mtu: 1420 }), "k=", {
    includeDns: false,
    keepalive: 0,
    mtu: null,
  });
  assert.doesNotMatch(config, /DNS|MTU|PersistentKeepalive/);
});

test("both addresses of a dual-stack peer land on one line", () => {
  const config = renderClientConfig(
    profile({ addresses: ["10.88.0.5/32", "fd00:88::5/128"] }),
    "k=",
  );
  assert.match(config, /^Address = 10\.88\.0\.5\/32, fd00:88::5\/128$/m);
});

test("an incomplete profile refuses to render", () => {
  assert.throws(
    () => renderClientConfig(profile({ server_public_key: null }), "k="),
    /missing the gateway's public key/,
  );
  assert.throws(() => renderClientConfig(profile({ endpoint: null }), "k="), /endpoint/);
  assert.throws(() => renderClientConfig(profile({ addresses: [] }), "k="), /address/);
  assert.throws(() => renderClientConfig(profile(), "   "), /no private key/);
});

test("comments can be dropped for a smaller QR", () => {
  const withComments = renderClientConfig(profile(), "k=");
  const without = renderClientConfig(profile(), "k=", { comments: false });
  assert.match(withComments, /^# ada-laptop \(ada-laptop\.fox\.internal\)$/m);
  assert.doesNotMatch(without, /^#/m);
  assert.ok(without.length < withComments.length);
});

// --------------------------------------------------------------------------- //
// file names -- an interface name, not a title
// --------------------------------------------------------------------------- //

test("file names are legal WireGuard interface names", () => {
  const cases: Array<[Partial<ClientConfigProfile>, string]> = [
    [{}, "ada-laptop.conf"],
    [{ fqdn: null, peer_name: "Ada's MacBook Pro (2019)" }, "Ada-s-MacBook-P.conf"],
    [{ fqdn: null, peer_name: "hôtel-café" }, "hotel-cafe.conf"],
    [{ fqdn: null, peer_name: "----" }, "foxguard.conf"],
    [{ fqdn: null, peer_name: "a".repeat(40) }, `${"a".repeat(15)}.conf`],
  ];
  for (const [overrides, expected] of cases) {
    const name = configFileName(profile(overrides));
    assert.equal(name, expected);
    const stem = name.replace(/\.conf$/, "");
    assert.ok(stem.length <= 15, `${stem} is longer than an interface name may be`);
    assert.match(stem, /^[a-zA-Z0-9_=+.-]+$/);
  }
});

// --------------------------------------------------------------------------- //
// the real tools
// --------------------------------------------------------------------------- //

test(
  "`wg-quick strip` accepts what we generate",
  { skip: HAS_WG ? false : "wireguard-tools not installed" },
  () => {
    const { privateKey } = generateKeypair();
    for (const variant of [
      profile(),
      profile({ dns: [], mtu: 1420, persistent_keepalive: 0 }),
      profile({ addresses: ["10.88.0.5/32", "fd00:88::5/128"], allowed_ips: ["0.0.0.0/0", "::/0"] }),
    ]) {
      const config = renderClientConfig(variant, privateKey);
      const stripped = withTempConfig(config, configFileName(variant), (path) =>
        execFileSync("wg-quick", ["strip", path]).toString(),
      );
      // strip removes the wg-quick-only directives and keeps the kernel ones.
      assert.match(stripped, /\[Interface\]/);
      assert.match(stripped, /\[Peer\]/);
      assert.doesNotMatch(stripped, /^Address/m);
      assert.doesNotMatch(stripped, /^DNS/m);
      assert.doesNotMatch(stripped, /^MTU/m);
      assert.match(stripped, new RegExp(`PublicKey = ${variant.server_public_key!.replace(/[+/=]/g, "\\$&")}`));
    }
  },
);

test(
  "the kernel accepts the config and reports the key we derived",
  { skip: LIVE ? false : "set FOXGUARD_LIVE_WG=1 (needs CAP_NET_ADMIN)" },
  () => {
    const { privateKey, publicKey } = generateKeypair();
    const config = renderClientConfig(profile(), privateKey);
    const iface = `fgt${process.pid % 100000}`;

    execFileSync("sudo", ["ip", "link", "add", iface, "type", "wireguard"]);
    try {
      withTempConfig(config, configFileName(profile()), (path) => {
        const stripped = execFileSync("wg-quick", ["strip", path]).toString();
        const strippedPath = `${path}.stripped`;
        writeFileSync(strippedPath, stripped, { mode: 0o600 });
        execFileSync("sudo", ["wg", "setconf", iface, strippedPath]);
      });

      // The claim under test: the public key our browser code derived is the
      // one the kernel computes from the same private key. If these ever
      // disagree, every config the dashboard hands out registers the wrong key
      // on the gateway and no tunnel comes up.
      const shown = execFileSync("sudo", ["wg", "show", iface, "public-key"])
        .toString()
        .trim();
      assert.equal(shown, publicKey);

      const dump = execFileSync("sudo", ["wg", "show", iface]).toString();
      assert.match(dump, /endpoint: 203\.0\.113\.4:51820/);
      assert.match(dump, /allowed ips: 10\.88\.0\.0\/24, 192\.168\.10\.0\/24/);
      assert.match(dump, /persistent keepalive: every 25 seconds/);
    } finally {
      execFileSync("sudo", ["ip", "link", "del", iface]);
    }
  },
);
