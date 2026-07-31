/**
 * The invariant the whole config generator exists to keep.
 *
 * "The private key never leaves the browser" is a claim about code, and code
 * changes. These tests read the actual sources and refuse the shapes that would
 * break it -- a server action that accepts key material, a storage call in the
 * generator, an import that gives the key-handling modules a way to reach the
 * network at all.
 *
 * They are deliberately blunt. A reviewer can be talked out of a concern; a
 * failing test on `localStorage` in `config-generator.tsx` cannot.
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";

/** `__dirname` is `.test-build/tests`; the sources are two levels up. */
const ROOT = dirname(dirname(__dirname));
const source = (path: string) => readFileSync(join(ROOT, path), "utf8");
const built = (path: string) => readFileSync(join(__dirname, "..", path), "utf8");

/**
 * The file with its comment lines removed.
 *
 * The comments in these modules name the things they promise not to do -- "the
 * key is never written to localStorage" -- so a plain substring search would
 * fail on the documentation of the very property it is checking.
 */
function code(path: string): string {
  return source(path)
    .split("\n")
    .filter((line) => {
      const trimmed = line.trim();
      return !(
        trimmed.startsWith("*") ||
        trimmed.startsWith("//") ||
        trimmed.startsWith("/*") ||
        trimmed.startsWith("{/*")
      );
    })
    .join("\n");
}

const ESCAPES = [
  "localStorage",
  "sessionStorage",
  "indexedDB",
  "document.cookie",
  "XMLHttpRequest",
  "navigator.sendBeacon",
  "WebSocket",
  "EventSource",
];

test("the key modules compile to code with no imports at all", () => {
  // No import means no way to reach a network client, a storage API or a
  // logger, whatever a future edit adds elsewhere in the app.
  for (const path of ["src/lib/wireguard.js", "src/lib/wg-config.js", "src/lib/qr.js"]) {
    const code = built(path);
    const requires = code.match(/require\(["'][^"']+["']\)/g) ?? [];
    assert.deepEqual(requires, [], `${path} gained a runtime import: ${requires.join(", ")}`);
  }
});

test("the key modules touch no storage and no transport", () => {
  for (const path of ["src/lib/wireguard.ts", "src/lib/wg-config.ts", "src/lib/qr.ts"]) {
    const body = code(path);
    for (const escape of [...ESCAPES, "fetch("]) {
      assert.ok(!body.includes(escape), `${path} references ${escape}`);
    }
  }
});

test("the generator persists nothing", () => {
  const body = code("src/app/config/config-generator.tsx");
  for (const escape of [...ESCAPES, "fetch("]) {
    assert.ok(!body.includes(escape), `the generator references ${escape}`);
  }
});

test("the generator calls exactly two server actions", () => {
  // Both carry public data only: a peer's public key on the way up, a profile
  // on the way down. A third would need this test updated, which is the point
  // -- adding one should be a decision, not a diff nobody looked at.
  const imported = source("src/app/config/config-generator.tsx").match(/import \{([^}]+)\} from "@\/lib\/actions"/s);
  assert.ok(imported, "the generator no longer imports from lib/actions");
  const names = imported[1]
    .split(",")
    .map((name) => name.trim())
    .filter(Boolean);
  assert.deepEqual(names.sort(), ["createPeer", "getConfigProfile"]);
});

test("no server action mentions a private key", () => {
  // Server actions run on the server. A parameter named for key material is the
  // exact shape of the mistake -- "just POST it and let the backend build the
  // file" -- and it would be a one-line change away from working.
  const body = code("src/lib/actions.ts");
  for (const term of ["privateKey", "private_key", "PrivateKey"]) {
    // The doc comment on `getConfigProfile` says the words on purpose; what
    // must not appear is one in a position where it could be a value.
    const uses = body.split("\n").filter((line) => line.includes(term));
    assert.deepEqual(uses, [], `lib/actions.ts handles ${term}`);
  }
});

test("the config renderer takes the key as an argument and returns a string", () => {
  // Structural, not stylistic: a renderer that fetched its own inputs, or that
  // reported what it produced, would have somewhere to send them.
  const body = code("src/lib/wg-config.ts");
  assert.match(body, /export function renderClientConfig\(/);
  assert.match(body, /privateKey: string,/);
  assert.ok(!body.includes("async"), "the renderer became asynchronous, so it awaits something");
});
