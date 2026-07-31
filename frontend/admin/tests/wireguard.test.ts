/**
 * The key derivation, checked against the thing that has to agree with it.
 *
 * An X25519 implementation that is subtly wrong still produces 44 plausible
 * base64 characters, and the failure only shows up as a tunnel that never
 * completes a handshake -- at which point nobody suspects the browser. So the
 * test of record here is not a golden file: it is `wg pubkey` itself, run over
 * hundreds of random keys. If the two ever disagree, the config generator is
 * producing keys the gateway cannot use, and that is the whole feature broken.
 */

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import test from "node:test";

import {
  clamp,
  fromBase64,
  generateKeypair,
  isValidKey,
  keyProblem,
  publicFromPrivate,
  toBase64,
} from "../src/lib/wireguard";

function hasWg(): boolean {
  try {
    execFileSync("wg", ["--version"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

function wgPubkey(privateKey: string): string {
  return execFileSync("wg", ["pubkey"], { input: `${privateKey}\n` }).toString().trim();
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function fromHex(text: string): Uint8Array {
  const out = new Uint8Array(text.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(text.slice(i * 2, i * 2 + 2), 16);
  return out;
}

test("RFC 7748 section 6.1 vectors", () => {
  // The canonical X25519 Diffie-Hellman example. Both directions, because a
  // ladder can be right for one scalar and wrong for another.
  const alice = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
  const alicePub = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
  const bob = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
  const bobPub = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";

  const derived = (secret: string) => {
    const pub = publicFromPrivate(toBase64(fromHex(secret)));
    assert.ok(pub !== null);
    const raw = fromBase64(pub);
    assert.ok(raw !== null);
    return hex(raw);
  };

  assert.equal(derived(alice), alicePub);
  assert.equal(derived(bob), bobPub);
});

test("clamping matches what wg genkey emits", () => {
  const raw = new Uint8Array(32).fill(0xff);
  const clamped = clamp(raw);
  assert.equal(clamped[0] & 0b111, 0, "low three bits cleared");
  assert.equal(clamped[31] & 0b1000_0000, 0, "top bit cleared");
  assert.equal(clamped[31] & 0b0100_0000, 0b0100_0000, "bit 254 forced on");
  // The input must not be mutated: the caller may still be holding it.
  assert.equal(raw[0], 0xff);
});

test("base64 round trips and agrees with Buffer", () => {
  for (let length = 0; length <= 64; length++) {
    const bytes = new Uint8Array(length);
    for (let i = 0; i < length; i++) bytes[i] = (i * 37 + length * 11) & 0xff;
    const encoded = toBase64(bytes);
    assert.equal(encoded, Buffer.from(bytes).toString("base64"), `length ${length}`);
    if (length === 0) continue;
    assert.deepEqual(Array.from(fromBase64(encoded)!), Array.from(bytes), `length ${length}`);
  }
});

test("base64 refuses what a bad paste looks like", () => {
  assert.equal(fromBase64("not base64!!"), null);
  assert.equal(fromBase64("abc"), null, "length not a multiple of four");
  assert.equal(fromBase64("QQ==QQ=="), null, "two keys pasted together");
  assert.equal(fromBase64(""), null);
});

test("keyProblem says what is wrong", () => {
  assert.equal(keyProblem("x".repeat(43)), "a WireGuard key is 44 base64 characters, this is 43");
  assert.equal(keyProblem(""), "empty");
  assert.equal(keyProblem("!".repeat(44)), "not valid base64");
  // 44 characters of valid base64 always decode to 32 bytes with one pad, so
  // the "wrong byte count" arm is only reachable through fromBase64 directly;
  // what matters here is that a real key passes.
  assert.equal(keyProblem(generateKeypair().privateKey), null);
  assert.ok(isValidKey("xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="));
});

test("generated keys are well formed and never repeat", () => {
  const seen = new Set<string>();
  for (let i = 0; i < 50; i++) {
    const pair = generateKeypair();
    assert.ok(isValidKey(pair.privateKey), pair.privateKey);
    assert.ok(isValidKey(pair.publicKey), pair.publicKey);
    assert.equal(seen.has(pair.privateKey), false, "CSPRNG repeated itself");
    seen.add(pair.privateKey);
    // Round trip: deriving twice from the same private key is stable.
    assert.equal(publicFromPrivate(pair.privateKey), pair.publicKey);
  }
});

test("publicFromPrivate refuses non-keys", () => {
  assert.equal(publicFromPrivate("nonsense"), null);
  assert.equal(publicFromPrivate(""), null);
  assert.equal(publicFromPrivate(toBase64(new Uint8Array(16))), null, "16 bytes is not a key");
});

test(
  "300 random keys agree with the real `wg pubkey`",
  { skip: hasWg() ? false : "wireguard-tools not installed" },
  () => {
    for (let i = 0; i < 300; i++) {
      const { privateKey, publicKey } = generateKeypair();
      assert.equal(publicKey, wgPubkey(privateKey), `disagreed on ${privateKey}`);
    }
  },
);

test(
  "keys made by `wg genkey` derive the same public key here",
  { skip: hasWg() ? false : "wireguard-tools not installed" },
  () => {
    // The other direction: their generator, our derivation. This is what an
    // operator does when they paste a key they already had.
    for (let i = 0; i < 100; i++) {
      const privateKey = execFileSync("wg", ["genkey"]).toString().trim();
      assert.equal(publicFromPrivate(privateKey), wgPubkey(privateKey), privateKey);
    }
  },
);

test(
  "an unclamped private key derives what wg derives",
  { skip: hasWg() ? false : "wireguard-tools not installed" },
  () => {
    // `wg pubkey` clamps its input, and so do we. A key that arrived from some
    // other tool without clamping must therefore not produce a different public
    // key here than it does on the gateway.
    for (let i = 0; i < 25; i++) {
      const raw = new Uint8Array(32);
      for (let j = 0; j < 32; j++) raw[j] = Math.floor(Math.random() * 256);
      const encoded = toBase64(raw);
      assert.equal(publicFromPrivate(encoded), wgPubkey(encoded), encoded);
    }
  },
);
