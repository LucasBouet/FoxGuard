/**
 * WireGuard key material, computed in the browser.
 *
 * This module is the reason the config generator can exist at all: it derives a
 * public key from a private one **without a server**, so the private half never
 * leaves the machine that will use it. Everything here is pure — no imports, no
 * network, no storage — which is also what makes it testable outside a browser.
 *
 * The scalar multiplication is the TweetNaCl construction (a Montgomery ladder
 * over 16-limb radix-2^16 field elements held in `Float64Array`). It is ported
 * rather than invented: X25519 is not a thing to improvise, and this particular
 * shape has the useful property that every limb product stays under 2^53, so
 * doubles hold it exactly and there is no bigint dependency to ship.
 *
 * A note on what is deliberately absent: **`PresharedKey`**. WireGuard's PSK is
 * symmetric, so the gateway would have to know it too — storing one would break
 * the single invariant this whole feature exists to keep. A deployment that
 * wants post-quantum hardening has to provision PSKs out of band.
 */

const FIELD_LIMBS = 16;

type Field = Float64Array;

function gf(init?: readonly number[]): Field {
  const r = new Float64Array(FIELD_LIMBS);
  if (init) for (let i = 0; i < init.length; i++) r[i] = init[i];
  return r;
}

/** (A - 2) / 4 for curve25519, the constant the ladder multiplies by. */
const A24 = gf([0xdb41, 1]);

function carry(o: Field): void {
  let c = 1;
  for (let i = 0; i < FIELD_LIMBS; i++) {
    const v = o[i] + c + 65535;
    c = Math.floor(v / 65536);
    o[i] = v - c * 65536;
  }
  // 2^256 = 38 (mod 2^255 - 19): the top carry folds back into the bottom limb.
  o[0] += c - 1 + 37 * (c - 1);
}

/**
 * Conditional swap, branch-free.
 *
 * The ladder must not take a different path depending on a bit of the secret,
 * so the swap is arithmetic. JavaScript gives no real timing guarantees — a JIT
 * may do as it likes — but writing the branchy version would make a side channel
 * certain rather than merely unproven.
 */
function swap(p: Field, q: Field, bit: number): void {
  const c = ~(bit - 1);
  for (let i = 0; i < FIELD_LIMBS; i++) {
    const t = c & (p[i] ^ q[i]);
    p[i] ^= t;
    q[i] ^= t;
  }
}

function pack(out: Uint8Array, n: Field): void {
  const m = gf();
  const t = gf();
  for (let i = 0; i < FIELD_LIMBS; i++) t[i] = n[i];
  carry(t);
  carry(t);
  carry(t);
  // Twice, because one conditional subtraction of p can leave a value that is
  // still >= p (limbs are only loosely reduced coming out of the ladder).
  for (let j = 0; j < 2; j++) {
    m[0] = t[0] - 0xffed;
    for (let i = 1; i < 15; i++) {
      m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
      m[i - 1] &= 0xffff;
    }
    m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
    const b = (m[15] >> 16) & 1;
    m[14] &= 0xffff;
    swap(t, m, 1 - b);
  }
  for (let i = 0; i < FIELD_LIMBS; i++) {
    out[2 * i] = t[i] & 0xff;
    out[2 * i + 1] = t[i] >> 8;
  }
}

function unpack(o: Field, n: Uint8Array): void {
  for (let i = 0; i < FIELD_LIMBS; i++) o[i] = n[2 * i] + (n[2 * i + 1] << 8);
  o[15] &= 0x7fff;
}

function add(o: Field, a: Field, b: Field): void {
  for (let i = 0; i < FIELD_LIMBS; i++) o[i] = a[i] + b[i];
}

function sub(o: Field, a: Field, b: Field): void {
  for (let i = 0; i < FIELD_LIMBS; i++) o[i] = a[i] - b[i];
}

function mul(o: Field, a: Field, b: Field): void {
  // Schoolbook into 31 limbs, then fold the top half back with 2^256 = 38.
  // Worst case per output limb is 16 * 65535^2 * 38, about 2.6e12 — three
  // orders of magnitude below the 2^53 where a double stops being exact.
  const t = new Float64Array(31);
  for (let i = 0; i < FIELD_LIMBS; i++) {
    for (let j = 0; j < FIELD_LIMBS; j++) t[i + j] += a[i] * b[j];
  }
  for (let i = 0; i < 15; i++) t[i] += 38 * t[i + 16];
  for (let i = 0; i < FIELD_LIMBS; i++) o[i] = t[i];
  carry(o);
  carry(o);
}

function square(o: Field, a: Field): void {
  mul(o, a, a);
}

function invert(o: Field, i: Field): void {
  // Fermat: x^(p-2) via the fixed 254-step addition chain for 2^255 - 21.
  const c = gf();
  for (let a = 0; a < FIELD_LIMBS; a++) c[a] = i[a];
  for (let a = 253; a >= 0; a--) {
    square(c, c);
    if (a !== 2 && a !== 4) mul(c, c, i);
  }
  for (let a = 0; a < FIELD_LIMBS; a++) o[a] = c[a];
}

/**
 * Clamp a scalar the way curve25519 requires.
 *
 * Clearing the low three bits kills the small-order subgroup; forcing bit 254
 * fixes the ladder's length so it cannot leak the scalar's magnitude. `wg
 * genkey` emits an already-clamped key, so doing it here means our generated
 * keys are byte-identical in form to the ones the tool produces.
 */
export function clamp(key: Uint8Array): Uint8Array {
  const k = new Uint8Array(key);
  k[0] &= 248;
  k[31] &= 127;
  k[31] |= 64;
  return k;
}

function scalarMult(scalar: Uint8Array, point: Uint8Array): Uint8Array {
  const z = clamp(scalar);
  const x = new Float64Array(80);
  const a = gf();
  const b = gf();
  const c = gf();
  const d = gf();
  const e = gf();
  const f = gf();

  unpack(x as unknown as Field, point);
  for (let i = 0; i < FIELD_LIMBS; i++) {
    b[i] = x[i];
    d[i] = a[i] = c[i] = 0;
  }
  a[0] = d[0] = 1;

  for (let i = 254; i >= 0; --i) {
    const r = (z[i >>> 3] >>> (i & 7)) & 1;
    swap(a, b, r);
    swap(c, d, r);
    add(e, a, c);
    sub(a, a, c);
    add(c, b, d);
    sub(b, b, d);
    square(d, e);
    square(f, a);
    mul(a, c, a);
    mul(c, b, e);
    add(e, a, c);
    sub(a, a, c);
    square(b, a);
    sub(c, d, f);
    mul(a, c, A24);
    add(a, a, d);
    mul(c, c, a);
    mul(a, d, f);
    mul(d, b, x.subarray(0, 16) as Field);
    square(b, e);
    swap(a, b, r);
    swap(c, d, r);
  }

  for (let i = 0; i < FIELD_LIMBS; i++) {
    x[i + 16] = a[i];
    x[i + 32] = c[i];
    x[i + 48] = b[i];
    x[i + 64] = d[i];
  }
  const x32 = x.subarray(32, 48) as Field;
  const x16 = x.subarray(16, 32) as Field;
  invert(x32, x32);
  mul(x16, x16, x32);

  const out = new Uint8Array(32);
  pack(out, x16);
  return out;
}

/** The curve25519 base point, u = 9. */
const BASE_POINT = (() => {
  const p = new Uint8Array(32);
  p[0] = 9;
  return p;
})();

// --------------------------------------------------------------------------- //
// base64
// --------------------------------------------------------------------------- //

const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * Encode 32 raw bytes as WireGuard writes them.
 *
 * Hand-rolled rather than `btoa`, which only speaks strings and so needs a
 * latin1 round trip that silently corrupts any byte above 0x7f under some
 * bundler polyfills. Fixed alphabet, always padded: `wg` accepts nothing else.
 */
export function toBase64(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i];
    const b1 = i + 1 < bytes.length ? bytes[i + 1] : 0;
    const b2 = i + 2 < bytes.length ? bytes[i + 2] : 0;
    out += B64[b0 >> 2];
    out += B64[((b0 & 3) << 4) | (b1 >> 4)];
    out += i + 1 < bytes.length ? B64[((b1 & 15) << 2) | (b2 >> 6)] : "=";
    out += i + 2 < bytes.length ? B64[b2 & 63] : "=";
  }
  return out;
}

/** Decode base64, or return null. Never throws: callers are validating input. */
export function fromBase64(text: string): Uint8Array | null {
  const clean = text.trim();
  if (clean.length === 0 || clean.length % 4 !== 0) return null;

  const bytes: number[] = [];
  let acc = 0;
  let bits = 0;
  let padding = 0;
  for (const ch of clean) {
    if (ch === "=") {
      padding++;
      continue;
    }
    // Padding is only ever trailing; a character after it means the input is
    // two concatenated keys or a truncated paste, not a key.
    if (padding > 0) return null;
    const value = B64.indexOf(ch);
    if (value < 0) return null;
    acc = (acc << 6) | value;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((acc >> bits) & 0xff);
    }
  }
  if (padding > 2) return null;
  return new Uint8Array(bytes);
}

// --------------------------------------------------------------------------- //
// the public surface
// --------------------------------------------------------------------------- //

export interface Keypair {
  privateKey: string;
  publicKey: string;
}

/** How a base64 string failed to be a WireGuard key, in words an operator can act on. */
export function keyProblem(text: string): string | null {
  const clean = text.trim();
  if (!clean) return "empty";
  if (clean.length !== 44) {
    return `a WireGuard key is 44 base64 characters, this is ${clean.length}`;
  }
  const raw = fromBase64(clean);
  if (raw === null) return "not valid base64";
  if (raw.length !== 32) return `decodes to ${raw.length} bytes, expected 32`;
  return null;
}

export function isValidKey(text: string): boolean {
  return keyProblem(text) === null;
}

/** Derive the public key of a base64 private key. Returns null if it is not one. */
export function publicFromPrivate(privateKey: string): string | null {
  const raw = fromBase64(privateKey.trim());
  if (raw === null || raw.length !== 32) return null;
  return toBase64(scalarMult(raw, BASE_POINT));
}

/**
 * A fresh keypair, from the platform CSPRNG.
 *
 * `crypto.getRandomValues` and nothing else: `Math.random` is seeded per tab
 * from a source with no security claim, and a VPN key generated from it is
 * worse than no VPN because it looks like one.
 */
export function generateKeypair(): Keypair {
  const source = globalThis.crypto;
  if (!source?.getRandomValues) {
    throw new Error("this browser has no Web Crypto: refusing to generate a key");
  }
  const raw = clamp(source.getRandomValues(new Uint8Array(32)));
  return {
    privateKey: toBase64(raw),
    publicKey: toBase64(scalarMult(raw, BASE_POINT)),
  };
}
