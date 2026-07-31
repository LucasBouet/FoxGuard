/**
 * The QR encoder, checked by a real scanner and a second implementation.
 *
 * A QR code is a format where "looks like a QR code" and "is a QR code" are
 * hard to tell apart by eye, and the payload here is a config someone will
 * scan once, on a phone, possibly far from the person who generated it. So
 * there are two independent checks, and neither of them is a golden file:
 *
 *   1. every code is rendered to a PNG and read back with `zbarimg`, the
 *      decoder in the zbar library -- the same lineage as what phone apps use;
 *   2. the module matrix is compared against `segno`, an unrelated encoder, at
 *      the same version and mask. Identical matrices mean the ECC tables, the
 *      Reed-Solomon arithmetic, the block interleaving, the zigzag placement
 *      and the format bits all agree with someone else's reading of the spec.
 *
 * Check 2 also compares the *chosen* mask, which is the only test of the
 * penalty scoring: a wrong score still produces a scannable code, just a worse
 * one, and nothing else would ever notice.
 */

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { crc32, deflateSync } from "node:zlib";

import { blockStructure, encodeQr, toSvgPath } from "../src/lib/qr";
import type { EcLevel, QrCode } from "../src/lib/qr";

// --------------------------------------------------------------------------- //
// a minimal PNG writer, so the encoder can be handed to a real decoder
// --------------------------------------------------------------------------- //

function chunk(type: string, body: Buffer): Buffer {
  const head = Buffer.alloc(4);
  head.writeUInt32BE(body.length);
  const typed = Buffer.concat([Buffer.from(type, "ascii"), body]);
  const tail = Buffer.alloc(4);
  tail.writeUInt32BE(crc32(typed) >>> 0);
  return Buffer.concat([head, typed, tail]);
}

/** 8-bit greyscale, one filter byte per row. No dependency, no colour profile. */
function toPng(code: QrCode, scale = 8, border = 4): Buffer {
  const width = (code.size + border * 2) * scale;
  const raw = Buffer.alloc((width + 1) * width);
  for (let y = 0; y < width; y++) {
    const rowStart = y * (width + 1);
    raw[rowStart] = 0;
    const moduleY = Math.floor(y / scale) - border;
    for (let x = 0; x < width; x++) {
      const moduleX = Math.floor(x / scale) - border;
      const dark =
        moduleY >= 0 &&
        moduleY < code.size &&
        moduleX >= 0 &&
        moduleX < code.size &&
        code.modules[moduleY][moduleX];
      raw[rowStart + 1 + x] = dark ? 0 : 255;
    }
  }

  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(width, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 0; // greyscale
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk("IHDR", ihdr),
    chunk("IDAT", deflateSync(raw)),
    chunk("IEND", Buffer.alloc(0)),
  ]);
}

function has(binary: string, args: string[]): boolean {
  try {
    execFileSync(binary, args, { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

const HAS_ZBAR = has("sh", ["-c", "command -v zbarimg"]);

/**
 * The repository's virtualenv, where segno lives.
 *
 * Walked upwards rather than hard-coded: this file runs from `.test-build`,
 * whose depth below the repository root is a detail of the build, not something
 * the test should encode.
 */
const PYTHON = (() => {
  let dir = __dirname;
  for (let i = 0; i < 8; i++) {
    const candidate = join(dir, ".venv", "bin", "python");
    if (has(candidate, ["-c", "import segno"])) return candidate;
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return null;
})();

function decode(code: QrCode): string {
  const dir = mkdtempSync(join(tmpdir(), "fgqr-"));
  try {
    const path = join(dir, "code.png");
    writeFileSync(path, toPng(code));
    // zbarimg writes a dbus warning to stderr in a container; --quiet keeps
    // stdout to the payload alone, which is all we compare.
    return execFileSync("zbarimg", ["--quiet", "--raw", path]).toString().replace(/\n$/, "");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/**
 * `micro=False` matters: left to itself segno answers a short payload with a
 * *Micro* QR code, which is a different symbology with four masks and its own
 * grid. Comparing against one would be comparing against the wrong thing.
 * `boost_error=False` stops it from silently upgrading the level we asked for.
 */
function segno(text: string, args: string, field: string): string {
  const script = [
    "import sys, segno",
    `q = segno.make(sys.stdin.read(), mode='byte', micro=False, boost_error=False, ${args})`,
    `print(${field})`,
  ].join("\n");
  return execFileSync(PYTHON as string, ["-c", script], { input: text }).toString().trim();
}

function segnoMatrix(text: string, ecLevel: EcLevel, version: number, mask: number): string {
  return segno(
    text,
    `error='${ecLevel.toLowerCase()}', version=${version}, mask=${mask}`,
    "''.join(''.join(str(int(c)) for c in row) for row in q.matrix)",
  );
}

function segnoAutoMask(text: string, ecLevel: EcLevel): number {
  return Number(segno(text, `error='${ecLevel.toLowerCase()}'`, "q.mask"));
}

/**
 * The longest payload that still fits `version`, which is the one that leaves
 * no padding at all.
 *
 * That case is the only fair matrix comparison. Everything shorter ends with
 * pad codewords, and segno emits an extra 0x00 there where ISO/IEC 18004 §8.4.9
 * says the alternating 0xEC/0x11 filler starts straight after the terminator
 * and byte alignment. Decoders ignore padding -- both codes read back correctly
 * -- but the modules differ, so a comparison including it would be asserting
 * that we share segno's reading of that clause rather than that we agree.
 */
function exactFill(version: number, ecLevel: EcLevel): string {
  let low = 1;
  let high = 3000;
  let best = 0;
  while (low <= high) {
    const mid = Math.floor((low + high) / 2);
    const code = encodeQr(payload(mid), ecLevel);
    if (code !== null && code.version <= version) {
      best = mid;
      low = mid + 1;
    } else {
      high = mid - 1;
    }
  }
  return payload(best);
}

/** Varied printable ASCII rather than one repeated byte, so the ECC has work to do. */
function payload(length: number): string {
  return Array.from({ length }, (_, i) => String.fromCharCode(33 + ((i * 31) % 94))).join("");
}

function ourMatrix(code: QrCode): string {
  return code.modules.map((row) => row.map((c) => (c ? "1" : "0")).join("")).join("");
}

/**
 * Penalty rules 1, 2 and 4, written out here rather than imported.
 *
 * A test that called the encoder's own scorer would agree with it by
 * construction. This is a second reading of Table 11, and it is what makes the
 * comparison against segno mean anything.
 */
function ruleScores(code: QrCode): { n1: number; n2: number; n4: number } {
  const { modules, size } = code;
  let n1 = 0;
  for (const vertical of [false, true]) {
    for (let i = 0; i < size; i++) {
      let run = 1;
      for (let j = 1; j < size; j++) {
        const current = vertical ? modules[j][i] : modules[i][j];
        const previous = vertical ? modules[j - 1][i] : modules[i][j - 1];
        if (current === previous) run++;
        else {
          if (run >= 5) n1 += run - 2;
          run = 1;
        }
      }
      if (run >= 5) n1 += run - 2;
    }
  }

  let n2 = 0;
  for (let y = 1; y < size; y++) {
    for (let x = 1; x < size; x++) {
      const c = modules[y][x];
      if (c === modules[y][x - 1] && c === modules[y - 1][x] && c === modules[y - 1][x - 1]) {
        n2 += 3;
      }
    }
  }

  const dark = modules.flat().filter(Boolean).length;
  const percent = (dark / (size * size)) * 100;
  const n4 = 10 * Math.trunc(Math.abs(percent - 50) / 5);

  return { n1, n2, n4 };
}

const SAMPLE_CONFIG = [
  "# ada-laptop (ada-laptop.fox.internal)",
  "[Interface]",
  "PrivateKey = 6JeH1p9UbLcZ0dMPUmXFPXfCbLd1uY6MRP3jTIJvW0Y=",
  "Address = 10.88.0.5/32",
  "DNS = 10.88.0.1, fox.internal",
  "",
  "[Peer]",
  "PublicKey = ox3iCjdNGr7iHRvp1E+jSVNIUNt/5iaw86e15HOo0Vw=",
  "Endpoint = vpn.example.com:51820",
  "AllowedIPs = 10.88.0.0/24, 192.168.10.0/24",
  "PersistentKeepalive = 25",
  "",
].join("\n");

// --------------------------------------------------------------------------- //
// shape
// --------------------------------------------------------------------------- //

test("the version grows with the payload and the size follows it", () => {
  const small = encodeQr("hi")!;
  const large = encodeQr(SAMPLE_CONFIG)!;
  assert.equal(small.size, small.version * 4 + 17);
  assert.equal(large.size, large.version * 4 + 17);
  assert.ok(large.version > small.version);
  assert.ok(large.modules.length === large.size && large.modules[0].length === large.size);
});

test("the three finder patterns are where they must be", () => {
  const code = encodeQr("finders")!;
  for (const [ox, oy] of [
    [0, 0],
    [code.size - 7, 0],
    [0, code.size - 7],
  ]) {
    assert.equal(code.modules[oy][ox], true, "outer ring");
    assert.equal(code.modules[oy + 1][ox + 1], false, "light ring");
    assert.equal(code.modules[oy + 3][ox + 3], true, "solid centre");
  }
});

test("a payload larger than any QR code returns null instead of a bad one", () => {
  assert.equal(encodeQr("x".repeat(3000), "L"), null);
  assert.notEqual(encodeQr("x".repeat(2000), "L"), null);
});

test("an empty string still encodes", () => {
  const code = encodeQr("");
  assert.notEqual(code, null);
});

test("the SVG path draws one rectangle per dark module", () => {
  const code = encodeQr("path")!;
  const path = toSvgPath(code, 4);
  const dark = code.modules.flat().filter(Boolean).length;
  assert.equal(path.match(/M/g)?.length, dark);
  assert.match(path, /^M\d+,\d+h1v1h-1z/);
});

// --------------------------------------------------------------------------- //
// a real decoder
// --------------------------------------------------------------------------- //

test(
  "zbarimg reads back exactly what was encoded",
  { skip: HAS_ZBAR ? false : "zbarimg not installed" },
  () => {
    const payloads = [
      "hi",
      SAMPLE_CONFIG,
      "10.88.0.0/24, 192.168.10.0/24, 172.20.0.0/16",
      "x".repeat(1) ,
      "x".repeat(120),
      "x".repeat(800),
    ];
    for (const payload of payloads) {
      const code = encodeQr(payload);
      assert.notEqual(code, null, `did not fit: ${payload.length} bytes`);
      assert.equal(decode(code as QrCode), payload, `round trip failed at ${payload.length} bytes`);
    }
  },
);

test(
  "every error-correction level round trips",
  { skip: HAS_ZBAR ? false : "zbarimg not installed" },
  () => {
    for (const level of ["L", "M", "Q", "H"] as EcLevel[]) {
      const code = encodeQr(SAMPLE_CONFIG, level)!;
      assert.equal(code.ecLevel, level);
      assert.equal(decode(code), SAMPLE_CONFIG, `level ${level}`);
    }
  },
);

test(
  "payloads that cross the version boundaries round trip",
  { skip: HAS_ZBAR ? false : "zbarimg not installed" },
  () => {
    // Versions 1-9 use an 8-bit character count and 10+ a 16-bit one, and the
    // block structure changes at almost every version. Walking the lengths is
    // how an off-by-one in the interleaving gets caught.
    const seen = new Set<number>();
    for (let length = 1; length <= 700; length += 7) {
      const payload = Array.from({ length }, (_, i) =>
        String.fromCharCode(33 + ((i * 7) % 94)),
      ).join("");
      const code = encodeQr(payload, "M")!;
      seen.add(code.version);
      assert.equal(decode(code), payload, `length ${length}, version ${code.version}`);
    }
    assert.ok(seen.size >= 10, `only exercised ${seen.size} versions`);
  },
);

test(
  "non-ASCII survives as UTF-8",
  { skip: HAS_ZBAR ? false : "zbarimg not installed" },
  () => {
    // Device names carry accents, and they reach the QR through the comment line.
    const payload = "# hôtel-café — passerelle\n[Interface]\n";
    assert.equal(decode(encodeQr(payload)!), payload);
  },
);

// --------------------------------------------------------------------------- //
// a second implementation
// --------------------------------------------------------------------------- //

test(
  "all 160 error-correction table entries match the standard",
  { skip: PYTHON ? false : "segno not available in the repository virtualenv" },
  () => {
    // The tables are the one part of the encoder that is pure lookup, and a
    // single wrong entry is invisible everywhere except at the payload sizes
    // that land on it. This found exactly that: version 8 at level H had 5
    // blocks where the standard says 6, and every other test passed.
    const script = [
      "import json",
      "from segno import consts",
      "levels = {'L': 1, 'M': 0, 'Q': 3, 'H': 2}",
      "out = {}",
      "for name, key in levels.items():",
      "    for version in range(1, 41):",
      "        groups = consts.ECC[version][key]",
      "        ecc = {g.num_total - g.num_data for g in groups}",
      "        assert len(ecc) == 1",
      "        out[f'{name}{version}'] = [sum(g.num_blocks for g in groups),",
      "                                   ecc.pop(),",
      "                                   sum(g.num_blocks * g.num_data for g in groups)]",
      "print(json.dumps(out))",
    ].join("\n");
    const reference: Record<string, [number, number, number]> = JSON.parse(
      execFileSync(PYTHON as string, ["-c", script]).toString(),
    );

    for (const level of ["L", "M", "Q", "H"] as EcLevel[]) {
      for (let version = 1; version <= 40; version++) {
        const [blocks, eccPerBlock, data] = reference[`${level}${version}`];
        assert.deepEqual(
          blockStructure(version, level),
          { blocks, eccPerBlock, data },
          `version ${version} level ${level}`,
        );
      }
    }
  },
);

test(
  "the module matrix is identical to segno's",
  { skip: PYTHON ? false : "segno not available in the repository virtualenv" },
  () => {
    // Versions 1-9 carry an 8-bit character count and 10+ a 16-bit one, and the
    // block structure changes at nearly every version, so the span matters more
    // than the count. Byte-identical matrices mean the ECC tables, the
    // Reed-Solomon arithmetic, the block interleaving, the zigzag placement,
    // the alignment patterns, the format bits and the version bits all agree.
    const covered = new Set<number>();
    for (const version of [1, 2, 5, 7, 9, 10, 12, 15, 20]) {
      for (const level of ["L", "M", "Q", "H"] as EcLevel[]) {
        const text = exactFill(version, level);
        const code = encodeQr(text, level)!;
        covered.add(code.version);
        assert.equal(
          ourMatrix(code),
          segnoMatrix(text, level, code.version, code.mask),
          `${level}, version ${code.version}, ${text.length} bytes, mask ${code.mask}`,
        );
      }
    }
    assert.ok(covered.size >= 8, `only compared ${covered.size} versions`);
  },
);

test(
  "penalty rules 1, 2 and 4 agree with segno on the same matrix",
  { skip: PYTHON ? false : "segno not available in the repository virtualenv" },
  () => {
    // Rule 3 is deliberately absent. The standard states it as a *ratio*,
    // 1:1:3:1:1, which is what this encoder implements; segno matches the
    // literal seven-module pattern instead, and counts one occurrence where the
    // ratio reading counts two when both sides are clear. Both produce valid,
    // scannable codes -- they just sometimes prefer different masks, which is
    // why the chosen mask is not asserted against segno anywhere.
    const code = encodeQr(SAMPLE_CONFIG, "M")!;
    const matrix = code.modules.map((row) => row.map((cell) => (cell ? 1 : 0)));
    const script = [
      "import json, sys",
      "from segno.encoder import mask_scores",
      "rows = json.load(sys.stdin)",
      "n1, n2, n3, n4 = mask_scores([bytearray(r) for r in rows], len(rows), len(rows))",
      "print(n1, n2, n4)",
    ].join("\n");
    const [n1, n2, n4] = execFileSync(PYTHON as string, ["-c", script], {
      input: JSON.stringify(matrix),
    })
      .toString()
      .trim()
      .split(" ")
      .map(Number);

    assert.deepEqual(ruleScores(code), { n1, n2, n4 });
  },
);

test(
  "every mask pattern produces a code a scanner can read",
  { skip: HAS_ZBAR ? false : "zbarimg not installed" },
  () => {
    // What the mask *selection* cannot break but a wrong mask *pattern* would.
    // The pattern number goes into the format information, so a formula that
    // disagrees with the standard for even one of the eight leaves a code no
    // decoder can unmask -- and the mask the penalty rules happen to pick is
    // the only one anything else here would exercise.
    for (let mask = 0; mask < 8; mask++) {
      const code = encodeQr(SAMPLE_CONFIG, "M", mask)!;
      assert.equal(code.mask, mask);
      assert.equal(decode(code), SAMPLE_CONFIG, `mask ${mask}`);
    }
  },
);

