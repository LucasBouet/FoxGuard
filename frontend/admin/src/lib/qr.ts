/**
 * A QR encoder, because the config must not leave the browser to become one.
 *
 * Getting a WireGuard config onto a phone means scanning it, and every hosted
 * "QR code API" works by receiving the thing you want encoded. For this payload
 * that would mean posting a private key to a third party -- so the encoder is
 * here, in the same page, with no network path of any kind.
 *
 * Byte mode only. That is all a `.conf` needs, and the alphanumeric and kanji
 * modes would be several hundred lines that no caller here could ever reach.
 *
 * The algorithm is ISO/IEC 18004 and the structure follows Nayuki's reference
 * design (finder and alignment patterns, Reed-Solomon over GF(256), interleaved
 * blocks, eight mask patterns scored by the standard's four penalty rules).
 * None of it is improvised: `tests/qr.test.ts` decodes the output with a real
 * `zbarimg` and compares the module matrix against `segno`, so an error in any
 * of the tables below shows up as a failing test rather than as a code that
 * only some phones can read.
 */

export type EcLevel = "L" | "M" | "Q" | "H";

export interface QrCode {
  /** Width and height in modules, excluding the quiet zone. */
  size: number;
  /** Row-major; true is dark. */
  modules: boolean[][];
  version: number;
  ecLevel: EcLevel;
  mask: number;
}

/** The two bits the format information uses -- not L, M, Q, H order. */
const EC_FORMAT_BITS: Record<EcLevel, number> = { L: 1, M: 0, Q: 3, H: 2 };

// Index [ecLevel][version]; entry 0 is unused so versions read naturally.
const ECC_CODEWORDS_PER_BLOCK: Record<EcLevel, number[]> = {
  L: [-1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28,
      28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
  M: [-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26,
      26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28],
  Q: [-1, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30,
      28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
  H: [-1, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28,
      30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
};

const NUM_ERROR_CORRECTION_BLOCKS: Record<EcLevel, number[]> = {
  L: [-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8,
      8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25],
  M: [-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16,
      17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49],
  Q: [-1, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20,
      23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68],
  H: [-1, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25,
      25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81],
};

// Both tables above are checked entry by entry against segno in
// `tests/qr.test.ts`. That is not ceremony: version 8 at level H was wrong here
// -- 5 blocks where the standard says 6 -- and nothing else noticed. The symbol
// still encoded, still masked, and still scanned at every other version; it
// would have produced an unreadable code for exactly one payload size on
// exactly one setting.

const MIN_VERSION = 1;
const MAX_VERSION = 40;

/** Total modules available for data and ECC, before the function patterns. */
function rawDataModules(version: number): number {
  let result = (16 * version + 128) * version + 64;
  if (version >= 2) {
    const alignments = Math.floor(version / 7) + 2;
    result -= (25 * alignments - 10) * alignments - 55;
    if (version >= 7) result -= 36;
  }
  return result;
}

function dataCodewords(version: number, ecLevel: EcLevel): number {
  return (
    Math.floor(rawDataModules(version) / 8) -
    ECC_CODEWORDS_PER_BLOCK[ecLevel][version] * NUM_ERROR_CORRECTION_BLOCKS[ecLevel][version]
  );
}

function alignmentPositions(version: number): number[] {
  if (version === 1) return [];
  const count = Math.floor(version / 7) + 2;
  const size = version * 4 + 17;
  // Version 32 is the one place the general formula disagrees with the
  // standard's table, and it is spelled out in the spec as an exception.
  const step = version === 32 ? 26 : Math.ceil((version * 4 + 4) / (count * 2 - 2)) * 2;
  const result = [6];
  for (let pos = size - 7; result.length < count; pos -= step) result.splice(1, 0, pos);
  return result;
}

// --------------------------------------------------------------------------- //
// GF(256), primitive polynomial x^8 + x^4 + x^3 + x^2 + 1
// --------------------------------------------------------------------------- //

function gfMultiply(x: number, y: number): number {
  let z = 0;
  for (let i = 7; i >= 0; i--) {
    z = (z << 1) ^ ((z >>> 7) * 0x11d);
    z ^= ((y >>> i) & 1) * x;
  }
  return z & 0xff;
}

function reedSolomonDivisor(degree: number): number[] {
  const result = new Array<number>(degree).fill(0);
  result[degree - 1] = 1;
  let root = 1;
  for (let i = 0; i < degree; i++) {
    for (let j = 0; j < degree; j++) {
      result[j] = gfMultiply(result[j], root);
      if (j + 1 < degree) result[j] ^= result[j + 1];
    }
    root = gfMultiply(root, 0x02);
  }
  return result;
}

function reedSolomonRemainder(data: number[], divisor: number[]): number[] {
  const result = new Array<number>(divisor.length).fill(0);
  for (const byte of data) {
    const factor = byte ^ (result.shift() as number);
    result.push(0);
    divisor.forEach((coefficient, i) => {
      result[i] ^= gfMultiply(coefficient, factor);
    });
  }
  return result;
}

// --------------------------------------------------------------------------- //
// bit stream
// --------------------------------------------------------------------------- //

class BitBuffer {
  readonly bits: number[] = [];

  push(value: number, length: number): void {
    for (let i = length - 1; i >= 0; i--) this.bits.push((value >>> i) & 1);
  }

  get length(): number {
    return this.bits.length;
  }

  toBytes(): number[] {
    const bytes = new Array<number>(Math.ceil(this.bits.length / 8)).fill(0);
    this.bits.forEach((bit, i) => {
      bytes[i >>> 3] |= bit << (7 - (i & 7));
    });
    return bytes;
  }
}

function encodeBytes(data: Uint8Array, version: number, ecLevel: EcLevel): number[] {
  const capacity = dataCodewords(version, ecLevel) * 8;
  const buffer = new BitBuffer();
  buffer.push(0b0100, 4); // byte mode
  buffer.push(data.length, version <= 9 ? 8 : 16);
  for (const byte of data) buffer.push(byte, 8);

  // Terminator, then pad to a byte boundary, then the standard's alternating
  // filler. The filler bytes are not arbitrary: a decoder uses them to tell
  // padding from data that happens to be zero.
  buffer.push(0, Math.min(4, capacity - buffer.length));
  buffer.push(0, (8 - (buffer.length % 8)) % 8);
  for (let pad = 0xec; buffer.length < capacity; pad ^= 0xec ^ 0x11) buffer.push(pad, 8);

  return buffer.toBytes();
}

/** Split into blocks, add ECC, and interleave -- which is what makes a burst of damage survivable. */
function interleave(data: number[], version: number, ecLevel: EcLevel): number[] {
  const blockCount = NUM_ERROR_CORRECTION_BLOCKS[ecLevel][version];
  const eccLength = ECC_CODEWORDS_PER_BLOCK[ecLevel][version];
  const rawCodewords = Math.floor(rawDataModules(version) / 8);
  const shortBlockLength = Math.floor(rawCodewords / blockCount);
  const shortBlockCount = blockCount - (rawCodewords % blockCount);
  const divisor = reedSolomonDivisor(eccLength);

  const blocks: number[][] = [];
  for (let i = 0, offset = 0; i < blockCount; i++) {
    const length = shortBlockLength - eccLength + (i < shortBlockCount ? 0 : 1);
    const block = data.slice(offset, offset + length);
    offset += length;
    const ecc = reedSolomonRemainder(block, divisor);
    // Short blocks are padded to the long length before the ECC is appended,
    // so that column `i` means the same thing in every block. The pad is then
    // skipped on the way out. Interleaving without it silently shifts every
    // error-correction byte by one and produces a code no scanner can read --
    // which is exactly what the first version of this function did.
    const padded = i < shortBlockCount ? [...block, 0] : block;
    blocks.push([...padded, ...ecc]);
  }

  const result: number[] = [];
  for (let i = 0; i < blocks[0].length; i++) {
    blocks.forEach((block, blockIndex) => {
      if (i !== shortBlockLength - eccLength || blockIndex >= shortBlockCount) {
        result.push(block[i]);
      }
    });
  }
  return result;
}

// --------------------------------------------------------------------------- //
// the grid
// --------------------------------------------------------------------------- //

class Grid {
  readonly size: number;
  readonly modules: boolean[][];
  /** Modules belonging to finder, timing, alignment and format areas. */
  readonly reserved: boolean[][];

  constructor(readonly version: number) {
    this.size = version * 4 + 17;
    this.modules = Array.from({ length: this.size }, () =>
      new Array<boolean>(this.size).fill(false),
    );
    this.reserved = Array.from({ length: this.size }, () =>
      new Array<boolean>(this.size).fill(false),
    );
  }

  private set(x: number, y: number, dark: boolean, isFunction = true): void {
    if (x < 0 || y < 0 || x >= this.size || y >= this.size) return;
    this.modules[y][x] = dark;
    if (isFunction) this.reserved[y][x] = true;
  }

  drawFunctionPatterns(ecLevel: EcLevel): void {
    for (let i = 0; i < this.size; i++) {
      // Timing patterns: the alternating row and column at index 6.
      this.set(6, i, i % 2 === 0);
      this.set(i, 6, i % 2 === 0);
    }
    for (const [x, y] of [
      [3, 3],
      [this.size - 4, 3],
      [3, this.size - 4],
    ]) {
      this.drawFinder(x, y);
    }

    const positions = alignmentPositions(this.version);
    for (let i = 0; i < positions.length; i++) {
      for (let j = 0; j < positions.length; j++) {
        // The three corners already carry finder patterns.
        const corner =
          (i === 0 && j === 0) ||
          (i === 0 && j === positions.length - 1) ||
          (i === positions.length - 1 && j === 0);
        if (!corner) this.drawAlignment(positions[i], positions[j]);
      }
    }

    this.reserveFormat();
    this.drawVersion();
  }

  /**
   * Claim the format modules without deciding what goes in them.
   *
   * They cannot be filled yet: the format information encodes the mask, and the
   * mask has not been chosen. Writing a placeholder and scoring it would make
   * the evaluation self-referential -- each candidate would be judged partly on
   * a field describing itself -- which is why ISO/IEC 18004 §7.8 says the
   * format and version information is added *after* masking is evaluated.
   * Reserved and light is the state the standard evaluates.
   */
  private reserveFormat(): void {
    for (let i = 0; i <= 8; i++) {
      // Index 6 is the timing pattern crossing the format strip, and it is
      // already drawn. Writing over it costs two modules that no decoder
      // tolerates -- and the symbol still scans, because the format bits
      // written later happen to restore one of them.
      if (i === 6) continue;
      this.set(8, i, false);
      this.set(i, 8, false);
    }
    for (let i = 0; i < 8; i++) this.set(this.size - 1 - i, 8, false);
    for (let i = 0; i < 8; i++) this.set(8, this.size - 1 - i, false);
  }

  private drawFinder(cx: number, cy: number): void {
    for (let dy = -4; dy <= 4; dy++) {
      for (let dx = -4; dx <= 4; dx++) {
        const distance = Math.max(Math.abs(dx), Math.abs(dy));
        this.set(cx + dx, cy + dy, distance !== 2 && distance !== 4);
      }
    }
  }

  private drawAlignment(cx: number, cy: number): void {
    for (let dy = -2; dy <= 2; dy++) {
      for (let dx = -2; dx <= 2; dx++) {
        this.set(cx + dx, cy + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
      }
    }
  }

  /** Format information: 5 data bits, 10 BCH bits, XORed with a fixed mask. */
  drawFormat(ecLevel: EcLevel, mask: number): void {
    const data = (EC_FORMAT_BITS[ecLevel] << 3) | mask;
    let rem = data;
    for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
    const bits = ((data << 10) | rem) ^ 0x5412;

    const bit = (i: number) => ((bits >>> i) & 1) === 1;
    for (let i = 0; i <= 5; i++) this.set(8, i, bit(i));
    this.set(8, 7, bit(6));
    this.set(8, 8, bit(7));
    this.set(7, 8, bit(8));
    for (let i = 9; i < 15; i++) this.set(14 - i, 8, bit(i));

    for (let i = 0; i < 8; i++) this.set(this.size - 1 - i, 8, bit(i));
    for (let i = 8; i < 15; i++) this.set(8, this.size - 15 + i, bit(i));
    this.set(8, this.size - 8, true); // the always-dark module
  }

  private drawVersion(): void {
    if (this.version < 7) return;
    let rem = this.version;
    for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
    const bits = (this.version << 12) | rem;
    for (let i = 0; i < 18; i++) {
      const dark = ((bits >>> i) & 1) === 1;
      const a = this.size - 11 + (i % 3);
      const b = Math.floor(i / 3);
      this.set(a, b, dark);
      this.set(b, a, dark);
    }
  }

  /** Lay the codewords out in the zigzag the standard prescribes. */
  drawCodewords(codewords: number[]): void {
    let i = 0;
    for (let right = this.size - 1; right >= 1; right -= 2) {
      // Column 6 is the vertical timing pattern; the zigzag steps over it.
      if (right === 6) right = 5;
      for (let vert = 0; vert < this.size; vert++) {
        for (let j = 0; j < 2; j++) {
          const x = right - j;
          const upward = ((right + 1) & 2) === 0;
          const y = upward ? this.size - 1 - vert : vert;
          if (this.reserved[y][x] || i >= codewords.length * 8) continue;
          this.modules[y][x] = ((codewords[i >>> 3] >>> (7 - (i & 7))) & 1) !== 0;
          i++;
        }
      }
    }
  }

  applyMask(mask: number): void {
    for (let y = 0; y < this.size; y++) {
      for (let x = 0; x < this.size; x++) {
        if (this.reserved[y][x]) continue;
        if (maskAt(mask, x, y)) this.modules[y][x] = !this.modules[y][x];
      }
    }
  }

  penalty(): number {
    return penaltyScore(this.modules, this.size);
  }
}

function maskAt(mask: number, x: number, y: number): boolean {
  switch (mask) {
    case 0:
      return (x + y) % 2 === 0;
    case 1:
      return y % 2 === 0;
    case 2:
      return x % 3 === 0;
    case 3:
      return (x + y) % 3 === 0;
    case 4:
      return (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0;
    case 5:
      return ((x * y) % 2) + ((x * y) % 3) === 0;
    case 6:
      return (((x * y) % 2) + ((x * y) % 3)) % 2 === 0;
    default:
      return ((((x + y) % 2) + ((x * y) % 3)) % 2) === 0;
  }
}

/**
 * The standard's four penalty rules.
 *
 * They exist to steer the mask away from patterns a scanner would misread --
 * long runs, solid blocks, and anything resembling a finder pattern in the
 * data area. Lower is better.
 */
function penaltyScore(modules: boolean[][], size: number): number {
  let result = 0;

  /**
   * Rule 3 is stated as a *ratio*, 1:1:3:1:1, not as a fixed seven modules --
   * a 2:2:6:2:2 run fools a scanner just as well. So the last six run lengths
   * are kept and tested proportionally, with the quiet zone counted as light on
   * the outermost run. An implementation that only looks for the literal
   * seven-module pattern under-counts, still produces a valid code, and quietly
   * picks a worse mask than the standard asks for -- which is why this is
   * checked against a second encoder rather than trusted.
   */
  const addHistory = (run: number, history: number[]) => {
    if (history[0] === 0) run += size; // the quiet zone beside the first run
    history.pop();
    history.unshift(run);
  };
  const countPatterns = (history: number[]): number => {
    const n = history[1];
    const core =
      n > 0 &&
      history[2] === n &&
      history[3] === n * 3 &&
      history[4] === n &&
      history[5] === n;
    return (
      (core && history[0] >= n * 4 && history[6] >= n ? 1 : 0) +
      (core && history[6] >= n * 4 && history[0] >= n ? 1 : 0)
    );
  };
  const terminate = (dark: boolean, run: number, history: number[]): number => {
    if (dark) {
      addHistory(run, history);
      run = 0;
    }
    addHistory(run + size, history);
    return countPatterns(history);
  };

  // Rules 1 and 3 walk the same runs, in both directions.
  for (const vertical of [false, true]) {
    for (let i = 0; i < size; i++) {
      let dark = false;
      let run = 0;
      const history = [0, 0, 0, 0, 0, 0, 0];
      for (let j = 0; j < size; j++) {
        const cell = vertical ? modules[j][i] : modules[i][j];
        if (cell === dark) {
          run++;
          if (run === 5) result += 3;
          else if (run > 5) result++;
        } else {
          addHistory(run, history);
          if (!dark) result += countPatterns(history) * 40;
          dark = cell;
          run = 1;
        }
      }
      result += terminate(dark, run, history) * 40;
    }
  }

  // Rule 2: every 2x2 block of one colour.
  for (let y = 0; y < size - 1; y++) {
    for (let x = 0; x < size - 1; x++) {
      const c = modules[y][x];
      if (c === modules[y][x + 1] && c === modules[y + 1][x] && c === modules[y + 1][x + 1]) {
        result += 3;
      }
    }
  }

  // Rule 4: deviation from an even balance of dark and light.
  let dark = 0;
  for (const row of modules) for (const cell of row) if (cell) dark++;
  const total = size * size;
  const k = Math.ceil(Math.abs(dark * 20 - total * 10) / total) - 1;
  return result + Math.max(k, 0) * 10;
}

// --------------------------------------------------------------------------- //
// public
// --------------------------------------------------------------------------- //

function toUtf8(text: string): Uint8Array {
  if (typeof TextEncoder !== "undefined") return new TextEncoder().encode(text);
  // Node before the global TextEncoder, and any exotic embedded runtime.
  const bytes: number[] = [];
  for (const char of unescape(encodeURIComponent(text))) bytes.push(char.charCodeAt(0));
  return new Uint8Array(bytes);
}

/**
 * Encode `text` in the smallest version that holds it.
 *
 * Returns null when it does not fit at all: a QR code tops out at 2953 bytes in
 * byte mode with the weakest error correction, and a config that large means
 * something else is wrong. The caller shows the text instead -- silently
 * dropping to an unreadably dense code would be worse.
 *
 * `forcedMask` skips the evaluation and uses the pattern given. Only the tests
 * pass it, to exercise all eight patterns rather than the one the penalty rules
 * happen to prefer.
 */
export function encodeQr(
  text: string,
  ecLevel: EcLevel = "M",
  forcedMask?: number,
): QrCode | null {
  const data = toUtf8(text);

  let version = MIN_VERSION;
  for (; version <= MAX_VERSION; version++) {
    const capacity = dataCodewords(version, ecLevel) * 8;
    const header = 4 + (version <= 9 ? 8 : 16);
    if (header + data.length * 8 <= capacity) break;
  }
  if (version > MAX_VERSION) return null;

  const codewords = interleave(encodeBytes(data, version, ecLevel), version, ecLevel);

  const build = (mask: number): Grid => {
    const grid = new Grid(version);
    grid.drawFunctionPatterns(ecLevel);
    grid.drawCodewords(codewords);
    grid.applyMask(mask);
    return grid;
  };

  let best: Grid | null = null;
  let bestMask = forcedMask ?? 0;
  if (forcedMask === undefined) {
    let bestPenalty = Infinity;
    for (let mask = 0; mask < 8; mask++) {
      const grid = build(mask);
      const score = grid.penalty();
      if (score < bestPenalty) {
        bestPenalty = score;
        best = grid;
        bestMask = mask;
      }
    }
  } else {
    best = build(forcedMask);
  }

  const grid = best as Grid;
  grid.drawFormat(ecLevel, bestMask);
  return {
    size: grid.size,
    modules: grid.modules,
    version,
    ecLevel,
    mask: bestMask,
  };
}

/**
 * An SVG path covering every dark module, for a viewBox of
 * `size + 2 * border` units.
 *
 * One path rather than one rect per module: a version-20 code is 9409 modules,
 * and that many DOM nodes makes a page visibly slow to open.
 */
export function toSvgPath(code: QrCode, border = 4): string {
  const parts: string[] = [];
  for (let y = 0; y < code.size; y++) {
    for (let x = 0; x < code.size; x++) {
      if (code.modules[y][x]) parts.push(`M${x + border},${y + border}h1v1h-1z`);
    }
  }
  return parts.join("");
}

/**
 * The block structure of one symbol.
 *
 * Exported for the table test rather than for callers: these three numbers are
 * the part of the encoder that cannot be derived from anything, only looked up,
 * and a single wrong entry stays invisible until someone scans a config of one
 * particular length.
 */
export function blockStructure(
  version: number,
  ecLevel: EcLevel,
): { blocks: number; eccPerBlock: number; data: number } {
  return {
    blocks: NUM_ERROR_CORRECTION_BLOCKS[ecLevel][version],
    eccPerBlock: ECC_CODEWORDS_PER_BLOCK[ecLevel][version],
    data: dataCodewords(version, ecLevel),
  };
}
