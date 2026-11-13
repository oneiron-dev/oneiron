/**
 * A raw deflate stream (RFC 1951) walked the way an inflater walks it, keeping
 * none of its output.
 *
 * SheetJS 0.20.3 inflates each deflated entry from the entry's data to the end
 * of the package, and its block loop never checks its read offset: past the
 * last byte every bit reads as 0, so a stream with no final block becomes
 * empty stored blocks for ever, and a code its Huffman table does not hold
 * reads as a zero-width literal for ever. The preflight therefore walks every
 * deflated entry first and refuses one that an inflater cannot finish inside
 * the entry's own compressed bytes. The walk is linear in the stream: each
 * symbol, header field and stored block consumes input, and the Huffman codes
 * are decoded bit by bit from their counts, so no table grows with a code's
 * length.
 */

/** Why the walk stopped: the stream is not one an inflater finishes inside its entry. */
class StreamFault extends Error {}

const MAX_BITS = 15;
const MAX_LITERAL_CODES = 286;
const MAX_DISTANCE_CODES = 30;
const FIXED_LITERAL_CODES = 288;
const END_OF_BLOCK = 256;

const LENGTH_BASE = [
  3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258,
];
const LENGTH_EXTRA = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
const DISTANCE_BASE = [
  1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145,
  8193, 12289, 16385, 24577,
];
const DISTANCE_EXTRA = [
  0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13,
];
/** The order a dynamic block lists its code-length code lengths in. */
const CODE_LENGTH_ORDER = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

/** A canonical Huffman code: how many codes each length has, and the symbols in code order. */
interface Code {
  readonly counts: Uint16Array;
  readonly symbols: Uint16Array;
}

/**
 * The canonical code for `lengths`. An over-subscribed set is refused. An
 * incomplete one is kept: only a code the stream actually uses must exist,
 * and decoding refuses one that does not.
 */
function canonicalCode(lengths: ArrayLike<number>, count: number): Code {
  const counts = new Uint16Array(MAX_BITS + 1);
  for (let symbol = 0; symbol < count; symbol += 1) {
    const length = lengths[symbol]!;
    counts[length] = counts[length]! + 1;
  }
  let left = 1;
  for (let length = 1; length <= MAX_BITS; length += 1) {
    left = (left << 1) - counts[length]!;
    if (left < 0) {
      throw new StreamFault("an over-subscribed Huffman code");
    }
  }
  const offsets = new Uint16Array(MAX_BITS + 2);
  for (let length = 1; length <= MAX_BITS; length += 1) {
    offsets[length + 1] = offsets[length]! + counts[length]!;
  }
  const symbols = new Uint16Array(count);
  for (let symbol = 0; symbol < count; symbol += 1) {
    const length = lengths[symbol]!;
    if (length !== 0) {
      symbols[offsets[length]!] = symbol;
      offsets[length] = offsets[length]! + 1;
    }
  }
  return { counts, symbols };
}

function fixedCodes(): { literals: Code; distances: Code } {
  const lengths = new Uint8Array(FIXED_LITERAL_CODES);
  lengths.fill(8, 0, 144);
  lengths.fill(9, 144, 256);
  lengths.fill(7, 256, 280);
  lengths.fill(8, 280, FIXED_LITERAL_CODES);
  return {
    literals: canonicalCode(lengths, FIXED_LITERAL_CODES),
    distances: canonicalCode(new Uint8Array(30).fill(5), 30),
  };
}

let fixed: { literals: Code; distances: Code } | undefined;

/** Reads a stream's bits, least significant first, never past `end`. */
class BitReader {
  private bits = 0;
  private held = 0;

  constructor(
    private readonly bytes: Uint8Array,
    private at: number,
    private readonly end: number,
  ) {}

  take(count: number): number {
    while (this.held < count) {
      if (this.at >= this.end) {
        throw new StreamFault("the stream runs past its entry without a final block");
      }
      this.bits |= this.bytes[this.at]! << this.held;
      this.at += 1;
      this.held += 8;
    }
    const value = this.bits & ((1 << count) - 1);
    this.bits >>>= count;
    this.held -= count;
    return value;
  }

  /** One symbol of `code`, its bits read most significant first. */
  decode(code: Code): number {
    let value = 0;
    let first = 0;
    let index = 0;
    for (let length = 1; length <= MAX_BITS; length += 1) {
      value |= this.take(1);
      const count = code.counts[length]!;
      if (value - count < first) {
        return code.symbols[index + (value - first)]!;
      }
      index += count;
      first = (first + count) << 1;
      value <<= 1;
    }
    throw new StreamFault("a code its Huffman table does not hold");
  }

  /** Drops the bits left in the current byte, then passes one stored block; answers its length. */
  storedBlock(): number {
    this.bits = 0;
    this.held = 0;
    if (this.at + 4 > this.end) {
      throw new StreamFault("the stream runs past its entry without a final block");
    }
    const length = this.bytes[this.at]! | (this.bytes[this.at + 1]! << 8);
    const inverse = this.bytes[this.at + 2]! | (this.bytes[this.at + 3]! << 8);
    if (length !== (~inverse & 0xffff)) {
      throw new StreamFault("a stored block whose length check disagrees");
    }
    this.at += 4;
    if (this.at + length > this.end) {
      throw new StreamFault("a stored block runs past its entry");
    }
    this.at += length;
    return length;
  }
}

function dynamicCodes(reader: BitReader): { literals: Code; distances: Code } {
  const literalCount = reader.take(5) + 257;
  const distanceCount = reader.take(5) + 1;
  const lengthCodeCount = reader.take(4) + 4;
  if (literalCount > MAX_LITERAL_CODES || distanceCount > MAX_DISTANCE_CODES) {
    throw new StreamFault("a dynamic block with too many codes");
  }
  const codeLengthLengths = new Uint8Array(19);
  for (let index = 0; index < lengthCodeCount; index += 1) {
    codeLengthLengths[CODE_LENGTH_ORDER[index]!] = reader.take(3);
  }
  const codeLengths = canonicalCode(codeLengthLengths, 19);
  const lengths = new Uint8Array(literalCount + distanceCount);
  let index = 0;
  while (index < lengths.length) {
    const symbol = reader.decode(codeLengths);
    if (symbol < 16) {
      lengths[index] = symbol;
      index += 1;
      continue;
    }
    let repeat: number;
    let value = 0;
    if (symbol === 16) {
      if (index === 0) {
        throw new StreamFault("a repeated code length with nothing before it");
      }
      value = lengths[index - 1]!;
      repeat = 3 + reader.take(2);
    } else if (symbol === 17) {
      repeat = 3 + reader.take(3);
    } else {
      repeat = 11 + reader.take(7);
    }
    if (index + repeat > lengths.length) {
      throw new StreamFault("code lengths that overrun their count");
    }
    lengths.fill(value, index, index + repeat);
    index += repeat;
  }
  if (lengths[END_OF_BLOCK] === 0) {
    throw new StreamFault("a dynamic block with no end-of-block code");
  }
  return {
    literals: canonicalCode(lengths.subarray(0, literalCount), literalCount),
    distances: canonicalCode(lengths.subarray(literalCount), distanceCount),
  };
}

/**
 * Why the raw deflate stream in `bytes[start, end)` is not one an inflater
 * finishes there writing exactly `expected` bytes, or `undefined` when it is.
 * The walk stops as soon as the stream writes past `expected`.
 */
export function deflateStreamFault(
  bytes: Uint8Array,
  start: number,
  end: number,
  expected: number,
): string | undefined {
  const reader = new BitReader(bytes, start, end);
  let written = 0;
  try {
    let last = 0;
    while (last === 0) {
      last = reader.take(1);
      const type = reader.take(2);
      if (type === 0) {
        written += reader.storedBlock();
      } else if (type === 3) {
        throw new StreamFault("a block of the reserved type");
      } else {
        const codes = type === 1 ? (fixed ??= fixedCodes()) : dynamicCodes(reader);
        for (;;) {
          const symbol = reader.decode(codes.literals);
          if (symbol < END_OF_BLOCK) {
            written += 1;
          } else if (symbol === END_OF_BLOCK) {
            break;
          } else {
            const lengthCode = symbol - 257;
            if (lengthCode >= LENGTH_BASE.length) {
              throw new StreamFault("a length code past the last one");
            }
            const length = LENGTH_BASE[lengthCode]! + reader.take(LENGTH_EXTRA[lengthCode]!);
            const distanceCode = reader.decode(codes.distances);
            if (distanceCode >= DISTANCE_BASE.length) {
              throw new StreamFault("a distance code past the last one");
            }
            const distance = DISTANCE_BASE[distanceCode]! + reader.take(DISTANCE_EXTRA[distanceCode]!);
            if (distance > written) {
              throw new StreamFault("a copy from before the stream's start");
            }
            written += length;
          }
          if (written > expected) {
            throw new StreamFault("the stream writes past its declared size");
          }
        }
      }
      if (written > expected) {
        throw new StreamFault("the stream writes past its declared size");
      }
    }
  } catch (err) {
    if (err instanceof StreamFault) {
      return err.message;
    }
    throw err;
  }
  return written === expected ? undefined : "the stream writes less than its declared size";
}
