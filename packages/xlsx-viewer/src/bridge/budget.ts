/**
 * Resource budgets for previewing an untrusted workbook.
 *
 * SheetJS inflates every entry of a package as soon as `XLSX.read` sees it,
 * whichever sheet was asked for, into a buffer sized by the entry's LOCAL
 * header, and that buffer grows without limit when the header says 0. So the
 * bridge first reads the package's ZIP records (end of central directory,
 * central directory, local headers) without decompressing anything, and
 * refuses a package over budget before SheetJS, or the copy sent to the
 * worker, ever sees it. The byte and entry numbers are the engine's own
 * document ceilings (its default docedit resource policy, applied through the
 * retained OPC `Limits`), so a package the engine opens the viewer previews.
 *
 * The walk reads the records SheetJS 0.20.3 reads, the way it reads them, and
 * refuses anything it would read differently: ZIP64, several disks,
 * encryption, a method other than stored or deflate, records that disagree.
 * Each entry's local record (header, data, descriptor) must stand apart from
 * every other one, so every byte SheetJS reads per entry is a distinct byte of
 * the package and the budgets count each once.
 */

/** The lines one preview stays within. */
export interface PreviewBudget {
  /** Bytes of the package. */
  readonly inputBytes: number;
  /** Entries in the package. */
  readonly entries: number;
  /** Declared expanded bytes of one entry. */
  readonly entryBytes: number;
  /** Declared expanded bytes of every entry together. */
  readonly expandedBytes: number;
  /** Declared expanded bytes per compressed byte of an entry over 1 MiB. */
  readonly compressionRatio: number;
  /**
   * Bytes SheetJS copies to inflate the deflated entries: it copies from each
   * one's data to the end of the package.
   */
  readonly copyBytes: number;
  /** Sheets the workbook lists. */
  readonly sheets: number;
  /** Cells one sheet holds. */
  readonly sheetCells: number;
  /** Characters of cell text and formula text in one sheet. */
  readonly sheetTextChars: number;
}

const MIB = 1024 * 1024;

/**
 * The default budget. Bytes and entries match the engine's document ceilings.
 * A real workbook stores each sheet in its own entry, so it lists no more
 * sheets than it has entries. The engine reads at most 1,000,000 XML nodes
 * from one part, and a cell is at least one node. A sheet's text stays within
 * one entry's bytes. Deflate compresses real sheet XML 10 to 20 times; 200 is
 * a tripwire for a crafted entry, not a size line. A real package of 512 MiB
 * holds a few dozen deflated entries, about 16 GiB of copying at most.
 */
export const PREVIEW_BUDGET: PreviewBudget = Object.freeze({
  inputBytes: 512 * MIB,
  entries: 10_000,
  entryBytes: 64 * MIB,
  expandedBytes: 512 * MIB,
  compressionRatio: 200,
  copyBytes: 16 * 1024 * MIB,
  sheets: 10_000,
  sheetCells: 1_000_000,
  sheetTextChars: 64 * MIB,
});

/** The compression ratio is not checked on an entry this small or smaller. */
const RATIO_FLOOR_BYTES = MIB;

/** Which line a refused workbook crossed: a budget, or a ZIP record the walk will not read. */
export type BudgetLine = keyof PreviewBudget | "structure";

/** A workbook refused before it was parsed further. The message names no workbook content. */
export class WorkbookBudgetError extends Error {
  readonly line: BudgetLine;

  constructor(line: BudgetLine, reason: string) {
    super(`workbook preview refused (${line}): ${reason}`);
    this.name = "WorkbookBudgetError";
    this.line = line;
  }
}

const LOCAL = 0x04034b50;
const CENTRAL = 0x02014b50;
const ZIP64_LOCATOR = 0x07064b50;
const DESCRIPTOR = 0x08074b50;
const ZIP64_EXTRA = 0x0001;
/** Encrypted, or strong encryption, or masked headers: SheetJS refuses these too. */
const ENCRYPTED = 0x2041;
/** Sizes follow the data in a descriptor; the local header may hold zeros. */
const DATA_DESCRIPTOR = 0x0008;
const STORED = 0;
const DEFLATE = 8;

function structure(reason: string): WorkbookBudgetError {
  return new WorkbookBudgetError("structure", reason);
}

function u16(bytes: Uint8Array, at: number): number {
  if (at < 0 || at + 2 > bytes.length) {
    throw structure("truncated ZIP record");
  }
  return bytes[at]! | (bytes[at + 1]! << 8);
}

function u32(bytes: Uint8Array, at: number): number {
  if (at < 0 || at + 4 > bytes.length) {
    throw structure("truncated ZIP record");
  }
  return (bytes[at]! | (bytes[at + 1]! << 8) | (bytes[at + 2]! << 16) | (bytes[at + 3]! << 24)) >>> 0;
}

function setU32(bytes: Uint8Array, at: number, value: number): void {
  bytes[at] = value & 0xff;
  bytes[at + 1] = (value >>> 8) & 0xff;
  bytes[at + 2] = (value >>> 16) & 0xff;
  bytes[at + 3] = (value >>> 24) & 0xff;
}

/** Refuse a ZIP64 field in an extra-field block, walked as SheetJS walks it. */
function refuseZip64(bytes: Uint8Array, start: number, length: number): void {
  const end = start + length;
  if (end > bytes.length) {
    throw structure("truncated extra field");
  }
  for (let at = start; at <= end - 4; at += 4 + u16(bytes, at + 2)) {
    if (u16(bytes, at) === ZIP64_EXTRA) {
      throw structure("ZIP64 entry");
    }
  }
}

function sameBytes(bytes: Uint8Array, a: number, b: number, length: number): boolean {
  if (a + length > bytes.length || b + length > bytes.length) {
    throw structure("truncated ZIP record");
  }
  for (let i = 0; i < length; i += 1) {
    if (bytes[a + i] !== bytes[b + i]) {
      return false;
    }
  }
  return true;
}

/** SheetJS takes the last end-of-central-directory signature in the file. */
function findEndRecord(bytes: Uint8Array): number {
  for (let at = bytes.length - 4; at >= 0; at -= 1) {
    if (bytes[at] === 0x50 && bytes[at + 1] === 0x4b && bytes[at + 2] === 0x05 && bytes[at + 3] === 0x06) {
      return at;
    }
  }
  throw structure("no end-of-central-directory record");
}

/**
 * Check a package against `budget` from its ZIP records alone, and return the
 * bytes to hand SheetJS: `bytes` itself, or, when a streamed entry left its
 * local sizes at zero, a copy whose local headers carry the central
 * directory's sizes, so SheetJS inflates every entry into a buffer of its
 * declared, budgeted size.
 */
export function preflightPackage(bytes: Uint8Array, budget: PreviewBudget = PREVIEW_BUDGET): Uint8Array {
  if (bytes.length > budget.inputBytes) {
    throw new WorkbookBudgetError("inputBytes", "package larger than the input budget");
  }
  if (bytes.length < 4 || u32(bytes, 0) !== LOCAL) {
    throw structure("not a ZIP package");
  }
  const end = findEndRecord(bytes);
  if (end + 22 + u16(bytes, end + 20) !== bytes.length) {
    throw structure("end-of-central-directory record does not end the package");
  }
  if (end >= 20 && u32(bytes, end - 20) === ZIP64_LOCATOR) {
    throw structure("ZIP64 package");
  }
  if (u16(bytes, end + 4) !== 0 || u16(bytes, end + 6) !== 0) {
    throw structure("package spans several disks");
  }
  const count = u16(bytes, end + 8);
  const directorySize = u32(bytes, end + 12);
  const directory = u32(bytes, end + 16);
  if (count !== u16(bytes, end + 10) || count === 0xffff || directory === 0xffffffff) {
    throw structure("ZIP64 or inconsistent entry count");
  }
  if (directory + directorySize !== end) {
    throw structure("central directory does not end at its end record");
  }
  if (count > budget.entries) {
    throw new WorkbookBudgetError("entries", "more entries than the budget");
  }
  const patches: [offset: number, compressed: number, expanded: number][] = [];
  /** Each local record, and where its name and extra field are checked once records are apart. */
  const records: [start: number, end: number, centralName: number, nameLength: number, extra: number][] = [];
  let expandedTotal = 0;
  let copyTotal = 0;
  let at = directory;
  for (let index = 0; index < count; index += 1) {
    if (u32(bytes, at) !== CENTRAL) {
      throw structure("bad central directory entry");
    }
    const name = at + 46;
    const flags = u16(bytes, at + 8);
    const method = u16(bytes, at + 10);
    const compressed = u32(bytes, at + 20);
    const expanded = u32(bytes, at + 24);
    const nameLength = u16(bytes, at + 28);
    const extraLength = u16(bytes, at + 30);
    const offset = u32(bytes, at + 42);
    refuseZip64(bytes, at + 46 + nameLength, extraLength);
    at += 46 + nameLength + extraLength + u16(bytes, at + 32);
    if (at > end) {
      throw structure("central directory overruns its end record");
    }
    if (flags & ENCRYPTED) {
      throw structure("encrypted entry");
    }
    if (method !== STORED && method !== DEFLATE) {
      throw structure("unsupported compression method");
    }

    if (u32(bytes, offset) !== LOCAL) {
      throw structure("bad local header");
    }
    const localFlags = u16(bytes, offset + 6);
    const localCompressed = u32(bytes, offset + 18);
    const localExpanded = u32(bytes, offset + 22);
    const localName = u16(bytes, offset + 26);
    const localExtra = u16(bytes, offset + 28);
    const data = offset + 30 + localName + localExtra;
    if (u16(bytes, offset + 8) !== method || localFlags & ENCRYPTED) {
      throw structure("local header disagrees with the central directory");
    }
    if (localCompressed !== compressed || localExpanded !== expanded) {
      // A streamed entry leaves its local sizes at zero and writes them after
      // the data. SheetJS would inflate it into a buffer that grows without
      // limit, so the copy it reads carries the central sizes instead.
      if (!(localFlags & DATA_DESCRIPTOR) || localCompressed !== 0 || localExpanded !== 0) {
        throw structure("local header disagrees with the central directory");
      }
      patches.push([offset, compressed, expanded]);
    }
    if (localName !== nameLength) {
      throw structure("local header disagrees with the central directory");
    }
    // SheetJS reads a data descriptor after the data, 16 bytes when it starts
    // with its signature and 12 when not.
    let recordEnd = data + compressed;
    if (localFlags & DATA_DESCRIPTOR) {
      recordEnd += u32(bytes, recordEnd) === DESCRIPTOR ? 16 : 12;
    }
    if (recordEnd > directory) {
      throw structure("entry data overruns the central directory");
    }
    records.push([offset, recordEnd, name, nameLength, localExtra]);

    if (expanded > budget.entryBytes) {
      throw new WorkbookBudgetError("entryBytes", "an entry expands past the entry budget");
    }
    expandedTotal += expanded;
    if (expandedTotal > budget.expandedBytes) {
      throw new WorkbookBudgetError("expandedBytes", "entries expand past the package budget");
    }
    if (method === STORED && compressed !== expanded) {
      throw structure("stored entry sizes disagree");
    }
    if (method === DEFLATE && expanded === 0) {
      // SheetJS returns an empty entry at once only for this two-byte stream;
      // any other stream with no declared size inflates without limit.
      if (compressed !== 2 || bytes[data] !== 3 || (bytes[data + 1]! & 3) !== 0) {
        throw structure("empty entry with a non-empty stream");
      }
    }
    if (method === DEFLATE && expanded > RATIO_FLOOR_BYTES && expanded > compressed * budget.compressionRatio) {
      throw new WorkbookBudgetError("compressionRatio", "an entry compresses past the ratio budget");
    }
    if (method === DEFLATE) {
      copyTotal += bytes.length - data;
      if (copyTotal > budget.copyBytes) {
        throw new WorkbookBudgetError("copyBytes", "inflating the entries copies past the copy budget");
      }
    }
  }
  if (at !== end) {
    throw structure("central directory size disagrees with its entries");
  }
  // Apart, the local names and extra fields together stay within the package,
  // however many central entries name one record.
  records.sort((a, b) => a[0] - b[0]);
  for (let index = 1; index < records.length; index += 1) {
    if (records[index]![0] < records[index - 1]![1]) {
      throw structure("local records overlap");
    }
  }
  for (const [offset, , name, nameLength, extra] of records) {
    if (!sameBytes(bytes, offset + 30, name, nameLength)) {
      throw structure("local header disagrees with the central directory");
    }
    refuseZip64(bytes, offset + 30 + nameLength, extra);
  }
  if (patches.length === 0) {
    return bytes;
  }
  const copy = bytes.slice();
  for (const [offset, compressed, expanded] of patches) {
    setU32(copy, offset + 18, compressed);
    setU32(copy, offset + 22, expanded);
  }
  return copy;
}

/** Refuse a workbook that lists more sheets than `budget` allows. */
export function checkSheetCount(count: number, budget: PreviewBudget = PREVIEW_BUDGET): void {
  if (count > budget.sheets) {
    throw new WorkbookBudgetError("sheets", "more sheets than the budget");
  }
}
