import { describe, expect, it } from "bun:test";
import { deflateRawSync } from "node:zlib";
import * as XLSX from "xlsx";
import { PREVIEW_BUDGET, WorkbookBudgetError, preflightPackage, type BudgetLine } from "../src/bridge/budget";
import { ParseSessionStore } from "../src/bridge/handler";
import { readSheet, readWorkbook, readWorkbookOutline, sheetId, worksheetToCellData } from "../src/bridge/parse";
import { createWorkerWorkbookSource, type ParseWorkerLike } from "../src/bridge/source";
import type { ParseRequest, ParseResponse } from "../src/bridge/protocol";
import { makeXlsxBytes } from "./helpers";

const MIB = 1024 * 1024;
const MAIN = "http://schemas.openxmlformats.org/spreadsheetml/2006/main";
const REL = "http://schemas.openxmlformats.org/package/2006/relationships";
const DOC_REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships";
const SHEET = "xl/worksheets/sheet1.xml";

interface Part {
  readonly name: string;
  /** Stored bytes, or a raw deflate stream with the size it really inflates to. */
  readonly body: Uint8Array | { readonly stream: Uint8Array; readonly size: number; readonly crc: number };
  /** Written as a streaming writer does: zero local sizes, a data descriptor after the data. */
  readonly streamed?: boolean;
  /** Extra-field bytes of the central directory entry. */
  readonly centralExtra?: readonly number[];
}

function le(bytes: number[], value: number, width: 2 | 4): void {
  for (let i = 0; i < width; i += 1) bytes.push((value >>> (8 * i)) & 0xff);
}

/** Test-only ZIP writer: the bridge never writes packages. */
function zip(parts: readonly Part[]): Uint8Array {
  const out: number[] = [];
  const central: number[] = [];
  for (const part of parts) {
    const name = new TextEncoder().encode(part.name);
    const stored = part.body instanceof Uint8Array;
    const data = part.body instanceof Uint8Array ? part.body : part.body.stream;
    const size = part.body instanceof Uint8Array ? data.length : part.body.size;
    const crc = part.body instanceof Uint8Array ? Bun.hash.crc32(data) : part.body.crc;
    const flags = part.streamed ? 8 : 0;
    const extra = part.centralExtra ?? [];
    const offset = out.length;
    le(out, 0x04034b50, 4);
    le(out, 20, 2);
    le(out, flags, 2);
    le(out, stored ? 0 : 8, 2);
    le(out, 0, 2);
    le(out, 0x21, 2);
    le(out, part.streamed ? 0 : crc, 4);
    le(out, part.streamed ? 0 : data.length, 4);
    le(out, part.streamed ? 0 : size, 4);
    le(out, name.length, 2);
    le(out, 0, 2);
    out.push(...name);
    for (const byte of data) out.push(byte);
    if (part.streamed) {
      le(out, 0x08074b50, 4);
      le(out, crc, 4);
      le(out, data.length, 4);
      le(out, size, 4);
    }
    le(central, 0x02014b50, 4);
    le(central, 20, 2);
    le(central, 20, 2);
    le(central, flags, 2);
    le(central, stored ? 0 : 8, 2);
    le(central, 0, 2);
    le(central, 0x21, 2);
    le(central, crc, 4);
    le(central, data.length, 4);
    le(central, size, 4);
    le(central, name.length, 2);
    le(central, extra.length, 2);
    le(central, 0, 2);
    le(central, 0, 2);
    le(central, 0, 2);
    le(central, 0, 4);
    le(central, offset, 4);
    central.push(...name, ...extra);
  }
  const directory = out.length;
  out.push(...central);
  le(out, 0x06054b50, 4);
  le(out, 0, 2);
  le(out, 0, 2);
  le(out, parts.length, 2);
  le(out, parts.length, 2);
  le(out, central.length, 4);
  le(out, directory, 4);
  le(out, 0, 2);
  return Uint8Array.from(out);
}

const text = (xml: string) => new TextEncoder().encode(xml);

/**
 * A one-sheet workbook whose sheet part is `sheet`. `streamed` deflates every
 * other part and writes them all as a streaming writer does.
 */
function workbook(sheet: Part["body"], streamed = false): Uint8Array {
  const xml = (source: string) => (streamed ? deflated(text(source)) : text(source));
  const parts: Part[] = [
    {
      name: "[Content_Types].xml",
      body: xml(
        `<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/${SHEET}" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>`,
      ),
    },
    {
      name: "_rels/.rels",
      body: xml(
        `<Relationships xmlns="${REL}"><Relationship Id="rId1" Type="${DOC_REL}/officeDocument" Target="xl/workbook.xml"/></Relationships>`,
      ),
    },
    {
      name: "xl/workbook.xml",
      body: xml(
        `<workbook xmlns="${MAIN}" xmlns:r="${DOC_REL}"><sheets><sheet name="S1" sheetId="1" r:id="rId1"/></sheets></workbook>`,
      ),
    },
    {
      name: "xl/_rels/workbook.xml.rels",
      body: xml(
        `<Relationships xmlns="${REL}"><Relationship Id="rId1" Type="${DOC_REL}/worksheet" Target="worksheets/sheet1.xml"/></Relationships>`,
      ),
    },
    { name: SHEET, body: sheet },
  ];
  return zip(parts.map((part) => ({ ...part, streamed })));
}

/** A two-entry package with `extra` in its first central directory entry. */
function withCentralExtra(sheet: Part["body"], extra: readonly number[]): Uint8Array {
  return zip([
    { name: "[Content_Types].xml", body: text("<Types/>"), centralExtra: extra },
    { name: SHEET, body: sheet },
  ]);
}

const SHEET_XML = `<worksheet xmlns="${MAIN}"><sheetData><row r="1"><c r="A1"><v>42</v></c><c r="B1" t="inlineStr"><is><t>kept</t></is></c></row></sheetData></worksheet>`;

function deflated(bytes: Uint8Array): Part["body"] {
  return { stream: deflateRawSync(bytes), size: bytes.length, crc: Bun.hash.crc32(bytes) };
}

/**
 * A raw deflate stream that really inflates to `1 + 258 * copies` zero bytes:
 * one fixed-Huffman block, a literal 0 then `copies` back-references of 258
 * bytes at distance 1 (13 bits each, about 159 bytes out per byte in).
 */
function zeros(copies: number): Part["body"] {
  const bytes: number[] = [];
  let acc = 0;
  let filled = 0;
  const bit = (value: number) => {
    acc |= (value & 1) << filled;
    filled += 1;
    if (filled === 8) {
      bytes.push(acc);
      acc = 0;
      filled = 0;
    }
  };
  // Huffman codes go most significant bit first; header fields least first.
  const code = (value: number, width: number) => {
    for (let i = width - 1; i >= 0; i -= 1) bit(value >>> i);
  };
  bit(1); // final block
  bit(1); // fixed Huffman (BTYPE 01, low bit first)
  bit(0);
  code(0x30, 8); // literal 0
  for (let i = 0; i < copies; i += 1) {
    code(0xc5, 8); // length 258 (symbol 285)
    code(0, 5); // distance 1
  }
  code(0, 7); // end of block
  if (filled > 0) bytes.push(acc);
  const size = 1 + 258 * copies;
  return { stream: Uint8Array.from(bytes), size, crc: Bun.hash.crc32(new Uint8Array(size)) };
}

/** Where each central directory entry of a test package starts. */
function centralEntries(bytes: Uint8Array): number[] {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const end = bytes.length - 22;
  const entries: number[] = [];
  let at = view.getUint32(end + 16, true);
  for (let i = 0; i < view.getUint16(end + 10, true); i += 1) {
    entries.push(at);
    at += 46 + view.getUint16(at + 28, true) + view.getUint16(at + 30, true) + view.getUint16(at + 32, true);
  }
  return entries;
}

/** `bytes` (one entry) with its central directory entry written `copies` times, all naming the one local record. */
function sharedRecord(bytes: Uint8Array, copies: number): Uint8Array {
  const [entry] = centralEntries(bytes);
  const end = bytes.length - 22;
  const central = bytes.subarray(entry!, end);
  const out = new Uint8Array(entry! + central.length * copies + 22);
  out.set(bytes.subarray(0, entry));
  for (let i = 0; i < copies; i += 1) out.set(central, entry! + i * central.length);
  out.set(bytes.subarray(end), out.length - 22);
  const view = new DataView(out.buffer, out.length - 22);
  view.setUint16(8, copies, true);
  view.setUint16(10, copies, true);
  view.setUint32(12, central.length * copies, true);
  return out;
}

function refusedWith(line: BudgetLine, run: () => unknown): void {
  let caught: unknown;
  try {
    run();
  } catch (err) {
    caught = err;
  }
  expect(caught).toBeInstanceOf(WorkbookBudgetError);
  expect((caught as WorkbookBudgetError).line).toBe(line);
}

interface RecordingWorker extends ParseWorkerLike {
  readonly requests: ParseRequest[];
}

function recordingWorker(): RecordingWorker {
  const store = new ParseSessionStore();
  const listeners = new Set<(e: { data: ParseResponse }) => void>();
  const requests: ParseRequest[] = [];
  return {
    requests,
    postMessage(message: ParseRequest) {
      requests.push(message);
      const res = store.handle(message);
      if (res) {
        queueMicrotask(() => {
          for (const l of listeners) l({ data: res });
        });
      }
    },
    addEventListener(type: "message" | "error", listener: (e: { data: ParseResponse }) => void) {
      if (type === "message") listeners.add(listener);
    },
    removeEventListener(type: "message" | "error", listener: (e: { data: ParseResponse }) => void) {
      if (type === "message") listeners.delete(listener);
    },
    terminate() {
      listeners.clear();
    },
  } as RecordingWorker;
}

describe("preview budgets: a package is refused from its ZIP records, before SheetJS inflates it", () => {
  it("refuses a zip bomb sheet before any parse, on every door", async () => {
    // C14: a 420 KB package whose sheet really inflates to 65 MiB of zeros.
    // SheetJS inflated every entry of it on each read, the worker first took a
    // full copy, and eager reads did both once per sheet.
    const bomb = workbook(zeros(Math.ceil((PREVIEW_BUDGET.entryBytes + 1) / 258)));
    expect(bomb.length).toBeLessThan(MIB);
    refusedWith("entryBytes", () => readWorkbookOutline(bomb));
    refusedWith("entryBytes", () => readSheet(bomb, "S1"));
    refusedWith("entryBytes", () => readWorkbook(bomb));
    const worker = recordingWorker();
    const source = createWorkerWorkbookSource(bomb, () => worker);
    await expect(source.outline()).rejects.toBeInstanceOf(WorkbookBudgetError);
    await expect(source.sheet("S1")).rejects.toBeInstanceOf(WorkbookBudgetError);
    expect(worker.requests).toHaveLength(0);
    source.dispose();
  });

  it("refuses entries that each fit but together expand past the package budget", () => {
    // Nine 60 MiB sheets at 159:1, each under the entry and ratio budgets.
    const sixty = zeros(Math.floor((60 * MIB) / 258));
    const sheets = Array.from({ length: 9 }, (_, i) => ({ name: `xl/worksheets/s${i}.xml`, body: sixty }));
    const parts = [{ name: "[Content_Types].xml", body: text("<Types/>") }, ...sheets];
    refusedWith("expandedBytes", () => readWorkbookOutline(zip(parts)));
    // Eight of the same entries stay within the budget.
    expect(() => preflightPackage(zip(parts.slice(0, 8)))).not.toThrow();
  });

  it("refuses an entry that compresses far past real sheet XML", () => {
    refusedWith("compressionRatio", () => readWorkbookOutline(workbook(deflated(new Uint8Array(2 * MIB)))));
  });

  it("refuses records SheetJS would read differently from the preflight", () => {
    // A deflate stream with no declared size: SheetJS inflates it into a
    // buffer that grows without limit.
    const sheet = deflated(text(SHEET_XML));
    const undeclared = workbook({ ...(sheet as { stream: Uint8Array; crc: number }), size: 0 });
    refusedWith("structure", () => readWorkbookOutline(undeclared));
    // A ZIP64 size field (extra field 0x0001) in a central directory entry,
    // which SheetJS would take over the 32-bit sizes.
    const zip64 = [0x01, 0x00, 0x10, 0x00, ...new Array<number>(16).fill(0)];
    refusedWith("structure", () => readWorkbookOutline(withCentralExtra(sheet, zip64)));
    // An extra field without one passes.
    const timestamp = [0x55, 0x54, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];
    expect(() => preflightPackage(withCentralExtra(sheet, timestamp))).not.toThrow();
    // A package that is not a ZIP at all.
    refusedWith("structure", () => readWorkbookOutline(text("A1,B1\n1,2\n")));
  });

  it("refuses local records that overlap, or that name another entry", () => {
    // Wonder r1: SheetJS reads one local record per central entry, so 1,000
    // central entries naming one record re-read it (and rebuilt its name) 1,000
    // times, within every byte budget.
    const empty = { stream: Uint8Array.of(3, 0), size: 0, crc: 0 };
    const one = zip([{ name: "[Content_Types].xml", body: empty }]);
    expect(() => preflightPackage(one)).not.toThrow();
    refusedWith("structure", () => preflightPackage(sharedRecord(one, 1_000)));

    // An entry whose declared data runs over the next entry's record.
    const parts = [
      { name: "[Content_Types].xml", body: text("<Types/>") },
      { name: SHEET, body: text(SHEET_XML) },
    ];
    const apart = zip(parts);
    const covering = apart.slice();
    const [first] = centralEntries(covering);
    const view = new DataView(covering.buffer);
    const size = first! - (30 + parts[0]!.name.length);
    for (const at of [first! + 20, first! + 24, 18, 22]) view.setUint32(at, size, true);
    expect(() => preflightPackage(apart)).not.toThrow();
    refusedWith("structure", () => preflightPackage(covering));

    // A local header whose name differs from its central directory entry.
    const renamed = apart.slice();
    renamed[30] = "_".charCodeAt(0);
    refusedWith("structure", () => preflightPackage(renamed));
  });

  it("refuses deflated entries that make SheetJS copy past the copy budget", () => {
    // SheetJS copies from each deflated entry's data to the end of the
    // package, so small deflated entries before a large one each copy it.
    const large = { name: "xl/media/image1.bin", body: new Uint8Array(256 * 1024) };
    const small = Array.from({ length: 8 }, (_, i) => ({
      name: `xl/worksheets/s${i}.xml`,
      body: deflated(text(SHEET_XML)),
    }));
    const types = { name: "[Content_Types].xml", body: text("<Types/>") };
    const budget = { ...PREVIEW_BUDGET, copyBytes: MIB };
    refusedWith("copyBytes", () => preflightPackage(zip([types, ...small, large]), budget));
    expect(() => preflightPackage(zip([types, large, ...small]), budget)).not.toThrow();
  });

  it("refuses a package SheetJS would read as something other than a workbook package", () => {
    // Round 2: without [Content_Types].xml SheetJS reads a stored Index.zip
    // as a whole new package, which this preflight never saw.
    const inner = workbook(zeros(Math.ceil((PREVIEW_BUDGET.entryBytes + 1) / 258)));
    refusedWith("entryBytes", () => preflightPackage(inner));
    refusedWith("structure", () => readWorkbookOutline(zip([{ name: "Index.zip", body: inner }])));
    // OpenDocument, Numbers and the like are read before [Content_Types].xml.
    const types = { name: "[Content_Types].xml", body: text("<Types/>") };
    for (const other of ["META-INF/manifest.xml", "Root Entry/objectdata.xml", "Index/Document.iwa"]) {
      refusedWith("structure", () => preflightPackage(zip([types, { name: other, body: text("<x/>") }])));
    }
    // Part names follow the engine's OPC rules, and SheetJS looks parts up
    // without case, so two names it would confuse are refused.
    for (const name of ["XL/workbook.xml", "../workbook.xml", "xl//workbook.xml", "xl\\workbook.xml"]) {
      const parts = [types, { name: "xl/workbook.xml", body: text("<w/>") }, { name, body: text("<w/>") }];
      refusedWith("structure", () => preflightPackage(zip(parts)));
    }
    expect(() => preflightPackage(zip([types, { name: "xl/workbook.xml", body: text("<w/>") }]))).not.toThrow();
  });

  it("previews a streamed package, which leaves its local sizes at zero, from its declared sizes", () => {
    const plain = readWorkbook(workbook(deflated(text(SHEET_XML))));
    const streamed = readWorkbook(workbook(deflated(text(SHEET_XML)), true));
    expect(streamed).toEqual(plain);
    const cells = streamed.sheets[sheetId("S1")]?.cellData as Record<number, Record<number, { v?: unknown }>>;
    expect(cells[0]?.[0]?.v).toBe(42);
    expect(cells[0]?.[1]?.v).toBe("kept");
  });
});

describe("preview budgets: sheets, cells and text", () => {
  const bytes = makeXlsxBytes({ sheets: 3, rows: 4, cols: 4, formulaCell: true });

  it("refuses a workbook over the sheet, cell, text or input budget, typed", async () => {
    refusedWith("inputBytes", () => readWorkbookOutline(bytes, "w", { ...PREVIEW_BUDGET, inputBytes: 100 }));
    refusedWith("sheets", () => readWorkbookOutline(bytes, "w", { ...PREVIEW_BUDGET, sheets: 2 }));
    refusedWith("sheets", () => readWorkbook(bytes, { budget: { ...PREVIEW_BUDGET, sheets: 2 } }));
    refusedWith("sheets", () => readSheet(bytes, "S1", { budget: { ...PREVIEW_BUDGET, sheets: 2 } }));
    refusedWith("sheetCells", () => readSheet(bytes, "S1", { budget: { ...PREVIEW_BUDGET, sheetCells: 15 } }));
    refusedWith("sheetTextChars", () =>
      readSheet(bytes, "S1", { budget: { ...PREVIEW_BUDGET, sheetTextChars: 10 } }),
    );
    // In the worker the sheet is refused there and the typed refusal comes back.
    const budget = { ...PREVIEW_BUDGET, sheetCells: 15 };
    const source = createWorkerWorkbookSource(bytes, recordingWorker, { budget });
    const refusal = await source.sheet("S1").catch((err: unknown) => err);
    expect(refusal).toBeInstanceOf(WorkbookBudgetError);
    expect((refusal as WorkbookBudgetError).line).toBe("sheetCells");
    source.dispose();
  });

  it("stops a sheet's dimensions at Excel's grid", () => {
    // A stored dimension past the grid mounted as given: 100 million rows.
    const ws = {
      "!ref": "A1:ZZZZ100000000",
      A1: { t: "n", v: 1 },
      A100000000: { t: "s", v: "past the grid" },
    } as unknown as XLSX.WorkSheet;
    const out = worksheetToCellData(ws, true);
    expect(out.rowCount).toBe(1_048_576);
    expect(out.columnCount).toBe(16_384);
    const cells = out.cellData as unknown as Record<number, Record<number, { v?: unknown }>>;
    expect(cells[0]?.[0]?.v).toBe(1);
    expect(Object.keys(cells)).toEqual(["0"]);
  });

  it("reads every sheet in one pass exactly as the lazy path reads each", () => {
    const eager = readWorkbook(bytes);
    for (const sid of eager.sheetOrder) {
      const name = eager.sheets[sid]!.name!;
      expect(eager.sheets[sid]).toEqual(readSheet(bytes, name));
    }
    // At the limits themselves, a sheet still previews.
    const exact = { ...PREVIEW_BUDGET, sheets: 3, sheetCells: 16 };
    expect(readWorkbook(bytes, { budget: exact }).sheetOrder).toHaveLength(3);
  });
});
