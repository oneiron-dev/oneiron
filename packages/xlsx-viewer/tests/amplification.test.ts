import { describe, expect, it } from "bun:test";
import { deflateRawSync } from "node:zlib";
import type { ICellData, IWorksheetData } from "@univerjs/core";
import { PREVIEW_BUDGET, WorkbookBudgetError, preflightPackage, type BudgetLine } from "../src/bridge/budget";
import { checkSheetExpansion } from "../src/bridge/expansion";
import { readSheet, readWorkbook, readWorkbookOutline } from "../src/bridge/parse";
import {
  FULL_GRID_HYPERLINK_SHEET,
  HUGE_ROW_HYPERLINK_SHEET,
  PLAIN_SHEET,
  fanOutSheet,
  sheetsPackage,
  worksheet,
  type CraftedKind,
} from "./crafted-packages";
import { makeXlsxBytes } from "./helpers";
import { deflated, text } from "./package-writer";

/** How long a child may read before its test counts the read as one that never ends. */
const CHILD_LIMIT_MS = 30_000;
/** The test's own limit: the child's, then the time to start it and build its package. */
const TEST_LIMIT_MS = 90_000;

/**
 * Reads S1 of a crafted package in a child process ({@link ./read-in-child.ts}):
 * its answer, or how it ended without one.
 */
function readInChild(kind: CraftedKind): unknown {
  const run = Bun.spawnSync({
    cmd: [process.execPath, `${import.meta.dir}/read-in-child.ts`, kind],
    stdout: "pipe",
    stderr: "pipe",
    timeout: CHILD_LIMIT_MS,
  });
  if ((run as { exitedDueToTimeout?: boolean }).exitedDueToTimeout) {
    return { unfinished: `still reading after ${CHILD_LIMIT_MS / 1000} s` };
  }
  if (!run.success) {
    return { ended: run.signalCode ?? run.exitCode, stderr: run.stderr.toString().slice(-400) };
  }
  return JSON.parse(run.stdout.toString().trim().split("\n").at(-1)!);
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

function cell(sheet: Partial<IWorksheetData>, row: number, column: number): ICellData | undefined {
  return (sheet.cellData as Record<number, Record<number, ICellData>> | undefined)?.[row]?.[column];
}

const MIXED_XML = text(
  worksheet(
    Array.from(
      { length: 400 },
      (_, r) =>
        `<row r="${r + 1}"><c r="A${r + 1}"><v>${(r * 7919) % 104729}</v></c><c r="B${r + 1}" t="inlineStr"><is><t>${"note ".repeat(r % 9)}${r.toString(36)}</t></is></c></row>`,
    ).join(""),
  ),
);

describe("xlsx preview: what SheetJS would expand is refused before it reads", () => {
  it(
    "refuses a deflated entry that never finishes, which SheetJS inflates for ever",
    () => {
      expect(readInChild("unfinished-deflate")).toEqual({ refused: "structure" });
    },
    TEST_LIMIT_MS,
  );

  it(
    "refuses a sheet whose one hyperlink names every cell of the grid",
    () => {
      expect(readInChild("full-grid-hyperlink")).toEqual({ refused: "sheetCells" });
    },
    TEST_LIMIT_MS,
  );

  it(
    "refuses a sheet whose shared formula copies a long master to many cells",
    () => {
      expect(readInChild("shared-formula-fan-out")).toEqual({ refused: "sheetTextChars" });
    },
    TEST_LIMIT_MS,
  );

  it(
    "refuses a hyperlink whose one address lies past 2^53, where SheetJS's loop cannot step",
    () => {
      expect(readInChild("huge-row-hyperlink")).toEqual({ refused: "sheetCells" });
    },
    TEST_LIMIT_MS,
  );

  it(
    "refuses a shared formula copied through SheetJS's fallback formula reader",
    () => {
      expect(readInChild("fallback-formula-fan-out")).toEqual({ refused: "sheetTextChars" });
    },
    TEST_LIMIT_MS,
  );

  it("counts what SheetJS would expand before it reads: far addresses, browser-decoded ranges, fallback followers", () => {
    const sheetPart = "xl/worksheets/sheet1.xml";
    const check = (bytes: Uint8Array, formulaText = false, budget = PREVIEW_BUDGET) => () =>
      checkSheetExpansion(sheetPart, bytes, budget, formulaText);
    // One address at row 2^53, alone or as both ends of a range.
    refusedWith("sheetCells", check(text(HUGE_ROW_HYPERLINK_SHEET)));
    refusedWith(
      "sheetCells",
      check(text(worksheet("", `<hyperlinks><hyperlink ref="A9007199254740994:A9007199254740994"/></hyperlinks>`))),
    );
    // E0 80 BA in place of the colon: SheetJS keeps byte 80 as its own
    // character, and its browser UTF-8 decode (utf8reada) reads the three
    // bytes as ':', so the ref names the whole grid.
    const marked = text(worksheet("", `<hyperlinks><hyperlink ref="A1|XFD1048576"/></hyperlinks>`));
    const bar = marked.indexOf(0x7c);
    const spliced = Uint8Array.from([...marked.subarray(0, bar), 0xe0, 0x80, 0xba, ...marked.subarray(bar + 1)]);
    refusedWith("sheetCells", check(spliced));
    // 100 characters copied to 50 cells through `<foo si="0"/>`, over a
    // 1,000-character line; one per cell, as SheetJS reads one.
    const budget = { ...PREVIEW_BUDGET, sheetTextChars: 1_000 };
    refusedWith("sheetTextChars", check(text(fanOutSheet(100, 50, `<foo si="0"/>`)), true, budget));
    expect(check(text(fanOutSheet(100, 9, `<foo si="0"/><foo si="0"/>`)), true, budget)).not.toThrow();
  });

  it("refuses a deflate stream an inflater cannot finish inside its entry, from the preflight alone", () => {
    const stream = deflateRawSync(MIXED_XML);
    const sheet = (body: { stream: Uint8Array; size: number }) => sheetsPackage([{ ...body, crc: 0 }]);
    // Cut short: the final block's end lies past the entry.
    const cut = stream.subarray(0, stream.length - 2);
    refusedWith("structure", () => preflightPackage(sheet({ stream: cut, size: MIXED_XML.length })));
    // Writes more, or less, than the size its records declare.
    refusedWith("structure", () => preflightPackage(sheet({ stream, size: MIXED_XML.length - 1 })));
    refusedWith("structure", () => preflightPackage(sheet({ stream, size: MIXED_XML.length + 1 })));
    // A fixed block whose first symbol copies from before the stream's start:
    // length 3 (symbol 257, code 0000001), distance 1 (code 00000).
    const copyFirst = Uint8Array.of(0b0000_0011, 0b0000_0010, 0, 0);
    refusedWith("structure", () => preflightPackage(sheet({ stream: copyFirst, size: 3 })));
    // A block of the reserved type 11.
    refusedWith("structure", () => preflightPackage(sheet({ stream: Uint8Array.of(0b0000_0111), size: 1 })));
  });

  it("previews real deflate streams as before: every zlib level, and SheetJS's own writer", () => {
    for (let level = 0; level <= 9; level += 1) {
      const stream = deflateRawSync(MIXED_XML, { level });
      const bytes = sheetsPackage([{ stream, size: MIXED_XML.length, crc: 0 }]);
      expect(preflightPackage(bytes)).toBe(bytes);
      expect(readSheet(bytes, "S1").rowCount).toBe(400);
    }
    const written = makeXlsxBytes({ sheets: 2, rows: 300, cols: 12, formulaCell: true });
    expect(readWorkbook(written).sheetOrder).toHaveLength(2);
    expect(readSheet(written, "S2").rowCount).toBe(300);
  });

  it("reads hyperlinks and shared formulas of real size as before", () => {
    const sheet = worksheet(
      `<row r="1"><c r="A1"><v>2</v></c><c r="B1"><f t="shared" ref="B1:B3" si="0">A1*2</f><v>4</v></c></row>` +
        `<row r="2"><c r="A2"><v>3</v></c><c r="B2"><f t="shared" si="0"/><v>6</v></c></row>` +
        `<row r="3"><c r="A3"><v>5</v></c><c r="B3"><f t="shared" si="0"/><v>10</v></c></row>`,
      `<hyperlinks><hyperlink ref="A1:B3" location="S1!A1"/><hyperlink ref="A3" location="S1!B3"/></hyperlinks>`,
    );
    const bytes = sheetsPackage([deflated(text(sheet))]);
    const read = readSheet(bytes, "S1");
    expect(read.rowCount).toBe(3);
    expect(cell(read, 2, 0)).toEqual({ v: 5, t: 2 } as ICellData);
    expect(cell(read, 2, 1)).toEqual({ v: 10, t: 2, custom: { oneironFormula: "=A3*2" } } as ICellData);
    expect(readWorkbook(bytes).sheets[read.id!]).toEqual(read);
  });

  it("checks only the sheet it reads, and shared formulas only when it keeps formula text", () => {
    const bytes = sheetsPackage([text(FULL_GRID_HYPERLINK_SHEET), text(PLAIN_SHEET)]);
    expect(readWorkbookOutline(bytes).sheetOrder).toHaveLength(2);
    expect(cell(readSheet(bytes, "S2"), 0, 0)?.v).toBe(1);

    // 100 characters copied to 50 cells, over a 1,000-character line.
    const fanOut = sheetsPackage([text(fanOutSheet(100, 50))]);
    const budget = { ...PREVIEW_BUDGET, sheetTextChars: 1_000 };
    refusedWith("sheetTextChars", () => readSheet(fanOut, "S1", { budget }));
    expect(readSheet(fanOut, "S1", { budget, includeFormulaText: false }).rowCount).toBe(51);
  });
});
