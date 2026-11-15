import { describe, expect, it } from "bun:test";
import { deflateRawSync } from "node:zlib";
import type { ICellData, IWorksheetData } from "@univerjs/core";
import { PREVIEW_BUDGET, WorkbookBudgetError, preflightPackage, type BudgetLine } from "../src/bridge/budget";
import { checkSheetExpansion, partTexts } from "../src/bridge/expansion";
import { readSheet, readWorkbookOutline } from "../src/bridge/parse";
import { readInChild, TEST_LIMIT_MS } from "./child-read";
import {
  FAR_COLUMN_FOLLOWER_SHEET,
  FULL_GRID_HYPERLINK_SHEET,
  HUGE_ROW_HYPERLINK_SHEET,
  PLAIN_SHEET,
  fanOutSheet,
  sheetsPackage,
  worksheet,
} from "./crafted-packages";
import { makeXlsxBytes } from "./helpers";
import { deflated, text } from "./package-writer";

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
      expect(readInChild("unfinished-deflate").answer).toEqual({ refused: "structure" });
    },
    TEST_LIMIT_MS,
  );

  it(
    "refuses a sheet whose one hyperlink names every cell of the grid",
    () => {
      expect(readInChild("full-grid-hyperlink").answer).toEqual({ refused: "sheetCells" });
    },
    TEST_LIMIT_MS,
  );

  it(
    "refuses a sheet whose shared formula copies a long master to many cells",
    () => {
      expect(readInChild("shared-formula-fan-out").answer).toEqual({ refused: "sheetTextChars" });
    },
    TEST_LIMIT_MS,
  );

  it(
    "refuses a hyperlink whose one address lies past 2^53, where SheetJS's loop cannot step",
    () => {
      expect(readInChild("huge-row-hyperlink").answer).toEqual({ refused: "sheetCells" });
    },
    TEST_LIMIT_MS,
  );

  it(
    "refuses a shared formula copied through SheetJS's fallback formula reader",
    () => {
      expect(readInChild("fallback-formula-fan-out").answer).toEqual({ refused: "sheetTextChars" });
    },
    TEST_LIMIT_MS,
  );

  it(
    "refuses a shared formula whose master names its index inside its text",
    () => {
      expect(readInChild("hidden-index-fan-out").answer).toEqual({ refused: "sheetTextChars" });
    },
    TEST_LIMIT_MS,
  );

  it(
    "refuses a shared formula follower whose column decodes past the safe integers",
    () => {
      expect(readInChild("far-column-follower").answer).toEqual({ refused: "sheetCells" });
    },
    TEST_LIMIT_MS,
  );

  it("counts what SheetJS would expand before it reads: far addresses, browser-decoded ranges, fallback followers", () => {
    const check = (bytes: Uint8Array, formulaText = false, budget = PREVIEW_BUDGET) => () =>
      checkSheetExpansion(partTexts(bytes), budget, formulaText);
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
    // The master's own tag names index 1; its text names 0, which SheetJS
    // reads last and files the master under. Without that text no follower
    // names the master.
    const hidden = { index: `si="1"`, tail: `N(" si='0' ")` };
    refusedWith("sheetTextChars", check(text(fanOutSheet(100, 50, undefined, hidden)), true, budget));
    expect(check(text(fanOutSheet(100, 50, undefined, { index: `si="1"` })), true, budget)).not.toThrow();
    // `si=a=b` names `si` with the value `a=b`, which SheetJS files under NaN.
    refusedWith(
      "sheetTextChars",
      check(text(fanOutSheet(100, 50, `<f t="shared" si="NaN"/>`, { index: "si=a=b" })), true, budget),
    );
    // A shared formula's cell at a column past the safe integers, follower or
    // master; the same cells without formula text are not shifted.
    refusedWith("sheetCells", check(text(FAR_COLUMN_FOLLOWER_SHEET), true));
    const farMaster = worksheet(
      `<row r="1"><c r="${"Z".repeat(220)}1"><f t="shared" si="0">A1</f><v>1</v></c><c r="A2"><f t="shared" si="0"/><v>1</v></c></row>`,
    );
    refusedWith("sheetCells", check(text(farMaster), true));
    expect(check(text(FAR_COLUMN_FOLLOWER_SHEET), false)).not.toThrow();
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
    expect(readWorkbookOutline(written).sheetOrder).toHaveLength(2);
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
    expect(readWorkbookOutline(bytes).sheetOrder).toEqual([read.id!]);
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
