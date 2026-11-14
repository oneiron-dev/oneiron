import { describe, expect, it } from "bun:test";
import type { ICellData, IWorksheetData } from "@univerjs/core";
import { PREVIEW_BUDGET, WorkbookBudgetError, type BudgetLine } from "../src/bridge/budget";
import { checkSheetExpansion, partTexts } from "../src/bridge/expansion";
import { readSheet } from "../src/bridge/parse";
import { readInChild, TEST_LIMIT_MS } from "./child-read";
import {
  arrayRangeChecksSheet,
  fanOutSheet,
  farShiftedCopiesSheet,
  nearShiftedCopiesSheet,
  rowTagCellsSheet,
  sheetJsFormulaChars,
  sheetsPackage,
  spilledFormulasSheet,
  unfinishedCdataSheet,
  utf16le,
  worksheet,
} from "./crafted-packages";
import { text } from "./package-writer";

function cell(sheet: Partial<IWorksheetData>, row: number, column: number): ICellData | undefined {
  return (sheet.cellData as Record<number, Record<number, ICellData>> | undefined)?.[row]?.[column];
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

/** A 1,000-character text line, which 10 copies of a 100-character master reach. */
const TEXT_LINE = { ...PREVIEW_BUDGET, sheetTextChars: 1_000 };

describe("xlsx preview: the loops SheetJS runs over what a read gathers are bounded", () => {
  it(
    "refuses array ranges whose per-cell checks cross the loop line",
    () => {
      expect(readInChild("array-range-checks").answer).toEqual({ refused: "loopSteps" });
      // The same sheet checked directly: its steps, over the line.
      const steps = checkSheetExpansion(partTexts(text(arrayRangeChecksSheet())), PREVIEW_BUDGET, true);
      expect(steps).toBeGreaterThan(PREVIEW_BUDGET.loopSteps);
    },
    TEST_LIMIT_MS,
  );

  it("previews real spilled formulas and keeps their text", () => {
    const bytes = sheetsPackage([text(spilledFormulasSheet())]);
    const sheet = readSheet(bytes, "S1");
    expect(sheet.rowCount).toBe(100);
    for (let row = 0; row < 100; row += 1) {
      expect(cell(sheet, row, 0)?.custom).toEqual({ oneironFormula: `=B${row + 1}*2` });
      expect(cell(sheet, row, 99)?.v).toBe(99);
    }
  });

  it(
    "refuses comments stacked on one cell",
    () => {
      expect(readInChild("stacked-comments").answer).toEqual({ refused: "loopSteps" });
    },
    TEST_LIMIT_MS,
  );

  it(
    "refuses threaded comments times people",
    () => {
      expect(readInChild("threaded-comments-people").answer).toEqual({ refused: "loopSteps" });
    },
    TEST_LIMIT_MS,
  );

  it(
    "charges a shared-formula copy for what its shift adds",
    () => {
      // 1,000 followers of a 64 KiB master: 66 million characters at the
      // master's length, under the line, and 633 million once each copy is
      // shifted.
      let caught: unknown;
      try {
        checkSheetExpansion(partTexts(text(farShiftedCopiesSheet(1_000))), PREVIEW_BUDGET, true);
      } catch (err) {
        caught = err;
      }
      expect(caught).toBeInstanceOf(WorkbookBudgetError);
      expect((caught as WorkbookBudgetError).line).toBe("sheetTextChars");
      const read = readInChild("far-shifted-copies");
      expect(read.answer).toEqual({ refused: "sheetTextChars" });
      expect(read.peakMiB).toBeLessThan(1_024);
    },
    TEST_LIMIT_MS,
  );

  it("reads a row's first cell address where SheetJS reads it: after the row's first `>`", () => {
    // Rows with no row tag: SheetJS reads each follower at a 12-letter column
    // and a 16-digit row, about 9 times the master's length per copy, over a
    // 2,000-character line that 10 copies at the master's length stay under.
    const line = { ...PREVIEW_BUDGET, sheetTextChars: 2_000 };
    const far = text(rowTagCellsSheet(false));
    expect(sheetJsFormulaChars(far)).toBeGreaterThan(9_000);
    refusedWith("sheetTextChars", () => checkSheetExpansion(partTexts(far), line, true));
    // The same cells after row tags, rows 2 to 11 below the master: the master
    // and 1,066 characters of copies.
    const near = text(rowTagCellsSheet(true));
    expect(sheetJsFormulaChars(near)).toBe(1_166);
    expect(() => checkSheetExpansion(partTexts(near), line, true)).not.toThrow();
  });

  it("counts a part after a UTF-16 byte-order mark as SheetJS parses it: written back as UTF-8", () => {
    // Š is C5 A0 in UTF-8, and SheetJS's attribute pattern reads A0, a
    // no-break space, as the space before `si`: 50 followers.
    const hidden = utf16le(fanOutSheet(100, 50, `<f t="shared" Šsi="0"/>`));
    expect(sheetJsFormulaChars(hidden)).toBeGreaterThan(5_000);
    refusedWith("sheetTextChars", () => checkSheetExpansion(partTexts(hidden), TEXT_LINE, true));
    // A UTF-16 sheet of real size still previews, its copies shifted.
    const sheet = readSheet(sheetsPackage([utf16le(fanOutSheet(100, 9))]), "S1");
    expect(sheet.rowCount).toBe(10);
    expect(cell(sheet, 9, 0)?.custom?.oneironFormula).toStartWith("=A10+A10+");
  });

  it(
    "charges a master whose CDATA section never ends at a bound of SheetJS's unescape, without building it",
    () => {
      // 40,000 characters before the marker: SheetJS copies the 600,000 after
      // it once per two of them, 12 billion characters.
      const unfinished = partTexts(text(unfinishedCdataSheet(40_000, 600_000)));
      refusedWith("sheetTextChars", () => checkSheetExpansion(unfinished, PREVIEW_BUDGET, true));
      expect(readInChild("unfinished-cdata-master").answer).toEqual({ refused: "sheetTextChars" });
      // A CDATA section that ends previews, its text as SheetJS keeps it.
      const closed = worksheet(
        `<row r="1"><c r="A1"><f t="shared" ref="A1:A2" si="0">A1+<![CDATA[B1]]>+C1</f><v>1</v></c></row>` +
          `<row r="2"><c r="A2"><f t="shared" si="0"/><v>1</v></c></row>`,
      );
      expect(cell(readSheet(sheetsPackage([text(closed)]), "S1"), 1, 0)?.custom).toEqual({
        oneironFormula: "=A2+B2+C2",
      });
    },
    TEST_LIMIT_MS,
  );

  it(
    "charges followers next to their master at about the master's length",
    () => {
      // A million followers of a 40-character master, below it: about 60
      // million characters, under the 64 MiB line. The walk over a million
      // cells took 6.4 s on kel, past bun's 5 s default.
      const texts = partTexts(text(nearShiftedCopiesSheet(1_000_000)));
      expect(() => checkSheetExpansion(texts, PREVIEW_BUDGET, true)).not.toThrow();
    },
    TEST_LIMIT_MS,
  );
});
