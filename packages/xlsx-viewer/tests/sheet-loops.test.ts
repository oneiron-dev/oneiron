import { describe, expect, it } from "bun:test";
import type { ICellData, IWorksheetData } from "@univerjs/core";
import { PREVIEW_BUDGET, WorkbookBudgetError } from "../src/bridge/budget";
import { checkSheetExpansion, partTexts } from "../src/bridge/expansion";
import { readSheet } from "../src/bridge/parse";
import { readInChild, TEST_LIMIT_MS } from "./child-read";
import {
  arrayRangeChecksSheet,
  farShiftedCopiesSheet,
  nearShiftedCopiesSheet,
  sheetsPackage,
  spilledFormulasSheet,
} from "./crafted-packages";
import { text } from "./package-writer";

function cell(sheet: Partial<IWorksheetData>, row: number, column: number): ICellData | undefined {
  return (sheet.cellData as Record<number, Record<number, ICellData>> | undefined)?.[row]?.[column];
}

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

  it("charges followers next to their master at about the master's length", () => {
    // A million followers of a 40-character master, below it: about 60
    // million characters, under the 64 MiB line.
    const texts = partTexts(text(nearShiftedCopiesSheet(1_000_000)));
    expect(() => checkSheetExpansion(texts, PREVIEW_BUDGET, true)).not.toThrow();
  });
});
