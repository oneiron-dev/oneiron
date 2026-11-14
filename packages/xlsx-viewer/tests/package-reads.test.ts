import { describe, expect, it } from "bun:test";
import type { ICellData, IWorksheetData } from "@univerjs/core";
import { readSheet, readSheetMetas, readWorkbookOutline } from "../src/bridge/parse";
import { readInChild, TEST_LIMIT_MS } from "./child-read";
import { macroWorkbookPackage, realShapedPackage } from "./crafted-packages";

function cell(sheet: Partial<IWorksheetData>, row: number, column: number): ICellData | undefined {
  return (sheet.cellData as Record<number, Record<number, ICellData>> | undefined)?.[row]?.[column];
}

describe("xlsx preview: every door reads the package through one guarded read", () => {
  it(
    "refuses a binary workbook part on the outline and sheet doors",
    () => {
      expect(readInChild("binary-workbook", "outline").answer).toEqual({ refused: "structure" });
      expect(readInChild("binary-workbook", "sheet").answer).toEqual({ refused: "structure" });
    },
    2 * TEST_LIMIT_MS,
  );

  it(
    "refuses an xlsx whose rels point a sheet at a binary part",
    () => {
      expect(readInChild("binary-sheet").answer).toEqual({ refused: "structure" });
    },
    TEST_LIMIT_MS,
  );

  it("previews an xlsm that carries vbaProject, printer-settings and embedded .bin parts", () => {
    const bytes = macroWorkbookPackage();
    expect(readWorkbookOutline(bytes).sheetOrder).toHaveLength(1);
    expect(readSheetMetas(bytes).map((meta) => meta.name)).toEqual(["S1"]);
    const sheet = readSheet(bytes, "S1");
    expect(sheet.rowCount).toBe(1);
    expect(cell(sheet, 0, 0)?.v).toBe(7);
  });

  it(
    "refuses a workbook listing more sheets than the budget before SheetJS walks them",
    () => {
      const read = readInChild("many-listed-sheets");
      expect(read.answer).toEqual({ refused: "sheets" });
      expect(read.readMs).toBeLessThan(5_000);
    },
    TEST_LIMIT_MS,
  );

  it(
    "refuses sheet lookups over the part-lookup line inside the sheet line",
    () => {
      expect(readInChild("listed-sheet-lookups").answer).toEqual({ refused: "partLookups" });
    },
    TEST_LIMIT_MS,
  );

  it(
    "refuses external links that make quadratic part lookups, on the outline door too",
    () => {
      expect(readInChild("external-link-lookups", "outline").answer).toEqual({ refused: "partLookups" });
      expect(readInChild("external-link-lookups", "sheet").answer).toEqual({ refused: "partLookups" });
    },
    2 * TEST_LIMIT_MS,
  );

  it("reads a real-shaped workbook with links, comments and many sheets as before", () => {
    const bytes = realShapedPackage();
    const outline = readWorkbookOutline(bytes);
    expect(outline.sheetOrder).toHaveLength(300);
    expect(outline.sheets[outline.sheetOrder[299]!]?.name).toBe("S300");
    const sheet = readSheet(bytes, "S300");
    expect(sheet.rowCount).toBe(2);
    expect(cell(sheet, 0, 0)?.v).toBe(300);
    expect(cell(sheet, 1, 0)?.v).toBe(3);
  });
});
