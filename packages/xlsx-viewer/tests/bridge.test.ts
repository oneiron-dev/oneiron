import { beforeAll, describe, expect, it } from "bun:test";
import { assembleWorkbook, loadedSheetCount } from "../src/bridge/assemble";
import { createWorkerWorkbookSource, type ParseWorkerLike } from "../src/bridge/source";
import type { IWorksheetData } from "@univerjs/core";
import { makeXlsxBytes } from "./helpers";

function realWorker(): ParseWorkerLike {
  return new Worker(new URL("../src/bridge/worker.ts", import.meta.url).href, {
    type: "module",
  }) as unknown as ParseWorkerLike;
}

describe("acceptance 1: >25MB xlsx renders via worker with lazy sheet mount", () => {
  let big: Uint8Array;

  beforeAll(() => {
    // 4 sheets x 40k rows x 8 cols -> ~29MB (see calibration in PR body).
    big = makeXlsxBytes({ sheets: 4, rows: 40000, cols: 8, formulaCell: true });
  });

  it(
    "parses a >25MB workbook in a real Web Worker, lazily per sheet",
    async () => {
      const source = createWorkerWorkbookSource(big, realWorker);
      try {
        // Outline is cheap and carries NO cell data (lazy).
        const outline = await source.outline();
        expect(outline.sheetOrder).toHaveLength(4);
        expect(loadedSheetCount(outline)).toBe(0);

        // Mount exactly one sheet; the rest stay unparsed.
        const s1 = await source.sheet("S1");
        expect(s1.rowCount).toBe(40000);
        expect(s1.columnCount).toBe(8);
        expect(source.loadedSheets()).toEqual(["S1"]);

        // The assembled, mountable workbook holds only the one loaded sheet.
        const loaded = new Map<string, Partial<IWorksheetData>>([["S1", s1]]);
        const workbook = assembleWorkbook(outline, loaded);
        expect(loadedSheetCount(workbook)).toBe(1);
      } finally {
        source.dispose();
      }
    },
    60_000,
  );

});

