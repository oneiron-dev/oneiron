import { beforeAll, describe, expect, it } from "bun:test";
import { assembleWorkbook, loadedSheetCount } from "../src/bridge/assemble";
import { readSheet, readWorkbookOutline } from "../src/bridge/parse";
import {
  createInlineParseWorker,
  createLocalWorkbookSource,
  createWorkerWorkbookSource,
  type ParseWorkerLike,
} from "../src/bridge/source";
import type { IWorksheetData } from "@univerjs/core";
import { makeXlsxBytes, MB } from "./helpers";

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

  it("the fixture actually exceeds 25MB", () => {
    expect(big.byteLength).toBeGreaterThan(25 * MB);
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

  it("inline worker path matches the direct parse (deterministic)", async () => {
    const source = createWorkerWorkbookSource(big, createInlineParseWorker);
    try {
      const outline = await source.outline();
      expect(outline.sheetOrder).toHaveLength(4);
      const direct = readWorkbookOutline(big);
      expect(outline.sheetOrder).toEqual(direct.sheetOrder);

      const s2 = await source.sheet("S2");
      expect(s2.rowCount).toBe(40000);
      // Cache: second request does not re-parse.
      const again = await source.sheet("S2");
      expect(again).toBe(s2);
    } finally {
      source.dispose();
    }
  }, 60_000);
});

describe("cached formula values (no client recalculation)", () => {
  it("surfaces the cached value and preserves formula text without a live formula", () => {
    const bytes = makeXlsxBytes({ sheets: 1, rows: 3, cols: 3, formulaCell: true });
    const sheet = readSheet(bytes, "S1");
    const cellData = sheet.cellData as Record<number, Record<number, Record<string, unknown>>>;
    const c1 = cellData[0]?.[2];
    expect(c1?.v).toBe(424242); // cached value shown
    expect("f" in (c1 ?? {})).toBe(false); // NO live formula => cannot recalc
    expect((c1?.custom as { oneironFormula?: string } | undefined)?.oneironFormula).toBe("=A1+B1");
  });

  it("local source lazily caches and never parses unrequested sheets", async () => {
    const bytes = makeXlsxBytes({ sheets: 3, rows: 10, cols: 3 });
    const source = createLocalWorkbookSource(bytes);
    const outline = await source.outline();
    expect(outline.sheetOrder).toHaveLength(3);
    expect(loadedSheetCount(outline)).toBe(0);
    await source.sheet("S1");
    expect(source.loadedSheets()).toEqual(["S1"]);
  });
});
