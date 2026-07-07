import { describe, expect, it } from "bun:test";
import { readSheet, readWorkbookOutline } from "../src/bridge/parse";
import { computeMountPlan } from "../src/univer/plan";
import { isEditCommandId } from "../src/univer/readonly";
import type { IWorksheetData } from "@univerjs/core";
import { makeXlsxBytes } from "./helpers";

describe("computeMountPlan: activate the requested sheet after remount (#9)", () => {
  it("resolves the active sheet id and includes its cell data", () => {
    const bytes = makeXlsxBytes({ sheets: 3, rows: 4, cols: 2 });
    const outline = readWorkbookOutline(bytes);
    const loaded = new Map<string, Partial<IWorksheetData>>([["S2", readSheet(bytes, "S2")]]);

    const plan = computeMountPlan(outline, loaded, "S2");

    expect(plan.workbook.sheets[plan.activeSheetId]?.name).toBe("S2");
    const cd = plan.workbook.sheets[plan.activeSheetId]?.cellData as Record<number, unknown>;
    expect(Object.keys(cd)).not.toHaveLength(0);
  });

  it("throws for a sheet that is not in the workbook", () => {
    const outline = readWorkbookOutline(makeXlsxBytes({ sheets: 1, rows: 2, cols: 2 }));
    expect(() => computeMountPlan(outline, new Map(), "Nope")).toThrow(/no such sheet/);
  });
});

describe("isEditCommandId: read-only guard (#10)", () => {
  it("blocks mutating commands", () => {
    for (const id of [
      "sheet.command.set-range-values",
      "sheet.command.insert-row",
      "sheet.command.remove-col",
      "sheet.command.delete-range-move-up",
      "sheet.command.move-range",
      "sheet.command.set-worksheet-name",
      "sheet.operation.set-cell-edit-visible",
      "doc.command.insert-text",
    ]) {
      expect(isEditCommandId(id)).toBe(true);
    }
  });

  it("allows navigation, selection, scroll, zoom, and active-sheet switching", () => {
    for (const id of [
      "sheet.operation.set-selections",
      "sheet.command.set-worksheet-active",
      "sheet.operation.set-scroll",
      "sheet.operation.set-zoom-ratio",
      "sheet.command.move-selection",
    ]) {
      expect(isEditCommandId(id)).toBe(false);
    }
  });
});
