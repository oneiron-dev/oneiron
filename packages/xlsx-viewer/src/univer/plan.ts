/**
 * Pure mount-planning helpers (no Univer runtime), so the "which sheet is
 * active and is its data present" logic is testable without a canvas.
 */
import { assembleWorkbook } from "../bridge/assemble";
import type { IWorkbookData, IWorksheetData } from "@univerjs/core";

export interface MountPlan {
  readonly workbook: IWorkbookData;
  /** Univer sheet id to activate after `createUnit`, so the grid opens here. */
  readonly activeSheetId: string;
}

/**
 * Assemble the mountable workbook and resolve the id of the sheet that must be
 * activated. Univer opens `sheetOrder[0]` by default, so after a remount the
 * viewer must explicitly re-activate the requested sheet — this returns the id
 * to hand to `setActiveSheet`.
 */
export function computeMountPlan(
  outline: IWorkbookData,
  loadedByName: ReadonlyMap<string, Partial<IWorksheetData>>,
  activeSheetName: string,
): MountPlan {
  const workbook = assembleWorkbook(outline, loadedByName);
  const activeSheetId = workbook.sheetOrder.find(
    (sid) => workbook.sheets[sid]?.name === activeSheetName,
  );
  if (activeSheetId === undefined) {
    throw new Error(`no such sheet: ${activeSheetName}`);
  }
  return { workbook, activeSheetId };
}
