/**
 * Compose a mountable `IWorkbookData` from a cheap outline plus whichever
 * sheets have actually been loaded. Pure data — no Univer runtime, no parsing —
 * so the lazy-mount composition is testable on its own. Unloaded sheets stay as
 * empty stubs; the viewer fills them in as tabs are visited.
 */
import type { IWorkbookData, IWorksheetData } from "@univerjs/core";

export function assembleWorkbook(
  outline: IWorkbookData,
  loadedByName: ReadonlyMap<string, Partial<IWorksheetData>>,
): IWorkbookData {
  const sheets: IWorkbookData["sheets"] = {};
  for (const sid of outline.sheetOrder) {
    const stub = outline.sheets[sid];
    if (!stub) {
      continue;
    }
    const loaded = stub.name !== undefined ? loadedByName.get(stub.name) : undefined;
    sheets[sid] = loaded ? { ...stub, ...loaded, id: sid } : stub;
  }
  return { ...outline, sheets };
}

/** Count sheets that carry actual cell data (loaded), for lazy-mount assertions. */
export function loadedSheetCount(workbook: IWorkbookData): number {
  let n = 0;
  for (const sid of workbook.sheetOrder) {
    const sheet = workbook.sheets[sid];
    const cellData = sheet?.cellData as Record<number, unknown> | undefined;
    if (cellData && Object.keys(cellData).length > 0) {
      n += 1;
    }
  }
  return n;
}
