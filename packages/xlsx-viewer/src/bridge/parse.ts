/**
 * SheetJS CE -> Univer `IWorkbookData` import bridge (OF-368 D8).
 *
 * View-only. The bridge emits cells carrying the workbook's **cached** values;
 * it never writes `ICellData.f` (a live formula) so Univer's formula engine has
 * nothing to recalculate. Formula *text* is preserved out-of-band under
 * `ICellData.custom.oneironFormula` for read-only display in the formula bar.
 * There is no export path here — round-tripping happens agent-side on the
 * original blob (OF-368 D5), which is what lets us skip the Univer-Pro
 * import/export packages entirely.
 *
 * `@univerjs/core` is a **type-only** import: the bridge (and the worker that
 * wraps it) run free of Univer runtime code so they stay hermetic and cheap in
 * a Web Worker and in tests.
 */
import * as XLSX from "xlsx";
import { checkSheetCount, PREVIEW_BUDGET, preflightPackage, WorkbookBudgetError } from "./budget";
import type { PreviewBudget } from "./budget";
import type {
  CellValueType,
  ICellData,
  IWorkbookData,
  IWorksheetData,
  LocaleType,
} from "@univerjs/core";

/**
 * Univer's `LocaleType` is a string enum whose members ARE these locale strings
 * (`LocaleType.EN_US === "enUS"`). Keeping the import type-only costs exactly
 * this one cast, in one place.
 */
const DEFAULT_LOCALE = "enUS" as unknown as LocaleType;
const APP_VERSION = "0.0.0-oneiron-xlsx-viewer";

/** Excel's grid: no real sheet holds a row or column past these. */
const MAX_ROWS = 1_048_576;
const MAX_COLUMNS = 16_384;

/** Univer `CellValueType` numeric members (STRING=1, NUMBER=2, BOOLEAN=3). */
const CELL_TYPE = { STRING: 1, NUMBER: 2, BOOLEAN: 3 } as const;

export interface ParseOptions {
  /**
   * Preserve each formula's source text under `custom.oneironFormula` for
   * read-only display. The value shown in the grid is always the cached value,
   * never a recomputation. Default: true.
   */
  readonly includeFormulaText?: boolean;
  /**
   * The lines the preview stays within; a workbook over one is refused with a
   * `WorkbookBudgetError`. Default: `PREVIEW_BUDGET`.
   */
  readonly budget?: PreviewBudget;
}

/** Minimal identity for a sheet, cheap to obtain without parsing its cells. */
export interface SheetMeta {
  readonly id: string;
  readonly name: string;
}

/** Base64url of a UTF-8 string. Browser- and worker-safe (uses global `btoa`). */
function base64url(input: string): string {
  const bytes = new TextEncoder().encode(input);
  let binary = "";
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i]!);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Collision-free sheet id derived from the sheet name. Univer keys sheets by
 * id, and xlsx sheet names are unique within a workbook, so base64url of the
 * full name is a deterministic bijection — no hash collisions can make one
 * sheet overwrite another in `workbook.sheets`.
 */
export function sheetId(name: string): string {
  return `sheet-${base64url(name)}`;
}

function emptyWorkbook(id: string, name: string): IWorkbookData {
  return {
    id,
    name,
    appVersion: APP_VERSION,
    locale: DEFAULT_LOCALE,
    styles: {},
    sheetOrder: [],
    sheets: {},
  };
}

/**
 * Read only the workbook directory (sheet names + order). Does NOT parse any
 * sheet's cell data — this is the cheap first pass that keeps a >25MB workbook
 * from being fully materialised up front. Every sheet in the returned workbook
 * is a stub with empty `cellData`; call {@link readSheet} to populate one.
 */
export function readWorkbookOutline(
  bytes: Uint8Array,
  name = "workbook",
  budget: PreviewBudget = PREVIEW_BUDGET,
): IWorkbookData {
  const wb = XLSX.read(preflightPackage(bytes, budget), { bookSheets: true, bookProps: true });
  const names = wb.SheetNames ?? [];
  checkSheetCount(names.length, budget);
  return outlineOf(names, name);
}

function outlineOf(names: readonly string[], name: string): IWorkbookData {
  const id = sheetId(name);
  const workbook = emptyWorkbook(id, name);
  const order: string[] = [];
  const sheets: IWorkbookData["sheets"] = {};
  for (const sheetName of names) {
    const sid = sheetId(sheetName);
    order.push(sid);
    sheets[sid] = {
      id: sid,
      name: sheetName,
      rowCount: 0,
      columnCount: 0,
      cellData: {},
    };
  }
  return { ...workbook, sheetOrder: order, sheets };
}

/** Sheet names in workbook order, without parsing cells. */
export function readSheetMetas(bytes: Uint8Array, budget: PreviewBudget = PREVIEW_BUDGET): SheetMeta[] {
  const wb = XLSX.read(preflightPackage(bytes, budget), { bookSheets: true });
  const names = wb.SheetNames ?? [];
  checkSheetCount(names.length, budget);
  return names.map((name) => ({ id: sheetId(name), name }));
}

function toCellData(cell: XLSX.CellObject, includeFormula: boolean): ICellData | undefined {
  // `t`: 'n' number, 's'/'str' string, 'b' boolean, 'd' date, 'e' error.
  const NUMBER = CELL_TYPE.NUMBER as unknown as CellValueType;
  const STRING = CELL_TYPE.STRING as unknown as CellValueType;
  const BOOLEAN = CELL_TYPE.BOOLEAN as unknown as CellValueType;
  let value: string | number | boolean | undefined;
  let type: CellValueType | undefined;
  switch (cell.t) {
    case "n":
      // A formula cell may carry `f` but no cached `v`; never emit NaN.
      if (typeof cell.v === "number" && Number.isFinite(cell.v)) {
        value = cell.v;
        type = NUMBER;
      }
      break;
    case "b":
      // Univer BOOLEAN cells expect a 0|1 value, not a JS boolean.
      value = cell.v ? 1 : 0;
      type = BOOLEAN;
      break;
    case "d":
      // View-only: show the formatted date text; no client-side date math.
      value = cell.w ?? (cell.v instanceof Date ? cell.v.toISOString() : undefined);
      if (value !== undefined) {
        type = STRING;
      }
      break;
    case "e":
      value = cell.w ?? (cell.v === undefined || cell.v === null ? undefined : String(cell.v));
      if (value !== undefined) {
        type = STRING;
      }
      break;
    default: // 's' | 'str' | undefined
      if (cell.v !== undefined && cell.v !== null) {
        value = String(cell.v);
        type = STRING;
      }
      break;
  }

  const hasFormula = includeFormula && typeof cell.f === "string" && cell.f.length > 0;
  if (value === undefined && !hasFormula) {
    return undefined;
  }
  const data: ICellData = {};
  if (value !== undefined) {
    data.v = value;
    if (type !== undefined) {
      data.t = type;
    }
  }
  if (hasFormula) {
    // Formula text only, NEVER `f` — the engine must not recalculate.
    data.custom = { oneironFormula: cell.f!.startsWith("=") ? cell.f! : `=${cell.f!}` };
  }
  return data;
}

/**
 * Parse a SINGLE sheet's cells on demand (lazy mount). Only the requested sheet
 * is materialised; the rest of the workbook is left unparsed.
 */
export function readSheet(
  bytes: Uint8Array,
  sheetName: string,
  options: ParseOptions = {},
): Partial<IWorksheetData> {
  const includeFormula = options.includeFormulaText ?? true;
  const budget = options.budget ?? PREVIEW_BUDGET;
  const wb = XLSX.read(preflightPackage(bytes, budget), {
    sheets: [sheetName],
    ...sheetReadOptions(includeFormula),
  });
  return sheetOf(wb, sheetName, includeFormula, budget);
}

function sheetReadOptions(includeFormula: boolean): XLSX.ParsingOptions {
  return {
    cellFormula: includeFormula,
    cellNF: false,
    cellStyles: false,
    cellDates: false,
    cellHTML: false,
  };
}

function sheetOf(
  wb: XLSX.WorkBook,
  sheetName: string,
  includeFormula: boolean,
  budget: PreviewBudget,
): Partial<IWorksheetData> {
  const ws = wb.Sheets[sheetName];
  const sid = sheetId(sheetName);
  if (!ws) {
    return { id: sid, name: sheetName, rowCount: 0, columnCount: 0, cellData: {} };
  }
  return { id: sid, name: sheetName, ...worksheetToCellData(ws, includeFormula, budget) };
}

/**
 * Convert a parsed SheetJS worksheet to Univer cell data + dimensions.
 *
 * Iterates the sheet's ACTUAL cell keys, never the full `!ref` rectangle: a
 * file whose stored dimension is inflated (e.g. `A1:XFD1048576`) but holds a
 * couple of far-apart cells must not spin billions of iterations. Dimensions
 * come from `!ref`; if it is absent they fall back to the observed extent.
 * Either way they stop at Excel's grid, and a cell past it is dropped: no
 * saved workbook holds one, so a dimension past it is crafted.
 * A sheet with more cells, or more cell and formula text, than `budget`
 * allows is refused with a `WorkbookBudgetError` rather than handed on.
 */
export function worksheetToCellData(
  ws: XLSX.WorkSheet,
  includeFormula: boolean,
  budget: PreviewBudget = PREVIEW_BUDGET,
): { rowCount: number; columnCount: number; cellData: IWorksheetData["cellData"] } {
  const cellData: Record<number, Record<number, ICellData>> = {};
  let maxRow = 0;
  let maxCol = 0;
  let cells = 0;
  let textChars = 0;
  for (const addr of Object.keys(ws)) {
    if (addr.startsWith("!")) {
      continue; // `!ref`, `!merges`, `!cols`, ... metadata keys
    }
    const raw = ws[addr] as XLSX.CellObject | undefined;
    if (!raw) {
      continue;
    }
    cells += 1;
    if (cells > budget.sheetCells) {
      throw new WorkbookBudgetError("sheetCells", "a sheet holds more cells than the budget");
    }
    const { r, c } = XLSX.utils.decode_cell(addr);
    if (r >= MAX_ROWS || c >= MAX_COLUMNS) {
      continue;
    }
    if (r > maxRow) maxRow = r;
    if (c > maxCol) maxCol = c;
    const cell = toCellData(raw, includeFormula);
    if (cell === undefined) {
      continue;
    }
    textChars += textLength(cell);
    if (textChars > budget.sheetTextChars) {
      throw new WorkbookBudgetError("sheetTextChars", "a sheet holds more text than the budget");
    }
    (cellData[r] ??= {})[c] = cell;
  }
  const ref = ws["!ref"];
  const range = ref ? XLSX.utils.decode_range(ref) : undefined;
  return {
    rowCount: Math.min(range ? range.e.r + 1 : maxRow + 1, MAX_ROWS),
    columnCount: Math.min(range ? range.e.c + 1 : maxCol + 1, MAX_COLUMNS),
    cellData: cellData as IWorksheetData["cellData"],
  };
}

/** Characters of text and formula text a converted cell carries. */
function textLength(cell: ICellData): number {
  const formula = (cell.custom as { oneironFormula?: string } | undefined)?.oneironFormula;
  return (typeof cell.v === "string" ? cell.v.length : 0) + (formula?.length ?? 0);
}

/**
 * Eagerly parse the entire workbook (outline + every sheet) in one SheetJS
 * pass. Convenience for small workbooks and tests; the lazy path
 * ({@link readWorkbookOutline} + {@link readSheet}) is what the viewer uses
 * for large files.
 */
export function readWorkbook(
  bytes: Uint8Array,
  options: ParseOptions & { name?: string } = {},
): IWorkbookData {
  const { name = "workbook", ...parseOptions } = options;
  const includeFormula = parseOptions.includeFormulaText ?? true;
  const budget = parseOptions.budget ?? PREVIEW_BUDGET;
  const wb = XLSX.read(preflightPackage(bytes, budget), sheetReadOptions(includeFormula));
  const names = wb.SheetNames ?? [];
  checkSheetCount(names.length, budget);
  const outline = outlineOf(names, name);
  const sheets: IWorkbookData["sheets"] = {};
  for (const sid of outline.sheetOrder) {
    const stub = outline.sheets[sid]!;
    sheets[sid] = sheetOf(wb, stub.name!, includeFormula, budget);
  }
  return { ...outline, sheets };
}
