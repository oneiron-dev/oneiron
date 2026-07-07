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

/** Univer `CellValueType` numeric members (STRING=1, NUMBER=2, BOOLEAN=3). */
const CELL_TYPE = { STRING: 1, NUMBER: 2, BOOLEAN: 3 } as const;

export interface ParseOptions {
  /**
   * Preserve each formula's source text under `custom.oneironFormula` for
   * read-only display. The value shown in the grid is always the cached value,
   * never a recomputation. Default: true.
   */
  readonly includeFormulaText?: boolean;
}

/** Minimal identity for a sheet, cheap to obtain without parsing its cells. */
export interface SheetMeta {
  readonly id: string;
  readonly name: string;
}

/** Deterministic, collision-resistant sheet id derived from the sheet name. */
export function sheetId(name: string): string {
  // Univer keys sheets by id; the source name is stable within a workbook.
  let hash = 5381;
  for (let i = 0; i < name.length; i += 1) {
    hash = ((hash << 5) + hash + name.charCodeAt(i)) >>> 0;
  }
  return `sheet-${hash.toString(16)}-${name.length}`;
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
export function readWorkbookOutline(bytes: Uint8Array, name = "workbook"): IWorkbookData {
  const wb = XLSX.read(bytes, { bookSheets: true, bookProps: true });
  const names = wb.SheetNames ?? [];
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
export function readSheetMetas(bytes: Uint8Array): SheetMeta[] {
  const wb = XLSX.read(bytes, { bookSheets: true });
  return (wb.SheetNames ?? []).map((name) => ({ id: sheetId(name), name }));
}

function toCellData(cell: XLSX.CellObject, includeFormula: boolean): ICellData | undefined {
  // `t`: 'n' number, 's'/'str' string, 'b' boolean, 'd' date, 'e' error.
  let value: string | number | boolean | undefined;
  let type: CellValueType | undefined;
  switch (cell.t) {
    case "n":
      value = typeof cell.v === "number" ? cell.v : Number(cell.v);
      type = CELL_TYPE.NUMBER as unknown as CellValueType;
      break;
    case "b":
      value = Boolean(cell.v);
      type = CELL_TYPE.BOOLEAN as unknown as CellValueType;
      break;
    case "d":
      // View-only: show the formatted date text; no client-side date math.
      value = cell.w ?? (cell.v instanceof Date ? cell.v.toISOString() : String(cell.v ?? ""));
      type = CELL_TYPE.STRING as unknown as CellValueType;
      break;
    case "e":
      value = cell.w ?? String(cell.v ?? "#ERR");
      type = CELL_TYPE.STRING as unknown as CellValueType;
      break;
    default: // 's' | 'str' | undefined
      value = cell.v === undefined || cell.v === null ? "" : String(cell.v);
      type = CELL_TYPE.STRING as unknown as CellValueType;
      break;
  }

  const hasFormula = includeFormula && typeof cell.f === "string" && cell.f.length > 0;
  if (value === undefined && !hasFormula) {
    return undefined;
  }
  const data: ICellData = { v: value ?? "", t: type };
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
  const wb = XLSX.read(bytes, {
    sheets: [sheetName],
    cellFormula: includeFormula,
    cellNF: false,
    cellStyles: false,
    cellDates: false,
    cellHTML: false,
  });
  const ws = wb.Sheets[sheetName];
  const sid = sheetId(sheetName);
  if (!ws || !ws["!ref"]) {
    return { id: sid, name: sheetName, rowCount: 0, columnCount: 0, cellData: {} };
  }
  const range = XLSX.utils.decode_range(ws["!ref"]);
  const cellData: Record<number, Record<number, ICellData>> = {};
  for (let r = range.s.r; r <= range.e.r; r += 1) {
    for (let c = range.s.c; c <= range.e.c; c += 1) {
      const addr = XLSX.utils.encode_cell({ r, c });
      const raw = ws[addr] as XLSX.CellObject | undefined;
      if (!raw) {
        continue;
      }
      const cell = toCellData(raw, includeFormula);
      if (cell === undefined) {
        continue;
      }
      (cellData[r] ??= {})[c] = cell;
    }
  }
  return {
    id: sid,
    name: sheetName,
    rowCount: range.e.r + 1,
    columnCount: range.e.c + 1,
    cellData: cellData as IWorksheetData["cellData"],
  };
}

/**
 * Eagerly parse the entire workbook (outline + every sheet). Convenience for
 * small workbooks and tests; the lazy path ({@link readWorkbookOutline} +
 * {@link readSheet}) is what the viewer uses for large files.
 */
export function readWorkbook(
  bytes: Uint8Array,
  options: ParseOptions & { name?: string } = {},
): IWorkbookData {
  const { name = "workbook", ...parseOptions } = options;
  const outline = readWorkbookOutline(bytes, name);
  const sheets: IWorkbookData["sheets"] = {};
  for (const sid of outline.sheetOrder) {
    const stub = outline.sheets[sid]!;
    sheets[sid] = readSheet(bytes, stub.name!, parseOptions);
  }
  return { ...outline, sheets };
}
