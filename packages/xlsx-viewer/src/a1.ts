/**
 * A1 <-> numeric coordinate conversion.
 *
 * Three coordinate systems meet in this instrument and each boundary converts
 * through here so the arithmetic lives in exactly one place:
 *
 *  - ARTL-2 anchors (`anchored_annotation`) carry an A1 *string* range
 *    (`"B2:D5"`, single cell `"B2"`) and a decoded 1-based-inclusive
 *    `A1Range { col_start, col_end, row_start, row_end }`.
 *  - ARTL-3 manifest ops (`EditManifest`) address cells as 1-based
 *    `{ col, row }` (`CellRef`) and ranges as `{ start, end }` (`RangeRef`).
 *  - Univer `IWorkbookData` is 0-based: `cellData[row][col]` and
 *    `IRange { startRow, startColumn, endRow, endColumn }`.
 *
 * Internally we standardise on 1-based `{ col, row }` (the ARTL-3 form, the
 * most precise) and only drop to 0-based at the Univer boundary.
 */

/** 1-based cell coordinate (column A == 1, row 1 == 1). Matches ARTL-3 `CellRef`. */
export interface Cell {
  readonly col: number;
  readonly row: number;
}

/** 1-based-inclusive rectangle. Matches ARTL-2 decoded `A1Range`. */
export interface CellRange {
  readonly colStart: number;
  readonly colEnd: number;
  readonly rowStart: number;
  readonly rowEnd: number;
}

/** 0-based-inclusive rectangle in Univer's `IRange` field names. */
export interface UniverRange {
  readonly startRow: number;
  readonly endRow: number;
  readonly startColumn: number;
  readonly endColumn: number;
}

const CELL_RE = /^([A-Z]+)([1-9][0-9]*)$/;

/** `"A"` -> 1, `"Z"` -> 26, `"AA"` -> 27. Case-sensitive (upper-case only). */
export function columnLabelToIndex(label: string): number {
  if (label.length === 0 || !/^[A-Z]+$/.test(label)) {
    throw new Error(`invalid column label: ${JSON.stringify(label)}`);
  }
  let index = 0;
  for (let i = 0; i < label.length; i += 1) {
    index = index * 26 + (label.charCodeAt(i) - 64); // 'A' is 65
  }
  return index;
}

/** 1 -> `"A"`, 26 -> `"Z"`, 27 -> `"AA"`. */
export function indexToColumnLabel(index: number): string {
  if (!Number.isInteger(index) || index < 1) {
    throw new Error(`invalid column index: ${index}`);
  }
  let n = index;
  let label = "";
  while (n > 0) {
    const rem = (n - 1) % 26;
    label = String.fromCharCode(65 + rem) + label;
    n = Math.floor((n - 1) / 26);
  }
  return label;
}

/** `"B2"` -> `{ col: 2, row: 2 }`. */
export function parseA1Cell(a1: string): Cell {
  const match = CELL_RE.exec(a1);
  if (!match) {
    throw new Error(`invalid A1 cell: ${JSON.stringify(a1)}`);
  }
  return { col: columnLabelToIndex(match[1]!), row: Number(match[2]) };
}

/** `{ col: 2, row: 2 }` -> `"B2"`. */
export function cellToA1(cell: Cell): string {
  if (!Number.isInteger(cell.col) || cell.col < 1 || !Number.isInteger(cell.row) || cell.row < 1) {
    throw new Error(`invalid cell: ${JSON.stringify(cell)}`);
  }
  return `${indexToColumnLabel(cell.col)}${cell.row}`;
}

/**
 * `"B2:D5"` -> `{ colStart: 2, colEnd: 4, rowStart: 2, rowEnd: 5 }`.
 * A single cell `"B2"` yields a 1x1 range. Corners are normalised so
 * start <= end regardless of the order they were written.
 */
export function parseA1Range(a1: string): CellRange {
  const [rawStart, rawEnd] = a1.split(":", 2);
  if (rawStart === undefined) {
    throw new Error(`invalid A1 range: ${JSON.stringify(a1)}`);
  }
  const start = parseA1Cell(rawStart);
  const end = rawEnd === undefined ? start : parseA1Cell(rawEnd);
  return {
    colStart: Math.min(start.col, end.col),
    colEnd: Math.max(start.col, end.col),
    rowStart: Math.min(start.row, end.row),
    rowEnd: Math.max(start.row, end.row),
  };
}

/** `{ colStart: 2, colEnd: 4, rowStart: 2, rowEnd: 5 }` -> `"B2:D5"`; 1x1 -> `"B2"`. */
export function rangeToA1(range: CellRange): string {
  const start = cellToA1({ col: range.colStart, row: range.rowStart });
  if (range.colStart === range.colEnd && range.rowStart === range.rowEnd) {
    return start;
  }
  return `${start}:${cellToA1({ col: range.colEnd, row: range.rowEnd })}`;
}

/** 1-based `{ col, row }` -> 0-based `{ row, column }` for Univer cellData indexing. */
export function toUniverCell(cell: Cell): { row: number; column: number } {
  return { row: cell.row - 1, column: cell.col - 1 };
}

/** 1-based-inclusive range -> 0-based-inclusive Univer `IRange`. */
export function toUniverRange(range: CellRange): UniverRange {
  return {
    startRow: range.rowStart - 1,
    endRow: range.rowEnd - 1,
    startColumn: range.colStart - 1,
    endColumn: range.colEnd - 1,
  };
}

/** Widen a single 1-based cell to a 1x1 `CellRange`. */
export function cellToRange(cell: Cell): CellRange {
  return { colStart: cell.col, colEnd: cell.col, rowStart: cell.row, rowEnd: cell.row };
}
