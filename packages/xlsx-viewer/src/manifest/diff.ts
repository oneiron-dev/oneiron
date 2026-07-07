/**
 * Manifest-op diff view (OF-368 D7). Turns an ARTL-3 `EditManifest` into diff
 * lines + grid highlights for the version scrubber. It renders MANIFEST OPS
 * ONLY: this module imports no binary parser (no SheetJS) and reads no bytes —
 * the manifest already IS the semantic diff, so there is no path here that
 * re-parses two workbooks to compute a difference.
 */
import {
  cellToA1,
  cellToRange,
  indexToColumnLabel,
  rangeToA1,
  toUniverCell,
  toUniverRange,
  type UniverRange,
} from "../a1";
import type { Axis, CellRef, CellValue, EditManifest, EditOp, RangeRef } from "./types";

export interface CellHighlight {
  readonly sheet: string;
  readonly kind: "set" | "move-from" | "move-to";
  readonly range: UniverRange;
  readonly opIndex: number;
}

export interface BandHighlight {
  readonly sheet: string;
  readonly axis: Axis;
  /** 0-based index of the first affected row/column. */
  readonly start: number;
  readonly count: number;
  readonly kind: "insert" | "delete" | "add-column";
  readonly opIndex: number;
}

export interface SheetChange {
  readonly sheet: string;
  readonly kind: "add" | "remove" | "rename";
  readonly renamedTo?: string;
  readonly opIndex: number;
}

export interface ManifestDiff {
  /** One human-readable line per op (mirrors ARTL-3 `EditManifest::render_diff`). */
  readonly lines: string[];
  readonly cells: CellHighlight[];
  readonly bands: BandHighlight[];
  readonly sheetChanges: SheetChange[];
}

/** Render an ARTL-3 `CellValue` for a diff line. */
export function formatCellValue(value: CellValue | null | undefined): string {
  if (value === null || value === undefined) {
    return "(none)";
  }
  if (value === "blank") {
    return "(blank)";
  }
  if ("number" in value) {
    return String(value.number);
  }
  if ("text" in value) {
    return value.text;
  }
  if ("bool" in value) {
    return value.bool ? "true" : "false";
  }
  if ("formula" in value) {
    const expr = value.formula.expr;
    return expr.startsWith("=") ? expr : `=${expr}`;
  }
  return `#${value.error}`;
}

function rangeRefToUniver(range: RangeRef): UniverRange {
  return toUniverRange({
    colStart: range.start.col,
    colEnd: range.end.col,
    rowStart: range.start.row,
    rowEnd: range.end.row,
  });
}

function renderOp(op: EditOp): string {
  if ("set_cell" in op) {
    const { sheet, cell, before, after } = op.set_cell;
    const at = `${sheet}!${cellToA1(cell)}`;
    const rhs = formatCellValue(after);
    return before === null || before === undefined
      ? `set ${at}: ${rhs}`
      : `set ${at}: ${formatCellValue(before)} -> ${rhs}`;
  }
  if ("set_range" in op) {
    const { sheet, range, writes } = op.set_range;
    const a1 = rangeToA1({
      colStart: range.start.col,
      colEnd: range.end.col,
      rowStart: range.start.row,
      rowEnd: range.end.row,
    });
    return `set ${sheet}!${a1}: ${writes.length} cell(s)`;
  }
  if ("add_formula_column" in op) {
    const { sheet, column, header, formula } = op.add_formula_column;
    const label = indexToColumnLabel(column);
    const head = header ? ` "${header}"` : "";
    return `add formula column ${sheet}!${label}${head}: ${formula}`;
  }
  if ("insert_rows" in op) {
    const { sheet, at, count } = op.insert_rows;
    return `insert ${count} row(s) at ${sheet}!row ${at}`;
  }
  if ("delete_rows" in op) {
    const { sheet, at, count } = op.delete_rows;
    return `delete ${count} row(s) at ${sheet}!row ${at}`;
  }
  if ("insert_columns" in op) {
    const { sheet, at, count } = op.insert_columns;
    return `insert ${count} column(s) at ${sheet}!column ${indexToColumnLabel(at)}`;
  }
  if ("delete_columns" in op) {
    const { sheet, at, count } = op.delete_columns;
    return `delete ${count} column(s) at ${sheet}!column ${indexToColumnLabel(at)}`;
  }
  if ("move_range" in op) {
    const { sheet, from, to } = op.move_range;
    const fromA1 = rangeToA1({
      colStart: from.start.col,
      colEnd: from.end.col,
      rowStart: from.start.row,
      rowEnd: from.end.row,
    });
    return `move ${sheet}!${fromA1} -> ${cellToA1(to)}`;
  }
  if ("add_sheet" in op) {
    return `add sheet ${op.add_sheet.name}`;
  }
  if ("remove_sheet" in op) {
    return `remove sheet ${op.remove_sheet.name}`;
  }
  return `rename sheet ${op.rename_sheet.from} -> ${op.rename_sheet.to}`;
}

function movedDestinationRange(from: RangeRef, to: CellRef): UniverRange {
  const width = from.end.col - from.start.col;
  const height = from.end.row - from.start.row;
  return toUniverRange({
    colStart: to.col,
    colEnd: to.col + width,
    rowStart: to.row,
    rowEnd: to.row + height,
  });
}

/**
 * Compute the diff between two artifact versions from the edit-manifest alone.
 * No binary is opened; this is the D7 "manifest is the diff" projection.
 */
export function diffManifest(manifest: EditManifest): ManifestDiff {
  const lines: string[] = [];
  const cells: CellHighlight[] = [];
  const bands: BandHighlight[] = [];
  const sheetChanges: SheetChange[] = [];

  manifest.ops.forEach((op, opIndex) => {
    lines.push(renderOp(op));

    if ("set_cell" in op) {
      cells.push({
        sheet: op.set_cell.sheet,
        kind: "set",
        range: toUniverRange(cellToRange(op.set_cell.cell)),
        opIndex,
      });
    } else if ("set_range" in op) {
      for (const write of op.set_range.writes) {
        cells.push({
          sheet: op.set_range.sheet,
          kind: "set",
          range: toUniverRange(cellToRange(write.cell)),
          opIndex,
        });
      }
    } else if ("add_formula_column" in op) {
      bands.push({
        sheet: op.add_formula_column.sheet,
        axis: "column",
        start: op.add_formula_column.column - 1,
        count: 1,
        kind: "add-column",
        opIndex,
      });
    } else if ("insert_rows" in op) {
      bands.push({ sheet: op.insert_rows.sheet, axis: "row", start: op.insert_rows.at - 1, count: op.insert_rows.count, kind: "insert", opIndex });
    } else if ("delete_rows" in op) {
      bands.push({ sheet: op.delete_rows.sheet, axis: "row", start: op.delete_rows.at - 1, count: op.delete_rows.count, kind: "delete", opIndex });
    } else if ("insert_columns" in op) {
      bands.push({ sheet: op.insert_columns.sheet, axis: "column", start: op.insert_columns.at - 1, count: op.insert_columns.count, kind: "insert", opIndex });
    } else if ("delete_columns" in op) {
      bands.push({ sheet: op.delete_columns.sheet, axis: "column", start: op.delete_columns.at - 1, count: op.delete_columns.count, kind: "delete", opIndex });
    } else if ("move_range" in op) {
      cells.push({ sheet: op.move_range.sheet, kind: "move-from", range: rangeRefToUniver(op.move_range.from), opIndex });
      cells.push({ sheet: op.move_range.sheet, kind: "move-to", range: movedDestinationRange(op.move_range.from, op.move_range.to), opIndex });
    } else if ("add_sheet" in op) {
      sheetChanges.push({ sheet: op.add_sheet.name, kind: "add", opIndex });
    } else if ("remove_sheet" in op) {
      sheetChanges.push({ sheet: op.remove_sheet.name, kind: "remove", opIndex });
    } else {
      sheetChanges.push({ sheet: op.rename_sheet.from, kind: "rename", renamedTo: op.rename_sheet.to, opIndex });
    }
  });

  return { lines, cells, bands, sheetChanges };
}

/** Univer 0-based cell for a highlight target (helper for the mount adapter). */
export function highlightCell(cell: CellRef): { row: number; column: number } {
  return toUniverCell(cell);
}
