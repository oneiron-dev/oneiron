/**
 * TypeScript mirror of ARTL-3 (ONE-1553) `EditManifest` shapes (canonical
 * source: `crates/oneiron/src/edit_roundtrip.rs`, PR #394).
 *
 * D7 law: the manifest IS the semantic diff. The viewer renders manifest ops
 * ONLY — it never re-parses two binaries. These types are the input to the diff
 * view; the engine hands the viewer a manifest, already deserialized.
 *
 * Serde encoding notes (so a napi/JSON binding mirrors the Rust exactly):
 *  - `EditOp` and `CellValue` are EXTERNALLY tagged: struct variants serialize
 *    as `{ "<tag>": { ...fields } }`, unit variants as the bare string
 *    `"<tag>"`. Variant tags are snake_case; inner field names are verbatim.
 *  - Op tags are `set_cell` / `set_range` (NOT `update_cell` / `update_cell_range`).
 *  - Cell/range addressing is structured `{ col, row }`, 1-based on both axes —
 *    NOT the A1-string locator ARTL-2 anchors use.
 *
 * RECONCILIATION SEAM: re-derive against ONE-1553's generated bindings when its
 * PR merges.
 */

export const EDIT_MANIFEST_SCHEMA_VERSION = 1;

export type OfficeFormat = "xlsx" | "docx" | "pptx";
export type MutationMode = "full" | "minimal";
export type Axis = "row" | "column";

export type WarningCode =
  | "heavy_pivot_minimal_mutation"
  | "charts_present_minimal_mutation"
  | "macros_present_minimal_mutation"
  | "session_reported";

export interface EditWarning {
  readonly code: WarningCode;
  readonly detail: string;
}

/** ARTL-3 `CellRef` — 1-based (A1 == { col: 1, row: 1 }). */
export interface CellRef {
  readonly col: number;
  readonly row: number;
}

/** ARTL-3 `RangeRef` — inclusive of both corners. */
export interface RangeRef {
  readonly start: CellRef;
  readonly end: CellRef;
}

/** ARTL-3 `CellValue`, externally tagged. */
export type CellValue =
  | "blank"
  | { readonly number: number }
  | { readonly text: string }
  | { readonly bool: boolean }
  | { readonly formula: { readonly expr: string; readonly cached?: CellValue | null } }
  | { readonly error: string };

/** ARTL-3 `CellWrite` — one entry per cell inside a `set_range`. */
export interface CellWrite {
  readonly cell: CellRef;
  readonly before?: CellValue | null;
  readonly after: CellValue;
}

/** ARTL-3 `EditOp`, externally tagged. Exactly one key, the variant tag. */
export type EditOp =
  | { readonly set_cell: { sheet: string; cell: CellRef; before?: CellValue | null; after: CellValue } }
  | { readonly set_range: { sheet: string; range: RangeRef; writes: CellWrite[] } }
  | {
      readonly add_formula_column: {
        sheet: string;
        column: number;
        header?: string | null;
        formula: string;
      };
    }
  | { readonly insert_rows: { sheet: string; at: number; count: number } }
  | { readonly delete_rows: { sheet: string; at: number; count: number } }
  | { readonly insert_columns: { sheet: string; at: number; count: number } }
  | { readonly delete_columns: { sheet: string; at: number; count: number } }
  | { readonly move_range: { sheet: string; from: RangeRef; to: CellRef } }
  | { readonly add_sheet: { name: string } }
  | { readonly remove_sheet: { name: string } }
  | { readonly rename_sheet: { from: string; to: string } };

export type EditOpTag = keyof EditOp extends never ? never : Extract<keyof EditOp, string>;

/** ARTL-3 `EditManifest` top-level. Version-agnostic and self-contained. */
export interface EditManifest {
  readonly schema_version: number;
  readonly format: OfficeFormat;
  readonly ops: EditOp[];
  readonly touched_parts: string[];
  readonly mutation_mode: MutationMode;
  readonly warnings: EditWarning[];
}

/** The single variant tag of an externally-tagged op. */
export function opTag(op: EditOp): EditOpTag {
  return Object.keys(op)[0] as EditOpTag;
}
