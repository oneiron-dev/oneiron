/**
 * Test helpers. Fixtures are generated programmatically at run time — no large
 * binary is ever committed (see `.gitignore`).
 */
import * as XLSX from "xlsx";
import type { EditManifest } from "../src/manifest/types";

/** Deterministic LCG so fixture size is stable across runs. */
function lcg(seed: number): () => number {
  let s = seed >>> 0;
  return () => {
    s = (s * 1664525 + 1013904223) >>> 0;
    return s / 0xffffffff;
  };
}

function randString(rand: () => number, len: number): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let out = "";
  for (let i = 0; i < len; i += 1) {
    out += alphabet[(rand() * alphabet.length) | 0];
  }
  return out;
}

export interface MakeXlsxOptions {
  sheets: number;
  rows: number;
  cols: number;
  /** Inject a formula cell with a cached value into the first sheet's C1. */
  formulaCell?: boolean;
  seed?: number;
}

/** Build an xlsx workbook of the requested shape and return its bytes. */
export function makeXlsxBytes(opts: MakeXlsxOptions): Uint8Array {
  const rand = lcg(opts.seed ?? 0x51ab1e);
  const wb = XLSX.utils.book_new();
  for (let s = 0; s < opts.sheets; s += 1) {
    const aoa: (string | number)[][] = [];
    for (let r = 0; r < opts.rows; r += 1) {
      const row: (string | number)[] = [];
      for (let c = 0; c < opts.cols; c += 1) {
        row.push((r + c) % 3 === 0 ? Math.round(rand() * 1_000_000) : randString(rand, 12));
      }
      aoa.push(row);
    }
    const ws = XLSX.utils.aoa_to_sheet(aoa);
    if (opts.formulaCell && s === 0) {
      // A cached formula value: SheetJS writes <f>..</f><v>..</v>; our bridge
      // must surface the cached value, never a live formula.
      (ws as Record<string, unknown>)["C1"] = { t: "n", f: "A1+B1", v: 424242, w: "424242" };
    }
    XLSX.utils.book_append_sheet(wb, ws, `S${s + 1}`);
  }
  return new Uint8Array(XLSX.write(wb, { type: "array", bookType: "xlsx", compression: true }));
}

/** A small ARTL-3 manifest fixture mirroring `edit_roundtrip` test data. */
export function sampleManifest(): EditManifest {
  return {
    schema_version: 1,
    format: "xlsx",
    ops: [
      { set_cell: { sheet: "Sheet1", cell: { col: 1, row: 1 }, before: { number: 5 }, after: { number: 3.5 } } },
      { add_formula_column: { sheet: "Sheet1", column: 4, header: "Total", formula: "A{row}*B{row}" } },
      { move_range: { sheet: "Sheet1", from: { start: { col: 1, row: 1 }, end: { col: 2, row: 2 } }, to: { col: 4, row: 1 } } },
      { insert_rows: { sheet: "Sheet1", at: 2, count: 1 } },
    ],
    touched_parts: ["xl/worksheets/sheet1.xml"],
    mutation_mode: "full",
    warnings: [{ code: "session_reported", detail: "note" }],
  };
}

export const MB = 1024 * 1024;
