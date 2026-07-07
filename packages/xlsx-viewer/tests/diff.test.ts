import { describe, expect, it } from "bun:test";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { diffManifest, formatCellValue } from "../src/manifest/diff";
import { sampleManifest } from "./helpers";

const MANIFEST_DIR = new URL("../src/manifest/", import.meta.url).pathname;

describe("acceptance 3: diff view renders manifest ops only", () => {
  it("renders one diff line per op from the manifest", () => {
    const diff = diffManifest(sampleManifest());
    expect(diff.lines).toEqual([
      "set Sheet1!A1: 5 -> 3.5",
      'add formula column Sheet1!D "Total": A{row}*B{row}',
      "move Sheet1!A1:B2 -> D1",
      "insert 1 row(s) at Sheet1!row 2",
    ]);
  });

  it("emits grid highlights in 0-based Univer coordinates", () => {
    const diff = diffManifest(sampleManifest());
    // set_cell A1 -> single-cell highlight at (0,0)
    expect(diff.cells).toContainEqual({
      sheet: "Sheet1",
      kind: "set",
      range: { startRow: 0, endRow: 0, startColumn: 0, endColumn: 0 },
      opIndex: 0,
    });
    // add_formula_column D -> column band at 0-based column 3
    expect(diff.bands).toContainEqual({
      sheet: "Sheet1",
      axis: "column",
      start: 3,
      count: 1,
      kind: "add-column",
      opIndex: 1,
    });
    // insert_rows at row 2 -> row band at 0-based row 1
    expect(diff.bands).toContainEqual({
      sheet: "Sheet1",
      axis: "row",
      start: 1,
      count: 1,
      kind: "insert",
      opIndex: 3,
    });
    // move_range -> from + to cell highlights
    const moves = diff.cells.filter((c) => c.kind === "move-from" || c.kind === "move-to");
    expect(moves).toHaveLength(2);
  });

  it("classifies sheet-level ops without touching cells", () => {
    const diff = diffManifest({
      schema_version: 1,
      format: "xlsx",
      ops: [
        { add_sheet: { name: "New" } },
        { remove_sheet: { name: "Old" } },
        { rename_sheet: { from: "A", to: "B" } },
      ],
      touched_parts: [],
      mutation_mode: "full",
      warnings: [],
    });
    expect(diff.sheetChanges).toEqual([
      { sheet: "New", kind: "add", opIndex: 0 },
      { sheet: "Old", kind: "remove", opIndex: 1 },
      { sheet: "A", kind: "rename", renamedTo: "B", opIndex: 2 },
    ]);
    expect(diff.cells).toHaveLength(0);
    expect(diff.bands).toHaveLength(0);
  });

  it("formats every CellValue variant", () => {
    expect(formatCellValue("blank")).toBe("(blank)");
    expect(formatCellValue({ number: 3.5 })).toBe("3.5");
    expect(formatCellValue({ text: "hi" })).toBe("hi");
    expect(formatCellValue({ bool: true })).toBe("true");
    expect(formatCellValue({ formula: { expr: "SUM(A1:A2)" } })).toBe("=SUM(A1:A2)");
    expect(formatCellValue({ error: "DIV/0" })).toBe("#DIV/0");
    expect(formatCellValue(null)).toBe("(none)");
  });

  it("the diff module contains NO binary re-parse path (D7)", () => {
    // The manifest IS the diff. No source in the manifest dir may import a
    // spreadsheet parser or read bytes. (The literal "xlsx" is allowed only as
    // an OfficeFormat discriminant / in docs — what is forbidden is a parser.)
    for (const file of readdirSync(MANIFEST_DIR).filter((f) => f.endsWith(".ts"))) {
      const src = readFileSync(join(MANIFEST_DIR, file), "utf8");
      expect(src).not.toMatch(/from\s+["']xlsx["']/); // no SheetJS import (its npm name is "xlsx")
      expect(src).not.toMatch(/require\(\s*["']xlsx["']\s*\)/);
      expect(src).not.toMatch(/\bXLSX\./); // no SheetJS API use
      expect(src).not.toMatch(/readFileSync|readFile\(|\.arrayBuffer\(|Buffer\.from/); // no byte reads
    }
  });
});
