import { describe, expect, it } from "bun:test";
import { opTag, type EditOpTag } from "../src/manifest/types";

describe("EditOp tag derivation (#7)", () => {
  it("opTag returns the variant tag for representative ops", () => {
    expect(opTag({ set_cell: { sheet: "S", cell: { col: 1, row: 1 }, after: { number: 1 } } })).toBe(
      "set_cell",
    );
    expect(opTag({ insert_rows: { sheet: "S", at: 1, count: 1 } })).toBe("insert_rows");
    expect(opTag({ rename_sheet: { from: "a", to: "b" } })).toBe("rename_sheet");
  });

  it("EditOpTag is the union of all tags, not `never` (compile-time)", () => {
    // If EditOpTag resolved to `never`, this typed array would fail typecheck.
    const tags: EditOpTag[] = [
      "set_cell",
      "set_range",
      "add_formula_column",
      "insert_rows",
      "delete_rows",
      "insert_columns",
      "delete_columns",
      "move_range",
      "add_sheet",
      "remove_sheet",
      "rename_sheet",
    ];
    expect(new Set(tags).size).toBe(11);
    const single: EditOpTag = "move_range";
    expect(single).toBe("move_range");
  });
});
