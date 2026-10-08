import { describe, expect, it } from "bun:test";
import type { EditOpTag } from "../src/manifest/types";

describe("EditOp tag derivation (#7)", () => {
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
