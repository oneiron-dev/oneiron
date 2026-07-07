import { describe, expect, it } from "bun:test";
import {
  cellToA1,
  cellToRange,
  columnLabelToIndex,
  indexToColumnLabel,
  parseA1Cell,
  parseA1Range,
  rangeToA1,
  toUniverCell,
  toUniverRange,
} from "../src/a1";

describe("column labels", () => {
  it("round-trips A..AA..ZZ", () => {
    expect(columnLabelToIndex("A")).toBe(1);
    expect(columnLabelToIndex("Z")).toBe(26);
    expect(columnLabelToIndex("AA")).toBe(27);
    expect(columnLabelToIndex("AZ")).toBe(52);
    expect(indexToColumnLabel(1)).toBe("A");
    expect(indexToColumnLabel(26)).toBe("Z");
    expect(indexToColumnLabel(27)).toBe("AA");
    for (const i of [1, 5, 26, 27, 52, 100, 703]) {
      expect(columnLabelToIndex(indexToColumnLabel(i))).toBe(i);
    }
  });
  it("rejects bad input", () => {
    expect(() => columnLabelToIndex("")).toThrow();
    expect(() => columnLabelToIndex("a")).toThrow();
    expect(() => indexToColumnLabel(0)).toThrow();
  });
});

describe("A1 cells and ranges", () => {
  it("parses cells (1-based)", () => {
    expect(parseA1Cell("B2")).toEqual({ col: 2, row: 2 });
    expect(parseA1Cell("AA10")).toEqual({ col: 27, row: 10 });
    expect(cellToA1({ col: 2, row: 2 })).toBe("B2");
  });
  it("parses ranges and normalises corners", () => {
    expect(parseA1Range("B2:D5")).toEqual({ colStart: 2, colEnd: 4, rowStart: 2, rowEnd: 5 });
    expect(parseA1Range("B2")).toEqual({ colStart: 2, colEnd: 2, rowStart: 2, rowEnd: 2 });
    expect(parseA1Range("D5:B2")).toEqual({ colStart: 2, colEnd: 4, rowStart: 2, rowEnd: 5 });
    expect(rangeToA1({ colStart: 2, colEnd: 4, rowStart: 2, rowEnd: 5 })).toBe("B2:D5");
    expect(rangeToA1({ colStart: 2, colEnd: 2, rowStart: 2, rowEnd: 2 })).toBe("B2");
  });
  it("converts to 0-based Univer coordinates", () => {
    expect(toUniverCell({ col: 2, row: 2 })).toEqual({ row: 1, column: 1 });
    expect(toUniverRange({ colStart: 2, colEnd: 4, rowStart: 2, rowEnd: 5 })).toEqual({
      startRow: 1,
      endRow: 4,
      startColumn: 1,
      endColumn: 3,
    });
    expect(toUniverRange(cellToRange({ col: 1, row: 1 }))).toEqual({
      startRow: 0,
      endRow: 0,
      startColumn: 0,
      endColumn: 0,
    });
  });
});
