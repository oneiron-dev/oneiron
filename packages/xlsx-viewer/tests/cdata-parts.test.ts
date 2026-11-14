import { describe, expect, it } from "bun:test";
import type { ICellData, IWorksheetData } from "@univerjs/core";
import { WorkbookBudgetError } from "../src/bridge/budget";
import { readSheet, readWorkbookOutline } from "../src/bridge/parse";
import { readInChild, TEST_LIMIT_MS } from "./child-read";
import { commentsPackage, sheetsPackage, worksheet } from "./crafted-packages";
import { MAIN, text } from "./package-writer";

function cell(sheet: Partial<IWorksheetData>, row: number, column: number): ICellData | undefined {
  return (sheet.cellData as Record<number, Record<number, ICellData>> | undefined)?.[row]?.[column];
}

function refusedAsStructure(run: () => unknown): void {
  let caught: unknown;
  try {
    run();
  } catch (err) {
    caught = err;
  }
  expect(caught).toBeInstanceOf(WorkbookBudgetError);
  expect((caught as WorkbookBudgetError).line).toBe("structure");
}

/** A package whose S1 cell A1 is a string of the bytes `bytes`. */
function stringCellPackage(bytes: readonly number[]): Uint8Array {
  const [head, tail] = worksheet(`<row r="1"><c r="A1" t="str"><v>@</v></c></row>`).split("@");
  return sheetsPackage([Uint8Array.from([...text(head!), ...bytes, ...text(tail!)])]);
}

describe("xlsx preview: a part holding a CDATA marker is refused before SheetJS unescapes it", () => {
  it(
    "refuses a cell string whose CDATA marker SheetJS's unescape would copy quadratically",
    () => {
      // 8,000 characters, the marker, 120,000 more: about 1.5 GiB before.
      const read = readInChild("cdata-cell-value");
      expect(read.answer).toEqual({ refused: "structure" });
      expect(read.peakMiB).toBeLessThan(512);
      // The marker escaped in a formula's string result, which SheetJS
      // unescapes twice.
      const escaped = readInChild("escaped-cdata-string-result");
      expect(escaped.answer).toEqual({ refused: "structure" });
      expect(escaped.peakMiB).toBeLessThan(512);
    },
    2 * TEST_LIMIT_MS,
  );

  it("refuses a marker that SheetJS's browser UTF-8 decode reads from an invalid form", () => {
    const marker = [..."![CDATA["].map((char) => char.charCodeAt(0));
    // C0 BC: an overlong `<`.
    refusedAsStructure(() => readSheet(stringCellPackage([0x78, 0xc0, 0xbc, ...marker, 0x79]), "S1"));
    // 80 80 BC: a continuation byte read as the lead of a three-byte form, `<`.
    refusedAsStructure(() => readSheet(stringCellPackage([0x78, 0x80, 0x80, 0xbc, ...marker, 0x79]), "S1"));
    // The same bytes without the `<` read as a plain string.
    expect(cell(readSheet(stringCellPackage([0x78, ...marker, 0x79]), "S1"), 0, 0)?.v).toBe("x![CDATA[y");
  });

  it("refuses the marker in any part the read takes; real text with other scripts still previews", () => {
    // A comments part with a closed CDATA section: the sheet read takes it, the outline does not.
    const comments = commentsPackage(
      `<comments xmlns="${MAIN}"><authors><author>owen</author></authors><commentList><comment ref="A1" authorId="0"><text><t><![CDATA[note]]></t></text></comment></commentList></comments>`,
    );
    expect(readWorkbookOutline(comments).sheetOrder).toHaveLength(1);
    refusedAsStructure(() => readSheet(comments, "S1"));
    // The marker as text in an inline string, unescaped once: it previews.
    const inline = sheetsPackage([
      text(worksheet(`<row r="1"><c r="A1" t="inlineStr"><is><t>&lt;![CDATA[note</t></is></c></row>`)),
    ]);
    expect(cell(readSheet(inline, "S1"), 0, 0)?.v).toBe("<![CDATA[note");
    // A numeric entity past 255 whose low byte is `<`: Node and Bun read it as `<`.
    refusedAsStructure(() =>
      readSheet(sheetsPackage([text(worksheet(`<row r="1"><c r="A1" t="str"><v>x&#x13C;![CDATA[y</v></c></row>`))]), "S1"),
    );
    // UTF-8 text in other scripts, valid in every byte: no marker read.
    const words = "日本語のテキスト、Ελληνικά, עברית, 😀 ".repeat(2_000);
    const sheet = readSheet(sheetsPackage([text(worksheet(`<row r="1"><c r="A1" t="str"><v>${words}</v></c></row>`))]), "S1");
    expect(cell(sheet, 0, 0)?.v).toBe(words);
  });
});
