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

/** A package whose sheet S1 holds `sheetData`, each `@` in it replaced by the next of `pieces`, as bytes. */
function sheetWithBytes(sheetData: string, ...pieces: readonly (readonly number[])[]): Uint8Array {
  const parts = worksheet(sheetData).split("@");
  const bytes: number[] = [...text(parts[0]!)];
  pieces.forEach((piece, i) => bytes.push(...piece, ...text(parts[i + 1]!)));
  return sheetsPackage([Uint8Array.from(bytes)]);
}

/** A package whose S1 cell A1 is a string of the bytes `bytes`. */
function stringCellPackage(bytes: readonly number[]): Uint8Array {
  return sheetWithBytes(`<row r="1"><c r="A1" t="str"><v>@</v></c></row>`, bytes);
}

/** A package whose S1 cell A1 is an inline rich string of two runs, between them `between`. */
function richStringPackage(first: readonly number[], second: readonly number[], between = ""): Uint8Array {
  return sheetWithBytes(
    `<row r="1"><c r="A1" t="inlineStr"><is><r><t>@</t></r>${between}<r><t>@</t></r></is></c></row>`,
    first,
    second,
  );
}

/** A package of one plain sheet whose styles part holds one number format, `formatCode`. */
function numberFormatPackage(formatCode: string): Uint8Array {
  return sheetsPackage([text(worksheet(`<row r="1"><c r="A1"><v>1</v></c></row>`))], {
    contentTypes: `<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>`,
    parts: [
      {
        name: "xl/styles.xml",
        body: text(
          `<styleSheet xmlns="${MAIN}"><numFmts count="1"><numFmt numFmtId="164" formatCode="${formatCode}"/></numFmts></styleSheet>`,
        ),
      },
    ],
  });
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

  it("follows the marker across the pieces SheetJS drops before it unescapes: run tags, phonetic runs, comments", () => {
    const marker = [..."![CDATA["].map((char) => char.charCodeAt(0));
    // SheetJS joins a rich string's runs: `C0 BC` ends one run, `![CDATA[` starts the next.
    refusedAsStructure(() => readSheet(richStringPackage([0x78, 0xc0, 0xbc], [...marker, 0x79]), "S1"));
    // The overlong `<` split between the runs, and a phonetic run SheetJS drops between them.
    refusedAsStructure(() => readSheet(richStringPackage([0x78, 0xc0], [0xbc, ...marker, 0x79]), "S1"));
    refusedAsStructure(() =>
      readSheet(richStringPackage([0x78, 0xc0, 0xbc], [...marker, 0x79], `<rPh sb="0" eb="1"><t>z</t></rPh>`), "S1"),
    );
    // SheetJS drops the styles part's comments before it reads a number format.
    refusedAsStructure(() => readSheet(numberFormatPackage("x<!<!--z-->[CDATA[y"), "S1"));
    // The marker as text over two runs, unescaped once: it previews.
    const escaped = richStringPackage(Array.from(text("&lt;!")), Array.from(text("[CDATA[note")));
    expect(cell(readSheet(escaped, "S1"), 0, 0)?.v).toBe("<![CDATA[note");
    expect(cell(readSheet(numberFormatPackage("0.00<!--z-->"), "S1"), 0, 0)?.v).toBe(1);
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
