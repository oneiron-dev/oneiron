/**
 * Workbook packages crafted to make SheetJS 0.20.3 expand far past their size
 * while it reads them. Each stays inside every byte line of the preview
 * budget, so only the checks of what SheetJS would expand refuse them.
 */
import { DOC_REL, MAIN, REL, text, zip, type Part } from "./package-writer";

const CONTENT_TYPES = "http://schemas.openxmlformats.org/package/2006/content-types";
const WORKBOOK_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml";
const WORKSHEET_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml";

/** A worksheet part's XML: `sheetData` rows, then the elements that follow them. */
export function worksheet(sheetData: string, after = ""): string {
  return `<worksheet xmlns="${MAIN}"><sheetData>${sheetData}</sheetData>${after}</worksheet>`;
}

/** A workbook package whose sheets S1, S2, ... are the parts in `sheets`, in order and last in the package. */
export function sheetsPackage(sheets: readonly Part["body"][]): Uint8Array {
  const each = (write: (n: number) => string) => sheets.map((_, i) => write(i + 1)).join("");
  const parts: Part[] = [
    {
      name: "[Content_Types].xml",
      body: text(
        `<Types xmlns="${CONTENT_TYPES}"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="${WORKBOOK_TYPE}"/>${each((n) => `<Override PartName="/xl/worksheets/sheet${n}.xml" ContentType="${WORKSHEET_TYPE}"/>`)}</Types>`,
      ),
    },
    {
      name: "_rels/.rels",
      body: text(
        `<Relationships xmlns="${REL}"><Relationship Id="rId1" Type="${DOC_REL}/officeDocument" Target="xl/workbook.xml"/></Relationships>`,
      ),
    },
    {
      name: "xl/workbook.xml",
      body: text(
        `<workbook xmlns="${MAIN}" xmlns:r="${DOC_REL}"><sheets>${each((n) => `<sheet name="S${n}" sheetId="${n}" r:id="rId${n}"/>`)}</sheets></workbook>`,
      ),
    },
    {
      name: "xl/_rels/workbook.xml.rels",
      body: text(
        `<Relationships xmlns="${REL}">${each((n) => `<Relationship Id="rId${n}" Type="${DOC_REL}/worksheet" Target="worksheets/sheet${n}.xml"/>`)}</Relationships>`,
      ),
    },
    ...sheets.map((body, i) => ({ name: `xl/worksheets/sheet${i + 1}.xml`, body })),
  ];
  return zip(parts);
}

/** One plain cell, A1 = 1. */
export const PLAIN_SHEET = worksheet(`<row r="1"><c r="A1"><v>1</v></c></row>`);

/**
 * One cell and one 40-byte hyperlink over the whole grid: SheetJS makes a cell
 * for each of its 17.2 billion addresses.
 */
export const FULL_GRID_HYPERLINK_SHEET = worksheet(
  `<row r="1"><c r="A1"><v>1</v></c></row>`,
  `<hyperlinks><hyperlink ref="A1:XFD1048576" location="S1!A1"/></hyperlinks>`,
);

/**
 * A shared formula whose master text is `masterLength` characters, followed by
 * `followers` cells below it; every cell caches the value 1.
 */
export function fanOutSheet(masterLength: number, followers: number): string {
  // References, so each follower gets its own shifted copy, not the master's
  // string back unchanged.
  const master = "A1+".repeat(Math.floor(masterLength / 3)).padEnd(masterLength, "1");
  const rows = [
    `<row r="1"><c r="A1"><f t="shared" ref="A1:A${followers + 1}" si="0">${master}</f><v>1</v></c></row>`,
  ];
  for (let row = 2; row <= followers + 1; row += 1) {
    rows.push(`<row r="${row}"><c r="A${row}"><f t="shared" si="0"/><v>1</v></c></row>`);
  }
  return worksheet(rows.join(""));
}

/**
 * The sheet deflated as one non-final stored block whose length runs from the
 * block to the end of the package. SheetJS inflates from the entry to the end
 * of the package, copies the block, then reads past the last byte, where every
 * bit is 0: empty stored blocks, for ever.
 */
function unfinishedDeflatePackage(): Uint8Array {
  const size = text(PLAIN_SHEET).length;
  // BFINAL 0 and BTYPE 00 (stored) in the first byte, then LEN and NLEN,
  // written once the package's length is known.
  const bytes = sheetsPackage([{ stream: new Uint8Array(5), size, crc: 0 }]);
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  // The sheet is the last entry, written just before the central directory.
  const stream = view.getUint32(bytes.length - 22 + 16, true) - 5;
  const length = bytes.length - (stream + 5);
  view.setUint16(stream + 1, length, true);
  view.setUint16(stream + 3, ~length & 0xffff, true);
  return bytes;
}

export type CraftedKind = "unfinished-deflate" | "full-grid-hyperlink" | "shared-formula-fan-out";

/** The crafted package of `kind`; its sheet is S1. */
export function craftedPackage(kind: CraftedKind): Uint8Array {
  switch (kind) {
    case "unfinished-deflate":
      return unfinishedDeflatePackage();
    case "full-grid-hyperlink":
      return sheetsPackage([text(FULL_GRID_HYPERLINK_SHEET)]);
    case "shared-formula-fan-out":
      // 64 KiB of master text copied to 300,000 cells: 19.7 billion
      // characters, from about 21 MB of stored XML.
      return sheetsPackage([text(fanOutSheet(64 * 1024, 300_000))]);
  }
}
