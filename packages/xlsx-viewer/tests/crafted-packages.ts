/**
 * Workbook packages crafted to make SheetJS 0.20.3 expand far past their size
 * while it reads them. Each stays inside every byte line of the preview
 * budget, so only the checks of what SheetJS would expand refuse them.
 */
import * as XLSX from "xlsx";
import { DOC_REL, MAIN, REL, text, zip, type Part } from "./package-writer";

const CONTENT_TYPES = "http://schemas.openxmlformats.org/package/2006/content-types";
const WORKBOOK_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml";
const WORKSHEET_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml";
/** The main part of an XLSB workbook, which SheetJS reads with its binary reader. */
const BINARY_WORKBOOK_TYPE = "application/vnd.ms-excel.sheet.binary.macroEnabled.main";
const MACRO_WORKBOOK_TYPE = "application/vnd.ms-excel.sheet.macroEnabled.main+xml";
const EXTERNAL_LINK_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.externalLink+xml";
const COMMENTS_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.comments+xml";

/** A worksheet part's XML: `sheetData` rows, then the elements that follow them. */
export function worksheet(sheetData: string, after = ""): string {
  return `<worksheet xmlns="${MAIN}"><sheetData>${sheetData}</sheetData>${after}</worksheet>`;
}

/** How a workbook package is laid out beyond its sheet parts ({@link sheetsPackage}). */
export interface PackageLayout {
  /** Sheets the workbook lists, each with its workbook relationship; at least the sheet parts. */
  readonly listed?: number;
  /** The workbook's content type. */
  readonly workbookType?: string;
  /** Content-type elements after the workbook's and the sheets' overrides. */
  readonly contentTypes?: string;
  /** Workbook relationships after the sheets'. */
  readonly workbookRelationships?: string;
  /** The name the workbook lists sheet `n` under. */
  readonly sheetName?: (n: number) => string;
  /** Where the workbook relationship of sheet `n` points, from `xl/`. */
  readonly sheetTarget?: (n: number) => string;
  /** Parts after the sheet parts. */
  readonly parts?: readonly Part[];
  /** One-byte parts, last in the package, that only lengthen its path list. */
  readonly fillers?: number;
}

/**
 * A workbook package whose sheets S1, S2, ... are the parts in `sheets`, in
 * order and after the workbook's own parts; `layout` adds listed sheets with
 * no part, parts and relationships of other kinds, and filler entries.
 */
export function sheetsPackage(sheets: readonly Part["body"][], layout: PackageLayout = {}): Uint8Array {
  const {
    listed = sheets.length,
    workbookType = WORKBOOK_TYPE,
    contentTypes = "",
    workbookRelationships = "",
    sheetName = (n: number) => `S${n}`,
    sheetTarget = (n: number) => `worksheets/sheet${n}.xml`,
    parts = [],
    fillers = 0,
  } = layout;
  const each = (count: number, write: (n: number) => string) =>
    Array.from({ length: count }, (_, i) => write(i + 1)).join("");
  const written: Part[] = [
    {
      name: "[Content_Types].xml",
      body: text(
        `<Types xmlns="${CONTENT_TYPES}"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="${workbookType}"/>${each(sheets.length, (n) => `<Override PartName="/xl/worksheets/sheet${n}.xml" ContentType="${WORKSHEET_TYPE}"/>`)}${contentTypes}</Types>`,
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
        `<workbook xmlns="${MAIN}" xmlns:r="${DOC_REL}"><sheets>${each(listed, (n) => `<sheet name="${sheetName(n)}" sheetId="${n}" r:id="rId${n}"/>`)}</sheets></workbook>`,
      ),
    },
    {
      name: "xl/_rels/workbook.xml.rels",
      body: text(
        `<Relationships xmlns="${REL}">${each(listed, (n) => `<Relationship Id="rId${n}" Type="${DOC_REL}/worksheet" Target="${sheetTarget(n)}"/>`)}${workbookRelationships}</Relationships>`,
      ),
    },
    ...sheets.map((body, i) => ({ name: `xl/worksheets/sheet${i + 1}.xml`, body })),
    ...parts,
    ...Array.from({ length: fillers }, (_, i) => ({ name: `xl/media/filler${i + 1}.txt`, body: Uint8Array.of(0x20) })),
  ];
  return zip(written);
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
 * One cell and one hyperlink whose single address decodes to row 2^53, where
 * SheetJS's `++R` leaves the row as it was: its loop never ends.
 */
export const HUGE_ROW_HYPERLINK_SHEET = worksheet(
  `<row r="1"><c r="A1"><v>1</v></c></row>`,
  `<hyperlinks><hyperlink ref="A9007199254740994" location="S1!A1"/></hyperlinks>`,
);

/**
 * A shared formula whose master text is `masterLength` characters, followed by
 * `followers` cells below it; every cell caches the value 1. Each follower
 * names the master with `followerTag`: the standard self-closing formula by
 * default, or a tag SheetJS's fallback formula reader also takes. The master's
 * start tag names its index with `master.index` (`si="0"` by default), and its
 * text ends with `master.tail`.
 */
export function fanOutSheet(
  masterLength: number,
  followers: number,
  followerTag = `<f t="shared" si="0"/>`,
  master: { readonly index?: string; readonly tail?: string } = {},
): string {
  const { index = `si="0"`, tail = "" } = master;
  // References, so each follower gets its own shifted copy, not the master's
  // string back unchanged.
  const references = masterLength - tail.length;
  const masterText = "A1+".repeat(Math.floor(references / 3)).padEnd(references, "1") + tail;
  const rows = [
    `<row r="1"><c r="A1"><f t="shared" ref="A1:A${followers + 1}" ${index}>${masterText}</f><v>1</v></c></row>`,
  ];
  for (let row = 2; row <= followers + 1; row += 1) {
    rows.push(`<row r="${row}"><c r="A${row}">${followerTag}<v>1</v></c></row>`);
  }
  return worksheet(rows.join(""));
}

/**
 * A two-character shared master at A1 and one follower beside it whose
 * address is 220 Zs and a row: its column decodes to Infinity, and SheetJS's
 * `encode_col` never finishes the shifted copy's column.
 */
export const FAR_COLUMN_FOLLOWER_SHEET = worksheet(
  `<row r="1"><c r="A1"><f t="shared" ref="A1:B1" si="0">A1</f><v>1</v></c>` +
    `<c r="${"Z".repeat(220)}1"><f t="shared" si="0"/><v>1</v></c></row>`,
);

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

/** One BIFF12 record of a type and data under 128 bytes, as SheetJS's `recordhopper` reads it. */
function biffRecord(type: number, data: readonly number[]): number[] {
  const typeBytes = type < 0x80 ? [type] : [(type & 0x7f) | 0x80, type >> 7];
  return [...typeBytes, data.length, ...data];
}

/**
 * An XLSB workbook part of 19 bytes listing one sheet (`BrtBundleSh`) whose
 * name is a wide string of 0xFFFFFFFF characters: off Node, SheetJS's binary
 * reader reads one character per count, far past the end of the part.
 */
function binaryWorkbookPart(): Uint8Array {
  // hsState, iTabID, a null strRelID, then the name's character count.
  return Uint8Array.from(
    biffRecord(0x9c, [0, 0, 0, 0, 1, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
  );
}

/** A real XLSB sheet part, from SheetJS's own writer: A1 = 1. */
function binarySheetPart(): Uint8Array {
  const wb = XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(wb, XLSX.utils.aoa_to_sheet([[1]]), "S1");
  const written = XLSX.write(wb, { type: "array", bookType: "xlsb" }) as ArrayBuffer;
  const container = XLSX.CFB.read(new Uint8Array(written), { type: "buffer" }) as {
    FullPaths: string[];
    FileIndex: { content: ArrayLike<number> }[];
  };
  const index = container.FullPaths.indexOf("Root Entry/xl/worksheets/sheet1.bin");
  return Uint8Array.from(container.FileIndex[index]!.content);
}

/** An XLSB workbook: its content types name a binary main part, which lists one sheet. */
function binaryWorkbookPackage(): Uint8Array {
  return zip([
    {
      name: "[Content_Types].xml",
      body: text(
        `<Types xmlns="${CONTENT_TYPES}"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Override PartName="/xl/workbook.bin" ContentType="${BINARY_WORKBOOK_TYPE}"/></Types>`,
      ),
    },
    {
      name: "_rels/.rels",
      body: text(
        `<Relationships xmlns="${REL}"><Relationship Id="rId1" Type="${DOC_REL}/officeDocument" Target="xl/workbook.bin"/></Relationships>`,
      ),
    },
    { name: "xl/workbook.bin", body: binaryWorkbookPart() },
    {
      name: "xl/_rels/workbook.bin.rels",
      body: text(
        `<Relationships xmlns="${REL}"><Relationship Id="rId1" Type="${DOC_REL}/worksheet" Target="worksheets/sheet1.bin"/></Relationships>`,
      ),
    },
    { name: "xl/worksheets/sheet1.bin", body: binarySheetPart() },
  ]);
}

/** One `<Override>` per external link part SheetJS would look up, `count` of them (about 150 bytes each). */
function externalLinkOverrides(count: number): string {
  return Array.from(
    { length: count },
    (_, i) => `<Override PartName="/xl/externalLinks/externalLink${i + 1}.xml" ContentType="${EXTERNAL_LINK_TYPE}"/>`,
  ).join("");
}

/** Filler entries that make SheetJS compare about 9,000 paths at each part lookup. */
const LOOKUP_FILLERS = 9_000;

export type CraftedKind =
  | "unfinished-deflate"
  | "full-grid-hyperlink"
  | "shared-formula-fan-out"
  | "huge-row-hyperlink"
  | "fallback-formula-fan-out"
  | "hidden-index-fan-out"
  | "far-column-follower"
  | "binary-workbook"
  | "binary-sheet"
  | "many-listed-sheets"
  | "listed-sheet-lookups"
  | "external-link-lookups"
  | "repeated-sheet-name";

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
    case "huge-row-hyperlink":
      return sheetsPackage([text(HUGE_ROW_HYPERLINK_SHEET)]);
    case "fallback-formula-fan-out":
      // The same fan-out, each follower an unknown `<foo si="0"/>`.
      return sheetsPackage([text(fanOutSheet(64 * 1024, 300_000, `<foo si="0"/>`))]);
    case "hidden-index-fan-out":
      // The same fan-out, the master's start tag naming index 1 and its text
      // ending in ` si='0' `: SheetJS reads the master's attributes over its
      // whole element, and the last `si` there files it under 0.
      return sheetsPackage([
        text(fanOutSheet(64 * 1024, 300_000, undefined, { index: `si="1"`, tail: `N(" si='0' ")` })),
      ]);
    case "far-column-follower":
      return sheetsPackage([text(FAR_COLUMN_FOLLOWER_SHEET)]);
    case "binary-workbook":
      return binaryWorkbookPackage();
    case "binary-sheet":
      // An xlsx whose workbook relationship points S1 at a binary part.
      return sheetsPackage([], {
        listed: 1,
        sheetTarget: () => "worksheets/sheet1.bin",
        parts: [{ name: "xl/worksheets/sheet1.bin", body: binarySheetPart() }],
      });
    case "many-listed-sheets":
      // 200,000 listed sheets over about 9,000 paths: SheetJS makes two
      // lookups per listed sheet before it applies its `sheets` option, 3.6
      // billion path comparisons.
      return sheetsPackage([text(PLAIN_SHEET)], { listed: 200_000, fillers: LOOKUP_FILLERS });
    case "listed-sheet-lookups":
      // 9,999 listed sheets, inside the sheet line, over about 9,000 paths:
      // 180 million path comparisons.
      return sheetsPackage([text(PLAIN_SHEET)], { listed: 9_999, fillers: LOOKUP_FILLERS });
    case "external-link-lookups":
      // 400,000 external links in 59 MiB of content types, over about 9,000
      // paths: SheetJS looks each one up before the outline doors return.
      return sheetsPackage([text(PLAIN_SHEET)], {
        contentTypes: externalLinkOverrides(400_000),
        fillers: LOOKUP_FILLERS,
      });
    case "repeated-sheet-name": {
      // 5,000 listed sheets, all named S1 and all pointing at one sheet part
      // of 100,000 cells: SheetJS reads S1 by name, without case, and so
      // parses the part 5,000 times.
      const rows = Array.from({ length: 100_000 }, (_, i) => `<row r="${i + 1}"><c r="A${i + 1}"><v>1</v></c></row>`);
      return sheetsPackage([text(worksheet(rows.join("")))], {
        listed: 5_000,
        sheetName: () => "S1",
        sheetTarget: () => "worksheets/sheet1.xml",
      });
    }
  }
}

/**
 * One comments part that sheet S1 names twice, through two relationships
 * whose targets differ only in case: SheetJS finds parts without case, and so
 * reads the part once per relationship.
 */
export function twiceNamedCommentsPackage(): Uint8Array {
  const comments = (target: string, n: number) =>
    `<Relationship Id="rId${n}" Type="${DOC_REL}/comments" Target="${target}"/>`;
  return sheetsPackage([text(PLAIN_SHEET)], {
    contentTypes: `<Override PartName="/xl/comments1.xml" ContentType="${COMMENTS_TYPE}"/>`,
    parts: [
      {
        name: "xl/worksheets/_rels/sheet1.xml.rels",
        body: text(
          `<Relationships xmlns="${REL}">${comments("../comments1.xml", 1)}${comments("../COMMENTS1.xml", 2)}</Relationships>`,
        ),
      },
      {
        name: "xl/comments1.xml",
        body: text(
          `<comments xmlns="${MAIN}"><authors><author>owen</author></authors><commentList><comment ref="A1" authorId="0"><text><r><t>once</t></r></text></comment></commentList></comments>`,
        ),
      },
    ],
  });
}

/**
 * An xlsm as Excel writes one: a VBA project, printer settings and an
 * embedded OLE object, each a `.bin` part SheetJS never takes with the
 * options the bridge sets.
 */
export function macroWorkbookPackage(): Uint8Array {
  const sheet = worksheet(
    `<row r="1"><c r="A1"><v>7</v></c></row>`,
    `<pageSetup orientation="portrait" r:id="rId1"/><oleObjects><oleObject progId="Package" shapeId="1025" r:id="rId2"/></oleObjects>`,
  ).replace("<worksheet ", `<worksheet xmlns:r="${DOC_REL}" `);
  const binary = (length: number) => Uint8Array.from({ length }, (_, i) => (i * 37 + 11) & 0xff);
  return sheetsPackage([text(sheet)], {
    workbookType: MACRO_WORKBOOK_TYPE,
    contentTypes:
      `<Default Extension="bin" ContentType="application/vnd.ms-office.vbaProject"/>` +
      `<Override PartName="/xl/printerSettings/printerSettings1.bin" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.printerSettings"/>` +
      `<Override PartName="/xl/embeddings/oleObject1.bin" ContentType="application/vnd.openxmlformats-officedocument.oleObject"/>`,
    workbookRelationships: `<Relationship Id="rIdVba" Type="http://schemas.microsoft.com/office/2006/relationships/vbaProject" Target="vbaProject.bin"/>`,
    parts: [
      {
        name: "xl/worksheets/_rels/sheet1.xml.rels",
        body: text(
          `<Relationships xmlns="${REL}"><Relationship Id="rId1" Type="${DOC_REL}/printerSettings" Target="../printerSettings/printerSettings1.bin"/><Relationship Id="rId2" Type="${DOC_REL}/oleObject" Target="../embeddings/oleObject1.bin"/></Relationships>`,
        ),
      },
      { name: "xl/vbaProject.bin", body: binary(4096) },
      { name: "xl/printerSettings/printerSettings1.bin", body: binary(1024) },
      { name: "xl/embeddings/oleObject1.bin", body: binary(2048) },
    ],
  });
}

/**
 * A workbook of real shape: 300 sheets, 3 external links, a comment on the
 * last sheet, and 1,500 entries in all.
 */
export function realShapedPackage(): Uint8Array {
  const sheets = Array.from({ length: 300 }, (_, i) =>
    text(worksheet(`<row r="1"><c r="A1"><v>${i + 1}</v></c><c r="B1"><v>2</v></c></row><row r="2"><c r="A2"><v>3</v></c></row>`)),
  );
  const links = [1, 2, 3].flatMap((n) => [
    {
      name: `xl/externalLinks/externalLink${n}.xml`,
      body: text(
        `<externalLink xmlns="${MAIN}"><externalBook xmlns:r="${DOC_REL}" r:id="rId1"><sheetNames><sheetName val="Other"/></sheetNames></externalBook></externalLink>`,
      ),
    },
    {
      name: `xl/externalLinks/_rels/externalLink${n}.xml.rels`,
      body: text(
        `<Relationships xmlns="${REL}"><Relationship Id="rId1" Type="${DOC_REL}/externalLinkPath" Target="other${n}.xlsx" TargetMode="External"/></Relationships>`,
      ),
    },
  ]);
  const parts: Part[] = [
    ...links,
    {
      name: "xl/worksheets/_rels/sheet300.xml.rels",
      body: text(
        `<Relationships xmlns="${REL}"><Relationship Id="rId1" Type="${DOC_REL}/comments" Target="../comments1.xml"/></Relationships>`,
      ),
    },
    {
      name: "xl/comments1.xml",
      body: text(
        `<comments xmlns="${MAIN}"><authors><author>owen</author></authors><commentList><comment ref="A1" authorId="0"><text><r><t>checked</t></r></text></comment></commentList></comments>`,
      ),
    },
  ];
  return sheetsPackage(sheets, {
    contentTypes:
      externalLinkOverrides(3) + `<Override PartName="/xl/comments1.xml" ContentType="${COMMENTS_TYPE}"/>`,
    workbookRelationships: [1, 2, 3]
      .map((n) => `<Relationship Id="rIdLink${n}" Type="${DOC_REL}/externalLink" Target="externalLinks/externalLink${n}.xml"/>`)
      .join(""),
    parts,
    // 4 workbook parts, 300 sheets and 8 more parts: 1,500 entries in all.
    fillers: 1_500 - 4 - 300 - parts.length,
  });
}
