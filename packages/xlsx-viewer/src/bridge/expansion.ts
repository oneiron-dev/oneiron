/**
 * What SheetJS 0.20.3 expands while it parses a sheet part, counted from the
 * part's bytes before it parses them.
 *
 * Three of its readers make work that grows far past the part's size, inside
 * every byte budget:
 * - each `<hyperlink ref>` becomes a cell object for every address of its
 *   range (`parse_ws_xml_hlinks`), so one 40-byte `ref="A1:XFD1048576"` asks
 *   17 billion;
 * - each cell that follows a shared formula (`<f t="shared" si="0"/>`) gets
 *   its own shifted copy of the master's text, so a long master and a million
 *   followers ask billions of characters, and a copy far from its master is
 *   longer than the master: each reference can grow to a 12-letter column and
 *   a 17-character row;
 * - with formula text kept, every cell is checked against every array range
 *   filed before it, so cells after many array formulas ask billions of steps.
 * The sheet's cell and text lines are checked again on the parsed sheet
 * (`worksheetToCellData`), but only after SheetJS has made all of that. So the
 * hyperlink cells are counted against `sheetCells`, the followers' copied
 * text against `sheetTextChars`, here first, and the array-range steps are
 * returned for the read to charge against `loopSteps`.
 *
 * The counts are upper bounds of what SheetJS reads, never less: the part is
 * read the ways SheetJS decodes it (each byte as the one character of its
 * value, and UTF-16 after a byte-order mark), each attribute's name and value
 * cut as SheetJS's `parsexmltag` cuts them, a hyperlink tag also after
 * SheetJS's lenient UTF-8 decode, each hyperlink counted on its own even where
 * ranges overlap, an address SheetJS's loop cannot step past counted as no
 * end, every formula naming a shared index counted as a follower, and so is
 * the first self-closing tag of a cell that SheetJS's fallback formula reader
 * takes (`<f[^<>]*\/>`, which also matches `<foo si="0"/>`). A master's
 * indexes are read from its whole element, its text and end tag included, as
 * SheetJS reads its attributes, and its text as SheetJS keeps it (decoded,
 * unescaped, without `_xlfn.`). A follower is charged for the longest copy
 * the masters filed so far under its index can make at its cell, from where
 * their references lie relative to their cells.
 *
 * A cell that holds a formula naming a shared index is refused unless its
 * address decodes to a column and a row that are safe integers: SheetJS shifts
 * a follower's copy by the distance between the two cells, and a column that
 * decodes to Infinity never finishes encoding (`encode_col`).
 */
import { WorkbookBudgetError } from "./budget";
import type { PreviewBudget } from "./budget";

/** SheetJS's hyperlink tag pattern (`hlinkregex`). */
const HYPERLINK_TAG = /<(?:\w+:)?hyperlink [^<>]*>/g;
/** SheetJS's attribute pattern (`attregexg`). */
const ATTRIBUTE = /\s([^"\s?>/]+)\s*=\s*((?:")([^"]*)(?:")|(?:')([^']*)(?:')|([^'">\s]+))/g;
/**
 * A formula element's start tag (self-closing or not) or its end tag, or a
 * self-closing tag whose name only starts with `f`, which SheetJS's fallback
 * formula reader (`/<f[^<>]*\/>/`, first match of a cell) takes as a formula
 * too; else where SheetJS cuts the sheet data into a new cell or row
 * (`cellregex`, `rowregex`): it looks for a formula's end inside its own cell
 * only, and reads the cell's address from the start of its cell.
 */
const FORMULA_SCAN = /(<(?:\w+:)?f\b[^<>]*>)|(<\/(?:\w+:)?f>)|(<f[^<>]*\/>)|<(?:\w+:)?c[ />]|<\/(?:\w+:)?row>/g;

/**
 * The key SheetJS files an attribute under, lower case (`parsexmltag`): a
 * prefix up to the first colon is dropped, and an unprefixed name ends at its
 * first underscore after the first character.
 */
function attributeKey(name: string): string {
  const colon = name.indexOf(":");
  if (colon === -1) {
    const underscore = name.indexOf("_");
    return (underscore > 0 ? name.slice(0, underscore) : name).toLowerCase();
  }
  const prefix = colon === 5 && name.slice(0, 5) === "xmlns" ? "xmlns" : "";
  return (prefix + name.slice(colon + 1)).toLowerCase();
}

/**
 * Every value a tag gives an attribute that SheetJS files under `key`, each
 * name and value cut from the match as `parsexmltag` cuts them: the name ends
 * at the match's first `=`, spaces after it are skipped, and one character is
 * taken off each end of the value only when a quote opens it. So `si=a=b`
 * names `si`, with the value `a=b`.
 */
export function attributeValues(tag: string, key: string): string[] {
  const values: string[] = [];
  for (const [match] of tag.matchAll(ATTRIBUTE)) {
    const pair = match.slice(1);
    let equals = pair.indexOf("=");
    const name = pair.slice(0, equals).trim();
    while (pair.charCodeAt(equals + 1) === 32) {
      equals += 1;
    }
    const opener = pair.charCodeAt(equals + 1);
    const quote = opener === 34 || opener === 39 ? 1 : 0;
    if (attributeKey(name) === key) {
      values.push(pair.slice(equals + 1 + quote, pair.length - quote));
    }
  }
  return values;
}

/**
 * Whether SheetJS's `decode_cell` reads `address` as a column and a row that
 * are safe integers: every digit anywhere in it builds the row, every capital
 * letter the column, and nothing else counts.
 */
function safeCellAddress(address: string): boolean {
  let row = 0;
  let column = 0;
  for (let i = 0; i < address.length; i += 1) {
    const code = address.charCodeAt(i);
    if (code >= 48 && code <= 57) {
      row = 10 * row + (code - 48);
    } else if (code >= 65 && code <= 90) {
      column = 26 * column + (code - 64);
    }
    if (row > Number.MAX_SAFE_INTEGER || column > Number.MAX_SAFE_INTEGER) {
      return false;
    }
  }
  return true;
}

/** SheetJS's lenient UTF-8 decode in a browser (`utf8reada`), overlong forms included. */
function lenientUtf8(text: string): string {
  let out = "";
  let i = 0;
  while (i < text.length) {
    const c = text.charCodeAt(i++);
    if (c < 128) {
      out += String.fromCharCode(c);
      continue;
    }
    const d = text.charCodeAt(i++);
    if (c > 191 && c < 224) {
      out += String.fromCharCode(((c & 31) << 6) | (d & 63));
      continue;
    }
    const e = text.charCodeAt(i++);
    if (c < 240) {
      out += String.fromCharCode(((c & 15) << 12) | ((d & 63) << 6) | (e & 63));
      continue;
    }
    const f = text.charCodeAt(i++);
    const w = (((c & 7) << 18) | ((d & 63) << 12) | ((e & 63) << 6) | (f & 63)) - 65536;
    out += String.fromCharCode(0xd800 + ((w >>> 10) & 1023), 0xdc00 + (w & 1023));
  }
  return out;
}

/**
 * How many addresses SheetJS visits for one range text: its loop runs over
 * every row of the range, and over every column of each row
 * (`safe_decode_range` has no clamp to Excel's grid, so a long row number
 * counts in full, and a row loop with no columns still runs). An address that
 * decodes past the safe integers counts as no end: there `++R` or `++C` leaves
 * the double as it was, so SheetJS's loop never ends, even over one address
 * (`A9007199254740994` decodes to row 2^53).
 */
function rangeVisits(range: string): number {
  let i = 0;
  let code = 0;
  const part = (letters: boolean): number => {
    let index = 0;
    for (; i < range.length; i += 1) {
      code = range.charCodeAt(i) - (letters ? 64 : 48);
      if (letters ? code < 1 || code > 26 : code < 0 || code > 9) {
        break;
      }
      index = (letters ? 26 : 10) * index + code;
    }
    return index - 1;
  };
  const startColumn = part(true);
  const startRow = part(false);
  if (!Number.isSafeInteger(startColumn) || !Number.isSafeInteger(startRow)) {
    return Number.POSITIVE_INFINITY;
  }
  if (i === range.length || code !== 10) {
    return 1;
  }
  i += 1;
  const endColumn = part(true);
  const endRow = part(false);
  if (!Number.isSafeInteger(endColumn) || !Number.isSafeInteger(endRow)) {
    return Number.POSITIVE_INFINITY;
  }
  const rows = endRow >= startRow ? endRow - startRow + 1 : 0;
  if (rows === 0) {
    return 0;
  }
  const columns = endColumn >= startColumn ? endColumn - startColumn + 1 : 0;
  return rows * Math.max(columns, 1);
}

/**
 * The bytes as one character each, of the byte's own value: what SheetJS's
 * `cc2str` makes of a part with no byte-order mark. Its browser path decodes
 * windows-1252 and then maps the characters of 80-9F back to their bytes, so
 * a windows-1252 decode alone would read `E0 80 BA` as other than `:` after
 * the lenient UTF-8 decode.
 */
function byteText(bytes: Uint8Array): string {
  let out = "";
  for (let at = 0; at < bytes.length; at += 8192) {
    out += String.fromCharCode(...bytes.subarray(at, at + 8192));
  }
  return out;
}

/** The part as the strings SheetJS may parse it as (`cc2str`). */
export function partTexts(bytes: Uint8Array): string[] {
  const texts = [byteText(bytes)];
  if (bytes[0] === 0xff && bytes[1] === 0xfe) {
    texts.push(new TextDecoder("utf-16le").decode(bytes.subarray(2)));
  }
  if ((bytes[0] === 0xfe && bytes[1] === 0xff) || (bytes[1] === 0xfe && bytes[2] === 0xff)) {
    texts.push(new TextDecoder("utf-16be").decode(bytes.subarray(2)));
  }
  return texts;
}

function checkHyperlinks(text: string, budget: PreviewBudget): void {
  let cells = 0;
  for (const [tag] of text.matchAll(HYPERLINK_TAG)) {
    let most = 0;
    for (const form of [tag, lenientUtf8(tag)]) {
      for (const ref of attributeValues(form, "ref")) {
        most = Math.max(most, rangeVisits(ref));
      }
    }
    cells += most;
    if (cells > budget.sheetCells) {
      throw new WorkbookBudgetError("sheetCells", "a sheet's hyperlinks name more cells than the budget");
    }
  }
}

/** SheetJS's cell reference pattern for shifting a shared formula's copy (`crefregex`, the guarded form). */
const CELL_REFERENCE =
  /(^|[^._A-Z0-9])([$]?)([A-Z]{1,2}|[A-W][A-Z]{2}|X[A-E][A-Z]|XF[A-D])([$]?)(10[0-3]\d{4}|104[0-7]\d{3}|1048[0-4]\d{2}|10485[0-6]\d|104857[0-6]|[1-9]\d{0,5})(?![_.(A-Za-z0-9])/g;

/**
 * The most letters a shifted column part takes: a column SheetJS shifts to
 * lies below 26^12 (a reference's column plus the difference of two cell
 * columns, each below 2^53).
 */
const COLUMN_PART_CEILING = 12;
/** The most characters `String` gives a number, which a shifted row part is (`-1.7976931348623157e+308`). */
const ROW_PART_CEILING = 24;

/**
 * The attributes SheetJS's `parsexmltag` files from a tag, by key: each name
 * and value cut as {@link attributeValues} cuts them, a later attribute
 * replacing an earlier one under the same key, except that a prefixed name
 * whose prefix ends in `ext` never replaces a value already filed.
 */
export function sheetJsAttributes(tag: string): Map<string, string> {
  const filed = new Map<string, string>();
  if (!/[ \n\r]/.test(tag)) {
    return filed;
  }
  for (const [match] of tag.matchAll(ATTRIBUTE)) {
    const pair = match.slice(1);
    let equals = pair.indexOf("=");
    let name = pair.slice(0, equals).trim();
    while (pair.charCodeAt(equals + 1) === 32) {
      equals += 1;
    }
    const opener = pair.charCodeAt(equals + 1);
    const quote = opener === 34 || opener === 39 ? 1 : 0;
    const value = pair.slice(equals + 1 + quote, pair.length - quote);
    const colon = name.indexOf(":");
    if (colon === -1) {
      const underscore = name.indexOf("_");
      if (underscore > 0) {
        name = name.slice(0, underscore);
      }
      filed.set(name, value);
      filed.set(name.toLowerCase(), value);
      continue;
    }
    const key = (colon === 5 && name.slice(0, 5) === "xmlns" ? "xmlns" : "") + name.slice(colon + 1);
    if (filed.get(key) && name.slice(colon - 3, colon) === "ext") {
      continue;
    }
    filed.set(key, value);
    filed.set(key.toLowerCase(), value);
  }
  return filed;
}

/** SheetJS's `decode_cell`: every digit anywhere builds the row, every capital letter the column. */
function decodeCell(address: string): { readonly column: number; readonly row: number } {
  let row = 0;
  let column = 0;
  for (let i = 0; i < address.length; i += 1) {
    const code = address.charCodeAt(i);
    if (code >= 48 && code <= 57) {
      row = 10 * row + (code - 48);
    } else if (code >= 65 && code <= 90) {
      column = 26 * column + (code - 64);
    }
  }
  return { column: column - 1, row: row - 1 };
}

/** Letters of SheetJS's `encode_col(column)`; it throws below 0, after which nothing more is copied. */
function columnPartLength(column: number): number {
  let letters = 0;
  for (let rest = column + 1; rest >= 1; rest = Math.floor((rest - 1) / 26)) {
    letters += 1;
  }
  return Math.max(letters, 1);
}

const XML_ENTITIES: Readonly<Record<string, string>> = {
  "&quot;": '"',
  "&apos;": "'",
  "&gt;": ">",
  "&lt;": "<",
  "&amp;": "&",
};

/** SheetJS's `unescapexml` outside CDATA: entities, then `_xHHHH_` escapes. */
function unescapeEntities(text: string): string {
  return text
    .replace(/&(?:quot|apos|gt|lt|amp|#x?([\da-fA-F]+));/gi, (entity: string, code: string | undefined) =>
      Object.hasOwn(XML_ENTITIES, entity)
        ? XML_ENTITIES[entity]!
        : String.fromCharCode(Number.parseInt(code as string, entity.includes("x") ? 16 : 10)) || entity,
    )
    .replace(/_x([\da-fA-F]{4})_/gi, (_, code: string) => String.fromCharCode(Number.parseInt(code, 16)));
}

/** SheetJS's `unescapexml` (`raw_unescapexml`), its recursion over CDATA sections written as a loop. */
function unescapeXml(text: string): string {
  let out = "";
  let rest = text;
  for (;;) {
    const open = rest.indexOf("<![CDATA[");
    if (open === -1) {
      return out + unescapeEntities(rest);
    }
    const close = rest.indexOf("]]>");
    out += unescapeEntities(rest.slice(0, open)) + rest.slice(open + 9, close);
    rest = rest.slice(close + 3);
  }
}

/**
 * The shared formula text SheetJS keeps for a master, from the element's text
 * as this walk reads it: decoded as UTF-8 (the browser's lenient decode, and
 * the decode Node and Bun run) when the text is the part's bytes, then
 * unescaped, with every `_xlfn.` dropped.
 */
function masterTexts(text: string, byteForm: boolean): string[] {
  const decoded = byteForm
    ? [lenientUtf8(text), new TextDecoder().decode(Uint8Array.from(text, (char) => char.charCodeAt(0)))]
    : [text];
  return decoded.map((form) => unescapeXml(form).replace(/_xlfn\./g, ""));
}

/**
 * What one copy of the masters filed under a shared index can reach, as an
 * upper bound over each of them: a copy keeps `kept` characters, and SheetJS
 * rewrites `columns` column parts and `rows` row parts of its references
 * (`shift_formula_str`), each moved by the distance from the master's cell to
 * the follower's. A shifted column is at most the follower's column plus
 * `columnReach`, and a shifted row lies between the follower's row plus
 * `rowFloor` and plus `rowReach`. `placed` is false when a master's cell has
 * no address SheetJS reads (it then counts cells to place one), so every
 * part is charged at its ceiling.
 */
interface CopyBound {
  kept: number;
  columns: number;
  rows: number;
  columnReach: number;
  rowReach: number;
  rowFloor: number;
  placed: boolean;
}

/** Where SheetJS places a cell: its address, or none when SheetJS counts cells to place it. */
type Placement = { readonly column: number; readonly row: number } | undefined;

/** The bound of one master: its text and where SheetJS places its cell (`decode_range(..).s`). */
function masterBound(texts: readonly string[], master: Placement): CopyBound {
  const bound: CopyBound = {
    kept: 0,
    columns: 0,
    rows: 0,
    columnReach: Number.NEGATIVE_INFINITY,
    rowReach: Number.NEGATIVE_INFINITY,
    rowFloor: Number.POSITIVE_INFINITY,
    placed: master !== undefined,
  };
  for (const text of texts) {
    let shifted = 0;
    let columns = 0;
    let rows = 0;
    for (const [, , columnFixed, column, rowFixed, row] of text.matchAll(CELL_REFERENCE)) {
      if (columnFixed !== "$") {
        columns += 1;
        shifted += column!.length;
        let index = 0;
        for (let i = 0; i < column!.length; i += 1) {
          index = 26 * index + column!.charCodeAt(i) - 64;
        }
        bound.columnReach = Math.max(bound.columnReach, index - 1 - (master?.column ?? 0));
      }
      if (rowFixed !== "$") {
        rows += 1;
        shifted += row!.length;
        const index = Number.parseInt(row!, 10) - 1 - (master?.row ?? 0);
        bound.rowReach = Math.max(bound.rowReach, index);
        bound.rowFloor = Math.min(bound.rowFloor, index);
      }
    }
    bound.kept = Math.max(bound.kept, text.length - shifted);
    bound.columns = Math.max(bound.columns, columns);
    bound.rows = Math.max(bound.rows, rows);
  }
  return bound;
}

function joinBounds(a: CopyBound | undefined, b: CopyBound): CopyBound {
  if (a === undefined) {
    return b;
  }
  return {
    kept: Math.max(a.kept, b.kept),
    columns: Math.max(a.columns, b.columns),
    rows: Math.max(a.rows, b.rows),
    columnReach: Math.max(a.columnReach, b.columnReach),
    rowReach: Math.max(a.rowReach, b.rowReach),
    rowFloor: Math.min(a.rowFloor, b.rowFloor),
    placed: a.placed && b.placed,
  };
}

/** The most characters one follower's copy can hold, under `bound`. */
function copyLength(bound: CopyBound, follower: Placement): number {
  if (follower === undefined || !bound.placed) {
    return bound.kept + bound.columns * COLUMN_PART_CEILING + bound.rows * ROW_PART_CEILING;
  }
  const columnPart = bound.columns > 0 ? columnPartLength(follower.column + bound.columnReach) : 0;
  const rowPart =
    bound.rows > 0
      ? Math.max(
          String(follower.row + bound.rowReach + 1).length,
          String(follower.row + bound.rowFloor + 1).length,
        )
      : 0;
  return bound.kept + bound.columns * columnPart + bound.rows * rowPart;
}

/**
 * Walks a part's formulas as SheetJS reads a sheet's cells, refusing one
 * whose shared formula copies cross `budget.sheetTextChars` and returning the
 * steps SheetJS's array-formula scan takes over it.
 *
 * Shared formulas, in document order as SheetJS reads them: a master is
 * filed under its index when its element closes, and a follower takes what
 * the masters filed under its index so far can copy (`copyLength`), at its
 * own cell's place; a follower before any master copies nothing.
 *
 * Array formulas: with formula text kept, SheetJS checks every cell against
 * every array range filed before it (`arrayf`), and files one for each cell
 * whose formula element holds `t="array"`. So each closed element holding
 * it counts a range, and each cell counts the ranges filed by then. A row
 * also counts as a cell when text other than a tag follows its start tag,
 * which SheetJS reads as a cell.
 */
function checkFormulas(text: string, byteForm: boolean, budget: PreviewBudget): number {
  /** What the masters filed so far under each index can copy, by the index SheetJS files them under. */
  const masters = new Map<string, CopyBound>();
  /** Characters the followers seen so far copy. */
  let copied = 0;
  /** Array ranges filed so far, and the steps of SheetJS's scan over them. */
  let ranges = 0;
  let steps = 0;
  /** Where the current cell's text starts: SheetJS reads the cell's address from there to its first `>`. */
  let cellStart = 0;
  /** Where the current row's text starts, and whether a cell of it has started. */
  let rowStart = 0;
  let rowCells = false;
  /** Whether the current cell's addresses have been checked, and the address SheetJS reads for it once they have. */
  let addressChecked = false;
  let address: string | undefined;
  /**
   * The current cell's first formula start tag that waits for an end tag:
   * SheetJS pairs it with the first end tag after it, and reads the master's
   * attributes from the whole element.
   */
  let open: { readonly tagStart: number; readonly textStart: number } | undefined;
  /** Whether the current cell's first fallback-only tag has been seen: SheetJS reads no other. */
  let fallbackSeen = false;
  /** Whether the text from `from` to `to` holds a row's start tag followed by text other than a tag. */
  const rowTextCell = (from: number, to: number): boolean => {
    const end = text.indexOf(">", from);
    return end !== -1 && end < to && text.slice(end + 1, to).trim().length > 0;
  };
  /**
   * Refuses the current cell when an address it may carry, up to `end`, is
   * not safe integers, and gives the address SheetJS reads from its start
   * tag (`r`), or none when SheetJS counts cells to place it.
   */
  const checkAddress = (end: number): string | undefined => {
    if (addressChecked) {
      return address;
    }
    addressChecked = true;
    for (const candidate of attributeValues(` ${text.slice(cellStart, end)}`, "r")) {
      if (!safeCellAddress(candidate)) {
        throw new WorkbookBudgetError("sheetCells", "a shared formula's cell address lies past every sheet's cells");
      }
    }
    const tagEnd = text.indexOf(">", cellStart);
    const startTag = tagEnd === -1 ? "" : text.slice(cellStart, tagEnd + 1);
    address = (startTag.includes("<") ? undefined : sheetJsAttributes(`<c ${startTag}`).get("r")) || undefined;
    return address;
  };
  const follow = (indexes: readonly string[], end: number): void => {
    const cell = checkAddress(end);
    // SheetJS shifts a follower's copy to `decode_cell` of its address.
    const follower = cell === undefined ? undefined : decodeCell(cell);
    let most = 0;
    for (const index of indexes) {
      for (const key of [index, String(Number.parseInt(index, 10))]) {
        const bound = masters.get(key);
        if (bound !== undefined) {
          most = Math.max(most, copyLength(bound, follower));
        }
      }
    }
    copied += most;
    if (copied > budget.sheetTextChars) {
      throw new WorkbookBudgetError("sheetTextChars", "a sheet's shared formulas copy more text than the budget");
    }
  };
  for (const match of text.matchAll(FORMULA_SCAN)) {
    const end = match.index + match[0].length;
    if (match[3] !== undefined) {
      if (!fallbackSeen) {
        fallbackSeen = true;
        const indexes = attributeValues(match[3], "si");
        if (indexes.length > 0) {
          follow(indexes, end);
        }
      }
    } else if (match[1] !== undefined) {
      const indexes = attributeValues(match[1], "si");
      if (indexes.length > 0) {
        follow(indexes, end);
      }
      open ??= { tagStart: match.index, textStart: end };
    } else if (match[2] !== undefined) {
      if (open !== undefined) {
        const element = text.slice(open.tagStart, end);
        if (element.includes('t="array"')) {
          ranges += 1;
        }
        const indexes = attributeValues(element, "si");
        if (indexes.length > 0) {
          // SheetJS shifts from the start of `decode_range` of the master's address.
          const cell = checkAddress(open.textStart);
          const master = cell === undefined ? undefined : decodeCell(cell.split(":")[0]!);
          const bound = masterBound(masterTexts(text.slice(open.textStart, match.index), byteForm), master);
          for (const index of indexes) {
            const key = String(Number.parseInt(index, 10));
            masters.set(key, joinBounds(masters.get(key), bound));
          }
        }
      }
      open = undefined;
    } else {
      if (match[0].startsWith("</")) {
        if (!rowCells && rowTextCell(rowStart, match.index)) {
          steps += ranges;
        }
        rowStart = end;
        rowCells = false;
      } else {
        if (!rowCells && rowTextCell(rowStart, match.index)) {
          steps += ranges;
        }
        rowCells = true;
        // The cell before this one is checked against every range filed by its end.
        steps += ranges;
      }
      cellStart = end;
      addressChecked = false;
      address = undefined;
      open = undefined;
      fallbackSeen = false;
    }
  }
  if (!rowCells && rowTextCell(rowStart, text.length)) {
    steps += ranges;
  }
  return steps + ranges;
}

/**
 * Refuses a part whose expansions, were SheetJS to parse it as a sheet, cross
 * `budget`, and returns the steps SheetJS's array-formula scan would take over
 * it (the most over the part's texts), which the read charges against
 * `budget.loopSteps`. `texts` is the part as SheetJS may decode it
 * ({@link partTexts}), the bytes as characters first. `formulaText` says
 * whether the read keeps formula text, without which SheetJS copies no shared
 * formula and scans no array range. A part SheetJS would read with its binary
 * reader is refused before this check (`package-read.ts`).
 */
export function checkSheetExpansion(texts: readonly string[], budget: PreviewBudget, formulaText: boolean): number {
  let steps = 0;
  texts.forEach((text, index) => {
    checkHyperlinks(text, budget);
    if (formulaText) {
      steps = Math.max(steps, checkFormulas(text, index === 0, budget));
    }
  });
  return steps;
}
