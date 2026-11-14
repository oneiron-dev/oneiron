/**
 * What SheetJS 0.20.3 expands while it parses a sheet part, counted from the
 * part's bytes before it parses them.
 *
 * Two of its readers make work that grows far past the part's size, inside
 * every byte budget:
 * - each `<hyperlink ref>` becomes a cell object for every address of its
 *   range (`parse_ws_xml_hlinks`), so one 40-byte `ref="A1:XFD1048576"` asks
 *   17 billion;
 * - each cell that follows a shared formula (`<f t="shared" si="0"/>`) gets
 *   its own shifted copy of the master's text, so a long master and a million
 *   followers ask billions of characters.
 * The sheet's cell and text lines are checked again on the parsed sheet
 * (`worksheetToCellData`), but only after SheetJS has made all of that. So the
 * hyperlink cells are counted against `sheetCells`, and the followers' copied
 * text against `sheetTextChars`, here first.
 *
 * The counts are upper bounds of what SheetJS reads, never less: the part is
 * read the ways SheetJS decodes it (each byte as the one character of its
 * value, and UTF-16 after a byte-order mark), each attribute's name and value
 * cut as SheetJS's `parsexmltag` cuts them, a hyperlink tag also after
 * SheetJS's lenient UTF-8 decode, each hyperlink counted on its own even where
 * ranges overlap, an address SheetJS's loop cannot step past counted as no
 * end, every formula naming a shared index counted at the longest master text
 * that index names anywhere in the part, and so is the first self-closing tag
 * of a cell that SheetJS's fallback formula reader takes (`<f[^<>]*\/>`, which
 * also matches `<foo si="0"/>`). A master's indexes are read from its whole
 * element, its text and end tag included, as SheetJS reads its attributes.
 *
 * A cell that holds a formula naming a shared index is refused unless its
 * address decodes to a column and a row that are safe integers: SheetJS shifts
 * a follower's copy by the distance between the two cells, and a column that
 * decodes to Infinity never finishes encoding (`encode_col`). Inside safe
 * integers a shifted reference can still grow to a 12-letter column and a
 * 17-character row, so a copy can be longer than its master; the check on the
 * parsed sheet bounds that.
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
function attributeValues(tag: string, key: string): string[] {
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
function partTexts(bytes: Uint8Array): string[] {
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

function checkSharedFormulas(text: string, budget: PreviewBudget): void {
  /** The longest master text each shared index names, by the index SheetJS files it under. */
  const masters = new Map<string, number>();
  /** How many formulas name each shared index, by the index's text. */
  const followers = new Map<string, number>();
  /** Where the current cell's text starts: SheetJS reads the cell's address from there to its first `>`. */
  let cellStart = 0;
  /** Whether the current cell's address has been checked. */
  let addressChecked = false;
  /**
   * The current cell's first formula start tag that waits for an end tag:
   * SheetJS pairs it with the first end tag after it, and reads the master's
   * attributes from the whole element.
   */
  let open: { readonly tagStart: number; readonly textStart: number } | undefined;
  /** Whether the current cell's first fallback-only tag has been seen: SheetJS reads no other. */
  let fallbackSeen = false;
  const follow = (indexes: readonly string[]): void => {
    for (const index of indexes) {
      followers.set(index, (followers.get(index) ?? 0) + 1);
    }
  };
  /** Refuses the current cell when an address it may carry, up to `end`, is not safe integers. */
  const checkAddress = (end: number): void => {
    if (addressChecked) {
      return;
    }
    addressChecked = true;
    for (const address of attributeValues(` ${text.slice(cellStart, end)}`, "r")) {
      if (!safeCellAddress(address)) {
        throw new WorkbookBudgetError("sheetCells", "a shared formula's cell address lies past every sheet's cells");
      }
    }
  };
  for (const match of text.matchAll(FORMULA_SCAN)) {
    const end = match.index + match[0].length;
    if (match[3] !== undefined) {
      if (!fallbackSeen) {
        fallbackSeen = true;
        const indexes = attributeValues(match[3], "si");
        if (indexes.length > 0) {
          follow(indexes);
          checkAddress(end);
        }
      }
    } else if (match[1] !== undefined) {
      const indexes = attributeValues(match[1], "si");
      if (indexes.length > 0) {
        follow(indexes);
        checkAddress(end);
      }
      open ??= { tagStart: match.index, textStart: end };
    } else if (match[2] !== undefined) {
      if (open !== undefined) {
        const indexes = attributeValues(text.slice(open.tagStart, end), "si");
        if (indexes.length > 0) {
          checkAddress(open.textStart);
          const length = match.index - open.textStart;
          for (const index of indexes) {
            const key = String(Number.parseInt(index, 10));
            masters.set(key, Math.max(masters.get(key) ?? 0, length));
          }
        }
      }
      open = undefined;
    } else {
      cellStart = end;
      addressChecked = false;
      open = undefined;
      fallbackSeen = false;
    }
  }
  let copied = 0;
  for (const [index, count] of followers) {
    const master = Math.max(masters.get(index) ?? 0, masters.get(String(Number.parseInt(index, 10))) ?? 0);
    copied += count * master;
    if (copied > budget.sheetTextChars) {
      throw new WorkbookBudgetError("sheetTextChars", "a sheet's shared formulas copy more text than the budget");
    }
  }
}

/**
 * Refuses a part whose expansions, were SheetJS to parse it as a sheet, cross
 * `budget`. `formulaText` says whether the read keeps formula text, without
 * which SheetJS copies no shared formula. A `.bin` part goes to SheetJS's
 * binary reader instead and is not read here.
 */
export function checkSheetExpansion(
  name: string,
  bytes: Uint8Array,
  budget: PreviewBudget,
  formulaText: boolean,
): void {
  if (name.slice(-4) === ".bin") {
    return;
  }
  for (const text of partTexts(bytes)) {
    checkHyperlinks(text, budget);
    if (formulaText) {
      checkSharedFormulas(text, budget);
    }
  }
}
