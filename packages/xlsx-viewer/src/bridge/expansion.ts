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
 * read the ways SheetJS decodes it (bytes as characters, and UTF-16 after a
 * byte-order mark), a hyperlink tag also after SheetJS's lenient UTF-8 decode,
 * each hyperlink counted on its own even where ranges overlap, and every
 * formula naming a shared index counted at the longest master text that index
 * names anywhere in the part. A shifted copy can be a few characters longer
 * than its master; the check on the parsed sheet still bounds that.
 */
import { WorkbookBudgetError } from "./budget";
import type { PreviewBudget } from "./budget";

/** SheetJS's hyperlink tag pattern (`hlinkregex`). */
const HYPERLINK_TAG = /<(?:\w+:)?hyperlink [^<>]*>/g;
/** SheetJS's attribute pattern (`attregexg`). */
const ATTRIBUTE = /\s([^"\s?>/]+)\s*=\s*((?:")([^"]*)(?:")|(?:')([^']*)(?:')|([^'">\s]+))/g;
/**
 * A formula element's start tag (self-closing or not) or its end tag, else
 * where SheetJS cuts the sheet data into a new cell or row (`cellregex`,
 * `rowregex`): it looks for a formula's end inside its own cell only.
 */
const FORMULA_SCAN = /(<(?:\w+:)?f\b[^<>]*>)|(<\/(?:\w+:)?f>)|<(?:\w+:)?c[ />]|<\/(?:\w+:)?row>/g;

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

/** Every value a tag gives an attribute that SheetJS files under `key`. */
function attributeValues(tag: string, key: string): string[] {
  const values: string[] = [];
  for (const match of tag.matchAll(ATTRIBUTE)) {
    if (attributeKey(match[1]!) === key) {
      values.push(match[3] ?? match[4] ?? match[5] ?? "");
    }
  }
  return values;
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
 * counts in full, and a row loop with no columns still runs).
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
  if (i === range.length || code !== 10) {
    return 1;
  }
  i += 1;
  const endColumn = part(true);
  const endRow = part(false);
  const rows = endRow >= startRow ? endRow - startRow + 1 : 0;
  if (rows === 0) {
    return 0;
  }
  const columns = endColumn >= startColumn ? endColumn - startColumn + 1 : 0;
  const visits = rows * Math.max(columns, 1);
  // Two row numbers past the largest double both read as Infinity; SheetJS's
  // loop then never ends.
  return Number.isNaN(visits) ? Number.POSITIVE_INFINITY : visits;
}

/** The part as the strings SheetJS may parse it as (`cc2str`). */
function partTexts(bytes: Uint8Array): string[] {
  const texts = [new TextDecoder("windows-1252").decode(bytes)];
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
  /** Formula start tags in the current cell that name a shared index and wait for an end tag. */
  let open: { readonly indexes: readonly string[]; readonly textStart: number }[] = [];
  for (const match of text.matchAll(FORMULA_SCAN)) {
    if (match[1] !== undefined) {
      const indexes = attributeValues(match[1], "si");
      for (const index of indexes) {
        followers.set(index, (followers.get(index) ?? 0) + 1);
      }
      if (indexes.length > 0) {
        open.push({ indexes, textStart: match.index + match[1].length });
      }
    } else if (match[2] !== undefined) {
      for (const start of open) {
        const length = match.index - start.textStart;
        for (const index of start.indexes) {
          const key = String(Number.parseInt(index, 10));
          masters.set(key, Math.max(masters.get(key) ?? 0, length));
        }
      }
      open = [];
    } else {
      open = [];
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
