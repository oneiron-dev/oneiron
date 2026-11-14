/**
 * One guarded read of a workbook package, for every door of the bridge.
 *
 * `readPackage` reads a package the way `XLSX.read` reads a ZIP package
 * (inflate every entry into a container, then parse the workbook from it),
 * and checks each part at the moment SheetJS 0.20.3 first takes its bytes,
 * before SheetJS parses it. So exactly the parts SheetJS parses are checked:
 * the outline doors' content types and workbook, and for a sheet read the
 * sheet asked for, never another sheet. SheetJS swallows an error some of its
 * reads throw, so a refusal is kept, every later take throws it again, and it
 * is thrown once the read returns.
 *
 * A real package has SheetJS take each part once per read, and two parts
 * twice, each first only to see that it is there: `xl/workbook.xml`, when the
 * content types name no workbook part (a `Default` can give its type), and,
 * in a sheet read, `xl/worksheets/sheet.xml` (a Numbers export names its
 * sheet so). SheetJS then parses each of them. A crafted package can make
 * SheetJS take a part again and again, and parse it each time: a workbook
 * listing one sheet name thousands of times, all pointing at one sheet part,
 * has SheetJS read that part once per listed sheet (its `sheets` option
 * matches names without case), and relationships whose targets differ only
 * in case have it read one comments part once per relationship. So a part
 * taken more often than that is refused; the second take of a probed part
 * reads the bytes its first take checked.
 *
 * Each take (`ReadTally.take`) checks, in order:
 * - a part SheetJS would read with its binary reader is refused. SheetJS picks
 *   a part's reader by the name it looks the part up by, not by the kind of
 *   workbook, so an xlsx whose relationships name a `.bin` sheet reaches the
 *   binary reader too. The engine opens no XLSB workbook, and a real xlsx or
 *   xlsm carries no `.bin` part SheetJS takes with the options the bridge sets
 *   (`vbaProject.bin` needs `bookVBA`; printer settings, OLE objects and
 *   ActiveX parts are never taken);
 * - a part holding a CDATA marker (`<![CDATA[`) is refused. SheetJS's
 *   unescape (`unescapexml`), which it runs on cell values, strings, formulas
 *   and names, copies the text after a marker that no `]]>` follows once per
 *   two characters before it, and the text before a marker once per `]]>`
 *   ahead of it, so a crafted text grows with the square of its length.
 *   Excel and LibreOffice write no CDATA in xlsx parts. The marker counts as
 *   SheetJS reads it: as it stands, through its browser UTF-8 decode, and in
 *   a cell value, which SheetJS unescapes, decodes and, for a formula's
 *   string result, unescapes again;
 * - the read's part lookups. SheetJS finds a part by comparing its name with
 *   every path of the container (`safegetzipfile`), and some reads make one
 *   lookup per record: two per listed sheet, before it applies the `sheets`
 *   option; two per external link its content types list, on the outline
 *   doors too; one per comment relationship of the sheet it reads. The
 *   records are counted in every part as it is taken, so the line is crossed
 *   at the take of the part whose records would make the lookups, before
 *   SheetJS walks them, and a workbook listing more sheets than the budget is
 *   refused there too;
 * - what SheetJS expands while it parses a sheet part (`checkSheetExpansion`).
 *
 * Each count is an upper bound of what SheetJS reads: a record is counted in
 * any part, in each text form SheetJS may decode the part as, with a tag name
 * in any namespace prefix.
 */
import * as XLSX from "xlsx";
import { preflightPackage, WorkbookBudgetError } from "./budget";
import type { PreviewBudget } from "./budget";
import { attributeValues, checkSheetExpansion, partTexts, sheetJsAttributes, unescapeEntities } from "./expansion";

/** A part of the package as SheetJS holds it once it has inflated it (a CFB file entry). */
interface ContainerEntry {
  readonly name: string;
  readonly type: number;
  content?: ArrayLike<number>;
}

/** The container SheetJS reads a ZIP package into: entries, and the path of each. */
interface Container {
  readonly FileIndex: ContainerEntry[];
  readonly FullPaths: string[];
}

/** The two steps `XLSX.read` takes for a ZIP package, both exported by SheetJS 0.20.3. */
interface SheetJsZipSteps {
  readonly CFB: { read(data: Uint8Array, options: { type: "buffer" }): Container };
  parse_zip(zip: Container, options: XLSX.ParsingOptions): XLSX.WorkBook;
}

/** A CFB file entry, as opposed to a folder or the root. */
const CFB_FILE = 2;

/**
 * The parts `parse_zip` takes once only to see that they are there: the
 * workbook it falls back to when the content types name none, and the sheet
 * a Numbers export names (its Numbers check).
 */
const PROBED_PARTS: readonly string[] = ["xl/workbook.xml", "xl/worksheets/sheet.xml"];

/**
 * The entries SheetJS finds for `PROBED_PARTS`, as `safegetzipfile` finds a
 * part: the first path that equals the name without case, its segments
 * parted by slashes or by backslashes.
 */
function probedEntries(paths: readonly string[]): Set<number> {
  const names = paths.map((path) => path.replace(/^Root Entry[\/]/, "").toLowerCase());
  const entries = new Set<number>();
  for (const part of PROBED_PARTS) {
    const backslashed = part.replace(/\//g, "\\");
    const index = names.findIndex((name) => name === part || name === backslashed);
    if (index !== -1) {
      entries.add(index);
    }
  }
  return entries;
}

/**
 * The lookups one read makes whatever the package holds: the format probes,
 * content types, workbook, its relationships, shared strings, styles,
 * properties, metadata, people, `xl/worksheets/sheet.xml`, and the read
 * sheet with its relationships, drawing and chart parts; rounded up.
 */
const FIXED_LOOKUPS = 32;

/** The content types SheetJS files as external links (`ct2type`). */
const EXTERNAL_LINK_TYPES: ReadonlySet<string> = new Set([
  "application/vnd.ms-excel.externalLink",
  "application/vnd.openxmlformats-officedocument.spreadsheetml.externalLink+xml",
]);

/**
 * A tag that may make lookups: a sheet the workbook lists (`<sheet`), a
 * relationship (`<Relationship`), or a content-type override (`<Override`,
 * named as `parse_ct` names it: its tag name up to a space or line break).
 */
const LOOKUP_TAGS = /<(?:\w*:)?(?:(sheet)[\s/>]|(Relationship)[\s/>]|(Override)[ \n\r])/g;

/** SheetJS's tag pattern (`tagregex1`), anchored: the tag `parse_ct` reads from a `<Override`. */
const TAG_AT = /<[\/\?]?[a-zA-Z0-9:_-]+(?:\s+[^"\s?<>\/]+\s*=\s*(?:"[^"]*"|'[^']*'|[^'"<>\s=]+))*\s*[\/\?]?>/y;

/** SheetJS's tag pattern (`tagregex1`), over a whole part: the tags its threaded-comment reader walks. */
const TAGS = new RegExp(TAG_AT.source, "g");
/** A comment's tag as SheetJS's comments reader cuts it (`parse_comments_xml`), anywhere in a part. */
const COMMENT_TAG = /<(?:\w+:)?comment[^<>]*>/g;
/** A person's tag (`parse_people_xml`). */
const PERSON_TAG = /<(?:\w+:)?person[ \n\r]/g;

/** The marker that opens a CDATA section. */
const CDATA_MARKER = "<![CDATA[";

/**
 * The character SheetJS's browser UTF-8 decode (`utf8reada`) reads at `at`
 * of a text of bytes, and how many bytes it takes. It checks no continuation
 * byte, so an invalid form can read as any character below 128; a four-byte
 * form reads as two surrogates, which no marker holds (-1).
 */
function lenientCharAt(text: string, at: number): readonly [number, number] {
  const c = text.charCodeAt(at);
  if (c < 128) {
    return [c, 1];
  }
  const d = text.charCodeAt(at + 1) & 63;
  if (c > 191 && c < 224) {
    return [((c & 31) << 6) | d, 2];
  }
  const e = text.charCodeAt(at + 2) & 63;
  return c < 240 ? [((c & 15) << 12) | (d << 6) | e, 3] : [-1, 4];
}

/** A cell value element as `str_match_xml_ns(d, "v")` finds it: a start tag, then the first end tag after it. */
const VALUE_ELEMENT = /<(?:\w+:)?v\b[^<>]*>([\s\S]*?)<\/(?:\w+:)?v>/g;

/**
 * Whether SheetJS's browser UTF-8 decode, started anywhere in `text`, reads
 * the CDATA marker. It is followed from every character, so wherever SheetJS
 * starts one, the characters it reads are among those followed.
 */
function decodesToCdataMarker(text: string): boolean {
  for (let start = 0; start < text.length; start += 1) {
    let at = start;
    let matched = 0;
    while (matched < CDATA_MARKER.length && at < text.length) {
      const [code, length] = lenientCharAt(text, at);
      if (code !== CDATA_MARKER.charCodeAt(matched)) {
        break;
      }
      matched += 1;
      at += length;
    }
    if (matched === CDATA_MARKER.length) {
      return true;
    }
  }
  return false;
}

/**
 * Whether a text SheetJS unescapes could hold the CDATA marker, after the
 * UTF-8 decode SheetJS may run first: its browser decode (any character
 * below 128 from an invalid form), or Node's and Bun's, which keep each
 * character's low byte and read the bytes strictly, so only a byte below 128
 * reads as one.
 */
function decodedTextHoldsCdataMarker(text: string): boolean {
  if (text.includes(CDATA_MARKER)) {
    return true;
  }
  const lowBytes = text.replace(/[\u0100-\uffff]/g, (char) => String.fromCharCode(char.charCodeAt(0) & 0xff));
  if (lowBytes.includes(CDATA_MARKER)) {
    return true;
  }
  return /[^\x00-\x7f]/.test(text) && decodesToCdataMarker(text);
}

/**
 * Whether SheetJS's unescape could meet a CDATA marker in a text it takes
 * from this part: in the text as it stands or decoded, or in a cell value
 * unescaped once and decoded, which SheetJS unescapes again for a formula's
 * string result (`t="str"`). A value is read up to the first end tag after
 * its start tag, as SheetJS reads it, and a value whose text SheetJS cuts
 * shorter is a part of it.
 */
function holdsCdataMarker(text: string): boolean {
  if (decodedTextHoldsCdataMarker(text)) {
    return true;
  }
  for (const [, value] of text.matchAll(VALUE_ELEMENT)) {
    if (/[&_]/.test(value!) && decodedTextHoldsCdataMarker(unescapeEntities(value!))) {
      return true;
    }
  }
  return false;
}

/** The records of one part that make lookups. */
interface LookupRecords {
  sheets: number;
  links: number;
  relationships: number;
}

function lookupRecords(text: string): LookupRecords {
  const records: LookupRecords = { sheets: 0, links: 0, relationships: 0 };
  for (const match of text.matchAll(LOOKUP_TAGS)) {
    if (match[1] !== undefined) {
      records.sheets += 1;
    } else if (match[2] !== undefined) {
      records.relationships += 1;
    } else {
      TAG_AT.lastIndex = match.index;
      const tag = TAG_AT.exec(text)?.[0];
      if (tag !== undefined && attributeValues(tag, "contenttype").some((type) => EXTERNAL_LINK_TYPES.has(type))) {
        records.links += 1;
      }
    }
  }
  return records;
}

/** What one read has taken so far, checked against `budget` at each take. */
class ReadTally {
  private sheets = 0;
  private links = 0;
  private relationships = 0;
  /** Loop steps charged so far. */
  private steps = 0;
  /** Comments gathered so far, by the cell address text SheetJS files them under. */
  private readonly comments = new Map<string, number>();
  /** People listed so far, which each threaded comment's author is looked up in. */
  private people = 0;
  /** Threaded comments gathered so far, which each later threaded-comments part copies again. */
  private threaded = 0;

  constructor(
    private readonly budget: PreviewBudget,
    /** The container's paths, every one of which each lookup compares. */
    private readonly paths: number,
    /** Whether the read keeps formula text, without which SheetJS copies no shared formula. */
    private readonly formulaText: boolean,
  ) {}

  /** Refuses the part `name`, about to be taken, or the read it would make cross a line. */
  take(name: string, bytes: Uint8Array): void {
    if (name.toLowerCase().endsWith(".bin")) {
      throw new WorkbookBudgetError("structure", "a part SheetJS would read with its binary reader");
    }
    const texts = partTexts(bytes);
    if (texts.some(holdsCdataMarker)) {
      throw new WorkbookBudgetError("structure", "a part holding a CDATA marker, which SheetJS unescapes in quadratic time");
    }
    let sheets = 0;
    let links = 0;
    let relationships = 0;
    for (const text of texts) {
      const records = lookupRecords(text);
      sheets = Math.max(sheets, records.sheets);
      links = Math.max(links, records.links);
      relationships = Math.max(relationships, records.relationships);
    }
    this.sheets += sheets;
    this.links += links;
    this.relationships += relationships;
    if (this.sheets > this.budget.sheets) {
      throw new WorkbookBudgetError("sheets", "more sheets than the budget");
    }
    const lookups = this.paths * (FIXED_LOOKUPS + 2 * this.sheets + 2 * this.links + this.relationships);
    if (lookups > this.budget.partLookups) {
      throw new WorkbookBudgetError("partLookups", "finding the parts would compare more paths than the budget");
    }
    this.steps += checkSheetExpansion(texts, this.budget, this.formulaText);
    for (const text of texts) {
      this.takeComments(text);
    }
    if (this.steps > this.budget.loopSteps) {
      throw new WorkbookBudgetError(
        "loopSteps",
        "the read's loops over its comments and array ranges take more steps than the budget",
      );
    }
  }

  /**
   * Charges the loops SheetJS runs over a part's comments. It puts each
   * comment on its cell after looking at every comment already there
   * (`sheet_insert_comments`), and looks up each threaded comment's author in
   * the people listed (`opts.people`), after it has copied the threaded
   * comments gathered so far (`tcomments.concat`). A plain comment is counted
   * at each of its tags, a threaded one at each end tag (SheetJS adds the last
   * comment started at every end tag), each under the cell address its tag
   * names.
   */
  private takeComments(text: string): void {
    for (const _ of text.matchAll(PERSON_TAG)) {
      this.people += 1;
    }
    for (const [tag] of text.matchAll(COMMENT_TAG)) {
      this.commentOn(sheetJsAttributes(tag).get("ref"));
    }
    this.steps += this.threaded;
    if (!text.includes("threadedComment")) {
      return;
    }
    let started: string | undefined;
    for (const [tag] of text.matchAll(TAGS)) {
      const name = /^[^ \n\r]*/.exec(tag)![0].replace(/<(\/?)\w+:/, "<$1");
      if (name === "<threadedComment") {
        started = sheetJsAttributes(tag).get("ref");
      } else if (name === "</threadedComment>") {
        this.steps += 1 + this.people;
        this.threaded += 1;
        this.commentOn(started);
      }
    }
  }

  /** One more comment on the cell `ref` names, after a step over each comment already there. */
  private commentOn(ref: string | undefined): void {
    const key = ref ?? "";
    const before = this.comments.get(key) ?? 0;
    this.steps += before;
    this.comments.set(key, before + 1);
  }
}

/**
 * Reads `bytes` with SheetJS's `options`, refusing it once it crosses a line
 * of `budget`: first from its ZIP records (`preflightPackage`), then at each
 * part SheetJS takes (`ReadTally`).
 */
export function readPackage(bytes: Uint8Array, budget: PreviewBudget, options: XLSX.ParsingOptions): XLSX.WorkBook {
  const steps = XLSX as unknown as SheetJsZipSteps;
  const zip = steps.CFB.read(preflightPackage(bytes, budget), { type: "buffer" });
  // SheetJS keeps formula text unless it is told not to.
  const tally = new ReadTally(budget, zip.FullPaths.length, options.cellFormula !== false);
  let refusal: WorkbookBudgetError | undefined;
  /** The part of the last access, while the second access of its take may follow. */
  let takeOpen: ContainerEntry | undefined;
  const probed = probedEntries(zip.FullPaths);
  for (const [index, entry] of zip.FileIndex.entries()) {
    const content = entry.content;
    if (entry.type !== CFB_FILE || content === undefined) {
      continue;
    }
    /** Takes left for this part: one, and one more for a part SheetJS also probes. */
    let takesLeft = probed.has(index) ? 2 : 1;
    let checked = false;
    Object.defineProperty(entry, "content", {
      configurable: true,
      enumerable: true,
      get(): ArrayLike<number> {
        if (refusal !== undefined) {
          throw refusal;
        }
        // SheetJS reads `content` twice per take (`data.content && data.type`,
        // then the bytes), one access straight after the other.
        if (takeOpen === entry) {
          takeOpen = undefined;
          return content;
        }
        try {
          if (takesLeft === 0) {
            throw new WorkbookBudgetError("structure", "a part SheetJS would read more than once");
          }
          if (!checked) {
            tally.take(entry.name, content instanceof Uint8Array ? content : Uint8Array.from(content));
          }
        } catch (err) {
          if (err instanceof WorkbookBudgetError) {
            refusal = err;
          }
          throw err;
        }
        takesLeft -= 1;
        checked = true;
        takeOpen = entry;
        return content;
      },
    });
  }
  let wb: XLSX.WorkBook;
  try {
    wb = steps.parse_zip(zip, { ...options, type: "array" });
  } catch (err) {
    throw refusal ?? err;
  }
  if (refusal !== undefined) {
    throw refusal;
  }
  return wb;
}
