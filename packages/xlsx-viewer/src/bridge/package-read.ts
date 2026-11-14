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
 * A real package has SheetJS take each part once per read. A crafted one can
 * make it take a part again and again, and parse it each time: a workbook
 * listing one sheet name thousands of times, all pointing at one sheet part,
 * has SheetJS read that part once per listed sheet (its `sheets` option
 * matches names without case), and relationships whose targets differ only
 * in case have it read one comments part once per relationship. So a second
 * take of a part is refused.
 *
 * Each take (`ReadTally.take`) checks, in order:
 * - a part SheetJS would read with its binary reader is refused. SheetJS picks
 *   a part's reader by the name it looks the part up by, not by the kind of
 *   workbook, so an xlsx whose relationships name a `.bin` sheet reaches the
 *   binary reader too. The engine opens no XLSB workbook, and a real xlsx or
 *   xlsm carries no `.bin` part SheetJS takes with the options the bridge sets
 *   (`vbaProject.bin` needs `bookVBA`; printer settings, OLE objects and
 *   ActiveX parts are never taken);
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
import { attributeValues, checkSheetExpansion, partTexts, sheetJsAttributes } from "./expansion";

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
  for (const entry of zip.FileIndex) {
    const content = entry.content;
    if (entry.type !== CFB_FILE || content === undefined) {
      continue;
    }
    let taken = false;
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
          if (taken) {
            throw new WorkbookBudgetError("structure", "a part SheetJS would read more than once");
          }
          tally.take(entry.name, content instanceof Uint8Array ? content : Uint8Array.from(content));
        } catch (err) {
          if (err instanceof WorkbookBudgetError) {
            refusal = err;
          }
          throw err;
        }
        taken = true;
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
