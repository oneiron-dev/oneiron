import { describe, expect, it } from "bun:test";
import * as XLSX from "xlsx";
import { PREVIEW_BUDGET, WorkbookBudgetError, type BudgetLine, type PreviewBudget } from "../src/bridge/budget";
import { readPackage } from "../src/bridge/package-read";
import { readSheet } from "../src/bridge/parse";
import {
  EXTERNAL_LINK_TYPE,
  PLAIN_SHEET,
  sheetsPackage,
  threadedCommentsPartsPackage,
  worksheet,
} from "./crafted-packages";
import { DOC_REL, text } from "./package-writer";

/**
 * SheetJS's `parsexmltag` files a tag's name under key `0`, and then each
 * attribute under its own key, so an attribute named `0`, `0_` and more, or
 * `<prefix>:0` replaces the name its part readers tell the tag by. Each case
 * below has a twin whose attribute is named `x0`, which SheetJS files under
 * `x0`: the twin reads as it is written.
 */

/** A loop line that a few hundred thousand steps cross. */
const LOOP_LINE: PreviewBudget = { ...PREVIEW_BUDGET, loopSteps: 100_000 };
/** A lookup line that 1,000 records over the 7 paths of these packages cross. */
const LOOKUP_LINE: PreviewBudget = { ...PREVIEW_BUDGET, partLookups: 5_000 };

/** The budget line `run` is refused at, or undefined when it reads. */
function refusal(run: () => unknown): BudgetLine | undefined {
  try {
    run();
  } catch (err) {
    if (err instanceof WorkbookBudgetError) {
      return err.line;
    }
    throw err;
  }
  return undefined;
}

/** One threaded comment on A1 by an author no person is, then `tail`, in the threaded-comments part. */
function afterOneComment(tail: string): Uint8Array {
  return threadedCommentsPartsPackage(`<threadedComment ref="A1" personId="{nobody}"><text>x</text>${tail}`, "");
}

describe("xlsx preview: a tag is read by the name SheetJS tells it by", () => {
  it("charges a tag an attribute renames to a threaded comment's end tag", () => {
    for (const attribute of [`0="</threadedComment>"`, `x:0="</threadedComment>"`, `0_y="</x:threadedComment>"`]) {
      const bytes = afterOneComment(`<x ${attribute}/>`.repeat(1_000));
      // SheetJS files the comment on A1 again at each renamed tag, each time
      // after a look at every comment already there: 500,000 steps.
      expect(XLSX.read(bytes, { type: "array" }).Sheets.S1!.A1!.c).toHaveLength(1_000);
      expect(refusal(() => readSheet(bytes, "S1", { budget: LOOP_LINE }))).toBe("loopSteps");
    }
    const twin = afterOneComment(`<x x0="</threadedComment>"/>`.repeat(1_000));
    expect(XLSX.read(twin, { type: "array" }).Sheets.S1!.A1!.c).toBeUndefined();
    expect(refusal(() => readSheet(twin, "S1", { budget: LOOP_LINE }))).toBeUndefined();
  });

  it("starts no threaded comment at a start tag an attribute renames away", () => {
    // 1,000 comments on B1, B2, ..., each start tag renamed: SheetJS starts
    // none of them, and files the A1 comment again at each end tag.
    const renamedStarts = (attribute: string) =>
      threadedCommentsPartsPackage(
        `<threadedComment ref="A1" personId="{nobody}"><text>x</text></threadedComment>` +
          Array.from(
            { length: 1_000 },
            (_, i) => `<threadedComment ref="B${i + 1}" ${attribute}></threadedComment>`,
          ).join(""),
        "",
      );
    const bytes = renamedStarts(`0="z"`);
    const sheet = XLSX.read(bytes, { type: "array" }).Sheets.S1!;
    expect(sheet.A1!.c).toHaveLength(1_001);
    expect(sheet.B1).toBeUndefined();
    expect(refusal(() => readSheet(bytes, "S1", { budget: LOOP_LINE }))).toBe("loopSteps");
    expect(refusal(() => readSheet(renamedStarts(`x0="z"`), "S1", { budget: LOOP_LINE }))).toBeUndefined();
  });

  it("counts a tag an attribute renames to a person", () => {
    // 100 threaded comments on their own cells, each looked up in 2,000
    // people: 200,000 steps.
    const comments = Array.from(
      { length: 100 },
      (_, i) => `<threadedComment ref="A${i + 1}" personId="{nobody}"><text>x</text></threadedComment>`,
    ).join("");
    const people = (attribute: string) => threadedCommentsPartsPackage(comments, `<x ${attribute} id="{p}"/>`.repeat(2_000));
    const options: XLSX.ParsingOptions & { people?: unknown[] } = { type: "array" };
    XLSX.read(people(`0="<person"`), options);
    expect(options.people).toHaveLength(2_000);
    expect(refusal(() => readSheet(people(`0="<person"`), "S1", { budget: LOOP_LINE }))).toBe("loopSteps");
    expect(refusal(() => readSheet(people(`x0="<person"`), "S1", { budget: LOOP_LINE }))).toBeUndefined();
  });

  it("counts sheets, relationships and external links that an attribute renames", () => {
    const sheets = (attribute: string) =>
      sheetsPackage([text(PLAIN_SHEET)], {
        listedAfter: Array.from(
          { length: 100 },
          (_, i) => `<x ${attribute} name="R${i + 1}" sheetId="${i + 2}" r:id="rIdR${i + 1}"/>`,
        ).join(""),
      });
    expect(XLSX.read(sheets(`0="<sheet"`), { type: "array", bookSheets: true }).SheetNames).toHaveLength(101);
    const sheetLine = { ...PREVIEW_BUDGET, sheets: 50 };
    expect(refusal(() => readPackage(sheets(`0="<sheet"`), sheetLine, { bookSheets: true }))).toBe("sheets");
    expect(readPackage(sheets(`x0="<sheet"`), sheetLine, { bookSheets: true }).SheetNames).toHaveLength(1);

    const relationships = (attribute: string) =>
      sheetsPackage([text(PLAIN_SHEET)], {
        workbookRelationships: Array.from(
          { length: 1_000 },
          (_, i) => `<x ${attribute} Id="rIdX${i + 1}" Type="${DOC_REL}/worksheet" Target="worksheets/x${i + 1}.xml"/>`,
        ).join(""),
      });
    expect(refusal(() => readSheet(relationships(`0="<Relationship"`), "S1", { budget: LOOKUP_LINE }))).toBe(
      "partLookups",
    );
    expect(refusal(() => readSheet(relationships(`x0="<Relationship"`), "S1", { budget: LOOKUP_LINE }))).toBeUndefined();

    const links = (attribute: string) =>
      sheetsPackage([text(PLAIN_SHEET)], {
        contentTypes: Array.from(
          { length: 1_000 },
          (_, i) =>
            `<x ${attribute} PartName="/xl/externalLinks/externalLink${i + 1}.xml" ContentType="${EXTERNAL_LINK_TYPE}"/>`,
        ).join(""),
      });
    expect(refusal(() => readPackage(links(`0="<Override"`), LOOKUP_LINE, { bookSheets: true }))).toBe("partLookups");
    expect(refusal(() => readPackage(links(`x0="<Override"`), LOOKUP_LINE, { bookSheets: true }))).toBeUndefined();
  });

  it("looks for a renaming attribute in linear time", () => {
    // A million `:0_` in one string: a search whose `0_...` name ran over
    // colons started again at each, 3.4 s at 40,000 on the Mac.
    const crowded = worksheet(`<row r="1"><c r="A1" t="inlineStr"><is><t> 0_${":0_".repeat(1_000_000)}</t></is></c></row>`);
    const started = performance.now();
    expect(readSheet(sheetsPackage([text(crowded)]), "S1").rowCount).toBe(1);
    expect(performance.now() - started).toBeLessThan(2_000);
  });
});
