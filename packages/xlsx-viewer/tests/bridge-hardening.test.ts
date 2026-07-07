import { describe, expect, it } from "bun:test";
import * as XLSX from "xlsx";
import { ParseSessionStore } from "../src/bridge/handler";
import { readSheet, readWorkbookOutline, sheetId, worksheetToCellData } from "../src/bridge/parse";
import { createWorkerWorkbookSource, type ParseWorkerLike } from "../src/bridge/source";
import type { ParseRequest, ParseResponse } from "../src/bridge/protocol";
import { makeXlsxBytes } from "./helpers";

type Cell = { v?: unknown; t?: number; custom?: { oneironFormula?: string } };
type Matrix = Record<number, Record<number, Cell>>;

describe("parse: sparse-sheet coordinate explosion (#4)", () => {
  it("iterates actual cells, not the full !ref rectangle", () => {
    // Inflated dimension (A1:XFD1048576) but two far-apart cells. Iterating the
    // rectangle would be ~1.7e10 steps; iterating keys is two.
    const ws = {
      "!ref": "A1:XFD1048576",
      A1: { t: "n", v: 1 },
      ZZ100: { t: "s", v: "far" },
    } as unknown as XLSX.WorkSheet;
    const start = Date.now();
    const out = worksheetToCellData(ws, true);
    expect(Date.now() - start).toBeLessThan(1000);
    expect(out.rowCount).toBe(1048576);
    expect(out.columnCount).toBe(16384);
    const cd = out.cellData as unknown as Matrix;
    expect(cd[0]?.[0]?.v).toBe(1);
    expect(cd[99]?.[701]?.v).toBe("far"); // ZZ100
  }, 5000);
});

describe("parse: cell value coercion", () => {
  function oneSheet(mutate: (ws: XLSX.WorkSheet) => void): Uint8Array {
    const wb = XLSX.utils.book_new();
    const ws = XLSX.utils.aoa_to_sheet([[true, false]]);
    mutate(ws);
    XLSX.utils.book_append_sheet(wb, ws, "S1");
    return new Uint8Array(XLSX.write(wb, { type: "array", bookType: "xlsx" }) as ArrayBuffer);
  }

  it("emits boolean cells as 0|1, not JS booleans (#8)", () => {
    const cd = readSheet(oneSheet(() => {}), "S1").cellData as unknown as Matrix;
    expect(cd[0]?.[0]).toEqual({ v: 1, t: 3 });
    expect(cd[0]?.[1]).toEqual({ v: 0, t: 3 });
  });

  it("never emits NaN for a formula cell with no cached value (#3)", () => {
    const bytes = oneSheet((ws) => {
      (ws as Record<string, unknown>)["C1"] = { t: "n", f: "A1+A1" }; // formula, no cached v
      (ws as Record<string, unknown>)["!ref"] = "A1:C1";
    });
    const c1 = (readSheet(bytes, "S1").cellData as unknown as Matrix)[0]?.[2];
    expect(c1).toBeDefined();
    expect("v" in (c1 ?? {})).toBe(false);
    expect(c1?.custom?.oneironFormula).toBe("=A1+A1");
  });
});

describe("parse: sheet ids are collision-free (#5)", () => {
  it("distinguishes the codex collision pair", () => {
    expect(sheetId("7SRY2R")).not.toBe(sheetId("831Y2R"));
  });

  it("keeps both colliding-hash sheets in the workbook outline", () => {
    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, XLSX.utils.aoa_to_sheet([[1]]), "7SRY2R");
    XLSX.utils.book_append_sheet(wb, XLSX.utils.aoa_to_sheet([[2]]), "831Y2R");
    const bytes = new Uint8Array(XLSX.write(wb, { type: "array", bookType: "xlsx" }) as ArrayBuffer);
    const outline = readWorkbookOutline(bytes);
    expect(outline.sheetOrder).toHaveLength(2);
    const names = outline.sheetOrder.map((sid) => outline.sheets[sid]?.name).sort();
    expect(names).toEqual(["7SRY2R", "831Y2R"]);
  });
});

interface RecordingWorker extends ParseWorkerLike {
  readonly requests: ParseRequest[];
}

function recordingWorker(): RecordingWorker {
  const store = new ParseSessionStore();
  const listeners = new Set<(e: { data: ParseResponse }) => void>();
  const requests: ParseRequest[] = [];
  return {
    requests,
    postMessage(message: ParseRequest) {
      requests.push(message);
      const res = store.handle(message);
      if (res) {
        queueMicrotask(() => {
          for (const l of listeners) l({ data: res });
        });
      }
    },
    addEventListener(type: "message" | "error", listener: (e: { data: ParseResponse }) => void) {
      if (type === "message") listeners.add(listener);
    },
    removeEventListener(type: "message" | "error", listener: (e: { data: ParseResponse }) => void) {
      if (type === "message") listeners.delete(listener);
    },
    terminate() {
      listeners.clear();
    },
  } as RecordingWorker;
}

describe("worker source: bytes cross the wire exactly once (#1)", () => {
  it("sends bytes only in init; sheet requests carry ids only", async () => {
    const bytes = makeXlsxBytes({ sheets: 2, rows: 5, cols: 3 });
    const worker = recordingWorker();
    const source = createWorkerWorkbookSource(bytes, () => worker);
    await source.outline();
    await source.sheet("S1");
    await source.sheet("S2");
    const withBytes = worker.requests.filter((r) => "bytes" in r);
    expect(withBytes).toHaveLength(1);
    expect(withBytes[0]!.kind).toBe("init");
    expect(worker.requests.filter((r) => r.kind === "sheet")).toHaveLength(2);
    source.dispose();
  });
});

describe("worker source: cancellation on dispose (#2)", () => {
  const silent: ParseWorkerLike = {
    postMessage() {},
    addEventListener() {},
    removeEventListener() {},
    terminate() {},
  };

  it("rejects an in-flight request instead of hanging", async () => {
    const bytes = makeXlsxBytes({ sheets: 1, rows: 2, cols: 2 });
    const source = createWorkerWorkbookSource(bytes, () => silent);
    const pending = source.outline();
    source.dispose();
    await expect(pending).rejects.toThrow(/disposed/);
  });

  it("rejects new requests after dispose", async () => {
    const bytes = makeXlsxBytes({ sheets: 1, rows: 2, cols: 2 });
    const source = createWorkerWorkbookSource(bytes, () => silent);
    source.dispose();
    await expect(source.sheet("S1")).rejects.toThrow(/disposed/);
  });
});
