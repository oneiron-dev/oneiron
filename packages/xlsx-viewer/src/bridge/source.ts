/**
 * `WorkbookSource` — the lazy-mount seam the viewer renders against. It exposes
 * a cheap outline plus per-sheet loading, and caches each parsed sheet so a
 * given sheet is materialised at most once. The viewer mounts the active sheet
 * and loads the rest on demand, so a >25MB workbook never sits fully parsed in
 * memory.
 */
import { handleParseRequest } from "./handler";
import { readSheet, readWorkbookOutline } from "./parse";
import type { ParseOptions } from "./parse";
import type { OutlineResponse, ParseRequest, ParseResponse, SheetResponse } from "./protocol";
import type { IWorkbookData, IWorksheetData } from "@univerjs/core";

export interface WorkbookSource {
  /** Cheap: sheet names + order, every sheet a stub with empty `cellData`. */
  outline(): Promise<IWorkbookData>;
  /** Parse (and cache) one sheet's cells on demand. */
  sheet(sheetName: string): Promise<Partial<IWorksheetData>>;
  /** Sheet names already parsed and cached. */
  loadedSheets(): readonly string[];
  /** Release the worker/bytes. */
  dispose(): void;
}

/** Parses on the calling thread. Used in tests and non-worker contexts. */
export function createLocalWorkbookSource(
  bytes: Uint8Array,
  options: ParseOptions & { name?: string } = {},
): WorkbookSource {
  const { name = "workbook", ...parseOptions } = options;
  const cache = new Map<string, Partial<IWorksheetData>>();
  return {
    outline() {
      return Promise.resolve(readWorkbookOutline(bytes, name));
    },
    sheet(sheetName: string) {
      const cached = cache.get(sheetName);
      if (cached) {
        return Promise.resolve(cached);
      }
      const parsed = readSheet(bytes, sheetName, parseOptions);
      cache.set(sheetName, parsed);
      return Promise.resolve(parsed);
    },
    loadedSheets() {
      return [...cache.keys()];
    },
    dispose() {
      cache.clear();
    },
  };
}

/** Minimal Worker surface we depend on (keeps this testable without the DOM). */
export interface ParseWorkerLike {
  postMessage(message: ParseRequest): void;
  addEventListener(type: "message", listener: (event: { data: ParseResponse }) => void): void;
  removeEventListener(type: "message", listener: (event: { data: ParseResponse }) => void): void;
  terminate(): void;
}

/**
 * Parses in a Web Worker. `workerFactory` builds the worker (in app code:
 * `() => new Worker(new URL("./worker.ts", import.meta.url), { type: "module" })`),
 * injected so this stays testable with a fake worker.
 */
export function createWorkerWorkbookSource(
  bytes: Uint8Array,
  workerFactory: () => ParseWorkerLike,
  options: ParseOptions & { name?: string } = {},
): WorkbookSource {
  const { name = "workbook", ...parseOptions } = options;
  const worker = workerFactory();
  const cache = new Map<string, Partial<IWorksheetData>>();
  let nextId = 1;

  function request<T extends ParseResponse>(message: ParseRequest, wantKind: T["kind"]): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      const listener = (event: { data: ParseResponse }) => {
        const res = event.data;
        if (res.id !== message.id) {
          return;
        }
        worker.removeEventListener("message", listener);
        if (res.kind === "error") {
          reject(new Error(res.message));
        } else if (res.kind === wantKind) {
          resolve(res as T);
        } else {
          reject(new Error(`unexpected response kind ${res.kind} for request ${message.kind}`));
        }
      };
      worker.addEventListener("message", listener);
      worker.postMessage(message);
    });
  }

  return {
    async outline() {
      const res = await request<OutlineResponse>(
        { kind: "outline", id: nextId++, bytes, name },
        "outline",
      );
      return res.workbook;
    },
    async sheet(sheetName: string) {
      const cached = cache.get(sheetName);
      if (cached) {
        return cached;
      }
      const res = await request<SheetResponse>(
        { kind: "sheet", id: nextId++, bytes, sheetName, options: parseOptions },
        "sheet",
      );
      cache.set(sheetName, res.sheet);
      return res.sheet;
    },
    loadedSheets() {
      return [...cache.keys()];
    },
    dispose() {
      cache.clear();
      worker.terminate();
    },
  };
}

/**
 * In-process worker stand-in that runs {@link handleParseRequest} synchronously
 * behind the async message API. Lets tests drive the exact worker code path
 * (and the app fall back) without a real Worker.
 */
export function createInlineParseWorker(): ParseWorkerLike {
  const listeners = new Set<(event: { data: ParseResponse }) => void>();
  return {
    postMessage(message: ParseRequest) {
      const response = handleParseRequest(message);
      queueMicrotask(() => {
        for (const listener of listeners) {
          listener({ data: response });
        }
      });
    },
    addEventListener(_type, listener) {
      listeners.add(listener);
    },
    removeEventListener(_type, listener) {
      listeners.delete(listener);
    },
    terminate() {
      listeners.clear();
    },
  };
}
