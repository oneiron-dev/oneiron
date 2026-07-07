/**
 * `WorkbookSource` — the lazy-mount seam the viewer renders against. It exposes
 * a cheap outline plus per-sheet loading, and caches each parsed sheet so a
 * given sheet is materialised at most once. The viewer mounts the active sheet
 * and loads the rest on demand, so a >25MB workbook never sits fully parsed in
 * memory.
 */
import { ParseSessionStore } from "./handler";
import { readSheet, readWorkbookOutline } from "./parse";
import type { ParseOptions } from "./parse";
import type { InitResponse, ParseRequest, ParseResponse, SheetResponse } from "./protocol";
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

type ParseMessageListener = (event: { data: ParseResponse }) => void;
type ParseErrorListener = (event: { message?: string }) => void;

/** Minimal Worker surface we depend on (keeps this testable without the DOM). */
export interface ParseWorkerLike {
  postMessage(message: ParseRequest, transfer?: Transferable[]): void;
  addEventListener(type: "message", listener: ParseMessageListener): void;
  addEventListener(type: "error", listener: ParseErrorListener): void;
  removeEventListener(type: "message", listener: ParseMessageListener): void;
  removeEventListener(type: "error", listener: ParseErrorListener): void;
  terminate(): void;
}

let sessionCounter = 0;

/**
 * Parses in a Web Worker. `workerFactory` builds the worker (in app code:
 * `() => new Worker(new URL("./worker.ts", import.meta.url), { type: "module" })`),
 * injected so this stays testable with a fake worker.
 *
 * Bytes are transferred to the worker exactly ONCE (on first use); subsequent
 * sheet requests carry only the session id. In-flight requests are tracked so
 * `dispose()` (or a worker error) rejects them instead of hanging.
 */
export function createWorkerWorkbookSource(
  bytes: Uint8Array,
  workerFactory: () => ParseWorkerLike,
  options: ParseOptions & { name?: string } = {},
): WorkbookSource {
  const { name = "workbook", ...parseOptions } = options;
  const worker = workerFactory();
  const session = `xlsx-${(sessionCounter += 1)}-${Date.now().toString(36)}`;
  const cache = new Map<string, Partial<IWorksheetData>>();
  const pending = new Map<number, { resolve: (res: ParseResponse) => void; reject: (err: Error) => void }>();
  let nextId = 1;
  let disposed = false;
  let initPromise: Promise<IWorkbookData> | null = null;

  const onMessage: ParseMessageListener = (event) => {
    const res = event.data;
    const entry = pending.get(res.id);
    if (!entry) {
      return;
    }
    pending.delete(res.id);
    if (res.kind === "error") {
      entry.reject(new Error(res.message));
    } else {
      entry.resolve(res);
    }
  };
  const onError: ParseErrorListener = (event) => {
    rejectAll(new Error(`parse worker error: ${event.message ?? "unknown"}`));
  };

  function rejectAll(err: Error): void {
    for (const entry of pending.values()) {
      entry.reject(err);
    }
    pending.clear();
  }

  worker.addEventListener("message", onMessage);
  worker.addEventListener("error", onError);

  function send<T extends ParseResponse>(
    build: (id: number) => ParseRequest,
    wantKind: T["kind"],
    transfer?: Transferable[],
  ): Promise<T> {
    if (disposed) {
      return Promise.reject(new Error("workbook source disposed"));
    }
    const id = (nextId += 1);
    const message = build(id);
    return new Promise<T>((resolve, reject) => {
      pending.set(id, {
        resolve: (res) =>
          res.kind === wantKind
            ? resolve(res as T)
            : reject(new Error(`unexpected response kind ${res.kind} for ${message.kind}`)),
        reject,
      });
      try {
        if (transfer) {
          worker.postMessage(message, transfer);
        } else {
          worker.postMessage(message);
        }
      } catch (err) {
        pending.delete(id);
        reject(err instanceof Error ? err : new Error(String(err)));
      }
    });
  }

  function ensureInit(): Promise<IWorkbookData> {
    if (!initPromise) {
      // Transfer a COPY so the caller's `bytes` are not detached; the workbook
      // crosses the wire exactly once, never per request.
      const copy = bytes.slice();
      initPromise = send<InitResponse>(
        (id) => ({ kind: "init", id, session, bytes: copy, name }),
        "init",
        [copy.buffer],
      ).then((res) => res.workbook);
    }
    return initPromise;
  }

  return {
    outline() {
      return ensureInit();
    },
    async sheet(sheetName: string) {
      const cached = cache.get(sheetName);
      if (cached) {
        return cached;
      }
      await ensureInit();
      const res = await send<SheetResponse>(
        (id) => ({ kind: "sheet", id, session, sheetName, options: parseOptions }),
        "sheet",
      );
      cache.set(sheetName, res.sheet);
      return res.sheet;
    },
    loadedSheets() {
      return [...cache.keys()];
    },
    dispose() {
      if (disposed) {
        return;
      }
      disposed = true;
      rejectAll(new Error("workbook source disposed"));
      try {
        worker.postMessage({ kind: "dispose", session });
      } catch {
        // worker may already be gone; nothing to free
      }
      worker.removeEventListener("message", onMessage);
      worker.removeEventListener("error", onError);
      cache.clear();
      worker.terminate();
    },
  };
}

/**
 * In-process worker stand-in backed by a real {@link ParseSessionStore}. Lets
 * tests drive the exact worker code path (and the app fall back) without a real
 * Worker. Transfers are ignored (same process); `error` events never fire.
 */
export function createInlineParseWorker(): ParseWorkerLike {
  const store = new ParseSessionStore();
  const messageListeners = new Set<ParseMessageListener>();
  return {
    postMessage(message: ParseRequest, _transfer?: Transferable[]) {
      const response = store.handle(message);
      if (response === null) {
        return;
      }
      queueMicrotask(() => {
        for (const listener of messageListeners) {
          listener({ data: response });
        }
      });
    },
    addEventListener(type: "message" | "error", listener: ParseMessageListener | ParseErrorListener) {
      if (type === "message") {
        messageListeners.add(listener as ParseMessageListener);
      }
    },
    removeEventListener(type: "message" | "error", listener: ParseMessageListener | ParseErrorListener) {
      if (type === "message") {
        messageListeners.delete(listener as ParseMessageListener);
      }
    },
    terminate() {
      messageListeners.clear();
    },
  };
}
