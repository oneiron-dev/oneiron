/** Local interpreter functions. These are not host effects. A step's result
 * has no size limit: it streams to the host as it is written, and a large one
 * comes back as a handle and a preview. */
/** Ends the step with `value` as its result; a later call replaces it. */
declare function finish(value: unknown): void;
/** Appends `bytes` to the step's file at `path`: call it again to write a
 * large file in pieces. */
declare function writeOutput(path: `/mnt/outputs/${string}`, bytes: Uint8Array | number[]): void;
declare const console: { log(...values: unknown[]): void };
/** A host answer too large for one reply (a `self.memory` verb answer past
 * 512 KiB of JSON) arrives as this handle in its place; nothing is refused for
 * its size. Read the stored body a chunk at a time:
 * `await sandbox.fs.read_file(`${r.read}/chunk/${offset}`)` returns up to
 * 64 KiB from `offset`. `name` is the run's name for it (`r3`), which later
 * steps pass to `describe`. A tainted result shows no preview and no shape.
 * Its reads are methods as well, which are not fields of its JSON:
 * `r.slice(...)`, `r.search(...)`, `r.query(...)`, `r.chunks(...)` and
 * `r.describe()` read it as the functions of the same names do. */
declare interface StoredResult {
  handle: string;
  name: string;
  bytes: number;
  kind: "text" | "binary";
  /** Absent on a range's card. */
  lines?: number;
  complete: boolean;
  preview: string;
  taint: { state: "clean" | "tainted_live" | "tainted_stale"; secret: string | null };
  read: `/mnt/outputs/.oneiron-result/${string}`;
  /** The reads that take the body apart without loading it. */
  more: ("slice" | "search" | "query" | "chunks")[];
  /** What the body's first 64 KiB show of its format; absent while it is
   * not clean. */
  shape?: ResultShape;
  /** On a range's card: the range's own ref and where it sits in its parent. */
  ref?: string;
  range?: [number, number];
  slice(sel: SliceSelection): Promise<SliceReply | WithheldReply>;
  search(pattern: string, opts?: SearchOptions): Promise<SearchReply | WithheldReply>;
  query(q: string | QuerySelection): Promise<QueryReply | WithheldReply>;
  chunks(by: ChunkBy): ResultChunks;
  describe(): Promise<StoredResult>;
}
/** A result as the reads take it: its name (`r7`), its handle, a range of
 * either (`r7#0-4096`, byte offsets, half-open), or a card or chunk. */
type ResultRef = StoredResult | ChunkRef | string;
type ResultShape =
  | { format: "json"; top: "object" | "array" | "string" | "number" | "bool" | "null"; keys?: string[]; partial: boolean }
  | { format: "jsonl" | "csv" | "tsv"; columns: string[] }
  | { format: "text" | "binary" };
/** What a read of a result holding a secret, or under a custody hold,
 * answers in place of any of its content. It is not a size limit. */
declare interface WithheldReply {
  withheld: "tainted_live" | "tainted_stale";
  ref: string;
  bytes: number;
  lines: number | null;
  kind: "text" | "binary";
  taint: { state: "tainted_live" | "tainted_stale"; secret: string | null };
  reason: string;
}
/** Where a read that stopped at `limits.code_result_scan_bytes` goes on. */
declare interface LineCursor { offset: number; line: number }
/** Bytes or lines (from 0, half-open; the end defaults to the end). Lines
 * are for text only. */
type SliceSelection = { bytes: [number, number?] } | { lines: [number, number?]; cursor?: LineCursor };
declare interface SliceReply {
  ref: string;
  /** The byte range returned; text is cut at character boundaries. */
  start: number;
  end: number;
  /** Text bodies: the text, with `lossy` set when a byte was replaced. */
  text?: string;
  lossy?: true;
  /** Binary bodies: the bytes as base64. */
  base64?: string;
  /** The first and last line (from 0) the text touches. */
  lines?: [number, number];
  done: boolean;
  /** Pass it back as the selection to read on. */
  next?: SliceSelection;
  scanned?: [number, number];
  limit?: "limits.code_result_scan_bytes";
}
/** A literal by default; `regex` takes Rust regex syntax (no lookaround or
 * backreferences). A binary body is searched by the pattern's bytes. */
declare interface SearchOptions {
  regex?: boolean;
  ignoreCase?: boolean;
  /** Matches per call; 100 by default. */
  limit?: number;
  /** Bytes of context each side; 80 by default, at most 1024. */
  context?: number;
  cursor?: SearchCursor;
}
declare interface SearchCursor { offset: number; line: number }
/** One match: its byte offset, length and line (from 0), its text (up to
 * 1 KiB) and its context; base64 throughout for a binary body. */
declare interface SearchMatch {
  offset: number;
  len: number;
  line: number;
  text: string;
  before: string;
  after: string;
  /** A match longer than the 8 MiB search window, cut at its end. */
  truncated?: true;
}
/** `done: false` with `next` means bytes are left to search: never read it
 * as "no match". */
declare interface SearchReply {
  ref: string;
  matches: SearchMatch[];
  encoding: "utf8" | "base64";
  scanned: [number, number];
  done: boolean;
  next?: SearchCursor;
  limit?: "limits.code_result_scan_bytes";
}
/** A JSON path (`$`, `.key`, `["key"]`, `[i]`, `[*]`) into a JSON body, or
 * rows of JSON lines, CSV or TSV (a table reads as an array of its rows).
 * `where` is `{column: value}` (each equal) or `[[column, op, value]]`;
 * numbers compare as numbers, strings lexically, `contains` tests a
 * substring or array member. `columns` keeps only those columns. */
declare interface QuerySelection {
  path?: string;
  columns?: string[];
  where?: Record<string, unknown> | [string, "=" | "!=" | "<" | "<=" | ">" | ">=" | "contains", unknown][];
  limit?: number;
  cursor?: QueryCursor;
}
declare interface QueryCursor { offset?: number; row?: number; skip?: number }
/** `value` for a path that picks one value, `values` for a `[*]` path,
 * `rows` with `columns` or `where`. A selection too big for one reply is
 * stored as a new result of the run and comes back as `derived`. */
type QueryReply =
  | {
      ref: string;
      value?: unknown;
      values?: unknown[];
      rows?: Record<string, unknown>[];
      count: number;
      done: boolean;
      next?: QueryCursor;
      skipped?: number;
      limit?: "limits.code_result_scan_bytes";
    }
  | { derived: StoredResult; count: number; done: boolean; next?: QueryCursor };
/** Chunks of `bytes` or of `lines` each (lines for text only), `overlap`
 * of the same unit, a byte chunk ending at the next newline by default for
 * text. `tokens` (text only, alone) grows each chunk line by line to about
 * that many tokens of the executor's tokenizer, at most `max_bytes`; one
 * call tokenizes at most 8 MiB and answers `next` to go on. */
declare interface ChunkBy {
  bytes?: number;
  lines?: number;
  tokens?: number;
  max_bytes?: number;
  overlap?: number;
  align?: "line" | "none";
  cursor?: ChunkCursor;
}
declare interface ChunkCursor { offset: number; line?: number }
/** One chunk: a range of its parent, read as any result is. `start` and
 * `end` are the parent's byte offsets. */
declare interface ChunkRef {
  ref: string;
  start: number;
  end: number;
  lines?: [number, number];
  /** A chunk cut short of its size (no newline near, or the scan bound). */
  cut?: true;
  slice(sel: SliceSelection): Promise<SliceReply | WithheldReply>;
  search(pattern: string, opts?: SearchOptions): Promise<SearchReply | WithheldReply>;
  query(q: string | QuerySelection): Promise<QueryReply | WithheldReply>;
  chunks(by: ChunkBy): ResultChunks;
  describe(): Promise<StoredResult>;
}
declare interface ChunkPage {
  ref: string;
  chunks: ChunkRef[];
  done: boolean;
  next?: ChunkCursor;
  limit?: "limits.code_result_scan_bytes";
}
/** Iterated with `for await`, a page per host call, fetched only as it is
 * reached; `page(cursor?)` answers one page. */
declare interface ResultChunks extends AsyncIterable<ChunkRef> {
  page(cursor?: ChunkCursor): Promise<ChunkPage | WithheldReply>;
}
/** Stores `value` as a result of the run and binds it to `name`, or to the
 * next free `r<n>`: a string as given, any other value as its JSON. The name
 * outlives the step; the value is never held whole in the interpreter.
 * `sources` are the results the value was made from: it inherits their
 * taint. `receipt` names a fold's inputs (the source it read, the reader
 * tasks it read it by, its summary tree); the host checks them, computes
 * the fold receipt and keeps it with the binding, and the card says what
 * was read. */
declare function store(value: unknown, name?: string, options?: StoreOptions): Promise<StoredResult & { receipt?: FoldCoverage }>;
declare interface StoreOptions {
  sources?: ResultRef[];
  receipt?: { source: ResultRef; tasks: string[]; tree?: { summary: ResultRef; inputs: ResultRef[] }[]; recipe?: unknown };
}
/** What a fold read of its source, in its byte offsets: ranges its readers
 * finished, ranges none read, readers that stopped short and why, and how
 * many it named. */
declare interface FoldCoverage {
  read: [number, number][];
  unread: [number, number][];
  partial: { task: string; reason: string }[];
  children: number;
}
/** One model call over a result and the results after it (`group`), made
 * by a host job, never inside the step, and memoised by those results and
 * the recipe: the same call again answers the same summary. A made summary
 * answers its card (with its `task`); `defer: true` answers `{task, state}`
 * at once, to wait on with `tasks.wait`; without it the run parks until the
 * summary is made, and the same call in a later step answers it. A withheld
 * member answers its withheld reply, and nothing is summarized. A group too
 * big for the model's window settles `group_exceeds_window`: split it. */
declare function summarize(r: ResultRef, opts?: { effort?: "low" | "medium" | "high"; group?: ResultRef[]; defer?: boolean }):
  Promise<(StoredResult & { task: string }) | { task: string; state: "queued" | "active" | "failed" | "partial" | "done"; reason?: string } | WithheldReply>;
/** Reads a result with reader children and folds what they find (an SDK
 * helper, not an engine verb): `can` first, then chunks of half the child
 * window, one `self.spawn` per chunk, `tasks.wait` until `until` (the
 * children's cutoff by default) or `n_of` of them, findings deduped by the
 * ranges they cite, then staged `summarize` groups until one is left, stored
 * as `rf_<key>` with a fold receipt. It runs in phases: call it again with
 * the same arguments until `done`; a parked phase goes on once the run
 * resumes. A refused source answers `{done: true, refused}`. */
declare function readAll(r: ResultRef, opts: { ask: string; by?: ChunkBy; window?: number; until?: number; n_of?: number; effort?: "low" | "medium" | "high"; key?: string }):
  Promise<{ done: true; result: StoredResult; coverage: FoldCoverage | null } | { done: true; refused: string; detail?: unknown } | { done: false; phase: string; waiting?: true; progress: { chunks: number; spawned: number; findings: number; groups: number; level: number } }>;
/** A diff of two results (an SDK helper, not an engine verb), stated in
 * `algorithm`: by lines, Myers' O(ND) inside lockstep windows of 4096 lines,
 * a hunk a window edge cuts closed there (`edge`), and a window past 512
 * edits one `coarse` hunk; by bytes, 64 KiB blocks compared. Hunks carry no
 * context lines, with both sides' offsets (from 0). Hunk text past 1 MiB is
 * stored as a result made from both (`stored`). Past one step's calls it
 * answers `next`: pass it back as `from`. */
declare function diff(a: ResultRef, b: ResultRef, opts?: { by?: "lines" | "bytes"; from?: { window: number }; name?: string }):
  Promise<{ algorithm: "myers-windowed/v1" | "blocks/v1"; window: number; by: "lines" | "bytes"; count: number; done: boolean; next?: { window: number };
    hunks?: { a: [number, number]; b: [number, number]; text: string; edge?: true; coarse?: true }[]; stored?: StoredResult } | { refused: string; ref: string; detail?: unknown }>;
/** The card of a result of this run, by its name, its handle, a range or its
 * card. An unknown name throws `unknown_handle` with the live names. Start a
 * big result here: its `shape` says which read fits. */
declare function describe(r: ResultRef): Promise<StoredResult>;
/** Bytes or lines of a result, at most one reply, with `next` to read on.
 * After `search`, slice around a match's `offset`. */
declare function slice(r: ResultRef, sel: SliceSelection): Promise<SliceReply | WithheldReply>;
/** Finds `pattern` in a result, each match with its offset, line and
 * context; then slice around the offset. Follow `next` until `done`. */
declare function search(r: ResultRef, pattern: string, opts?: SearchOptions): Promise<SearchReply | WithheldReply>;
/** Reads a big JSON result by path, or a table by column and row; a big
 * selection comes back as a stored result (`derived`) to read in turn. */
declare function query(r: ResultRef, q: string | QuerySelection): Promise<QueryReply | WithheldReply>;
/** Cuts a result into range refs to read or hand on one at a time, copying
 * nothing: `for await (const c of chunks(r, {lines: 2000})) ...`. */
declare function chunks(r: ResultRef, by: ChunkBy): ResultChunks;
/** Whether this run may read a result now, by the checks every read of it
 * makes (its served rows, then its taint), without reading it: no preview,
 * no bytes. A read made after still makes them. With `child: {}`, also
 * whether `self.spawn` could hand it to a reader child now, by the checks a
 * spawn makes, spawning nothing. */
declare function can(input: { read: ResultRef; child?: {} }): Promise<CanReadReply>;
/** `can({read})`'s answer: the result's ref, size, kind and taint, or why
 * not, with the detail a read of it would refuse with. With `child`, the
 * children's cutoff, the meter they spend on (`scope`, with what it may
 * still spend, or `host`, the host's own meter, with no figure), the window
 * of the model they run on, in tokens, and the memory one child may hold. */
type CanReadReply =
  | { can: true; ref: string; bytes: number; kind: "text" | "binary"; taint: { state: "clean"; secret: null }; child?: { cutoff_unix_ms: number; meter: "scope" | "host"; spend_available_units?: number; window_tokens: number; memory_bytes: number } }
  | { can: false; reason: "unknown_handle" | "withheld_rows" | "tainted" | "outside_delegated_range" | "reader_task_settled" | "spawn_unbound" | "past_cutoff" | "unmetered" | "denied"; [detail: string]: unknown };
/** Foreign tier only. Proposals are data; they never commit host writes. */
declare const propose: {
  file(path: `/mnt/outputs/${string}` | `/mnt/workspace/${string}`, bytes: Uint8Array | number[]): void;
  claim(input: { id: string; predicate: string; subject: unknown; value: unknown; confidence?: number; occurred?: { start: number; end: number }; learnedAt?: number }): void;
  delete(path: `/mnt/workspace/${string}`): void;
  rename(from: `/mnt/workspace/${string}`, to: `/mnt/workspace/${string}`): void;
};
