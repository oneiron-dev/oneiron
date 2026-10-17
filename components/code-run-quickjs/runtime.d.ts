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
 * text. */
declare interface ChunkBy {
  bytes?: number;
  lines?: number;
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
 * outlives the step; the value is never held whole in the interpreter. */
declare function store(value: unknown, name?: string): Promise<StoredResult>;
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
 * children's cutoff and what their scope may still spend. */
type CanReadReply =
  | { can: true; ref: string; bytes: number; kind: "text" | "binary"; taint: { state: "clean"; secret: null }; child?: { cutoff_unix_ms: number; spend_available_units: number } }
  | { can: false; reason: "unknown_handle" | "withheld_rows" | "tainted" | "outside_delegated_range" | "reader_task_settled" | "spawn_unbound" | "past_cutoff" | "unmetered" | "denied"; [detail: string]: unknown };
/** Foreign tier only. Proposals are data; they never commit host writes. */
declare const propose: {
  file(path: `/mnt/outputs/${string}` | `/mnt/workspace/${string}`, bytes: Uint8Array | number[]): void;
  claim(input: { id: string; predicate: string; subject: unknown; value: unknown; confidence?: number; occurred?: { start: number; end: number }; learnedAt?: number }): void;
  delete(path: `/mnt/workspace/${string}`): void;
  rename(from: `/mnt/workspace/${string}`, to: `/mnt/workspace/${string}`): void;
};
