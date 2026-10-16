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
 * steps pass to `describe`. A tainted result shows no preview. */
declare interface StoredResult {
  handle: string;
  name: string;
  bytes: number;
  kind: "text" | "binary";
  lines: number;
  complete: boolean;
  preview: string;
  taint: { state: "clean" | "tainted_live" | "tainted_stale"; secret: string | null };
  read: `/mnt/outputs/.oneiron-result/${string}`;
}
/** Stores `value` as a result of the run and binds it to `name`, or to the
 * next free `r<n>`: a string as given, any other value as its JSON. The name
 * outlives the step; the value is never held whole in the interpreter. */
declare function store(value: unknown, name?: string): Promise<StoredResult>;
/** The card of a result of this run, by its name, its handle or its card. An
 * unknown name throws `unknown_handle` with the live names. */
declare function describe(r: StoredResult | string): Promise<StoredResult>;
/** Foreign tier only. Proposals are data; they never commit host writes. */
declare const propose: {
  file(path: `/mnt/outputs/${string}` | `/mnt/workspace/${string}`, bytes: Uint8Array | number[]): void;
  claim(input: { id: string; predicate: string; subject: unknown; value: unknown; confidence?: number; occurred?: { start: number; end: number }; learnedAt?: number }): void;
  delete(path: `/mnt/workspace/${string}`): void;
  rename(from: `/mnt/workspace/${string}`, to: `/mnt/workspace/${string}`): void;
};
