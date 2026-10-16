/** Local interpreter functions. These are not host effects. A step's result
 * has no size limit: it streams to the host as it is written, and a large one
 * comes back as a handle and a preview. */
/** Ends the step with `value` as its result; a later call replaces it. */
declare function finish(value: unknown): void;
/** Appends `bytes` to the step's file at `path`: call it again to write a
 * large file in pieces. */
declare function writeOutput(path: `/mnt/outputs/${string}`, bytes: Uint8Array | number[]): void;
declare const console: { log(...values: unknown[]): void };
/** Foreign tier only. Proposals are data; they never commit host writes. */
declare const propose: {
  file(path: `/mnt/outputs/${string}` | `/mnt/workspace/${string}`, bytes: Uint8Array | number[]): void;
  claim(input: { id: string; predicate: string; subject: unknown; value: unknown; confidence?: number; occurred?: { start: number; end: number }; learnedAt?: number }): void;
  delete(path: `/mnt/workspace/${string}`): void;
  rename(from: `/mnt/workspace/${string}`, to: `/mnt/workspace/${string}`): void;
};
