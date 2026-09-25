/** Local interpreter functions. These are not host effects. */
declare function finish(value: unknown): void;
declare function writeOutput(path: `/mnt/outputs/${string}`, bytes: Uint8Array | number[]): void;
declare const console: { log(...values: unknown[]): void };
/** Foreign tier only. Proposals are data; they never commit host writes. */
declare const propose: {
  file(path: `/mnt/outputs/${string}` | `/mnt/workspace/${string}`, bytes: Uint8Array | number[]): void;
  claim(input: { id: string; predicate: string; subject: unknown; value: unknown; confidence?: number; occurred?: { start: number; end: number }; learnedAt?: number }): void;
};
