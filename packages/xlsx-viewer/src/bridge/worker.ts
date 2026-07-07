/**
 * Web Worker entry: parses xlsx bytes off the main thread (OF-368 open
 * question #2 — "SheetJS parse in a worker; lazy sheet mount"). It is a thin
 * shell over {@link handleParseRequest}; all logic is in `handler.ts`/`parse.ts`
 * so it can be tested without a Worker.
 */
/// <reference lib="webworker" />
import { handleParseRequest } from "./handler";
import type { ParseRequest } from "./protocol";

const ctx = self as unknown as DedicatedWorkerGlobalScope;

ctx.onmessage = (event: MessageEvent<ParseRequest>) => {
  ctx.postMessage(handleParseRequest(event.data));
};
