/**
 * Web Worker entry: parses xlsx bytes off the main thread (OF-368 open
 * question #2 — "SheetJS parse in a worker; lazy sheet mount"). It is a thin
 * shell over a {@link ParseSessionStore}; all logic lives in
 * `handler.ts`/`parse.ts` so it can be tested without a Worker.
 */
/// <reference lib="webworker" />
import { ParseSessionStore } from "./handler";
import type { ParseRequest } from "./protocol";

const ctx = self as unknown as DedicatedWorkerGlobalScope;
const store = new ParseSessionStore();

ctx.onmessage = (event: MessageEvent<ParseRequest>) => {
  const response = store.handle(event.data);
  if (response !== null) {
    ctx.postMessage(response);
  }
};
