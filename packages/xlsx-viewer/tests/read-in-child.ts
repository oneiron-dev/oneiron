/**
 * Reads one crafted package in its own process, through one door (`sheet`,
 * the default: sheet S1; or `outline`), and prints one JSON line: the answer
 * (the refusal's budget line, or how many rows or sheets the read gave), how
 * long the read took, and the most resident memory the child held. The test that starts it bounds its time, and a
 * watch on its own thread ({@link ./memory-watch.ts}) bounds its memory, so a
 * read that never ends fails that test instead of stopping the runner.
 */
import { WorkbookBudgetError } from "../src/bridge/budget";
import { readSheet, readWorkbookOutline } from "../src/bridge/parse";
import type { ChildDoor } from "./child-read";
import { craftedPackage, type CraftedKind } from "./crafted-packages";

const watch = new Worker(`${import.meta.dir}/memory-watch.ts`);
await new Promise<void>((resolve) => {
  watch.onmessage = () => resolve();
});
const door = (process.argv[3] ?? "sheet") as ChildDoor;
const bytes = craftedPackage(process.argv[2] as CraftedKind);
const started = performance.now();
let answer: unknown;
try {
  answer =
    door === "outline"
      ? { sheets: readWorkbookOutline(bytes).sheetOrder.length }
      : { read: readSheet(bytes, "S1").rowCount };
} catch (err) {
  answer = err instanceof WorkbookBudgetError ? { refused: err.line } : { failed: String(err) };
}
const readMs = Math.round(performance.now() - started);
const peakBytes = await new Promise<number>((resolve) => {
  watch.onmessage = (event: MessageEvent<number>) => resolve(event.data);
  watch.postMessage("peak");
});
console.log(JSON.stringify({ answer, readMs, peakMiB: Math.round(peakBytes / 1024 ** 2) }));
watch.terminate();
