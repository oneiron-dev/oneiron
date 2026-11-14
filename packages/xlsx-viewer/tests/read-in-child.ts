/**
 * Reads one crafted package in its own process, through one door (`sheet`,
 * the default: sheet S1; or `outline`), and prints one JSON line: the answer
 * (the refusal's budget line, or how many rows or sheets the read gave) and
 * how long the read took. The test that starts it bounds its time, and a
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
console.log(JSON.stringify({ answer, readMs: Math.round(performance.now() - started) }));
watch.terminate();
