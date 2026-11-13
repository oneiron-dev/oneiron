/**
 * Reads sheet S1 of one crafted package in its own process and prints one
 * JSON line: the refusal's budget line, or how many rows the read gave. The
 * test that starts it bounds its time, and a watch on its own thread
 * ({@link ./memory-watch.ts}) bounds its memory, so a read that never ends
 * fails that test instead of stopping the runner.
 */
import { WorkbookBudgetError } from "../src/bridge/budget";
import { readSheet } from "../src/bridge/parse";
import { craftedPackage, type CraftedKind } from "./crafted-packages";

const watch = new Worker(`${import.meta.dir}/memory-watch.ts`);
await new Promise<void>((resolve) => {
  watch.onmessage = () => resolve();
});
watch.unref();
const bytes = craftedPackage(process.argv[2] as CraftedKind);
let answer: unknown;
try {
  answer = { read: readSheet(bytes, "S1").rowCount };
} catch (err) {
  answer = err instanceof WorkbookBudgetError ? { refused: err.line } : { failed: String(err) };
}
console.log(JSON.stringify(answer));
