/**
 * Reads sheet S1 of one crafted package in its own process and prints one
 * JSON line: the refusal's budget line, or how many rows the read gave. The
 * test that starts it bounds its time, so a read that never ends fails that
 * test instead of stopping the runner.
 */
import { WorkbookBudgetError } from "../src/bridge/budget";
import { readSheet } from "../src/bridge/parse";
import { craftedPackage, type CraftedKind } from "./crafted-packages";

const bytes = craftedPackage(process.argv[2] as CraftedKind);
let answer: unknown;
try {
  answer = { read: readSheet(bytes, "S1").rowCount };
} catch (err) {
  answer = err instanceof WorkbookBudgetError ? { refused: err.line } : { failed: String(err) };
}
console.log(JSON.stringify(answer));
