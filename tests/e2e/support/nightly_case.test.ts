/** The nightly-only case tag ([E2E-NIGHTLY-ONLY-CASE-TAG], Engine E2E-NIGHTLY-TODO = A): a nightly budget case
 * reports BLOCKED in a PR run and runs its body when the nightly stage sets E2E_NIGHTLY=1.
 * Pure: no Linux launch, no build manifest. */
import { test } from "bun:test";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { caseRegistry, expect, NIGHTLY_ENV, NIGHTLY_REASON, type IdResult } from "./run.ts";

/** Records what a case file registers with Bun instead of registering it. */
function recordingReporter() {
  const registered: { kind: "test" | "todo"; name: string; body: () => unknown }[] = [];
  const reporter = Object.assign(
    (name: string, body: () => unknown) => { registered.push({ kind: "test", name, body }) },
    { todo: (name: string, body: () => unknown) => { registered.push({ kind: "todo", name, body }) } });
  return { reporter: reporter as unknown as typeof test, registered };
}

test("a nightly case is BLOCKED without E2E_NIGHTLY=1 and runs its body with it", async () => {
  const root = await mkdtemp(join(tmpdir(), "e2e-nightly-case-"));
  try {
    const declaration = { profile: "deterministic", slots: 1 } as const;
    const report = async (path: string) => (JSON.parse(await readFile(path, "utf8")) as { results: IdResult[] }).results;
    let ran = 0;
    const body = () => { ran++; expect(ran).toBe(1) };

    const prRun = recordingReporter();
    const prSuite = caseRegistry("runs.test.ts", declaration, { E2E_RESULT_FILE: join(root, "pr.json") });
    prSuite.nightly(prRun.reporter, "RUNS-04", "wake stops at its wall-clock ceiling", body, 200_000);
    await prSuite.flush();
    expect(prRun.registered.map(r => [r.kind, r.name])).toEqual([["todo", `RUNS-04 wake stops at its wall-clock ceiling [${NIGHTLY_REASON}]`]]);
    expect(await report(join(root, "pr.json"))).toEqual([{ id: "RUNS-04", outcome: "BLOCKED", durationMs: 0, reason: NIGHTLY_REASON }]);
    expect(NIGHTLY_REASON).toContain("nightly budget case");
    expect(ran).toBe(0);

    const nightlyRun = recordingReporter();
    const nightlySuite = caseRegistry("runs.test.ts", declaration, { E2E_RESULT_FILE: join(root, "nightly.json"), [NIGHTLY_ENV]: "1" });
    nightlySuite.nightly(nightlyRun.reporter, "RUNS-04", "wake stops at its wall-clock ceiling", body, 200_000);
    expect(nightlyRun.registered.map(r => [r.kind, r.name])).toEqual([["test", "RUNS-04 wake stops at its wall-clock ceiling"]]);
    await nightlyRun.registered[0]!.body();
    expect(ran).toBe(1);
    expect(await report(join(root, "nightly.json"))).toMatchObject([{ id: "RUNS-04", outcome: "PASS", assertions: 1 }]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
