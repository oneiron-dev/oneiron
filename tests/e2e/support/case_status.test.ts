/** The runner sets each case's status (L8-01-L8-03-MECH 5A): one fixture row per status, the reds PROVEN refuses,
 * and the counted expect that tells a probe from a written case. Pure: no Linux launch, no build manifest. */
import { describe, test } from "bun:test";
import { caseStatus, expect, observeAssertions, withStatuses, type IdResult } from "./run.ts";

const HEAD = "b".repeat(40);
const EARLIER = "a".repeat(40);
const row = (fields: Partial<IdResult> & Pick<IdResult, "outcome">): IdResult => ({ id: "BOOT-01", durationMs: 1, ...fields });
const assertionRed = row({ outcome: "FAIL", assertions: 2, failedAssertion: true, reason: "expect(received).toBe(expected)" });

describe("caseStatus", () => {
  test("PLANNED: no body ran", () => {
    expect(caseStatus(undefined, HEAD)).toBe("PLANNED");
    expect(caseStatus(row({ outcome: "SKIPPED", durationMs: 0, reason: "waits on a door" }), HEAD)).toBe("PLANNED");
    expect(caseStatus(row({ outcome: "BLOCKED", durationMs: 0, reason: "waits on vault.x" }), HEAD)).toBe("PLANNED");
    expect(caseStatus(row({ outcome: "FAIL", assertions: 0, failedAssertion: false, reason: "door refused" }), HEAD)).toBe("PLANNED");
  });

  test("PROBED: the body ran to its end with no assertion", () => {
    expect(caseStatus(row({ outcome: "PASS", assertions: 0 }), HEAD)).toBe("PROBED");
    expect(caseStatus(row({ outcome: "PASS" }), HEAD)).toBe("PROBED");
    expect(caseStatus(row({ outcome: "PASS", assertions: 1 }), HEAD)).not.toBe("PROBED");
  });

  test("WRITTEN: assertions are in and no red is on record", () => {
    expect(caseStatus(row({ outcome: "PASS", assertions: 3 }), HEAD)).toBe("WRITTEN");
    expect(caseStatus(row({ outcome: "FAIL", assertions: 3, failedAssertion: true }), HEAD)).toBe("WRITTEN");
    expect(caseStatus(row({ outcome: "FAIL", assertions: 1, failedAssertion: false, reason: "door refused" }), HEAD)).toBe("WRITTEN");
  });

  test("PROVEN: green with assertions after an assertion red on another build head", () => {
    const green = row({ outcome: "PASS", assertions: 3 });
    expect(caseStatus(green, HEAD, { buildHead: EARLIER, result: assertionRed })).toBe("PROVEN");
    expect(caseStatus(row({ outcome: "PASS", assertions: 0 }), HEAD, { buildHead: EARLIER, result: assertionRed })).toBe("PROBED");
    expect(caseStatus(row({ outcome: "FAIL", assertions: 3, failedAssertion: true }), HEAD, { buildHead: EARLIER, result: assertionRed })).toBe("WRITTEN");
  });

  test("PROVEN refuses a red that is BLOCKED, a deadline, a harness or cleanup error, or on the same build", () => {
    const green = row({ outcome: "PASS", assertions: 3 });
    const reds: readonly IdResult[] = [
      row({ outcome: "BLOCKED", durationMs: 0, reason: "waits on vault.x" }),
      row({ outcome: "FAIL", assertions: 1, failedAssertion: false, reason: "BOOT-01 exceeded 30000ms" }),
      row({ outcome: "FAIL", assertions: 2, failedAssertion: true, harnessError: "Bun testcase outcome differs from recorded PASS" }),
      row({ outcome: "FAIL", assertions: 2, failedAssertion: true, cleanupError: "owned process still running" }),
      row({ outcome: "SKIPPED", durationMs: 0, reason: "waits on a door" }),
      row({ outcome: "PASS", assertions: 3 }),
      { ...assertionRed, id: "BOOT-02" },
    ];
    for (const red of reds) expect(caseStatus(green, HEAD, { buildHead: EARLIER, result: red })).toBe("WRITTEN");
    expect(caseStatus(green, HEAD, { buildHead: HEAD, result: assertionRed })).toBe("WRITTEN");
  });
});

describe("withStatuses", () => {
  test("sets a status on every row from the red report and counts each status", () => {
    const results: IdResult[] = [
      row({ id: "BOOT-01", outcome: "PASS", assertions: 4 }),
      row({ id: "BOOT-02", outcome: "PASS", assertions: 2 }),
      row({ id: "BOOT-03", outcome: "PASS", assertions: 0 }),
      row({ id: "BOOT-04", outcome: "SKIPPED", durationMs: 0, reason: "waits on a door" }),
    ];
    const red = { buildHead: EARLIER, results: [assertionRed, { ...assertionRed, id: "BOOT-02", failedAssertion: false }] };
    const out = withStatuses(results, HEAD, red);
    expect(out.results.map(r => [r.id, r.status])).toEqual([["BOOT-01", "PROVEN"], ["BOOT-02", "WRITTEN"], ["BOOT-03", "PROBED"], ["BOOT-04", "PLANNED"]]);
    expect(out.statusCounts).toEqual({ PLANNED: 1, PROBED: 1, WRITTEN: 1, PROVEN: 1 });
    expect(withStatuses(results, HEAD).statusCounts).toEqual({ PLANNED: 1, PROBED: 1, WRITTEN: 2, PROVEN: 0 });
  });
});

describe("counted expect", () => {
  test("counts each expect call in a flow, under .not, .resolves and asymmetric matchers", async () => {
    const seen = await observeAssertions("BOOT-01", async () => {
      expect(1).toBe(1);
      expect(1).not.toBe(2);
      expect({ n: 3 }).toEqual({ n: expect.any(Number) });
      await expect(Promise.resolve(4)).resolves.toBe(4);
      await expect(Promise.reject(new Error("refused"))).rejects.toThrow("refused");
    });
    expect(seen).toEqual({ assertions: 5, failedAssertion: false });
  });

  test("a probe makes no assertion", async () => {
    expect(await observeAssertions("BOOT-01", async () => { await Promise.resolve("door answered") })).toEqual({ assertions: 0, failedAssertion: false });
  });

  test("a failing matcher marks the case's error as an assertion failure, sync or async", async () => {
    expect(await observeAssertions("BOOT-01", () => { expect(1).toBe(2) })).toEqual({ assertions: 1, failedAssertion: true });
    expect(await observeAssertions("BOOT-01", () => { expect(1).not.toBe(1) })).toEqual({ assertions: 1, failedAssertion: true });
    expect(await observeAssertions("BOOT-01", async () => { await expect(Promise.resolve(1)).resolves.toBe(2) }))
      .toEqual({ assertions: 1, failedAssertion: true });
  });

  test("a door error after a passing assertion is not an assertion failure", async () => {
    expect(await observeAssertions("BOOT-01", () => { expect(1).toBe(1); throw new Error("door refused") }))
      .toEqual({ assertions: 1, failedAssertion: false });
  });
});
