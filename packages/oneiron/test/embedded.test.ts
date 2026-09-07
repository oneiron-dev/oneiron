/**
 * The embedded behaviour matrix (ONE-1441 §Test/Embedded, §Quickstarts G8).
 *
 * These need a built native artifact. Each test opens its own temporary vault
 * so nothing depends on order, and the default-path test sets an isolated
 * `HOME` so it leaves no state in the runner account.
 */

import { mkdtempSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

import { afterAll, beforeAll, describe, expect, test } from "bun:test"

import { Oneiron, OneironError } from "../src/index.js"

const roots: string[] = []

/** A fresh vault directory that is cleaned up when the file finishes. */
function vaultPath(): string {
  const root = mkdtempSync(join(tmpdir(), "oneiron-node-"))
  roots.push(root)
  return join(root, "vault")
}

afterAll(() => {
  for (const root of roots) rmSync(root, { recursive: true, force: true })
})

describe("embedded constructor", () => {
  test("opens an explicit path and binds an actor with no ceremony", () => {
    const memory = Oneiron.open(vaultPath())
    expect(memory.receipts(10)).toBeArray()
  })

  test("accepts an explicit dimensions option", () => {
    const memory = Oneiron.open(vaultPath(), { dimensions: 256 })
    expect(memory.receipts(10)).toBeArray()
  })

  test("a same-path reopen with divergent options is BAD_REQUEST", () => {
    const path = vaultPath()
    Oneiron.open(path, { dimensions: 256 })
    try {
      Oneiron.open(path, { dimensions: 512 })
      throw new Error("expected a divergent reopen to fail")
    } catch (error) {
      expect(error).toBeInstanceOf(OneironError)
      expect((error as OneironError).code).toBe("BAD_REQUEST")
    }
  })
})

describe("the canonical four-call quickstart", () => {
  let memory: Oneiron
  let witnessed: ReturnType<Oneiron["witness"]>
  let claimed: ReturnType<Oneiron["claimUpsert"]>

  beforeAll(() => {
    memory = Oneiron.open(vaultPath())
    witnessed = memory.witness({
      conversationRef: "11111111111111111111111111111111",
      messages: [
        {
          author: "user",
          messageType: "dialogue",
          content: "I prefer a window seat when I fly.",
          order: 0,
        },
      ],
    })
    claimed = memory.claimUpsert({
      id: "22222222222222222222222222222222",
      predicate: "preference.travel.seat",
      subjectRef: witnessed.turnShortId,
      value: { seat: "window" },
      confidence: 1,
      source: "user_stated",
    })
  })

  test("G8: the witness receipt ref is a witness marker", () => {
    expect(witnessed.receiptRef.startsWith("witness:")).toBe(true)
    expect(witnessed.messageShortIds).toHaveLength(1)
  })

  test("G8: the claim carries a real gate receipt", () => {
    expect(claimed.receiptRef.length).toBeGreaterThan(0)
    expect(["auto", "proposed", "rejected"]).toContain(claimed.approval)
  })

  test("G8: recall returns pack version 1 and finds the claim", () => {
    const recalled = memory.recall("window seat")
    expect(recalled.packVersion).toBe(1)
    const texts = recalled.items.map((item) => item.valueText).join(" ")
    expect(texts.toLowerCase()).toContain("window seat")
  })

  test("G8: receipts carries at least one real gate row", () => {
    const receipts = memory.receipts()
    expect(receipts.length).toBeGreaterThan(0)
    for (const row of receipts) {
      expect(row.receiptRef.length).toBeGreaterThan(0)
      expect(typeof row.outcome).toBe("string")
      expect(row.reasonCodes).toBeArray()
    }
  })

  test("an omitted timestamp is stamped in Unix seconds", () => {
    // The witness above omitted `occurredAt`. The gate receipt it produced
    // therefore carries a boundary-stamped time, which must be seconds — a
    // milliseconds value would be ~1000x larger and centuries in the future.
    const now = Math.floor(Date.now() / 1000)
    for (const row of memory.receipts()) {
      expect(Math.abs(row.createdAt - now)).toBeLessThanOrEqual(300)
    }
  })
})

describe("typed refusals", () => {
  let memory: Oneiron

  beforeAll(() => {
    memory = Oneiron.open(vaultPath())
  })

  /** Runs `operation` and returns the OneironError it must throw. */
  function refusal(operation: () => unknown): OneironError {
    try {
      operation()
    } catch (error) {
      expect(error).toBeInstanceOf(OneironError)
      return error as OneironError
    }
    throw new Error("expected a typed refusal")
  }

  test("deep recall is lease-gated", () => {
    const error = refusal(() => memory.recall("window seat", { effort: "deep" }))
    expect(error.code).toBe("LEASE_REQUIRED")
    expect(error.suggestions.length).toBeGreaterThan(0)
  })

  test("an over-8-KiB query is refused", () => {
    const error = refusal(() => memory.recall("x".repeat(8 * 1024 + 1)))
    expect(error.code).toBe("BAD_REQUEST")
  })

  test("a negative timestamp is refused before core entry", () => {
    const error = refusal(() =>
      memory.witness({
        conversationRef: "11111111111111111111111111111111",
        messages: [{ author: "user", messageType: "dialogue", content: "hi", order: 0 }],
        occurredAt: -1,
      }),
    )
    expect(error.code).toBe("BAD_REQUEST")
  })

  test("a non-finite confidence is refused before narrowing", () => {
    for (const confidence of [Number.NaN, Number.POSITIVE_INFINITY]) {
      const error = refusal(() =>
        memory.claimUpsert({
          predicate: "preference.travel.seat",
          subjectRef: "11111111111111111111111111111111",
          value: { seat: "window" },
          confidence,
          source: "user_stated",
        }),
      )
      expect(error.code).toBe("BAD_REQUEST")
    }
  })

  test("a malformed actor key is refused", () => {
    const error = refusal(() => memory.asActor("not-an-actor-key"))
    expect(error.code.length).toBeGreaterThan(0)
    expect(error.suggestions.length).toBeGreaterThan(0)
  })
})
