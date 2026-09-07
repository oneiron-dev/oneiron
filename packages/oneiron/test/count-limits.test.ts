/** Real N-API + public wrapper regression; requires a current native artifact. */

import { mkdtempSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

import { afterAll, beforeAll, describe, expect, test } from "bun:test"

import { Oneiron, OneironError } from "../src/index.js"

const root = mkdtempSync(join(tmpdir(), "oneiron-count-limits-"))
afterAll(() => rmSync(root, { recursive: true, force: true }))

function badRequest(operation: () => unknown): OneironError {
  try {
    operation()
  } catch (error) {
    expect(error).toBeInstanceOf(OneironError)
    const typed = error as OneironError
    expect(typed.code).toBe("BAD_REQUEST")
    expect(typed.message).toContain("limit")
    expect(typed.suggestions.length).toBeGreaterThan(0)
    return typed
  }
  throw new Error("expected BAD_REQUEST before backend dispatch")
}

for (const backend of ["embedded", "remote"] as const) {
  describe(`${backend} recall and receipts counts before integer narrowing`, () => {
    let memory: Oneiron

    beforeAll(() => {
      memory = backend === "embedded"
        ? Oneiron.open(join(root, "vault"))
        // No server or waiting fixture: invalid counts must fail before HTTP dispatch.
        : Oneiron.connect("http://127.0.0.1:9", "count-limit-probe")
      if (backend === "embedded") {
        const witnessed = memory.witness({
          conversationRef: "11111111111111111111111111111111",
          messages: [{ author: "user", messageType: "dialogue", content: "window seat", order: 0 }],
        })
        memory.claimUpsert({
          predicate: "preference.travel.seat", subjectRef: witnessed.turnShortId,
          value: { seat: "window" }, confidence: 1, source: "user_stated",
        })
      }
    })

    for (const verb of ["recall", "receipts"] as const) {
      test.each([
        0, -0, -1, -0.5, 0.5, 1.5, 1000.5, 1001,
        2 ** 32 - 1, 2 ** 32, 2 ** 32 + 1, 2 ** 32 + 1000,
        Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER + 1,
        Number.MAX_VALUE, Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY,
      ])(`${verb} rejects %s without changing the count`, (limit) => {
        const error = badRequest(() => verb === "recall"
          ? memory.recall("window seat", { limit })
          : memory.receipts(limit))
        if (limit === 1.5) {
          expect(error.suggestions.some((suggestion) => suggestion.includes("whole number"))).toBe(true)
        }
      })
    }

    if (backend === "embedded") {
      test.each([1, 10, 100, 1000])("accepts the integer limit %s", (limit) => {
        const pack = memory.recall("window seat", { limit })
        expect(pack.packVersion).toBe(1)
        expect(pack.items.length).toBeGreaterThan(0)
        expect(pack.items.length).toBeLessThanOrEqual(limit)
        const receipts = memory.receipts(limit)
        expect(receipts.length).toBeGreaterThan(0)
        expect(receipts.length).toBeLessThanOrEqual(limit)
      })

      test("omitted limits retain the recall and receipts defaults", () => {
        expect(memory.recall("window seat")).toEqual(memory.recall("window seat", { limit: 10 }))
        expect(memory.receipts()).toEqual(memory.receipts(100))
      })
    }
  })
}
