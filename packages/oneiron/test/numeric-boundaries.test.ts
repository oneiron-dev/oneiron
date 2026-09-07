/** Numeric validation must see the original JavaScript number, not an N-API cast. */

import { existsSync, mkdtempSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

import { afterAll, beforeAll, describe, expect, test } from "bun:test"

import { Oneiron, OneironError } from "../src/index.js"

const root = mkdtempSync(join(tmpdir(), "oneiron-numeric-"))
let nextPath = 0
const freshPath = () => join(root, `vault-${nextPath++}`)

afterAll(() => rmSync(root, { recursive: true, force: true }))

function badRequest(operation: () => unknown): OneironError {
  try {
    operation()
  } catch (error) {
    expect(error).toBeInstanceOf(OneironError)
    const typed = error as OneironError
    expect(typed.code).toBe("BAD_REQUEST")
    expect(typed.suggestions.length).toBeGreaterThan(0)
    return typed
  }
  throw new Error("expected BAD_REQUEST before backend dispatch")
}

describe("dimensions before integer narrowing", () => {
  test.each([
    0, -1, 256.5, 16385, 4294967552,
    Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY,
  ])("rejects %s without creating a vault", (dimensions) => {
    const path = freshPath()
    expect(badRequest(() => Oneiron.open(path, { dimensions })).message).toContain("dimensions")
    expect(existsSync(path)).toBe(false)
  })

  test.each([1, 16384])("accepts the inclusive dimension boundary %s", (dimensions) => {
    const memory = Oneiron.open(freshPath(), { dimensions })
    expect(memory.receipts(1)).toBeArray()
  })
})

for (const backend of ["embedded", "remote"] as const) {
  describe(`${backend} claim timestamps before integer narrowing`, () => {
    let memory: Oneiron
    let subjectRef = "11111111111111111111111111111111"

    beforeAll(() => {
      memory = backend === "embedded"
        ? Oneiron.open(freshPath())
        : Oneiron.connect("http://127.0.0.1:9", "numeric-boundary-probe")
      if (backend === "embedded") {
        subjectRef = memory.witness({
          conversationRef: subjectRef,
          messages: [{ author: "user", messageType: "dialogue", content: "window seat", order: 0 }],
        }).turnShortId
      }
    })

    for (const [field, engineField] of [
      ["validFrom", "valid_from"], ["validTo", "valid_to"],
      ["occurredAt", "occurred_at"], ["learnedAt", "learned_at"],
    ] as const) {
      test.each([
        -1, 1700000000.9, Number.MAX_SAFE_INTEGER + 1, Number.MAX_SAFE_INTEGER + 3,
        Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY,
      ])(`${field} rejects %s as a typed boundary error`, (value) => {
        const before = backend === "embedded" ? memory.receipts() : undefined
        const error = badRequest(() => memory.claimUpsert({
          predicate: "preference.travel.seat", subjectRef,
          value: { seat: "window" }, confidence: 1, source: "user_stated",
          [field]: value,
        }))
        expect(error.message).toContain(engineField)
        if (before) expect(memory.receipts()).toEqual(before)
      })
    }

    test("witness rejects the first unsafe integer too", () => {
      const error = badRequest(() => memory.witness({
        conversationRef: "33333333333333333333333333333333",
        occurredAt: Number.MAX_SAFE_INTEGER + 1,
        messages: [{ author: "user", messageType: "dialogue", content: "refused", order: 0 }],
      }))
      expect(error.message).toContain("occurred_at")
    })
  })
}
