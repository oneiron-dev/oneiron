/** Real native + public wrapper regression; requires a current native artifact. */

import { mkdtempSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

import { afterAll, beforeAll, describe, expect, test } from "bun:test"

import { Oneiron, OneironError } from "../src/index.js"
import type { WitnessMessage, WitnessTurn } from "../src/index.js"

const root = mkdtempSync(join(tmpdir(), "oneiron-witness-input-"))
afterAll(() => rmSync(root, { recursive: true, force: true }))

function turn(message: Partial<WitnessMessage>): WitnessTurn {
  return {
    conversationRef: "11111111111111111111111111111111",
    occurredAt: 1_700_000_000,
    messages: [{ author: "user", messageType: "dialogue", content: "hi", order: 0, ...message }],
  }
}

function refusal(operation: () => unknown): OneironError {
  try {
    operation()
  } catch (error) {
    expect(error).toBeInstanceOf(OneironError)
    return error as OneironError
  }
  throw new Error("expected a typed refusal")
}

for (const backend of ["embedded", "remote"] as const) {
  describe(`${backend} witness input errors through the public wrapper`, () => {
    let memory: Oneiron

    beforeAll(() => {
      memory = backend === "embedded"
        ? Oneiron.open(join(root, "vault"))
        // No server: invalid input must fail at the N-API boundary, before dispatch.
        : Oneiron.connect("http://127.0.0.1:9", "witness-input-probe")
    })

    function badInput(message: Partial<WitnessMessage>): OneironError {
      const before = backend === "embedded" ? memory.receipts() : undefined
      const error = refusal(() => memory.witness(turn(message)))
      expect(error.code).toBe("BAD_REQUEST")
      if (before) expect(memory.receipts()).toEqual(before)
      return error
    }

    test("unknown author carries the valid roles in actionable suggestions", () => {
      // Simulate JavaScript input outside the TypeScript union without mocking native code.
      const error = badInput({ author: "assistant" as WitnessMessage["author"] })
      expect(error.message).toContain("author must be one of user, companion, system")
      expect(error.message).toContain("assistant")
      expect(error.suggestions).toContain("Set messages[].author to user, companion, or system.")
    })

    for (const [label, metadata] of [
      ["array", ["not", "an object"]],
      ["string", "not an object"],
      ["number", 7],
      ["boolean", true],
    ] as const) {
      test(`${label} metadata suggests an object or omission`, () => {
        const error = badInput({ metadata })
        expect(error.message).toContain("metadata must be a JSON object")
        expect(error.suggestions).toContain(
          "Set messages[].metadata to a JSON object, or omit metadata.",
        )
      })
    }

    if (backend === "embedded") {
      test("valid object metadata still reaches the engine", () => {
        const receipt = memory.witness(turn({ metadata: { trace: "input-regression" } }))
        expect(receipt.messageShortIds).toHaveLength(1)
      })

      test("engine authority refusal stays FORBIDDEN, not BAD_REQUEST", () => {
        // A new turn needs a non-system speaker before system-row authority is checked.
        const input = turn({})
        input.messages.push({ author: "system", messageType: "dialogue", content: "hi", order: 1 })
        const error = refusal(() => memory.witness(input))
        expect(error.code).toBe("FORBIDDEN")
        expect(error.suggestions.length).toBeGreaterThan(0)
      })
    }
  })
}
