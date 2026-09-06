/**
 * The typed error contract (ONE-1441 §Typed error contract, I7).
 *
 * These run against the translation layer directly, with no native module and
 * no vault, because the property under test is that the engine's payload
 * survives the boundary unedited — including codes this package has never
 * heard of.
 */

import { describe, expect, test } from "bun:test"

import { OneironError, translateNativeError } from "../src/error.js"

/** Builds what the native boundary actually throws: JSON in a message. */
function nativeThrow(payload: unknown): Error {
  return new Error(JSON.stringify(payload))
}

describe("native error translation", () => {
  test("preserves code, message and suggestions byte-for-byte", () => {
    const error = translateNativeError(
      nativeThrow({
        code: "LEASE_REQUIRED",
        message: "deep recall requires a budget lease",
        suggestions: ["Use effort 'standard'.", "Deep recall has no issuer yet."],
      }),
    )
    expect(error).toBeInstanceOf(OneironError)
    expect(error.code).toBe("LEASE_REQUIRED")
    expect(error.message).toBe("deep recall requires a budget lease")
    expect(error.suggestions).toEqual([
      "Use effort 'standard'.",
      "Deep recall has no issuer yet.",
    ])
  })

  test("passes unknown future codes through as strings", () => {
    const error = translateNativeError(
      nativeThrow({ code: "SOME_FUTURE_CODE", message: "m", suggestions: ["s"] }),
    )
    expect(error.code).toBe("SOME_FUTURE_CODE")
  })

  test("never yields an empty suggestion list", () => {
    const error = translateNativeError(
      nativeThrow({ code: "BAD_REQUEST", message: "m", suggestions: [] }),
    )
    expect(error.suggestions.length).toBeGreaterThan(0)
  })

  test("turns an unparseable payload into a typed internal error", () => {
    // A bug in this package or the boundary below it. It still arrives as an
    // OneironError, so a caller needs exactly one catch shape.
    for (const thrown of [new Error("<html>502</html>"), "plain string", 42]) {
      const error = translateNativeError(thrown)
      expect(error).toBeInstanceOf(OneironError)
      expect(error.code).toBe("INTERNAL_SERVER_ERROR")
      expect(error.suggestions.length).toBeGreaterThan(0)
    }
  })

  test("is idempotent on an already-typed error", () => {
    const original = new OneironError("FORBIDDEN", "no", ["reconnect"])
    expect(translateNativeError(original)).toBe(original)
  })

  test("suggestions are frozen so a caller cannot mutate the contract", () => {
    const error = new OneironError("BAD_REQUEST", "m", ["s"])
    expect(Object.isFrozen(error.suggestions)).toBe(true)
  })
})
