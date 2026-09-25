import { expect, test } from "bun:test"
import { OneironError } from "../src/error.js"
import { keyedJson } from "../src/key-value.js"

// DTO behavior is observable without a native policy exception. Explicitly
// undefined source becomes the engine's generated default, not user_stated.
test("undefined optional envelope fields omit, undefined JSON data refuses", () => {
  expect(JSON.parse(keyedJson({ namespace: ["n"], key: "k", request_id: "r",
    value: { n: 2 }, source: undefined }))).toEqual({ namespace: ["n"], key: "k",
    request_id: "r", value: { n: 2 } })
  expect(JSON.parse(keyedJson({ namespace_prefix: [], limit: undefined,
    offset: undefined, filter: undefined }))).toEqual({ namespace_prefix: [] })
  expect(JSON.parse(keyedJson({ prefix: undefined, suffix: undefined,
    max_depth: undefined }))).toEqual({})
  for (const value of [
    { value: { nested: undefined } },
    { value: { source: undefined } },
    { value: { nested: [undefined] } },
    { filter: { n: undefined } },
    { value: undefined },
    { value: { n: Number.POSITIVE_INFINITY } },
  ]) expect(() => keyedJson(value)).toThrow(OneironError)
})


test("keyed JSON refuses lossy native objects, custom serialization and cycles", () => {
  const cycle: Record<string, unknown> = {}
  cycle.self = cycle
  for (const value of [new Map([["key", 1]]), new Set([1]), new Date(0), /pattern/,
    { toJSON: () => ({ replaced: true }) }, { [Symbol("hidden")]: 1 }, cycle, Array(1)]) {
    expect(() => keyedJson({ value })).toThrow(OneironError)
  }
  const shared = { number: 2 }
  expect(JSON.parse(keyedJson({ value: { left: shared, right: shared } })))
    .toEqual({ value: { left: { number: 2 }, right: { number: 2 } } })
  const nullPrototype = Object.assign(Object.create(null), { a: 3 })
  expect(JSON.parse(keyedJson({ value: nullPrototype }))).toEqual({ value: { a: 3 } })
})

test("keyed JSON serializes the validated accessor result, not a second read", () => {
  let read = false
  const value = { get number() { if (read) return Number.NaN; read = true; return 3 } }
  expect(JSON.parse(keyedJson({ value }))).toEqual({ value: { number: 3 } })
})
