import { test, expect, mock } from "bun:test"
// The SDK factories are identity wrappers here. This unit test tests adaptation,
// not model execution; the example exercises the real AI SDK in a consumer.
mock.module("ai", () => ({ tool: (value) => value, jsonSchema: (value) => ({ jsonSchema: value }) }))
const { memoryTools } = await import("./index.js")

test("only the three Memory Wire verbs delegate on the supplied handle", async () => {
  const calls = []
  const receipt = { receiptRef: "gate:1" }
  const memory = Object.fromEntries(["witness", "recall", "receipts"].map((name) => [name, (...args) => {
    calls.push([name, args]); return receipt
  }]))
  const tools = memoryTools(memory)
  expect(Object.keys(tools)).toEqual(["witness", "recall", "receipts"])
  const turn = { conversationRef: "1".repeat(32), messages: [{ author: "user", messageType: "dialogue", content: "tea", order: 0 }] }
  const options = { scope: { worldRef: "2".repeat(32) }, limit: 5 }
  expect(await tools.witness.execute(turn)).toBe(receipt)
  expect(await tools.recall.execute({ query: "tea", options })).toBe(receipt)
  expect(await tools.receipts.execute({ limit: 7 })).toBe(receipt)
  expect(calls).toEqual([["witness", [turn]], ["recall", ["tea", options]], ["receipts", [7]]])
  expect(tools.witness.inputSchema.jsonSchema.additionalProperties).toBe(false)
})

test("engine error identity and suggestions are not rewritten", () => {
  const refusal = Object.assign(new Error("denied"), { code: "FORBIDDEN", suggestions: ["review consent"] })
  const tools = memoryTools({ witness() { throw refusal } })
  try { tools.witness.execute({}); throw new Error("missing refusal") } catch (error) { expect(error).toBe(refusal) }
})


test("read limit schemas match the engine's inclusive bounds", () => {
  const tools = memoryTools({})
  for (const limit of [
    tools.recall.inputSchema.jsonSchema.properties.options.properties.limit,
    tools.receipts.inputSchema.jsonSchema.properties.limit,
  ]) {
    expect(limit).toEqual({ type: "integer", minimum: 1, maximum: 1000 })
  }
})
