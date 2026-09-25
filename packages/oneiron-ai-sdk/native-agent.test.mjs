// Real AI SDK orchestration and real Oneiron native bindings. Only the external
// model response is deterministic; no memory method or AI SDK module is mocked.
import { test } from "node:test"
import assert from "node:assert/strict"
import { mkdtempSync, rmSync, realpathSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { generateText, stepCountIs } from "ai"
import { MockLanguageModelV3 } from "ai/test"
import { Oneiron } from "oneiron"
import { memoryTools } from "./index.js"

const response = (content, reason) => ({
  content,
  finishReason: { unified: reason, raw: reason },
  usage: {
    inputTokens: { total: 1, noCache: 1, cacheRead: 0, cacheWrite: 0 },
    outputTokens: { total: 1, text: 1, reasoning: 0 },
  },
  warnings: [],
})
const call = (toolName, input) => response([{
  type: "tool-call", toolCallId: toolName, toolName, input: JSON.stringify(input),
}], "tool-calls")

test("an AI SDK agent writes, recalls and reads receipts through native Memory Wire", async () => {
  const root = mkdtempSync(join(realpathSync(tmpdir()), "oneiron-ai-native-"))
  try {
    const memory = Oneiron.open(join(root, "vault"))
    const seed = memory.witness({
      conversationRef: "1".repeat(32),
      messages: [{ author: "user", messageType: "dialogue", content: "I prefer a window seat when I fly.", order: 0 }],
    })
    memory.claimUpsert({
      id: "2".repeat(32), predicate: "preference.travel.seat",
      subjectRef: seed.turnShortId, value: { seat: "window" },
      confidence: 1, source: "user_stated",
    })
    const model = new MockLanguageModelV3({ doGenerate: [
      call("witness", {
        conversationRef: "3".repeat(32),
        messages: [{ author: "user", messageType: "dialogue", content: "Please remember my travel plans.", order: 0 }],
      }),
      call("recall", { query: "window seat" }),
      call("receipts", { limit: 10 }),
      response([{ type: "text", text: "You prefer a window seat." }], "stop"),
    ] })
    const result = await generateText({
      model, tools: memoryTools(memory), stopWhen: stepCountIs(4),
      prompt: "Remember this turn, recall my travel preference, and check the receipts.",
    })
    const outputs = result.steps.flatMap(step => step.toolResults)
    assert.deepEqual(outputs.map(row => row.toolName), ["witness", "recall", "receipts"])
    assert.ok(outputs[0].output.receiptRef.startsWith("witness:"))
    assert.equal(outputs[0].output.messageShortIds.length, 1)
    assert.equal(outputs[1].output.packVersion, 1)
    assert.match(outputs[1].output.items.map(row => row.valueText).join(" ").toLowerCase(), /window seat/)
    assert.ok(outputs[2].output.length > 0)
    assert.ok(outputs[2].output.every(row => row.receiptRef && Array.isArray(row.reasonCodes)))
    // The next provider request really receives the engine result as a tool message.
    const memoryPrompt = model.doGenerateCalls[2].prompt.find(message => message.role === "tool")
    assert.ok(memoryPrompt)
    assert.equal(result.text, "You prefer a window seat.")
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})
