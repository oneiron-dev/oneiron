#!/usr/bin/env node
// Native agent-verb boundary proof. Build oneiron-napi, then supply the shared
// library path. No mock native module and no package installation are used.
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

if (!process.argv[2]) throw new Error("supply the built oneiron-napi shared library");
const native = { exports: {} };
process.dlopen(native, resolve(process.argv[2]));
const { NativeClient } = native.exports;
const root = mkdtempSync(join(tmpdir(), "oneiron-agent-native-"));
try {
  const memory = NativeClient.open(join(root, "vault"));
  const witnessed = memory.witness({
    conversationRef: "11111111111111111111111111111111",
    messages: [{ author: "user", messageType: "dialogue", content: "Native SDK result", order: 0 }],
  });
  const result = "22222222222222222222222222222222";
  const claim = memory.claimUpsert({
    id: result, predicate: "preference.sdk_result", subjectRef: witnessed.turnShortId,
    value: "ready", confidence: 1, source: "user_stated",
  });
  const owner = memory.receipts(100).find(row => row.receiptRef === claim.receiptRef)?.actorRef;
  assert.match(owner, /^[0-9a-f]{32}$/);
  assert.ok(Array.isArray(memory.roomsList({})));
  for (const answerFirst of [false, true]) {
    const spec = {
      question: { text: "Choose the native result" }, holders: [owner],
      idempotency_key: `native-${answerFirst}`,
      outcome_binding: {
        source: { kind: "claim", predicate: "preference.sdk_outcome" },
        horizon: 60, mapping: { won: true }, noise_weight: 0.8,
      },
    };
    const receipt = memory.tasksAsk(spec);
    assert.equal(memory.tasksAsk(spec).handle.task_ref, receipt.handle.task_ref);
    const request = { handle: receipt.handle, step_key: "native-step" };
    if (!answerFirst) assert.ok("Pending" in memory.tasksWait(request));
    // Waiting only parks that step. Other operations remain callable.
    assert.ok(memory.receipts(100).length > 0);
    const answer = memory.tasksAnswer({ handle: receipt.handle, result_ref: result });
    assert.equal(answer.result_ref, result);
    assert.equal(answer.question_version, 1);
    assert.match(answer.answer_ref, /^[0-9a-f]{32}$/);
    assert.deepEqual(memory.tasksWait(request), { Ready: answer });
    assert.deepEqual(memory.tasksWait(request), { AlreadyResumed: answer });
    assert.deepEqual(memory.tasksAnswer({ handle: receipt.handle, result_ref: result }), answer);
    memory.claimUpsert({
      id: answerFirst ? "44444444444444444444444444444444" : "33333333333333333333333333333333",
      predicate: "preference.sdk_outcome", subjectRef: result,
      value: "won", confidence: 1, source: "user_stated",
    });
    const pairs = memory.tasksOutcomes(receipt.handle);
    assert.ok(pairs.length >= 1);
    assert.ok(pairs.every(pair => pair.outcome.label && pair.outcome.answer === answer.answer_ref));
  }
  console.log("Native agent verbs: both wait orders, first answer, outcome binding, and live room listing passed");
} finally {
  rmSync(root, { recursive: true, force: true });
}
