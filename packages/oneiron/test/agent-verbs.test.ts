import { expect, test } from "bun:test"
import { agentVerbs } from "../src/agent-verbs"
import type { TaskAskAnswer, TaskAskResult, TaskAskShort, TaskAskSpec, TaskAskWord } from "../src/agent-verbs"

test("generated task and room projections keep the caller step and settlement data", () => {
  const calls: [string, unknown][] = []
  const actor = "11".repeat(16), question = "22".repeat(16), group = "33".repeat(16)
  const spec: TaskAskSpec = {
    intent_key: "one", who: { people: [actor] },
    what: { reference: { turn: question }, revision: 1, options: { yes: "Yes" }, context_refs: [] },
    until: 100, decide: "first",
  }
  const word: TaskAskWord = { result_ref: question, option: "yes" }
  const answer: TaskAskAnswer = { task_ref: "44".repeat(16), actor_ref: actor, result_ref: question, word_ref: "55".repeat(16) }
  const result: TaskAskResult = {
    coverage: { met: true, required: 1, responded: [actor], unknown: [], unmet_people: [] },
    decision: { first: answer }, fallback: null, effect_authorization: "not_evaluated_by_ask",
    evidence: [{ answer, word, source: "human", person_ref: actor, order: 1, reason: "counted" }],
    settlement: { group_ref: group, reference: "66".repeat(16), revision: 1, at: 2, cutoff_order: 1,
      reason: "first_word", requested: spec, effective: { ...spec, default: "ask_me", need: { count: 1, of: "any" }, provisional: "inform", on_disagree: { branch: "hold", surface: "card" }, remind: [] },
      base_policy_version: 1, electorate: [actor], question_digest: Array(32).fill(0), unmet_sources: [], outcome_answer_ref: null },
  }
  const api = agentVerbs((method, input) => {
    calls.push([method, input])
    if (method === "tasksAsk") return { handle: { group_ref: group }, task_refs: [answer.task_ref], hold: null, idempotent_replay: false }
    if (method === "tasksWait") return { Ready: result }
    return answer
  })
  const receipt = api.tasks.ask(spec)
  expect(api.tasks.wait(receipt.handle, "step-two")).toEqual({ Ready: result })
  expect(api.tasks.answer(receipt.handle, word)).toEqual(answer)
  api.rooms.claim("room", "turn")
  expect(calls[0]).toEqual(["tasksAsk", spec])
  expect(calls[1]).toEqual(["tasksWait", { handle: receipt.handle, step_key: "step-two" }])
  expect(calls[2]).toEqual(["tasksAnswer", { handle: receipt.handle, word }])
  expect(calls[3]).toEqual(["roomsClaim", { room_ref: "room", turn_ref: "turn" }])
})

test("retired task names are not projected", () => {
  // ARCH-0067's 2026-09-22 amendment renamed the four task rows, with no alias.
  const tasks = agentVerbs(() => undefined).tasks
  for (const retired of ["check", "expand", "ack", "cancel"]) {
    expect(Object.keys(tasks)).not.toContain(retired)
  }
  expect(Object.keys(tasks)).toContain("update")
})

test("one tasks.ask verb accepts both SDK call shapes without merging authority into the answer", () => {
  const calls: [string, unknown][] = []
  const question = { reference: { turn: "22".repeat(16) }, revision: 1, options: {}, context_refs: [] }
  const who = { people: ["11".repeat(16)] }
  const api = agentVerbs((method, input) => {
    calls.push([method, input])
    return { handle: { group_ref: "33".repeat(16) }, task_refs: [], hold: null, idempotent_replay: false }
  })
  api.tasks.ask(who, question, 123, "hold")
  api.tasks.ask("11".repeat(16), question)
  api.tasks.ask(["11".repeat(16)], question)
  api.tasks.ask(undefined, question)
  const optionalDeadline: TaskAskShort = { who, what: question, until: null }
  api.tasks.ask(optionalDeadline.who, optionalDeadline.what, optionalDeadline.until)
  api.tasks.ask({ intent_key: "rich", who, what: question, until: 123, decide: "first" })
  expect(calls).toEqual([
    ["tasksAsk", { who, what: question, until: 123, default: "hold" }],
    ["tasksAsk", { who: {people: ["11".repeat(16)]}, what: question, until: undefined, default: undefined }],
    ["tasksAsk", { who: {people: ["11".repeat(16)]}, what: question, until: undefined, default: undefined }],
    ["tasksAsk", { who: undefined, what: question, until: undefined, default: undefined }],
    ["tasksAsk", { who, what: question, until: null, default: undefined }],
    ["tasksAsk", { intent_key: "rich", who, what: question, until: 123, decide: "first" }],
  ])
})
