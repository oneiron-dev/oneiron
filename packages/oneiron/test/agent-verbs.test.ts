import { expect, test } from "bun:test"
import { agentVerbs } from "../src/agent-verbs"

test("generated task and room projections keep the caller step and winner data", () => {
  const calls: [string, unknown][] = []
  const winner = { task_ref: "task", actor_ref: "first", result_ref: "result", at: 1, answer_ref: null, question_version: null }
  const api = agentVerbs((method, input) => {
    calls.push([method, input])
    if (method === "tasksAsk") return { handle: { task_ref: "task" }, count: 1, replayed: false }
    if (method === "tasksWait") return { Ready: winner }
    return winner
  })
  const receipt = api.tasks.ask({ question: { text: "Proceed?" }, holders: ["first"], idempotency_key: "one" })
  expect(api.tasks.wait(receipt.handle, "step-two")).toEqual({ Ready: winner })
  expect(api.tasks.answer(receipt.handle, "result")).toEqual(winner)
  api.rooms.claim("room", "turn")
  expect(calls[1]).toEqual(["tasksWait", { handle: receipt.handle, step_key: "step-two" }])
  expect(calls[3]).toEqual(["roomsClaim", { room_ref: "room", turn_ref: "turn" }])
})
