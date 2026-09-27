// Compile-only caller contract: the published entry exports the prediction,
// and the generated ask facade accepts it and returns a readable label.
import { agentVerbs } from "../src/agent-verbs.js"
import type { TaskAskLadderPrediction, TaskAskResult, TaskAskSpec } from "../src/index.js"

const prediction: TaskAskLadderPrediction = {
  option: "yes",
  rung: "system_one",
  probability: 0.6,
}
const spec: TaskAskSpec = {
  intent_key: "typed-band-ask",
  what: {
    reference: { turn: "11".repeat(16) },
    revision: 1,
    options: { yes: "Yes", no: "No" },
    context_refs: [],
    class_key: "decision-class",
    ladder_answer: prediction,
  },
  until: 100,
}
const client = agentVerbs(() => undefined)
const handle = client.tasks.ask(spec).handle
const response = client.tasks.wait(handle)
if ("Ready" in response) {
  const settled: TaskAskResult = response.Ready
  const label: boolean | null = settled.evidence[0]?.ladder_changed ?? null
  void label
}
