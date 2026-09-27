// Compile with strict tsc: the exported short DTO and positional call agree.
import type { TaskAskShort } from "../src/agent-verbs.js"
import { agentVerbs } from "../src/agent-verbs.js"

export function nullableShortCall(input: TaskAskShort): void {
  agentVerbs(() => undefined).tasks.ask(input.who, input.what, input.until)
}
