import type { agentVerbs } from "../src/agent-verbs.js"
import type { RetrievalMeta } from "../src/types.js"

export function partialFlag(metadata: RetrievalMeta): boolean {
  return metadata.partial
}

export function tasksCheckRows(api: ReturnType<typeof agentVerbs>): unknown[] {
  return api.tasks.check().rows
}
