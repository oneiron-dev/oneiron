import type { Oneiron, TaskCancelReceipt, TaskDescription } from "../src/index.js"
import type { RetrievalMeta } from "../src/types.js"

export function partialFlag(metadata: RetrievalMeta): boolean {
  return metadata.partial
}

export function describedTaskRows(api: Oneiron): unknown[] {
  const description: TaskDescription = api.describe()
  return description.kind === "tasks_section" ? description.rows : []
}

export function cancelStoppedWork(api: Oneiron, taskRef: string): boolean {
  const receipt: TaskCancelReceipt = api.cancel(taskRef)
  return receipt.effected
}
