import type { Oneiron } from "../src/index.js"
import type { RetrievalMeta } from "../src/types.js"

export function partialFlag(metadata: RetrievalMeta): boolean {
  return metadata.partial
}

export function describedTaskRows(api: Oneiron): unknown[] {
  const description = api.describe()
  return description.kind === "tasks_section" ? description.rows : []
}
