import type { RetrievalMeta } from "../src/types.js"

export function partialFlag(metadata: RetrievalMeta): boolean {
  return metadata.partial
}
