import type { Tool } from "ai"
import type { Oneiron, WitnessTurn, WitnessReceipt, RecallOptions, MemoryPack, FacadeReceipt } from "oneiron"
export declare function memoryTools(memory: Pick<Oneiron, "witness" | "recall" | "receipts">): {
  witness: Tool<WitnessTurn, WitnessReceipt>
  recall: Tool<{ query: string; options?: RecallOptions }, MemoryPack>
  receipts: Tool<{ limit?: number }, FacadeReceipt[]>
}
