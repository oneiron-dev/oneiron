import type { Tool } from "ai"
import type { Oneiron, WitnessTurn, WitnessReceipt, RecallOptions, MemoryPack, FacadeReceipt } from "oneiron"
export declare function memoryTools(memory: { vault: Pick<Oneiron["vault"], "witness" | "recall" | "receipts"> }): {
  witness: Tool<WitnessTurn, WitnessReceipt>
  recall: Tool<{ query: string; options?: RecallOptions }, MemoryPack>
  receipts: Tool<{ limit?: number; kinds?: string[] }, FacadeReceipt[]>
}
