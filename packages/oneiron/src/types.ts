/**
 * The public DTO contract for the `oneiron` package (ONE-1441 §HEAD-CONTRACT).
 *
 * Every type here is the camelCase projection of an engine facade DTO. They
 * are declarations only — no runtime value is exported from this module — so
 * the package's public runtime surface stays exactly `Oneiron` and
 * `OneironError`.
 *
 * Timestamps are Unix SECONDS everywhere, with no unit conversion anywhere in
 * the SDK. A caller supplying one explicitly passes `Math.floor(Date.now() /
 * 1000)`; a caller omitting one gets the current wall clock stamped at the
 * call boundary.
 */

/** Options for an embedded {@link Oneiron.open}. */
export type OpenOptions = {
  /** Embedding vector dimensions; omitted takes the engine default. */
  dimensions?: number
}

/** Who authored one witnessed message. */
export type WitnessAuthor = "user" | "companion" | "system"

/** One message inside a witnessed turn. */
export type WitnessMessage = {
  /** Deterministic 32-hex entity id; omitted means generated. */
  id?: string
  author: WitnessAuthor
  /** Message type token, opaque to the engine. */
  messageType: string
  content: string
  /** Opaque metadata; must be a JSON object when present. */
  metadata?: unknown
  /** Visibility flag; omitted means true. */
  isVisible?: boolean
  /** Position within the turn; unique across the call. */
  order: number
}

/** One conversational turn to witness. */
export type WitnessTurn = {
  /** CONVERSATION ref: a 32-hex id (create-or-get) or an existing short ref. */
  conversationRef: string
  /** TURN ref; omitted means a fresh TURN. */
  turnRef?: string
  messages: WitnessMessage[]
  /** Unix seconds; omitted is stamped at the call boundary. */
  occurredAt?: number
}

/** Receipt for one witnessed turn. */
export type WitnessReceipt = {
  turnShortId: string
  messageShortIds: string[]
  /** Facade write marker; always begins `witness:`. */
  receiptRef: string
}

/** One claim to commit. `approval` is deliberately not settable by callers. */
export type ClaimInput = {
  /** Deterministic 32-hex claim id; omitted means generated. */
  id?: string
  /** Dotted predicate; the `edge.*` namespace is reserved. */
  predicate: string
  subjectRef: string
  value: unknown
  /** Calibrated-absolute confidence in [0, 1]. */
  confidence: number
  /** One of `user_stated`, `observed`, `inferred`, `imported`, `tool_output`, `generated`. */
  source: string
  worldRef?: string
  scope?: unknown
  /** Unix seconds. */
  validFrom?: number
  /** Unix seconds. */
  validTo?: number
  /** Unix seconds. */
  occurredAt?: number
  /** Unix seconds. */
  learnedAt?: number
  /** Salience in [0, 1]. */
  salience?: number
}

/** Receipt for one committed (or refused) claim. */
export type CommitReceipt = {
  claimShortId: string
  /** `auto`, `proposed`, or `rejected`. */
  approval: string
  supersededShortId?: string
  /** `gate:<hex>` when a gate decision exists. */
  receiptRef: string
}

/** Retrieval effort dial. `deep` is lease-gated and returns `LEASE_REQUIRED`. */
export type Effort = "minimal" | "standard" | "deep"

/** Rendered pack formats; these are the engine's exact tokens. */
export type PackFormat = "json" | "yaml" | "toon" | "md" | "txt"

/** Recall scoping: narrowing only; unset is the vault floor. */
export type RecallScope = {
  worldRef?: string
  facet?: string
}

/** Options for {@link Oneiron.recall}. */
export type RecallOptions = {
  /** Defaults to `standard`. */
  effort?: Effort
  /** Defaults to the vault floor. */
  scope?: RecallScope
  /** Defaults to 10. */
  limit?: number
  /** Omitted returns a typed pack with no rendering. */
  format?: PackFormat
}

/** Where one recalled item came from. */
export type MemoryProvenance = {
  source: string
  sourceRevisionIds: string[]
  evidenceTurnIds: string[]
}

/** One ranked memory pack item. */
export type MemoryItem = {
  shortId: string
  kind: string
  predicate?: string
  valueText: string
  confidence: number
  hedgeBucket: string
  provenance: MemoryProvenance
  world?: string
  facet?: string
  salience?: number
}

/** What the requested scope excluded. */
export type ScopeHonesty = {
  outOfScopeWorlds: string[]
}

/** Retrieval accounting. */
export type RetrievalMeta = {
  sparse?: boolean
  totalCandidates: number
  claimsReturned: number
  deepPending?: boolean
}

/** The engine `MemoryPack`, unchanged apart from field spelling. */
export type MemoryPack = {
  items: MemoryItem[]
  scopeHonesty: ScopeHonesty
  retrievalMeta: RetrievalMeta
  /** Always equal to the engine's `MEMORY_PACK_VERSION`, and to this package's major. */
  packVersion: number
  rendered?: string
}

/** One gate decision receipt. */
export type FacadeReceipt = {
  /** `gate:<hex>`. */
  receiptRef: string
  /** `allow`, `pending`, or `deny`. */
  outcome: string
  /** Unix seconds. */
  createdAt: number
  reasonCodes: string[]
  actorClass: string
  actorRef?: string
  contentKind: string
  claimRef?: string
}
