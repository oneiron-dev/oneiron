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

/** Retrieval effort dial. `high`, `xhigh` and `max` need a budget lease and return `LEASE_REQUIRED` without one. `call` is call mode for live calls: light effort under a hard deadline. */
export type Effort = "light" | "medium" | "high" | "xhigh" | "max" | "call"

/** Rendered pack formats; these are the engine's exact tokens. */
export type PackFormat = "json" | "yaml" | "toon" | "md" | "txt"

/** Recall scoping: narrowing only; unset is the vault floor. */
export type RecallScope = {
  worldRef?: string
  facet?: string
  /** Registry kinds to return (`MESSAGE`, `CLAIM`, `PERSON`, ...). Unset returns every kind but conversations, sessions, facets and worlds. */
  kinds?: string[]
}

/** Options for `vault.recall` on {@link Oneiron}. */
export type RecallOptions = {
  /** Defaults to `medium`. */
  effort?: Effort
  /** Defaults to the vault floor. */
  scope?: RecallScope
  /** Defaults to 10. */
  limit?: number
  /** Omitted returns a typed pack with no rendering. */
  format?: PackFormat
  /** Unix seconds the query's time words resolve against; omitted is now. */
  asOf?: number
  /** A hard deadline in milliseconds, 1 to 60000: recall answers with the best results ready, marked `partial`. Omitted, recall runs to the end, except `call`, which takes the vault's call-mode deadline. */
  deadlineMs?: number
}

/** Where one recalled item came from. */
export type MemoryProvenance = {
  source: string
  sourceRevisionIds: string[]
  evidenceTurnIds: string[]
}

/** One ranked memory pack item. */
export type MemoryItem = {
  /** The same `name:hash` a witness receipt returns. */
  shortId: string
  /**
   * The revision the item was read at; `${shortId}@${sourceRevisionRef}` hydrates exactly it.
   * A TURN's pins its messages' words too, and reads those words back after an edit
   * while the messages' history holds them.
   */
  sourceRevisionRef?: string
  kind: string
  predicate?: string
  valueText: string
  confidence: number
  hedgeBucket: string
  provenance: MemoryProvenance
  world?: string
  facet?: string
  salience?: number
  /** A conversation record's current reactions, one grouped line per glyph (`👍×8 (Anna, Ben, +6)`); empty for every other item. */
  reactions: string[]
  /** For a TURN item, the messages whose words the query matched, best first. */
  citedMessages: CitedMessage[]
  /** For a TURN or MESSAGE item, the conversation it is in (32 hex), when the reader may read it. */
  conversationId?: string
}

/** A MESSAGE a TURN item quotes: the words a query matched, as they were said. */
export type CitedMessage = {
  shortId: string
  valueText: string
}

/** What the requested scope excluded. */
export type ScopeHonesty = {
  outOfScopeWorlds: string[]
  /** The census stopped at its scan cap or at the answer's deadline, so a world past it may be missing. */
  censusCapped: boolean
}

/** One time phrase read from a recall query. `used` narrowed the window; `unresolved` and `future` were skipped. */
export type TemporalHint = {
  phrase: string
  status: "used" | "unresolved" | "future"
  /** Unix seconds, inclusive. */
  start?: number
  end?: number
}

/** Retrieval accounting. */
export type RerankReport =
  | { status: "applied"; model: string; served_model?: string; candidates: number; calls: number }
  | { status: "skipped"; reason: "no_reranker" | "no_candidates" | "deadline" | "device_only" }

export type RetrievalMeta = {
  quality: "full" | "degraded" | "passthrough"
  degradation: ("ppr_cache_miss" | "embedding_timeout" | "bm25_stale" | "temporal_signal_skipped")[]
  confidenceAdjustment: number
  rerank?: RerankReport
  partial: boolean
  sparse?: boolean
  totalCandidates: number
  claimsReturned: number
  deepPending?: boolean
  temporalHints?: TemporalHint[]
  /** The request's limit was past the ceiling and was served at it. */
  limitClamped?: boolean
}

/** A full-vault render in one of the five pack serialization formats. */
/** The whole-vault archive (OF-222): a ZIP, standard base64 in `archive`. */
export type MemoryExport = { format: string; archive: string; digest: string }

/** One read scope: which entity types, sensitivity, staleness, confidence and salience it admits. */
export type ReadScope = {
  /** Admitted entity type bytes; absent means every registered type. */
  entityTypes?: number[]
  maxSensitivityBand: number
  includeStale: boolean
  minConfidence: number
  minSalience: number
  /** The scope admits nothing. */
  denyAll: boolean
}

/** The mandatory receipt every read returns: what was asked, the actor's ceiling, what applied, and which axes narrowed. */
export type ReadReceipt = {
  requested: ReadScope
  actorCeiling: ReadScope
  applied: ReadScope
  narrowedAxes: string[]
  /** Stored rows this actor may not read. */
  suppressedCount: number
  replanHint: string[]
}

/** The engine `MemoryPack`, unchanged apart from field spelling. */
export type MemoryPack = {
  items: MemoryItem[]
  scopeHonesty: ScopeHonesty
  retrievalMeta: RetrievalMeta
  /** Always equal to the engine's `MEMORY_PACK_VERSION`, and to this package's major. */
  packVersion: number
  rendered?: string
  /** The actor-scoped read receipt for candidates and rendered content. */
  narrowing: ReadReceipt
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

/** Exact namespace/key address in the bound actor/class's WORLDLESS store. */
export interface KeyValueAddress { namespace: string[]; key: string }
export interface KeyValuePut extends KeyValueAddress {
  value: Record<string, unknown>
  /** Reuse only for an identical retry. */
  requestId: string
  /** Omitted means generated. The gate still decides admission. */
  source?: string
}
export interface KeyValueItem extends KeyValueAddress {
  value: Record<string, unknown>
  createdAt: number
  updatedAt: number
  revision: string
}
export interface KeyValuePutReceipt { item: KeyValueItem; replayed: boolean; receiptRef: string }
export interface KeyValueDeleteReceipt { existed: boolean; receiptRefs: string[] }
export interface KeyValueSearch {
  namespacePrefix?: string[]
  /** Exact top-level field equality; operators are refused. */
  filter?: Record<string, unknown> | null
  limit?: number
  offset?: number
}
export interface KeyValueNamespaces {
  prefix?: string[]
  suffix?: string[]
  maxDepth?: number | null
  limit?: number
  offset?: number
}
