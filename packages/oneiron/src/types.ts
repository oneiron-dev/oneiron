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
  /**
   * The class of machine the host declares this install to be, set before the
   * vault opens (FIX 5560): `"computer"`, the default when omitted, or
   * `"phone"`. Never read off the operating system.
   */
  deviceClass?: "computer" | "phone"
  /**
   * Holds this install's host root as the vault's checkpoint signer for the
   * handle's life (FIX 5343): the device sync's steady pass attests with it
   * the images its home writes. Only {@link Oneiron.openWithHostRoot} reads
   * it; omitted is `false`. A secret that went unused is never held.
   */
  holdCheckpointRootSigner?: boolean
}

/**
 * What {@link Oneiron.openWithHostRoot} did with the host root it was given
 * (FIX 4730).
 */
export type HostRootProfile = {
  /**
   * This open enrolled this install in the vault as an `Unanswered` machine;
   * `false` when its live profile already stood, and nothing was written.
   */
  readonly enrolled: boolean
  /**
   * The given root is not this vault's settled root, so it went unused: this
   * install already carried its profile, and the handle stands under the
   * settled root as before. Reported, never refused, so the host can show it
   * or re-key. Never `true` with `enrolled`.
   */
  readonly wrongRoot: boolean
}

/** What {@link Oneiron.startEngine} takes besides the path (OF-237). */
export type EngineOptions = {
  /** Embedding vector dimensions; omitted takes the config's. */
  dimensions?: number
  /** The `oneiron serve --config` file the engine resolves; omitted resolves none. */
  configFile?: string
  /** The host keychain by exact name (`auth_secret`, `vault_password`), each value UTF-8. */
  secrets?: Record<string, string>
  /** Memory the engine may size its bounds from, in bytes; omitted is unbounded. */
  memoryBytes?: number
  /** CPU time per second, in milliseconds; omitted is unbounded. */
  cpuMillisPerSecond?: number
}

/** One header of a request to the embedded engine or of its reply (FIX 4895). */
export type EngineHeader = { name: string; value: Uint8Array }

/** One request the app sends its embedded engine: the request a socket's client sends, bringing its own auth. */
export type EngineRequest = {
  method: string
  /** The path and query, e.g. `/v1/core/health`. */
  path: string
  headers?: EngineHeader[]
  body?: Uint8Array
}

/** The engine's whole reply to one request. A 4xx or 5xx status is a reply, not an error. */
export type EngineReply = {
  status: number
  /** Every header the reply carried, repeats included. */
  headers: EngineHeader[]
  body: Uint8Array
}

/** An authority key's signature suite. */
export type CheckpointPinSuite = "ed25519" | "p256"

/** One authority public key in a checkpoint pin. */
export type CheckpointPinKey = {
  suite: CheckpointPinSuite
  /** Lowercase hex: 32 bytes for Ed25519, the compressed SEC1 point for P-256. */
  key: string
}

/** A root's classical signature over a key binding. */
export type CheckpointPinSignature = {
  suite: CheckpointPinSuite
  /** The key that verifies the signature. */
  publicKey: CheckpointPinKey
  /** Lowercase hex. */
  signature: string
}

/** One eligible root of the pinned policy. */
export type CheckpointPinRoot = {
  key: CheckpointPinKey
  tier: "software" | "hardware" | "cloud_custodial"
  /** The managed host root, which managed mode requires. */
  host: boolean
}

/** The eligible roots and the quorum a checkpoint needs from them. */
export type CheckpointPinPolicy = {
  posture: "managed" | "relay" | "self_host"
  /** Ascending by key, one row per root. */
  roots: CheckpointPinRoot[]
  /** Distinct eligible roots that must attest. */
  quorum: number
  /** One attesting root must be hardware-backed. */
  hardware: boolean
  /** The owner selected these roots and this quorum: no host root need attest. */
  ownerSelected: boolean
}

/** An eligible root's certificate for its checkpoint SLH-DSA key. */
export type CheckpointPinBinding = {
  /** 32 bytes, lowercase hex. */
  vaultId: string
  /** The authority genesis entry hash, lowercase hex. */
  genesis: string
  root: CheckpointPinKey
  /** The install whose checkpoint signing seed holds the key: 16 bytes, lowercase hex. */
  install: string
  /** The SLH-DSA-SHA2-256s public key, lowercase hex. */
  slhdsa: string
  /** The crypto epoch the key signs at. */
  epoch: number
  signature: CheckpointPinSignature
}

/**
 * The checkpoint pin {@link Oneiron.pair} returns (OF-469): what a joining
 * device trusts the vault's checkpoint by, fixed by the pairing link. It is
 * already checked against the link and is stored nowhere; a machine that will
 * run a local replica keeps it whole beside the server origin and the
 * credential, and supplies it when that replica starts.
 */
export type CheckpointPin = {
  /** The single-use pairing link's nonce, lowercase hex. */
  challenge: string
  /** 32 bytes, lowercase hex. */
  vaultId: string
  /** The authority genesis entry hash, lowercase hex. */
  genesis: string
  /** The pinned checkpoint image id, lowercase hex. */
  checkpoint: string
  policy: CheckpointPinPolicy
  /** Ascending by root key, one per root. */
  bindings: CheckpointPinBinding[]
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
  /** This message's quote: a span of one MESSAGE in the same room, cited by this message. */
  quote?: QuoteSpan
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
  /** A new project room thread root's audience seed (32-hex ids); edited later through vault.rooms.thread_audience. */
  threadAudience?: string[]
  /** The records this reply names as cited or created, judged by the engine under the writer's own read; omitted means it asserts nothing. */
  assertions?: WitnessAssertions
}

/** The records one witnessed reply names. A supplied assertion is the engine's input, never proof of creation: a `created` record whose birth does not prove the writer made it is recorded `creation_not_proven`. */
export type WitnessAssertions = {
  /** Records the reply cites. */
  cited: RecordRef[]
  /** Records the reply reports it created. */
  created: RecordRef[]
}

/** The quoted span of one MESSAGE: half-open Unicode scalar indices, never UTF-16 units. */
export type QuoteSpan = {
  /** The quoted MESSAGE (not the TURN that holds it), as 32 hex. */
  message: string
  /** First quoted scalar. */
  start: number
  /** One past the last quoted scalar. */
  end: number
}

/** Receipt for one witnessed turn. */
export type WitnessReceipt = {
  turnShortId: string
  messageShortIds: string[]
  /** Facade write marker; always begins `witness:`. */
  receiptRef: string
  /** What the wake this turn owes its actor's armed programs came to; absent when it owes none. */
  wakeOutcome?: TurnProgramWakeOutcome
}

/** What a landed turn's program wake came to. The turn is accepted either way. */
export type TurnProgramWakeOutcome = {
  outcome: "not_armed" | "evaluated" | "unpersisted"
  /** Wakes this landing recorded, when `evaluated`; zero is no failure. */
  newlyRecorded?: number
  /** Why no wake was recorded, when `unpersisted`. */
  reason?: "no_authority" | "storage_failure"
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
  /** RELATIONSHIP refs: omitted means all relationships, `[]` the explicit empty set. */
  relationshipRef?: string[]
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
  /** Project audience ids to select from. Unset or empty adds no narrowing to what the caller may read. */
  projectRefs?: string[]
  /** Conversation entity refs. Empty adds no narrowing; with `personRef`, only conversations selected by both axes remain. */
  conversationRefs?: string[]
  /** PERSON entity ref; selects conversations where they authored at least one live MESSAGE, never conversations that merely mention them. */
  personRef?: string
}

/** A recall's media query (OF-370): bytes the server embeds into one declared space, searched as that space's list beside the query's. An embedded client returns `MODEL_UNAVAILABLE`. */
export type RecallMedia = {
  /** Declared embedding space id: an `ai.embed` rung id, then `@where`. */
  space: string
  /** Media type of the bytes: `image/*`, `audio/*` or `text/*`. */
  mime: string
  /** The bytes, standard base64. */
  bytesB64: string
  /** The kinds of item the space's list keeps; every kind the space holds when unset. */
  kinds?: ("text" | "image" | "audio")[]
}

/** A recall's query affect (OF-423): emotion congruence ranks a candidate by how near its own valence, arousal and dominance sit. Out of range returns `BAD_REQUEST`. */
export type QueryAffect = {
  /** Valence, -1 to 1. */
  valence: number
  /** Arousal, 0 to 1. */
  arousal: number
  /** Dominance, 0 to 1. */
  dominance: number
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
  /** A media query the server embeds into its declared space and searches beside the query. */
  media?: RecallMedia
  /** The affect the query is asked in; omitted, recall ranks as before. */
  queryAffect?: QueryAffect
  /** The token budget `format`'s rendering is cut to; 0 renders it uncut. Omitted, the window budget of `readerAgentRef`'s memory profile, else 4,000. */
  tokenBudget?: number
  /** An agent definition whose memory profile sizes the rendering when `tokenBudget` is omitted; it grants no read. */
  readerAgentRef?: string
}

/** Where one recalled item came from. */
export type MemoryProvenance = {
  source: string
  sourceRevisionIds: string[]
  evidenceTurnIds: string[]
}

/** A retained foreign world's stale stamp, present only on an admitted recall item. */
export type MemoryStaleStamp = {
  /** Unix seconds; absent when the terminal fold is visible before its stamp sweep. */
  staleSince?: number
  /** Seconds since staleSince; absent when the stamp time is unknown. */
  ageSecs?: number
  /** The terminal reason: disconnected, dissolved or promoted. */
  reason: string
  pactEpoch: number
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
  /** Retained foreign content stopped refreshing; selecting its world grants no read authority. */
  stale?: MemoryStaleStamp
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
  /** The message as a typed record ref, the one the reader's read of it admitted. It carries no revision pin. */
  record?: RecordRef
}

/** A typed record ref: a record the reader's own read admitted, with its display label. Display data only, never authority. */
export type RecordRef = {
  /** Registry kind string (`CLAIM`, `MESSAGE`, `PERSON`, ...). */
  kind: string
  /** 32-hex entity id. */
  id: string
  /** The vault's short id, when one is assigned; never revision-pinned. */
  shortId?: string
  /** A bounded, single-line display label. */
  label: string
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
/** One whole-vault export written to the caller's file (FIX 11177): its format, length and BLAKE3. The archive is the caller's file. */
export type ExportReceipt = { format: string; bytes: number; digest: string }

/** One read scope: which entity types, sensitivity, staleness, confidence and salience it admits. */
export type ReadScope = {
  /** Admitted entity types as registry kinds (`CLAIM`, `MESSAGE`, ...); absent means every registered type. */
  entityTypes?: string[]
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
  /** Finalized serving-run id bytes; absent when local capture is off. */
  retrievalRunId?: number[]
  /** What a device that syncs only what it opened says of the windows it does not hold; absent when it holds every window or runs no sync. */
  residence?: RecallResidence
}

/** What an opened device's recall says of the windows it does not hold (FIX 2905): the home's hits are separate references the local pack does not hold, and a hit's window opens it. */
export type RecallResidence = {
  source: "home" | "local_only"
  /** The home answered in full; false also marks the pack partial. */
  complete: boolean
  /** The home was asked for no more than the residence `search_limit`. */
  capped: boolean
  /** The home's references, in its order, each entity once. */
  hits: RecallResidenceHit[]
}

/** One reference the home holds that the local pack does not. */
export type RecallResidenceHit = {
  /** The entity's full id, 32 lowercase hex. */
  id: string
  /** The home's own score, never compared with a local item's. */
  score: number
  /** The month window (`YYYY-MM`) that holds the hit. */
  window: string
}

/** One governance receipt: a gate decision, or a receipt of another family. */
export type FacadeReceipt = {
  /** `gate:<hex>`, or the family receipt's id. */
  receiptRef: string
  /** The receipt family kind (`gate`, `hook`, `outbound`, ...). */
  kind: string
  /** `allow`, `pending`, or `deny`; the receipt's own outcome for another kind. */
  outcome: string
  /** Unix seconds. */
  createdAt: number
  reasonCodes: string[]
  actorClass: string
  actorRef?: string
  contentKind: string
  claimRef?: string
  /** That claim as a typed record ref, labelled with its kind and id. */
  claim?: RecordRef
  /** A family receipt's own fields; empty on a gate-ledger row. */
  fields: Record<string, string>
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
