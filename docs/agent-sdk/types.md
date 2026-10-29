# Memory Wire type contract

## JavaScript / TypeScript

```ts
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
  /** Project audience ids to select from. Unset or empty adds no narrowing to what the caller may read. */
  projectRefs?: string[]
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
```

## Python

```python
"""Typed contract for the `oneiron` package (ONE-1441 §HEAD-CONTRACT).

Every DTO is a `TypedDict` with snake_case keys, which is the engine's own
field spelling — the JavaScript package carries the same types in camelCase and
the two are semantically isomorphic.

Timestamps are Unix SECONDS everywhere and are never converted. Blob content is
`bytes`; base64 is a native-boundary implementation detail and appears nowhere
in these stubs.
"""

import os
from typing import Any, Literal, NotRequired, TypedDict, overload

from . import facade_types as Facade

__all__ = ["Oneiron", "OneironError"]

WitnessAuthor = Literal["user", "companion", "system"]
Effort = Literal["light", "medium", "high", "xhigh", "max", "call"]
PackFormat = Literal["json", "yaml", "toon", "md", "txt"]

class QuoteSpan(TypedDict):
    # The quoted MESSAGE (not the TURN that holds it), as 32 hex.
    message: str
    # Half-open Unicode scalar indices into its text.
    start: int
    end: int

class WitnessMessage(TypedDict):
    id: NotRequired[str]
    author: WitnessAuthor
    message_type: str
    content: str
    metadata: NotRequired[dict[str, Any] | None]
    is_visible: NotRequired[bool]
    order: int
    # This message's quote: a span of one MESSAGE in the same room, cited by this message.
    quote: NotRequired[QuoteSpan | None]

class WitnessTurn(TypedDict):
    conversation_ref: str
    turn_ref: NotRequired[str | None]
    messages: list[WitnessMessage]
    # Unix seconds; omitted is stamped at the call boundary.
    occurred_at: NotRequired[int]
    # A new project room thread root's audience seed; edited later through vault.rooms.thread_audience.
    thread_audience: NotRequired[list[str] | None]

class WitnessReceipt(TypedDict):
    turn_short_id: str
    message_short_ids: list[str]
    # Always begins `witness:`.
    receipt_ref: str

class ClaimInput(TypedDict):
    id: NotRequired[str]
    predicate: str
    subject_ref: str
    value: Any
    confidence: float
    source: str
    world_ref: NotRequired[str | None]
    scope: NotRequired[dict[str, Any] | None]
    valid_from: NotRequired[int | None]
    valid_to: NotRequired[int | None]
    occurred_at: NotRequired[int | None]
    learned_at: NotRequired[int | None]
    salience: NotRequired[float | None]

class CommitReceipt(TypedDict):
    claim_short_id: str
    approval: str
    superseded_short_id: str | None
    receipt_ref: str

class RecallScope(TypedDict):
    world_ref: NotRequired[str | None]
    facet: NotRequired[str | None]
    kinds: NotRequired[list[str] | None]

class RecallMedia(TypedDict):
    """A recall's media query (OF-370): bytes the server embeds into one declared space."""
    space: str
    mime: str
    bytes_b64: str
    kinds: NotRequired[list[Literal["text", "image", "audio"]]]

class QueryAffect(TypedDict):
    """A recall's query affect (OF-423): valence in -1..1, arousal and dominance in 0..1."""
    valence: float
    arousal: float
    dominance: float

class MemoryProvenance(TypedDict):
    source: str
    source_revision_ids: list[str]
    evidence_turn_ids: list[str]

MemoryStaleStamp = Facade.MemoryStaleStamp

class MemoryItem(TypedDict):
    short_id: str
    source_revision_ref: NotRequired[str]
    kind: str
    predicate: str | None
    value_text: str
    confidence: float
    hedge_bucket: str
    provenance: MemoryProvenance
    stale: NotRequired[MemoryStaleStamp]
    world: str | None
    facet: str | None
    salience: float | None
    cited_messages: NotRequired[list[CitedMessage]]
    conversation_id: NotRequired[str]

class CitedMessage(TypedDict):
    short_id: str
    value_text: str
    record: NotRequired[RecordRef]

class RecordRef(TypedDict):
    kind: str
    id: str
    # Always present; null when the record has no short id (FIX 4802).
    short_id: str | None
    label: str

class ScopeHonesty(TypedDict):
    out_of_scope_worlds: list[str]

class TemporalHint(TypedDict):
    phrase: str
    status: Literal["used", "unresolved", "future"]
    start: int | None
    end: int | None

class RetrievalMeta(TypedDict):
    quality: Literal["full", "degraded", "passthrough"]
    degradation: NotRequired[list[Literal["ppr_cache_miss", "embedding_timeout", "bm25_stale", "temporal_signal_skipped"]]]
    confidence_adjustment: float
    partial: bool
    sparse: bool | None
    total_candidates: int
    claims_returned: int
    deep_pending: bool | None
    temporal_hints: NotRequired[list[TemporalHint]]
    limit_clamped: NotRequired[bool]

class RecallResidenceHit(TypedDict):
    # The entity's full id, 32 lowercase hex.
    id: str
    # The home's own score, never compared with a local item's.
    score: float
    # The month window (YYYY-MM) that holds the hit.
    window: str

class RecallResidence(TypedDict):
    # What an opened device's recall says of the windows it does not hold:
    # the home's hits are separate references the local pack does not hold.
    source: Literal["home", "local_only"]
    complete: bool
    capped: bool
    hits: list[RecallResidenceHit]

class MemoryPack(TypedDict):
    items: list[MemoryItem]
    scope_honesty: ScopeHonesty
    retrieval_meta: RetrievalMeta
    # Always equal to the engine's MEMORY_PACK_VERSION, and to this package's major.
    pack_version: int
    rendered: str | None
    # Absent when this device holds every window it may read, or runs no sync.
    residence: NotRequired[RecallResidence]

class FacadeReceipt(TypedDict):
    receipt_ref: str
    kind: str
    outcome: str
    created_at: int
    reason_codes: list[str]
    actor_class: str
    actor_ref: str | None
    content_kind: str
    claim_ref: str | None
    # That claim as a typed record ref, labelled with its kind and id.
    claim: RecordRef | None
    fields: NotRequired[dict[str, str]]


class KeyValueAddress(TypedDict):
    namespace: list[str]
    key: str

class KeyValuePut(KeyValueAddress):
    value: dict[str, Any]
    request_id: str
    source: NotRequired[str]

class KeyValueItem(KeyValueAddress):
    value: dict[str, Any]
    created_at: int
    updated_at: int
    revision: str

class KeyValuePutReceipt(TypedDict):
    item: KeyValueItem
    replayed: bool
    receipt_ref: str

class KeyValueDeleteReceipt(TypedDict):
    existed: bool
    receipt_refs: list[str]

class KeyValueSearch(TypedDict):
    namespace_prefix: NotRequired[list[str]]
    filter: NotRequired[dict[str, Any] | None]
    limit: NotRequired[int]
    offset: NotRequired[int]

class KeyValueNamespaces(TypedDict):
    prefix: NotRequired[list[str]]
    suffix: NotRequired[list[str]]
    max_depth: NotRequired[int | None]
    limit: NotRequired[int]
    offset: NotRequired[int]

# `describe`'s answer, every variant the engine writes (the generated type).
TaskDescription = Facade.TaskDescription

class TaskCancelReceipt(TypedDict):
    approval: Literal["auto", "proposed", "approved", "rejected"]
    effected: bool
    proposal_ref: str | None
    gate_decision_ref: str | None
    status: Literal["queued", "running", "paused", "completed", "failed", "cancelled", "abandoned"] | None
    cancel_requested: bool
    forced: bool

TaskCanAskRequest = dict[str, Any]
TaskAskHandle = dict[str, str]

class TaskAskPreflightRecipient(TypedDict):
    who: str
    face: str | None
    channel: str | None
    word_required: bool

class TaskAskPreflight(TypedDict):
    recipients: list[TaskAskPreflightRecipient]

class TaskAskPersonEvidence(TypedDict):
    who: str
    answer: dict[str, Any] | None
    kind: Literal["word", "companion", "default", "unknown"]
    at: int
    source: str | None

# OF-181: a host-rendered lens card's event and close. These keep the wire's
# camelCase keys: they are the server route's bodies, not snake_case DTOs.
# `selectedContext` (FIX 3268): the clicker's selectionRefs on this card,
# context for a model round trip only; empty when absent.
LensFrameEventRequest = TypedDict(
    "LensFrameEventRequest",
    {
        "event": Facade.GeneratedUiActionEvent,
        "idempotencyKey": str,
        "selectedContext": NotRequired[list[str]],
    },
)
LensFrameLocalReply = TypedDict("LensFrameLocalReply", {"$state": Facade.GeneratedUiStateSnapshot})
LensFrameToolReply = TypedDict(
    "LensFrameToolReply",
    {"outcome": Any, "readReceipt": Facade.ScopedReadReceipt},
)
LensFrameCallbackReply = TypedDict(
    "LensFrameCallbackReply",
    {"queued": bool, "callbackId": str},
)
LensFrameEventReply = LensFrameLocalReply | LensFrameToolReply | LensFrameCallbackReply

class CloseLensFrameReply(TypedDict):
    closed: bool

# OF-469: the checkpoint pin `Oneiron.pair` returns, every byte value as
# lowercase hex. It is the trust input a local replica adopts the vault's
# checkpoint by; keep it whole beside the server origin and the credential.
class CheckpointPinKey(TypedDict):
    suite: Literal["ed25519", "p256"]
    # 32 bytes for Ed25519; the compressed SEC1 point for P-256.
    key: str

class CheckpointPinSignature(TypedDict):
    suite: Literal["ed25519", "p256"]
    public_key: CheckpointPinKey
    signature: str

class CheckpointPinRoot(TypedDict):
    key: CheckpointPinKey
    tier: Literal["software", "hardware", "cloud_custodial"]
    # The managed host root, which managed mode requires.
    host: bool

class CheckpointPinPolicy(TypedDict):
    posture: Literal["managed", "relay", "self_host"]
    # Ascending by key, one row per root.
    roots: list[CheckpointPinRoot]
    # Distinct eligible roots that must attest.
    quorum: int
    # One attesting root must be hardware-backed.
    hardware: bool
    # The owner selected these roots and this quorum: no host root need attest.
    owner_selected: bool

class CheckpointPinBinding(TypedDict):
    vault_id: str
    genesis: str
    root: CheckpointPinKey
    # The install whose checkpoint signing seed holds the key (16 bytes).
    install: str
    # The SLH-DSA-SHA2-256s public key.
    slhdsa: str
    epoch: int
    signature: CheckpointPinSignature

class CheckpointPin(TypedDict):
    # The single-use pairing link's nonce.
    challenge: str
    vault_id: str
    # The authority genesis entry hash.
    genesis: str
    # The pinned checkpoint image id.
    checkpoint: str
    policy: CheckpointPinPolicy
    # Ascending by root key, one per root.
    bindings: list[CheckpointPinBinding]

class Paired(TypedDict):
    # A handle connected with the credential.
    memory: "Oneiron"
    # Store as ONEIRON_KEY; the link cannot be redeemed twice.
    credential: str
    # Checked against the link and stored nowhere; None when the vault has
    # no attested checkpoint.
    pin: CheckpointPin | None
    # Whom an agent paired by the credential may address, as the server took it.
    comm: Facade.CommReach

class HostRootProfile(TypedDict):
    # This open enrolled this install as an Unanswered machine; False when
    # its live profile already stood, and nothing was written.
    enrolled: bool
    # The given root is not the vault's settled root, so it went unused: the
    # handle stands under the settled root as before. Reported, never
    # refused. Never True with enrolled.
    wrong_root: bool

class HostRootOpened(TypedDict):
    # The embedded handle, bound to the local owner actor.
    memory: "Oneiron"
    host_root: HostRootProfile

class OneironError(RuntimeError):
    code: str
    message: str
    suggestions: tuple[str, ...]
    wrong_root: dict[str, str] | None
    # The verb hook's stop; on PENDING_ASK `{"status": "pending", "invocation", "ask"}`.
    hook: dict[str, Any] | None
    # When to call again, as the refusal's source said: seconds, and Unix-second resets.
    retry_after: int | None
    resets_at: tuple[int, ...] | None
    def __init__(
        self,
        code: str,
        message: str,
        suggestions: list[str],
        wrong_root: dict[str, str] | None = None,
        hook: dict[str, Any] | None = None,
        retry_after: int | None = None,
        resets_at: list[int] | None = None,
    ) -> None: ...

class Oneiron:
    @classmethod
    def open(
        cls,
        path: str | os.PathLike[str] | None = None,
        *,
        dimensions: int | None = None,
        device_class: Literal["computer", "phone"] | None = None,
    ) -> "Oneiron": ...
    @classmethod
    def open_with_host_root(
        cls,
        path: str | os.PathLike[str] | None,
        host_root_secret: bytes,
        *,
        dimensions: int | None = None,
        device_class: Literal["computer", "phone"] | None = None,
    ) -> HostRootOpened:
        """open, then this install's machine profile from the vault's host root secret's exact bytes (FIX 5342)."""
    @classmethod
    def connect(cls, url: str, key: str) -> "Oneiron": ...
    @classmethod
    def pair(cls, link: str) -> Paired: ...
    def as_actor(self, actor_key: str) -> "Oneiron": ...
    def in_room_turn(self, room_ref: str) -> "Oneiron": ...
    def in_off_record_session(self, session_ref: str) -> "Oneiron": ...
    def last_receipt_ref(self) -> str | None: ...
    def retry(self, pending: OneironError, verb: str, input: Any) -> Any:
        """Resends a PENDING_ASK call under its invocation; the reply is the verb's shared wire JSON."""
    def lens_frame_event(self, card_id: str, request: LensFrameEventRequest) -> LensFrameEventReply:
        """Sends one event on a lens card the connected server rendered; embedded raises BAD_REQUEST."""
    def close_lens_frame(self, card_id: str) -> CloseLensFrameReply:
        """Closes a lens card the connected server rendered and frees its frame."""
# BEGIN GENERATED FACADE VERBS
    @property
    def vault(self) -> "Oneiron._VaultVerbs": ...
    def fetch(self, spec: Facade.WebFetchRequest) -> Facade.FetchResult:
        """Fetches one HTTP(S) page through the renderer ladder and retains its source as Imported evidence with Proposed claims; never walks links."""
    def crawl(self, spec: Facade.WebCrawlRequest) -> Facade.CrawlResult:
        """Crawls from one seed under an explicit attempted-page budget, same-origin by default; retains Imported evidence and Proposed claims, and returns failures and completion."""
    def report(self, spec: Facade.ReportRequest) -> Facade.ReportReceipt:
        """Files one feedback report on a skill or run: its subject, category and evidence; the host supplies the actor."""
    @property
    def feedback(self) -> "Oneiron._FeedbackVerbs": ...
    @property
    def self(self) -> "Oneiron._SelfVerbs": ...
    def cancel(self, task_ref: str) -> TaskCancelReceipt: ...
    def steer(self, spec: Facade.SteerRequest) -> Facade.SteerReceipt:
        """The TASK's spawner nudges its live run; a resend with the same key answers the first receipt."""
    def describe(self, task_ref: str | None = None) -> TaskDescription: ...
    @property
    def tasks(self) -> "Oneiron._TasksVerbs": ...
    @property
    def ai(self) -> "Oneiron._AiVerbs": ...
    @property
    def reveal(self) -> "Oneiron._RevealVerbs": ...
    @property
    def host(self) -> "Oneiron._HostVerbs": ...
    def mount(self, spec: Facade.GraphFsMountRequest) -> Facade.GraphFsMounted:
        """Open the caller-scoped live graph or a retained repository snapshot, resolving a snapshot id to its exact fork hash."""
    @property
    def graph_fs(self) -> "Oneiron._GraphFsVerbs": ...
    def execute_code(self, spec: Facade.ForeignCodeRunRequest) -> Facade.ForeignCodeRunResult:
        """Run foreign JavaScript with only scoped record snapshots and inert, receipted proposals in the existing isolated tier; no host writes, credentials or network grant are lent."""
    def can(self, request: TaskCanAskRequest) -> TaskAskPreflight: ...
    def peek(self, request: TaskAskHandle) -> list[TaskAskPersonEvidence]: ...
    @overload
    def ask(self, spec_or_who: Facade.TaskAskRequest) -> Facade.TaskAskReceipt: ...
    @overload
    def ask(self, spec_or_who: str | list[str] | set[str] | tuple[str, ...] | dict[str, Any] | None, what: dict[str, Any], until: int | None = None, default: str = "ask_me") -> Facade.TaskAskReceipt: ...
    def wait(self, handle: Facade.TaskAskHandle, step_key: str = "sdk.wait") -> Facade.TaskAskWait:
        """Waits on an ask, or on a world-privacy request its caller opened, at a step with no other work: pending, changed, ready with its result or the request's applied or declined state, or a park for code mode."""
    @property
    def connector(self) -> "Oneiron._ConnectorVerbs": ...
    @property
    def calendar(self) -> "Oneiron._CalendarVerbs": ...
    class _VaultVerbs:
        @property
        def commitments(self) -> "Oneiron._VaultCommitmentsVerbs": ...
        @property
        def reports(self) -> "Oneiron._VaultReportsVerbs": ...
        @property
        def diagnostics(self) -> "Oneiron._VaultDiagnosticsVerbs": ...
        @property
        def coach(self) -> "Oneiron._VaultCoachVerbs": ...
        @property
        def people(self) -> "Oneiron._VaultPeopleVerbs": ...
        @property
        def entities(self) -> "Oneiron._VaultEntitiesVerbs": ...
        @property
        def identity(self) -> "Oneiron._VaultIdentityVerbs": ...
        @property
        def shape(self) -> "Oneiron._VaultShapeVerbs": ...
        @property
        def companions(self) -> "Oneiron._VaultCompanionsVerbs": ...
        @property
        def personas(self) -> "Oneiron._VaultPersonasVerbs": ...
        @property
        def fanout(self) -> "Oneiron._VaultFanoutVerbs": ...
        @property
        def budgets(self) -> "Oneiron._VaultBudgetsVerbs": ...
        @property
        def runners(self) -> "Oneiron._VaultRunnersVerbs": ...
        def commit_message(self, spec: Facade.CommitMessageRequest) -> Facade.WitnessReceipt:
            """Writes one whole MESSAGE atomically through the witness gate; birth supplies its immutable conversation, turn and author axes."""
        def begin_message_stream(self, spec: Facade.BeginMessageStreamRequest) -> Facade.MessageStreamHandle:
            """Opens one caller-owned MESSAGE stream, with birth axes for a new message or stored axes for a continuation."""
        def append_to_stream(self, spec: Facade.AppendToStreamRequest) -> None:
            """Appends one authored delta to this actor's generation-bound stream through its existing write gate."""
        def flush_stream(self, spec: Facade.MessageStreamRequest) -> None:
            """Publishes the current partial at once when streamed visibility allows it; atomic mode stays private."""
        def finalize_stream(self, spec: Facade.MessageStreamRequest) -> Facade.MessageStreamReceipt:
            """Commits the stream as final and releases its handle, returning the immutable terminal receipt."""
        def cancel_stream(self, spec: Facade.CancelStreamRequest) -> Facade.MessageStreamReceipt:
            """Keeps the stream's text as one incomplete MESSAGE with cancelled finality and the caller's explicit reason."""
        def message_stream_partial(self, spec: Facade.MessageStreamRequest) -> Facade.MessageStreamPartial:
            """Reads only this actor's accepted in-memory partial using its generation-bound stream handle."""
        @property
        def messages(self) -> "Oneiron._VaultMessagesVerbs": ...
        def witness(self, turn: WitnessTurn) -> WitnessReceipt: ...
        @property
        def claims(self) -> "Oneiron._VaultClaimsVerbs": ...
        def recall(self, query: str, *, effort: Effort = 'medium', scope: RecallScope | None = None, limit: int = 10, format: PackFormat | None = None, as_of: int | None = None, deadline_ms: int | None = None, media: RecallMedia | None = None, query_affect: QueryAffect | None = None, token_budget: int | None = None, reader_agent_ref: str | None = None) -> MemoryPack: ...
        @property
        def retrieval(self) -> "Oneiron._VaultRetrievalVerbs": ...
        @property
        def affect(self) -> "Oneiron._VaultAffectVerbs": ...
        @property
        def tagging(self) -> "Oneiron._VaultTaggingVerbs": ...
        @property
        def cluster(self) -> "Oneiron._VaultClusterVerbs": ...
        @property
        def export(self) -> "Oneiron._VaultExportVerbs": ...
        @property
        def scope(self) -> "Oneiron._VaultScopeVerbs": ...
        @property
        def receipts(self) -> "Oneiron._VaultReceiptsVerbs": ...
        @property
        def assets(self) -> "Oneiron._VaultAssetsVerbs": ...
        @property
        def search(self) -> "Oneiron._VaultSearchVerbs": ...
        @property
        def images(self) -> "Oneiron._VaultImagesVerbs": ...
        @property
        def explain(self) -> "Oneiron._VaultExplainVerbs": ...
        @property
        def kv(self) -> "Oneiron._VaultKvVerbs": ...
        @property
        def campaign(self) -> "Oneiron._VaultCampaignVerbs": ...
        @property
        def turn_programs(self) -> "Oneiron._VaultTurnProgramsVerbs": ...
        @property
        def weave(self) -> "Oneiron._VaultWeaveVerbs": ...
        @property
        def inbox(self) -> "Oneiron._VaultInboxVerbs": ...
        @property
        def skills(self) -> "Oneiron._VaultSkillsVerbs": ...
        @property
        def skill_hubs(self) -> "Oneiron._VaultSkillHubsVerbs": ...
        @property
        def packs(self) -> "Oneiron._VaultPacksVerbs": ...
        @property
        def projects(self) -> "Oneiron._VaultProjectsVerbs": ...
        @property
        def connectors(self) -> "Oneiron._VaultConnectorsVerbs": ...
        @property
        def authority(self) -> "Oneiron._VaultAuthorityVerbs": ...
        @property
        def wire_health(self) -> "Oneiron._VaultWireHealthVerbs": ...
        @property
        def slim(self) -> "Oneiron._VaultSlimVerbs": ...
        @property
        def mesh(self) -> "Oneiron._VaultMeshVerbs": ...
        @property
        def inspection(self) -> "Oneiron._VaultInspectionVerbs": ...
        @property
        def shared(self) -> "Oneiron._VaultSharedVerbs": ...
        @property
        def org_admin(self) -> "Oneiron._VaultOrgAdminVerbs": ...
        @property
        def members(self) -> "Oneiron._VaultMembersVerbs": ...
        @property
        def federation(self) -> "Oneiron._VaultFederationVerbs": ...
        @property
        def trusted_contacts(self) -> "Oneiron._VaultTrustedContactsVerbs": ...
        @property
        def guests(self) -> "Oneiron._VaultGuestsVerbs": ...
        @property
        def support_grants(self) -> "Oneiron._VaultSupportGrantsVerbs": ...
        @property
        def files(self) -> "Oneiron._VaultFilesVerbs": ...
        @property
        def residence(self) -> "Oneiron._VaultResidenceVerbs": ...
        @property
        def off_record(self) -> "Oneiron._VaultOffRecordVerbs": ...
        @property
        def records(self) -> "Oneiron._VaultRecordsVerbs": ...
        @property
        def research(self) -> "Oneiron._VaultResearchVerbs": ...
        @property
        def evals(self) -> "Oneiron._VaultEvalsVerbs": ...
        @property
        def roots(self) -> "Oneiron._VaultRootsVerbs": ...
        @property
        def cleanup(self) -> "Oneiron._VaultCleanupVerbs": ...
        @property
        def archive(self) -> "Oneiron._VaultArchiveVerbs": ...
        @property
        def usage(self) -> "Oneiron._VaultUsageVerbs": ...
        @property
        def legal_holds(self) -> "Oneiron._VaultLegalHoldsVerbs": ...
        @property
        def courtesy_delete(self) -> "Oneiron._VaultCourtesyDeleteVerbs": ...
        @property
        def embedding_spaces(self) -> "Oneiron._VaultEmbeddingSpacesVerbs": ...
        @property
        def policy(self) -> "Oneiron._VaultPolicyVerbs": ...
        @property
        def consent(self) -> "Oneiron._VaultConsentVerbs": ...
        @property
        def gate(self) -> "Oneiron._VaultGateVerbs": ...
        @property
        def learning(self) -> "Oneiron._VaultLearningVerbs": ...
        @property
        def seal(self) -> "Oneiron._VaultSealVerbs": ...
        @property
        def settings(self) -> "Oneiron._VaultSettingsVerbs": ...
        @property
        def secrets(self) -> "Oneiron._VaultSecretsVerbs": ...
        @property
        def widen_proposals(self) -> "Oneiron._VaultWidenProposalsVerbs": ...
        @property
        def craft_candidates(self) -> "Oneiron._VaultCraftCandidatesVerbs": ...
        @property
        def lenses(self) -> "Oneiron._VaultLensesVerbs": ...
        @property
        def disclosure(self) -> "Oneiron._VaultDisclosureVerbs": ...
        @property
        def shares(self) -> "Oneiron._VaultSharesVerbs": ...
        @property
        def hooks(self) -> "Oneiron._VaultHooksVerbs": ...
        @property
        def artifacts(self) -> "Oneiron._VaultArtifactsVerbs": ...
        @property
        def code(self) -> "Oneiron._VaultCodeVerbs": ...
        @property
        def results(self) -> "Oneiron._VaultResultsVerbs": ...
        @property
        def agents(self) -> "Oneiron._VaultAgentsVerbs": ...
        @property
        def repo(self) -> "Oneiron._VaultRepoVerbs": ...
        @property
        def standing_blocks(self) -> "Oneiron._VaultStandingBlocksVerbs": ...
        @property
        def workflows(self) -> "Oneiron._VaultWorkflowsVerbs": ...
        @property
        def task_types(self) -> "Oneiron._VaultTaskTypesVerbs": ...
        @property
        def tasks(self) -> "Oneiron._VaultTasksVerbs": ...
        @property
        def runs(self) -> "Oneiron._VaultRunsVerbs": ...
        @property
        def consults(self) -> "Oneiron._VaultConsultsVerbs": ...
        @property
        def workspace(self) -> "Oneiron._VaultWorkspaceVerbs": ...
        @property
        def critic(self) -> "Oneiron._VaultCriticVerbs": ...
        @property
        def rooms(self) -> "Oneiron._VaultRoomsVerbs": ...
        @property
        def conversations(self) -> "Oneiron._VaultConversationsVerbs": ...
        @property
        def models(self) -> "Oneiron._VaultModelsVerbs": ...
        @property
        def voices(self) -> "Oneiron._VaultVoicesVerbs": ...
        @property
        def graph(self) -> "Oneiron._VaultGraphVerbs": ...
        @property
        def questions(self) -> "Oneiron._VaultQuestionsVerbs": ...
        @property
        def decisions(self) -> "Oneiron._VaultDecisionsVerbs": ...
        def commit(self, input: Facade.ScopedCommitRequest) -> list[Facade.CommitOutcome]:
            """Commits claims through the gate, each element its own write; each answers its landed receipt, or its typed refusal and refusal receipt when nothing of it persisted."""
        def remember(self, input: Facade.ClaimInput) -> Facade.CommitReceipt:
            """Commits one claim through the gate, the same as vault.claims.upsert."""
        def forget(self, input: Facade.ForgetRequest) -> list[Facade.CommitReceipt]:
            """Retracts claims by exact claim or by subject and predicate; never a hard delete."""
        @property
        def booking(self) -> "Oneiron._VaultBookingVerbs": ...
        @property
        def calendar(self) -> "Oneiron._VaultCalendarVerbs": ...
        def delete(self, input: Facade.SafeDeleteRequest) -> Facade.DeleteReceipt:
            """Deletes one entity under a named reason; an owner verb that only a verified human may call."""
        @property
        def writes(self) -> "Oneiron._VaultWritesVerbs": ...
        def hydrate(self, input: Facade.HydrateRequest) -> Facade.ScopedReadResult[list[Facade.EntityView]]:
            """Hydrates short refs or hex ids to full entity views, with the read's receipt."""
        def get(self, input: Facade.EntityRequest) -> Facade.ScopedReadResult[Facade.EntityView | None]:
            """Reads one entity as a typed view, or none when absent or withheld; the receipt says which."""
        @property
        def refs(self) -> "Oneiron._VaultRefsVerbs": ...
        @property
        def vectors(self) -> "Oneiron._VaultVectorsVerbs": ...
        def neighbors(self, input: Facade.NeighborsRequest) -> Facade.ScopedReadResult[list[Facade.NeighborHit]]:
            """The weighted-edge neighbourhood of one entity, filtered by edge kind and minimum weight."""
        @property
        def structural(self) -> "Oneiron._VaultStructuralVerbs": ...
        @property
        def habits(self) -> "Oneiron._VaultHabitsVerbs": ...
        @property
        def productivity(self) -> "Oneiron._VaultProductivityVerbs": ...
        @property
        def esign(self) -> "Oneiron._VaultEsignVerbs": ...
        def batch(self, spec: Facade.CoreBatchWriteInput) -> Facade.CoreBatchWriteReceipt:
            """Commits every core entity put it names atomically, all or none, at the grade of the credential that sent them; an embedded handle commits below owner grade."""
        @property
        def consolidation(self) -> "Oneiron._VaultConsolidationVerbs": ...
        @property
        def sieve(self) -> "Oneiron._VaultSieveVerbs": ...
        @property
        def free_time(self) -> "Oneiron._VaultFreeTimeVerbs": ...
        @property
        def memory(self) -> "Oneiron._VaultMemoryVerbs": ...
        @property
        def channel_identities(self) -> "Oneiron._VaultChannelIdentitiesVerbs": ...
        @property
        def delivery_window(self) -> "Oneiron._VaultDeliveryWindowVerbs": ...
        @property
        def summaries(self) -> "Oneiron._VaultSummariesVerbs": ...
        @property
        def notes(self) -> "Oneiron._VaultNotesVerbs": ...
        def revert_run(self, spec: Facade.RevertRunRequest) -> Facade.RevertRunOutcome:
            """The owner compensates all or selected changes of a settled run, preserving later work and listing every change not undone and why."""
    class _VaultCommitmentsVerbs:
        def create(self, spec: Facade.CommitmentCreateRequest) -> Facade.CommitmentCreateReceipt:
            """Creates an authored commitment series and its due index atomically, without approving a reminder."""
        def get(self, spec: Facade.CommitmentRefRequest) -> Facade.CommitmentView:
            """Reads a commitment with its schedule, birth provenance, separate occurrence and learning times, and lifecycle receipt."""
        def instances(self, spec: Facade.CommitmentRefRequest) -> list[Facade.CommitmentView]:
            """Lists the materialized occurrences of a commitment series, including closed obligations."""
        def proposals(self, spec: Facade.CommitmentRefRequest) -> list[Facade.CommitmentWakeProposal]:
            """Observes real timer-wake reminder proposals and their run approval keys without authorizing delivery."""
        def fulfill(self, spec: Facade.CommitmentFulfillRequest) -> Facade.CommitmentView:
            """Explicitly confirms an obligation fulfilled with witness evidence through the existing fulfillment dispatcher."""
        def release(self, spec: Facade.CommitmentCloseRequest) -> Facade.CommitmentView:
            """Explicitly releases an obligation with witness evidence and clears its due phases in the same transaction."""
        def supersede(self, spec: Facade.CommitmentCloseRequest) -> Facade.CommitmentView:
            """Explicitly supersedes an obligation with witness evidence and clears its due phases in the same transaction."""
    class _VaultReportsVerbs:
        def disclosure(self, spec: Facade.ReportDisclosureRequest) -> Facade.ReportIssue:
            """The owner decides whether one publisher-routed report's exact quoted text may cross to its publisher: approve once, stop asking, or deny."""
        def route(self, spec: Facade.ReportRouteRequest) -> Facade.ReportRouteReceipt:
            """The owner replaces one durable subject's maker route: the owner inbox, or one admitted publisher its feedback is delivered to."""
        def outbound(self, spec: Facade.ReportOutboundRequest) -> Facade.ReportOutboundView:
            """The owner reads the content-free payload a publisher delivery for one report issue would carry now, with its quoted text only when disclosure approved it."""
    class _VaultDiagnosticsVerbs:
        def list(self, spec: Facade.DiagnosticsListRequest) -> Facade.ScopedReadResult[list[Facade.DiagnosticEventView]]:
            """Lists the engine-authored diagnostic events the caller reads, by class, actor, or evidence, with the read's narrowing receipt."""
        def get(self, spec: Facade.DiagnosticsGetRequest) -> Facade.ScopedReadResult[Facade.DiagnosticEventView | None]:
            """Reads one diagnostic event the caller may read, by ref, with the read's narrowing receipt."""
    class _VaultCoachVerbs:
        def inspect(self, spec: Facade.CoachInspectRequest) -> Facade.ScopedReadResult[Facade.CoachInspectionView]:
            """Inspects one blocked report as the Coach reads it: its fenced receipt, linked diagnostic band, working set, and the repair proposal the Coach filed, through the caller's own lane."""
        @property
        def training_offers(self) -> "Oneiron._VaultCoachTrainingOffersVerbs": ...
    class _VaultCoachTrainingOffersVerbs:
        def __call__(self, spec: Facade.OfferListRequest) -> list[Facade.OfferView]:
            """Read Coach offer snapshots, their exact owner answers and later promise checks; optionally select a seat or only pending offers."""
        def get(self, spec: Facade.OfferRef) -> Facade.OfferView | None:
            """Read one Coach offer snapshot with its owner answer and receipt-backed promise checks."""
        def trigger(self, spec: Facade.OfferPassRequest) -> Facade.OfferPassRef:
            """Queue one production Coach training-offer pass under the owner proof; the offer skill decides what to raise and no caller supplies an offer body."""
        def result(self, spec: Facade.OfferPassRef) -> Facade.OfferPassResult | None:
            """Read the production Coach offer attempt state and the exact snapshots it raised; a completed pass may raise no offer."""
        def answer(self, spec: Facade.OfferAnswerRequest) -> Facade.OfferAnswerRecord:
            """Answer the exact shown Coach snapshot: keep baseline, decline, postpone, approve switch or approve train; training still needs its separate result-swap choice."""
        def undo(self, spec: Facade.OfferRef) -> Facade.OfferUndoReceipt:
            """Undo an approved stock switch only while its own seat still holds the switched binding; restore the previous whole binding."""
        @property
        def candidates(self) -> "Oneiron._VaultCoachTrainingOffersCandidatesVerbs": ...
        @property
        def pilots(self) -> "Oneiron._VaultCoachTrainingOffersPilotsVerbs": ...
    class _VaultCoachTrainingOffersCandidatesVerbs:
        def __call__(self, spec: Facade.OfferCandidateQuery) -> list[Facade.OfferCandidateRecord]:
            """Read pinned own-seat stock or training-recipe candidates, including their incumbent and explicit compute destination."""
        def prepare(self, spec: Facade.OfferCandidateSetup) -> Facade.OfferCandidateRecord:
            """Pin an own-seat catalog stock candidate or existing training recipe and its destination; this nominates only and never switches, downloads or trains."""
    class _VaultCoachTrainingOffersPilotsVerbs:
        def prepare(self, spec: Facade.OfferPilotPrepare) -> Facade.OfferPilotPrepared:
            """Prepare an eval-only pilot of a pinned seat candidate, counting its sealed cohort exposure before releasing receipt-backed cases; launch no compute or egress."""
        def complete(self, spec: Facade.OfferPilotComplete) -> Facade.OfferPilot:
            """Record immutable owner-evaluator pilot measurements bound to counted own-seat families; fixed code derives sufficiency and preserves unknown cost and score."""
        def get(self, spec: Facade.OfferPilotRef) -> Facade.OfferPilot | None:
            """Read one counted Coach pilot, its pins, measurement receipts, one-off cost and computed sufficiency card."""
    class _VaultPeopleVerbs:
        def list(self, spec: Facade.PeopleListRequest) -> Facade.PeoplePage:
            """One page of the people the caller reads, in handle order."""
        def get(self, spec: Facade.PersonRequest) -> Facade.PersonRow:
            """One person the vault knows, by their pr handle."""
        def create(self, spec: Facade.PersonCreateRequest) -> Facade.PersonCreated:
            """The owner creates a distinct PERSON with declared identity hints and existing identity-evidence refs, looking before minting an opaque id without selecting or merging a namesake."""
    class _VaultEntitiesVerbs:
        def look_before_mint(self, spec: Facade.IdentityLookupRequest) -> Facade.IdentityLookup:
            """The owner queries the declared PERSON, ORG or PLACE identity hints for N candidates with evidence and provenance; only stored mention evidence is scored by the waterfall, and no entity is restored, linked or minted."""
        def mention(self, spec: Facade.EntityMentionRequest) -> Facade.EntityResolutionWaterfallDecision:
            """The owner resolves an evidence-backed mention through the existing waterfall, restoring its selected archived record in place and never minting a duplicate."""
    class _VaultIdentityVerbs:
        def mention(self, spec: Facade.MentionProvenance) -> Facade.IdentityMentionView:
            """The owner reads one saved mention as unresolved, candidates or resolved, preserving the original tagger suggestion and the resolving owner evidence and provenance."""
        def merge(self, spec: Facade.IdentityMergeRequest) -> Facade.IdentityTopologyResult:
            """The owner merges source identities into a survivor, retaining claim subjects and append-only evidence."""
        def split(self, spec: Facade.IdentitySplitRequest) -> Facade.IdentityTopologyResult:
            """The owner splits an identity into zero, one or many heads using an evidence-guided reassignment map."""
        def facet(self, spec: Facade.IdentityFacetRequest) -> Facade.IdentityTopologyResult:
            """The owner mints identity facets and forks assigned claims under their masks without restamping original claims."""
        def assert_distinct(self, spec: Facade.IdentityAssertDistinctRequest) -> Facade.IdentityTopologyResult:
            """The owner asserts two identities are distinct through one symmetric claim that suppresses merge re-proposals."""
        def propose(self, spec: Facade.IdentityProposeRequest) -> Facade.IdentityTopologyResult:
            """The owner parks a nominated merge or split candidate with no topology effects; distinct pairs suppress merge proposals."""
        def undo(self, spec: Facade.IdentityUndoRequest) -> Facade.IdentityTopologyResult:
            """The owner undoes one current topology event by appending a counter-event under its observed revision."""
        def resolve(self, spec: Facade.IdentityEntityRequest) -> Facade.IdentityResolution:
            """The owner resolves an identity to its current head set and reads shell edges, facets and evidence assignments."""
        @property
        def events(self) -> "Oneiron._VaultIdentityEventsVerbs": ...
        @property
        def proposals(self) -> "Oneiron._VaultIdentityProposalsVerbs": ...
    class _VaultIdentityEventsVerbs:
        def get(self, spec: Facade.IdentityEventRequest) -> Facade.IdentityTopologyReceipt:
            """The owner reads one topology decision with its actor, evidence, action and current decision revision."""
    class _VaultIdentityProposalsVerbs:
        def resolve(self, spec: Facade.IdentityProposalResolveRequest) -> Facade.IdentityProposalResolutionResult:
            """The owner approves, amends then approves, or rejects a parked topology proposal under its observed revision."""
        def for_pair(self, spec: Facade.IdentityPairRequest) -> Facade.IdentityPairProposals:
            """The owner reads open merge proposals and effective distinctness claims for an unordered identity pair."""
    class _VaultShapeVerbs:
        def read(self, spec: Facade.EmptyRequest | None = None) -> Facade.ShapeRead:
            """The vault's stored seed and its live setup plane held as one document (ARCH-0070), as the caller's read admits it: seed rows and open apply items naming structure it cannot read are left out; a free read."""
        def plan(self, spec: Facade.ShapePlanRequest) -> Facade.ShapePlan:
            """The difference between a seed, or the stored one, and the vault, item by item at a pinned frontier; structure the caller cannot read is neither shown nor planned as missing; a free read that writes nothing."""
        def apply(self, spec: Facade.ShapeApplyRequest) -> Facade.ShapeApplyReceipt:
            """Lands a shape plan one item at a time through the vault's named doors, or resumes its apply; a widening lands only on the owner's word for that item while its previewed reach holds, else it asks for a fresh plan."""
    class _VaultCompanionsVerbs:
        @property
        def access_requests(self) -> "Oneiron._VaultCompanionsAccessRequestsVerbs": ...
        @property
        def sharing(self) -> "Oneiron._VaultCompanionsSharingVerbs": ...
    class _VaultCompanionsAccessRequestsVerbs:
        def answer(self, spec: Facade.CompanionAccessRequestAnswerRequest) -> Facade.CompanionAccessRequestAnswered:
            """The owner approves or denies one pending companion-profile request, atomically recording the answer and its exact grant."""
    class _VaultCompanionsSharingVerbs:
        def get(self, spec: Facade.CompanionSharingRequest) -> Facade.CompanionSharingView:
            """One contact's clearance in a companion's source vault, for the principal who controls that vault."""
        def set(self, spec: Facade.CompanionSharingSetRequest) -> Facade.CompanionSharingView:
            """The owner's standing yes to one frozen clearance offer for a companion's contact."""
    class _VaultPersonasVerbs:
        def preview(self, spec: Facade.PersonaSnapshotPreviewRequest) -> Facade.PersonaSnapshotPreview:
            """Previews the owner's strikeable persona snapshot, with sources and its content-bound consent stamp."""
        def export(self, spec: Facade.PersonaSnapshotCopyRequest) -> Facade.PersonaSnapshotExportedCopy:
            """Issues the exact previewed mode-A persona copy after explicit row strikes; a changed preview refuses stale consent."""
        def edit(self, spec: Facade.PersonaSnapshotCopyEditRequest) -> Facade.PersonaSnapshotExportedCopy:
            """Edits an accepted persona copy into a new receipted export, preserving citations, exclusions and the already handed version."""
    class _VaultFanoutVerbs:
        def spawn(self, spec: Facade.LiveRunRequest[Facade.FanoutBatchInput]) -> Facade.FanoutBatchView:
            """Admits input-order child slots under this credential's attached live run, through the frozen fan-out approval gate and one shared parent spend tree."""
        def slots(self, spec: Facade.FanoutLaunchRequest) -> Facade.FanoutBatchView | None:
            """Reads a batch launch in input slot order, with child errors, results, reservations, settled spend and released holds from its shared parent lease tree."""
        def launch(self, spec: Facade.FanoutLaunchRequest) -> Facade.FanoutLaunchView | None:
            """One held or launched fan-out by its launch ref, with the statement frozen before it launched; readable by the vault owner, its creator, or a live lead/board holder of its project, anything else reads as none."""
        def resume(self, spec: Facade.FanoutResumeRequest) -> Facade.ActAnswer[Facade.FanoutLaunchView]:
            """The owner rules on a held fan-out launch by the digest they saw: approve once, approve and remember under a cap, or deny, which keeps the hold visible."""
        def resume_as(self, spec: Facade.FanoutResumeRequest) -> Facade.ActAnswer[Facade.FanoutLaunchView]:
            """A live lead or board holder of a held fan-out launch's project rules on it by the digest they saw: approve once, or deny, which keeps the hold visible; only the owner may remember."""
        def ack(self, spec: Facade.FanoutAckRequest) -> Facade.ActAnswer[Facade.FanoutLaunchView]:
            """The owner acknowledges the width check of a fan-out that already went out, once or remembered under a cap; nothing was held, so nothing is denied."""
    class _VaultBudgetsVerbs:
        @property
        def lease(self) -> "Oneiron._VaultBudgetsLeaseVerbs": ...
        @property
        def hold(self) -> "Oneiron._VaultBudgetsHoldVerbs": ...
        def local(self, spec: Facade.LocalRunnerBudgetRequest) -> Facade.LocalRunnerBudgetView:
            """The owner observes a device-local runner budget counter without creating it, including absence after an owner restore."""
        def reservations(self, spec: Facade.RunnerBudgetReservationsRequest) -> Facade.RunnerBudgetReservationsView:
            """The owner reads a device-local runner budget counter and one page of the child reservations held against it, without creating or refilling it."""
        def settlements(self, spec: Facade.RunSettlementsRequest) -> Facade.RunSettlementsView:
            """The owner reads a served run's persisted physical-rung settlement receipts, with reservation, settled units and stamped cost when priced."""
        @property
        def rsi(self) -> "Oneiron._VaultBudgetsRsiVerbs": ...
    class _VaultBudgetsLeaseVerbs:
        def __call__(self, spec: Facade.SpendScopeRequest) -> Facade.SpendLeaseView:
            """The owner reads a persisted spend lease, its remaining allowance and the hard ancestor that binds it."""
        def open(self, spec: Facade.OpenSpendLeaseRequest) -> Facade.SpendLeaseView:
            """The owner opens a persisted launch spend lease under the maximum the customer set and saw, in its declared unit."""
        def top_up(self, spec: Facade.TopUpSpendLeaseRequest) -> Facade.SpendLeaseView:
            """The owner raises a hard lease to a shown replacement maximum; replay adds nothing twice and a child's increase stays within its ancestor's cap."""
    class _VaultBudgetsHoldVerbs:
        def __call__(self, spec: Facade.BudgetHoldRequest) -> Facade.PartialResultHold | None:
            """The owner reads a held run's notice, saved partial results, exact checkpoints and whether its existing lease permits resume."""
        def resume(self, spec: Facade.BudgetHoldRequest) -> Facade.PartialResultHold:
            """The owner resumes the same held attempts from their checkpoints after their lease has funds; no model substitution or terminal completion."""
    class _VaultBudgetsRsiVerbs:
        def __call__(self, spec: Facade.RsiLineRequest) -> Facade.RsiLineView:
            """The owner reads both RSI lines, every soft and pinned share, and whether new loop work is held. A hold reads as suspended, never as a terminal failure."""
        def configure(self, spec: Facade.RsiBudgetConfig) -> Facade.RsiLineView:
            """The owner creates the vault RSI line once: its token limit, its independent exploration exposure limit, and its soft and owner-pinned shares. Reconfiguration cannot erase receipts or spend."""
        def top_up(self, spec: Facade.RsiTopUp) -> Facade.RsiLineView:
            """The owner raises one exact limiting RSI line by its units: the token limit, the exploration exposure limit, or one named share. A top-up never lowers a line and never resumes held work by itself."""
        @property
        def hold(self) -> "Oneiron._VaultBudgetsRsiHoldVerbs": ...
    class _VaultBudgetsRsiHoldVerbs:
        def __call__(self, spec: Facade.RsiLineRequest) -> Facade.RsiLineView:
            """The owner holds new RSI loop work rather than killing it; admitted reservations can still settle, and pending attempts, candidates and partial outputs stay."""
        def resume(self, spec: Facade.RsiLineRequest) -> Facade.RsiLineView:
            """The owner releases the RSI hold on the same line and receipts, so the same pending try continues without a new experiment or a duplicate terminal receipt."""
    class _VaultRunnersVerbs:
        @property
        def seats(self) -> "Oneiron._VaultRunnersSeatsVerbs": ...
    class _VaultRunnersSeatsVerbs:
        def quotas(self, spec: Facade.RunnerSeatQuotasRequest) -> Facade.RunnerSeatQuotasView:
            """The owner reads the named runner seats' quotas as their captures last recorded them: each spend, when the seat is back, whether it may take work, and the capture each reading came from."""
        def top_up(self, spec: Facade.RunnerSeatCreditTopUpRequest) -> Facade.RunnerSeatTopUpReceipt:
            """The owner says a runner seat's spent credit is topped up: only the named capture's credit spend, while it is still the seat's last reading, is cleared; a second, stale or non-credit top-up changes nothing and says so."""
    class _VaultMessagesVerbs:
        def durability(self, spec: Facade.MessageDurabilityRequest) -> Facade.ScopedReadResult[Facade.MessageDurability | None]:
            """Reads a MESSAGE's completion, terminal-generation receipts and retained document history through the caller's own read lane."""
        def react(self, spec: Facade.MessageReactionRequest) -> Facade.MessageReactionReceipt:
            """Puts or removes the caller's own reaction on a message or turn; an owner-grade host also brings a provider's reaction as connector ingress."""
    class _VaultClaimsVerbs:
        def upsert(self, spec: Facade.ScopedClaimInput) -> Facade.CommitReceipt:
            """Admits an explicitly four-axis claim through the caller credential and existing gate, with host-authored provenance."""
        def review(self, spec: Facade.ClaimProposalReviewRequest) -> Facade.ClaimProposalReview:
            """The owner reviews one proposed claim: the claim as the owner may read it, its opener and tray row, and the review_id that settles exactly this content."""
        def settle(self, spec: Facade.ClaimSettleRequest) -> Facade.ClaimSettlement:
            """The owner approves or rejects exactly the reviewed proposed claim through the gate and keeps its Settlement; a claim changed since its review_id is refused."""
        def retract(self, input: Facade.ClaimRefRequest) -> Facade.CommitReceipt:
            """Retracts one active claim: a deliberate withdrawal that preserves the record."""
        def list(self, input: Facade.ClaimListFilter) -> Facade.ScopedReadResult[list[Facade.ClaimView]]:
            """Lists claims by subject, predicate and lifecycle, with the read's narrowing receipt."""
        def demote(self, input: Facade.ClaimDemoteRequest) -> Facade.ClaimDemoteView:
            """Demotes one active claim by one rung through the caller credential: decay its claim_of weight, weaken it to a successor at lower confidence, or mark it stale in place so retrieval stops surfacing it."""
        def list_filtered(self, input: Facade.ClaimFilteredListRequest) -> Facade.ScopedReadResult[list[Facade.ClaimView]]:
            """Lists surfaceable claims by subject, predicate and lifecycle under the caller retrieval filter met with the actor ceiling, with the read narrowing receipt."""
        def read_filtered(self, input: Facade.ClaimFilteredReadRequest) -> Facade.ScopedReadResult[Facade.ClaimView | None]:
            """Reads one claim as retrieval would surface it under the caller retrieval filter met with the actor ceiling, with the read narrowing receipt."""
        def history(self, input: Facade.ClaimRefRequest) -> Facade.ScopedReadResult[list[Facade.ClaimView]]:
            """The supersession timeline of one claim, oldest first, with the read's narrowing receipt."""
        def admit(self, input: Facade.AdmitImportedClaimInput) -> Facade.CommitReceipt:
            """Admits one imported-evidence claim through its ingest source's trust ceiling; the gate still decides."""
        def vet(self, spec: Facade.ClaimSettleRequest) -> Facade.ClaimSettlement:
            """Vets a reviewed generated-origin Auto claim or proposal through the owner Gate and signed settlement; it still contributes zero corroboration."""
        def vetting(self, spec: Facade.ClaimProposalReviewRequest) -> Facade.ClaimProposalReview:
            """Reviews an exact generated-origin Auto claim or proposal before owner vetting, returning the content-bound review handle."""
        def seed(self, input: Facade.ScopedCommitRequest) -> list[Facade.CommitOutcome]:
            """Seeds claims through their individual gates, forced proposed, returning per claim its landed receipt or its typed refusal and refusal receipt."""
        def supersede(self, spec: Facade.LiveRunRequest[Facade.MemorySupersedeInput]) -> Facade.MemoryWriteOutput:
            """Supersedes through this credential's attached generated-writing run and its existing gates; spec is {newId,oldId,now}, never an actor or source override."""
    class _VaultRetrievalVerbs:
        @property
        def aging(self) -> "Oneiron._VaultRetrievalAgingVerbs": ...
        @property
        def weights(self) -> "Oneiron._VaultRetrievalWeightsVerbs": ...
        @property
        def hyde(self) -> "Oneiron._VaultRetrievalHydeVerbs": ...
        def recall(self, spec: Facade.RecallRequest) -> Facade.MemoryPack:
            """Recalls through the normal credential-bound serving pipeline as the owner, with typed opt-in turn and trace capture and the actual finalized run handle."""
        def runs(self, spec: Facade.RetrievalRunsRequest) -> list[Facade.RetrievalRunEvidence]:
            """The owner reads finalized local retrieval runs and their independent outcome sidecars, newest first."""
        def run(self, spec: Facade.RetrievalRunRequest) -> Facade.RetrievalRunEvidence | None:
            """The owner reads one finalized local serving run, its turn, policy state, trace and explicit outcomes; an unknown run reads as none."""
        def turn(self, spec: Facade.RetrievalTurnRequest) -> list[Facade.RetrievalRunEvidence]:
            """The owner reads the independent finalized retrieval runs linked to one exact turn, in recorded order."""
        @property
        def outcomes(self) -> "Oneiron._VaultRetrievalOutcomesVerbs": ...
        def trace(self, spec: Facade.RetrievalTraceRequest) -> Facade.RetrievalTrace | None:
            """The owner reads an opt-in trace by its vault-local keyed fork hash; hashes are never comparable across vaults."""
        def export(self, spec: Facade.RetrievalDiagnosticRequest) -> Facade.RetrievalDiagnosticExport:
            """The owner exports finalized run evidence without query or pack text, raw frontier samples, trace keys or free-form outcome metadata."""
        def replay(self, spec: Facade.RetrievalDiagnosticRequest) -> Facade.RetrievalDiagnosticReplay:
            """The owner replays recorded state, ordered pack scores and trace from exact finalized runs; no fresh search, clock or outcome-derived feature is used."""
        @property
        def policy(self) -> "Oneiron._VaultRetrievalPolicyVerbs": ...
    class _VaultRetrievalAgingVerbs:
        def get(self, spec: Facade.EmptyRequest | None = None) -> Facade.ClaimAgingProfilesView:
            """The owner reads class-level exponential aging profiles and the trusted manifest hash; confidence never ages."""
        def configure(self, spec: Facade.ClaimAgingProfilesConfigureRequest) -> Facade.ClaimAgingProfilesReceipt:
            """The owner edits all class-aging profiles against the current manifest hash without rewriting confidence, lifecycle or claim bodies."""
    class _VaultRetrievalWeightsVerbs:
        def get(self, spec: Facade.EmptyRequest | None = None) -> Facade.RetrievalWeightsView:
            """The owner reads effective affect, arousal, community and semantic-edge VAD priors with the trusted manifest hash."""
        def configure(self, spec: Facade.RetrievalWeightsConfigureRequest) -> Facade.RetrievalWeightsReceipt:
            """The owner sets independent retrieval priors against the current manifest hash; zero disables each prior without changing confidence or authority."""
    class _VaultRetrievalHydeVerbs:
        def configure(self, spec: Facade.HydeHostConfigureRequest) -> Facade.HydeHostConfiguration:
            """The owner binds or disables a host HyDE expander for paid recall; replacing the binding cancels unanswered work."""
        def get(self, spec: Facade.EmptyRequest | None = None) -> Facade.HydeHostConfiguration:
            """The owner reads the serving host HyDE binding, grounding and bounded retry options."""
        def pending(self, spec: Facade.HydeHostPendingRequest) -> list[Facade.HydeHostWork]:
            """Lists pending expansion and evidence-assessment work for the same credential that called recall; free efforts enqueue nothing."""
        def complete(self, spec: Facade.HydeHostCompleteRequest) -> Facade.HydeHostReceipt:
            """Completes one credential-bound host expansion or evidence assessment, or reports failure; late bytes are receipted and discarded."""
        def receipt(self, spec: Facade.HydeHostReceiptRequest) -> Facade.HydeHostReceipt | None:
            """Reads one credential-bound host completion receipt, including expired work and late answers discarded at the recall deadline."""
    class _VaultRetrievalOutcomesVerbs:
        def put(self, spec: Facade.RetrievalOutcome) -> list[Facade.RetrievalOutcomeRecord]:
            """The owner attaches an explicit observation to one local serving run; raw reward stays telemetry, never a gated training label."""
        def end(self, spec: Facade.RetrievalEndOutcome) -> list[Facade.RetrievalRunEvidence]:
            """The owner records a gate-attributed turn outcome for its exact contributing retrievalRunIds; the engine validates the links and shapes the reward."""
    class _VaultRetrievalPolicyVerbs:
        def get(self, spec: Facade.EmptyRequest | None = None) -> Facade.RetrievalPolicyView:
            """The owner reads the served retrieval policy: active blend weights with their origins, owner pins, the learned posterior and model routing pins."""
        def pin(self, spec: Facade.RetrievalPolicyPinRequest) -> Facade.RetrievalPolicyView:
            """The owner pins one retrieval blend weight at a declared share, or clears its pin; learned updates may move only the unpinned remainder."""
        def train(self, spec: Facade.RetrievalPolicyTrainRequest) -> Facade.RetrievalPolicyCandidate:
            """The owner trains a retrieval-policy candidate from gate-attributed outcomes, judged on held-out runs, without serving it."""
        def evaluate(self, spec: Facade.RetrievalPolicyEvaluateRequest) -> Facade.RetrievalPolicyEvaluation:
            """The owner judges candidate blend weights against the active weights on the same held-out runs the tuner never trains on."""
        def admit(self, spec: Facade.RetrievalPolicyAdmitRequest) -> Facade.RetrievalPolicyAdmitReceipt:
            """The owner admits candidate blend weights judged on the named evidence manifest; owner pins and held-out regressions refuse admission."""
        def update(self, spec: Facade.RetrievalPolicyTrainRequest) -> Facade.RetrievalPolicyUpdateReceipt:
            """The owner declares one retrieval-policy update: train, admit only a not-worse candidate, and rebuild the learned action posterior."""
    class _VaultAffectVerbs:
        @property
        def annotations(self) -> "Oneiron._VaultAffectAnnotationsVerbs": ...
        @property
        def claims(self) -> "Oneiron._VaultAffectClaimsVerbs": ...
        @property
        def coping(self) -> "Oneiron._VaultAffectCopingVerbs": ...
        @property
        def wellness(self) -> "Oneiron._VaultAffectWellnessVerbs": ...
    class _VaultAffectAnnotationsVerbs:
        def put(self, spec: Facade.AffectAnnotationPut) -> Facade.CommitReceipt:
            """Writes one sourced TURN VAD annotation through ordinary scoped claim admission and the caller credential; the receipt states its approval."""
    class _VaultAffectClaimsVerbs:
        def consolidate(self, spec: Facade.AffectClaimConsolidateRequest) -> Facade.AffectClaimConsolidation:
            """The owner consolidates a claim from stored TURN VAD evidence, updating only derived affect state and semantic-edge VAD through the existing engine transaction."""
    class _VaultAffectCopingVerbs:
        def record(self, spec: Facade.CopingOutcomeRecordRequest) -> Facade.CopingOutcomeReceipt:
            """Records a first coping outcome from two stored VAD-annotated turns for one person, with scoped claim admission and caller attribution; no factual claim is superseded."""
        def update(self, spec: Facade.CopingOutcomeUpdateRequest) -> Facade.CopingOutcomeReceipt:
            """Updates an active coping aggregate from its strategy turn and a later annotated turn through the existing engine transaction, preserving scope and both evidence refs."""
        def aggregate(self, spec: Facade.CopingAggregateRequest) -> Facade.CopingAggregate:
            """Reads all admitted active coping aggregates for one person and optional exact scope, including unsuccessful outcomes and their attribution and evidence refs."""
    class _VaultAffectWellnessVerbs:
        @property
        def policy(self) -> "Oneiron._VaultAffectWellnessPolicyVerbs": ...
        def derive(self, spec: Facade.WellnessPersonRequest) -> Facade.WellnessProjection:
            """Derives one person's non-clinical wellness projection using the existing state measurements and configured mode bands, with a routed receipt and source refs."""
        def get(self, spec: Facade.WellnessPersonRequest) -> Facade.WellnessProjection:
            """Reads one person's measured wellness state, configured advisory mode and coping aggregates with source refs, without refreshing or revising factual claims."""
    class _VaultAffectWellnessPolicyVerbs:
        def get(self, spec: Facade.EmptyRequest | None = None) -> Facade.ActionModePolicy | None:
            """Reads the configured non-clinical wellness window, targets and advisory mode bands as the owner; absent policy stays absent."""
        def configure(self, spec: Facade.WellnessPolicyConfigureRequest) -> Facade.ActionModePolicy | None:
            """Configures or clears the existing action-mode policy as the owner; no universal wellness cutoff or diagnostic label is supplied by the engine."""
    class _VaultTaggingVerbs:
        def status(self, spec: Facade.TaggingTurnRequest) -> Facade.ScopedReadResult[Facade.TaggingStatusView]:
            """Reads one turn tagging marker as pending retrying settled or failed, with the configured checkpoint, serving model, live marker, failure reason and how current its saved tags are, under the lane's scope receipt."""
        def tags(self, spec: Facade.TaggingTurnRequest) -> Facade.ScopedReadResult[Facade.TaggingTagsView]:
            """Reads the tags saved for one turn: mention spans and targets, coreference, mood, PII and other labels, and the derivation that made them, marked stale and pending retag after an edit, under the lane's scope receipt."""
        def history(self, spec: Facade.TaggingTurnRequest) -> Facade.ScopedReadResult[Facade.TaggingHistoryView]:
            """Reads one turn recorded tagging traces oldest first: each attempt, checkpoint, model, try number and saved shadowed skipped or failed outcome, under the lane's scope receipt."""
        def mentions(self, spec: Facade.TaggingMentionsRequest) -> Facade.ScopedReadResult[Facade.TaggingMentionsView]:
            """Reads the saved tagger mentions naming one entity, bounded by limit and each served only while its turn reads for the caller, each marked with how current its turn's tags are, under the lane's scope receipt."""
    class _VaultClusterVerbs:
        def __call__(self, spec: Facade.ClusterRequest) -> Facade.ScopedReadResult[Facade.ClusterProposal]:
            """Proposes deterministic complete-link cohorts from readable stored claims and supplied embeddings; exact subject, predicate-root, world and facet partitions never decide truth."""
        def proposal(self, spec: Facade.ClusterProposalRequest) -> Facade.ScopedReadResult[Facade.ClusterProposalView]:
            """Inspects a parked merge or split, its original evidence, current resolution and revision for a gated ruling; every reference must remain readable."""
        def propose(self, spec: Facade.ClusterProposeRequest) -> Facade.ClusterTopologyReceipt:
            """Parks an explicit merge or split judgment with zero topology effects, under the caller's own owner proof or topology_seal Grant."""
        def merge(self, spec: Facade.ClusterMergeRequest) -> Facade.ClusterTopologyReceipt:
            """Applies a merge judgment through the existing topology gate, preserving claim subjects and recording its redirect shells, evidence and receipt."""
        def split(self, spec: Facade.ClusterSplitRequest) -> Facade.ClusterTopologyReceipt:
            """Applies a split judgment through the existing topology gate, including zero-head retirement, evidence-guided reassignment and explicit residue."""
        def resolve_proposal(self, spec: Facade.ClusterResolveRequest) -> Facade.ClusterTopologyReceipt:
            """Approves, amends then approves, or rejects a parked merge or split under the caller's own authority, comparing its revision and recording the ruling atomically."""
    class _VaultExportVerbs:
        def __call__(self, format: PackFormat | None = None) -> Facade.ExportAnswer: ...
        def scoped(self, spec: Facade.ScopedExportRequest) -> Facade.ScopedExport:
            """Exports rows selected under the caller credential and named channel, preserving the engine export fences and provenance withholding."""
    class _VaultScopeVerbs:
        def position(self, spec: Facade.RecordPositionRequest) -> Facade.ScopedReadResult[Facade.RecordPosition | None]:
            """Reads a positively stamped record position through the caller credential and existing read gate, with its narrowing receipt."""
        def ceiling(self, spec: Facade.EmptyRequest | None = None) -> Facade.CredentialCeiling:
            """Reads the caller credential ceiling as a typed ceiling, never as a record position."""
    class _VaultReceiptsVerbs:
        def __call__(self, limit: int = 100, kinds: list[str] | None = None, after: str | None = None) -> Facade.VaultReceiptsPage: ...
        def get(self, spec: Facade.CallReceiptRequest) -> Facade.CallReceipt | None:
            """One call receipt by ref, readable by its own actor or the vault's live owner; anything else reads as none."""
        def context(self, spec: Facade.CallReceiptRequest) -> Facade.ContextEmitReceipt | None:
            """Read the frozen context of one actual reply emit, as its actor or the live vault owner; never rebuild the assembly."""
        def craft_reply_manifest(self, spec: Facade.CallReceiptRequest) -> list[Facade.ManifestEntry] | None:
            """Read the craft manifest of one reply emit, as its actor or the live vault owner; never rebuild the pack."""
    class _VaultAssetsVerbs:
        def ingest(self, spec: Facade.AssetIngestRequest) -> Facade.AssetIngestReceipt:
            """Lands typed text, image or audio bytes as an ASSET and optional source-bound text form, atomically under the caller's content gate."""
        def resolve(self, spec: Facade.AssetResolveRequest) -> Facade.ScopedReadResult[Facade.AssetResolved]:
            """Serves an admitted ASSET in the reader's declared image, audio or text form, with a handle and committed served-form receipt refs."""
    class _VaultSearchVerbs:
        @property
        def vector(self) -> "Oneiron._VaultSearchVectorVerbs": ...
        def hybrid(self, input: Facade.HybridSearchRequest) -> Facade.ScopedReadResult[list[Facade.HybridSearchHit]]:
            """Searches explicit vector, text, phonetic, temporal and PPR channels under the caller read ceiling, with optional fixed-time blend replay and per-hit score evidence."""
        def temporal(self, input: Facade.TemporalSearchRequest) -> Facade.ScopedReadResult[Facade.TemporalSearchResult]:
            """Searches occurrence, learning or both temporal anchors under the caller's read ceiling, with sigma, adaptive widening, hard outer ranges, admitted dates and the effective request sigma and rounds."""
        def bm25(self, input: Facade.QueryBm25Request) -> Facade.Bm25Search:
            """BM25 text search over the engine index; surfaceable claims only. On a device that syncs only what it opened, a server's door asks the home under the caller's own proof, and its references ride in residence."""
    class _VaultSearchVectorVerbs:
        def __call__(self, input: Facade.VectorSearchRequest) -> Facade.ScopedReadResult[Facade.VectorSearchResult]:
            """Searches the text index or a declared embedding space with per-kind matches and revision pins; text-index MRL reads report refinement, and explicit voice_hot skips rescore at the reduced voice limit."""
        def config(self, spec: Facade.EmptyRequest | None = None) -> Facade.ScopedReadResult[Facade.VectorSearchConfig]:
            """Reads this vault open's persisted dimensions and optional MRL fast_dims prefix; graph shape is configured before open, never changed by a search."""
    class _VaultImagesVerbs:
        def view(self, request: Facade.ImageViewRequest) -> Facade.PulledImage: ...
    class _VaultExplainVerbs:
        def memory(self, spec: Facade.ExplainMemoryRequest) -> Facade.ExplainMemoryReply | None:
            """Why one memory appeared in the caller's session: the run that served it and its place, its board tier and the run's score breakdown; none when the session was not served it or the caller cannot read it."""
        def gate(self, spec: Facade.ExplainGateRequest) -> Facade.ExplainGateReply | None:
            """Why a write needed approval: the gate decision behind one gate receipt, its outcome, reason codes and cited policy rows; none when the caller may not read it."""
    class _VaultKvVerbs:
        def get(self, request: KeyValueAddress) -> KeyValueItem | None: ...
        def put(self, request: KeyValuePut) -> KeyValuePutReceipt: ...
        def delete(self, request: KeyValueAddress) -> KeyValueDeleteReceipt: ...
        def search(self, request: KeyValueSearch) -> list[KeyValueItem]: ...
        def namespaces(self, request: KeyValueNamespaces) -> list[list[str]]: ...
    class _VaultCampaignVerbs:
        @property
        def compliance(self) -> "Oneiron._VaultCampaignComplianceVerbs": ...
        def enroll(self, spec: Facade.CampaignEnrollRequest) -> Facade.CampaignEnrollmentReceipt:
            """Enrolls a person in a campaign the caller owns, with evidence-backed channels and sticky senders. Writes no earned stage and sends nothing."""
        @property
        def stage(self) -> "Oneiron._VaultCampaignStageVerbs": ...
        def unsubscribe(self, spec: Facade.CampaignUnsubscribeRequest) -> Facade.CampaignUnsubscribeReceipt:
            """Immediately honors an unsubscribe with a channel-scoped enforcement claim and every suppressed membership head in one transaction."""
        @property
        def program(self) -> "Oneiron._VaultCampaignProgramVerbs": ...
    class _VaultCampaignComplianceVerbs:
        def install(self, spec: Facade.ComplianceAmendRequest) -> Facade.ComplianceReceipt:
            """The owner installs cited compliance rows through the versioned amendment classifier; a loosening still waits for an exact-hash owner approval."""
        def amend(self, spec: Facade.ComplianceAmendRequest) -> Facade.ComplianceReceipt:
            """Proposes cited compliance rows against the active version. Tightening activates with a notice only within the caller ceiling; loosening waits for the owner stamp."""
        def approve(self, spec: Facade.ComplianceApprovalRequest) -> Facade.ComplianceReceipt:
            """The owner approves the exact pending compliance proposal hash against the active version, with a durable authority receipt."""
        def reject(self, spec: Facade.ComplianceApprovalRequest) -> Facade.ComplianceReceipt:
            """The owner rejects the exact pending compliance proposal hash without changing the effective rules."""
        def verify(self, spec: Facade.ComplianceVerifyRequest) -> Facade.ComplianceReceipt:
            """The owner records cited verification dates for existing compliance rows, including an explicitly stale date, without changing requirements or freshness policy."""
        def result(self, spec: Facade.ComplianceResultRequest) -> Facade.ComplianceResult:
            """Reads the active compliance pack, exact pending proposal, activation notices and amendment or owner-verification receipts from one snapshot."""
    class _VaultCampaignStageVerbs:
        def evidence(self, spec: Facade.CampaignStageEvidenceRequest) -> Facade.CampaignStageEvidenceReceipt:
            """Records earned-stage evidence under an authored ladder transition, in AUTO or propose mode. Owner-attested evidence requires the request owner proof; elapsed time earns nothing."""
    class _VaultCampaignProgramVerbs:
        def create(self, spec: Facade.CreateCampaignProgramRequest) -> Facade.CampaignProgramRecord:
            """Creates a campaign program (ordered steps and an optional saved-query audience) under a campaign the caller owns."""
        def read(self, spec: Facade.CampaignProgramReadRequest) -> Facade.CampaignProgramReadResult:
            """One campaign program under a campaign the caller owns, with whether its audience gets automatic intake now."""
        def update(self, spec: Facade.UpdateCampaignProgramRequest) -> Facade.CampaignProgramRecord:
            """Replaces a campaign program's name, steps and audience whole under a version check; work queued at a dropped step stops."""
        def archive(self, spec: Facade.ArchiveCampaignProgramRequest) -> Facade.CampaignProgramRecord:
            """Archives a campaign program: it stays readable, enrolls no one, and its queued enrollment work stops."""
    class _VaultTurnProgramsVerbs:
        def arm(self, spec: Facade.ArmTurnProgram) -> Facade.TurnProgramRegistration:
            """Arms a pinned callable skill entry for the caller's own future turns, in one conversation or any of its own; arming the same definition again returns the standing registration."""
        def disarm(self, spec: Facade.DisarmTurnProgram) -> bool:
            """Disarms one of the caller's own armed turn programs; true when it was armed."""
        def admission(self, spec: Facade.TurnProgramAdmissionRequest) -> Facade.TurnProgramAdmissionView | None:
            """Reads one page of the admissions a landed turn's wakes decided for the caller's own turn programs, or for every program when the owner asks, withholding each field whose record does not read on the caller's credential."""
    class _VaultWeaveVerbs:
        def report(self, spec: Facade.WeaveReportRequest) -> Facade.WeaveReportView:
            """The live weave report for the bound actor, read through its own scope and the vault's weave policy for its role."""
        @property
        def digest(self) -> "Oneiron._VaultWeaveDigestVerbs": ...
        def lens(self, spec: Facade.WeaveReportRequest) -> Facade.LensFrameCard:
            """Renders the caller's live weave report through the weave-report skill on the server's model, as a card whose wrong controls are its declared actions; the server holds its frame for the card's events."""
        @property
        def link(self) -> "Oneiron._VaultWeaveLinkVerbs": ...
        @property
        def owner(self) -> "Oneiron._VaultWeaveOwnerVerbs": ...
        @property
        def item(self) -> "Oneiron._VaultWeaveItemVerbs": ...
        def enqueue(self, spec: Facade.WeaveEnqueueRequest) -> Facade.DreamerAttemptRef:
            """Admits a generated candidate weave recipe under the owner's proof and queues its pinned execution; poll vault.consolidation.status for completion."""
        @property
        def schedules(self) -> "Oneiron._VaultWeaveSchedulesVerbs": ...
        @property
        def setting_changes(self) -> "Oneiron._VaultWeaveSettingChangesVerbs": ...
        @property
        def digest_feedback(self) -> "Oneiron._VaultWeaveDigestFeedbackVerbs": ...
    class _VaultWeaveDigestVerbs:
        def __call__(self, spec: Facade.WeaveDigestRequest) -> Facade.WeaveDigestView | None:
            """One of the bound actor's saved weave digests, or the newest, under the current read policy. Its lens is a card; a server holds its frame for the card's events, an embedded handle holds none."""
        def render(self, spec: Facade.EmptyRequest | None = None) -> Facade.WeaveDigestRendered | None:
            """Publishes the bound reader's due digest through the same live scoped lens and returns its saved period and narrowing receipt, or null when nothing is due."""
    class _VaultWeaveLinkVerbs:
        def wrong(self, spec: Facade.WeaveWrongLinkRequest) -> Facade.WeaveLinkCorrectionView:
            """A person labels a link in their own lens as wrong; the label teaches the loops and the link stays."""
        def corrections(self, spec: Facade.WeaveWrongLinkRequest) -> list[Facade.WeaveLinkCorrectionView]:
            """Reads persisted wrong-link labels for a link still admitted by the caller's live weave lens, without changing the link."""
    class _VaultWeaveOwnerVerbs:
        @property
        def link(self) -> "Oneiron._VaultWeaveOwnerLinkVerbs": ...
        @property
        def item(self) -> "Oneiron._VaultWeaveOwnerItemVerbs": ...
        @property
        def digest(self) -> "Oneiron._VaultWeaveOwnerDigestVerbs": ...
    class _VaultWeaveOwnerLinkVerbs:
        def wrong(self, spec: Facade.WeaveWrongLinkRequest) -> Facade.WeaveLinkCorrectionView:
            """The owner labels a link in the owner lens as wrong, under the owner's own credential; the label teaches the loops and the link stays."""
    class _VaultWeaveOwnerItemVerbs:
        def wrong(self, spec: Facade.WeaveWrongItemRequest) -> Facade.WeaveItemCorrectionView:
            """The owner labels a claim, project or budget item in the owner lens as wrong, under the owner's own credential; the label teaches the loops and the record stays."""
    class _VaultWeaveOwnerDigestVerbs:
        def render(self, spec: Facade.EmptyRequest | None = None) -> Facade.WeaveDigestRendered | None:
            """Publishes the owner's due digest through the live owner lens and returns the saved period and narrowing receipt, or null when nothing is due."""
    class _VaultWeaveItemVerbs:
        def wrong(self, spec: Facade.WeaveWrongItemRequest) -> Facade.WeaveItemCorrectionView:
            """A person labels a claim, project or budget item in their own lens as wrong; the label teaches the loops and the record stays."""
    class _VaultWeaveSchedulesVerbs:
        def list(self, spec: Facade.EmptyRequest | None = None) -> list[Facade.WeaveScheduleView]:
            """Lists every reader's daily or weekly weave digest schedule under the owner's proof."""
        def put(self, spec: Facade.WeaveScheduleView) -> Facade.WeaveScheduleView:
            """Sets one reader's daily or weekly digest schedule and section recipe under the owner's proof."""
        def clear(self, spec: Facade.WeaveReaderRef) -> Facade.WeaveScheduleCleared:
            """Stops one reader's digest schedule under the owner's proof, keeping its saved periods."""
    class _VaultWeaveSettingChangesVerbs:
        def list(self, spec: Facade.EmptyRequest | None = None) -> list[Facade.WeaveDigestSettingChange]:
            """Lists the Coach's proposed and applied changes to the owner's own digest rhythm and section order, newest first, under the owner's proof."""
        def answer(self, spec: Facade.WeaveDigestSettingAnswer) -> Facade.WeaveDigestSettingChange:
            """Accepts, as the owner's own act, or declines one proposed change to the owner's digest settings; a stale accept applies nothing."""
        def undo(self, spec: Facade.WeaveDigestSettingUndo) -> Facade.WeaveDigestSettingChange:
            """Undoes one applied or accepted change to the owner's digest settings, restoring the rhythm and section order before it while the settings are unchanged since."""
    class _VaultWeaveDigestFeedbackVerbs:
        def put(self, spec: Facade.WeaveDigestFeedback) -> Facade.WeaveDigestFeedback:
            """Tells the Coach the owner's own digest preference: a rhythm, a section to lead with, or keep the settings as they are."""
    class _VaultInboxVerbs:
        @property
        def concerns(self) -> "Oneiron._VaultInboxConcernsVerbs": ...
        def lens(self, spec: Facade.InboxLensRequest) -> Facade.InboxLensPage:
            """Reads the owner's cross-identity inbox lens in impact order, optionally filtered by identity or agent, with concern groups per agent."""
        def groups(self, spec: Facade.InboxRunGroupsRequest) -> list[Facade.InboxGroup]:
            """Reads membership of real gate-held Dreamer consent proposals grouped by run, under the owner's proof."""
    class _VaultInboxConcernsVerbs:
        def review(self, spec: Facade.EmptyRequest | None = None) -> Facade.DreamerAttemptRef:
            """Queues the Coach's real health review under the owner's proof; findings and recipients come from engine evidence, never supplied concern rows."""
    class _VaultSkillsVerbs:
        def bootstrap(self, spec: Facade.EmptyRequest | None = None) -> list[Facade.BootstrapSkillView]:
            """Reads the bootstrap four and their actual resident source, lifecycle and receipts without seeding or restoring missing skills."""
        def restoreDefaults(self, spec: Facade.EmptyRequest | None = None) -> list[Facade.HubImportReceipt]:
            """The owner explicitly re-imports missing or retired bootstrap and pinned first-hub defaults as fresh candidates, leaving unchanged defaults and local forks alone."""
        def import_(self, spec: Facade.HubImportRequest) -> Facade.HubSkillImported:
            """The owner imports a pinned hub skill through scanning and publisher admission, pending its permission ask."""
        def sync(self, spec: Facade.HubSkillRequest) -> Facade.HubSkillSyncReceipt:
            """The owner syncs a hub skill under its ref policy; widening proposes without changing trusted capabilities."""
        def receipts(self, spec: Facade.HubSkillRequest) -> Facade.HubSkillReceipts:
            """Reads every hub source and import receipt of a skill, and its held-out admission ruling, as the owner."""
        def convert(self, spec: Facade.SkillConvertRequest) -> Facade.SkillConvertReceipt:
            """Converts selected messages through the configured refiner; user initiation approves conversion, never admission."""
        def get(self, spec: Facade.HubSkillRequest) -> Facade.SkillLibraryView:
            """Reads skill lifecycle, exact source, provenance, source availability, scan and admission receipts, and retained fork ancestry."""
        def list(self, spec: Facade.SkillLibraryListRequest) -> Facade.SkillLibraryPage:
            """Lists a page of the owner skill library, including inactive skills and their retained evidence."""
        def archive(self, spec: Facade.HubSkillRequest) -> Facade.SkillLibraryView:
            """The owner soft-retires an active skill without deleting its body, source or receipts; running callable invocations are cancelled."""
        def restore(self, spec: Facade.SkillLibraryRestoreRequest) -> Facade.SkillLibraryRestoreReceipt:
            """The owner restores an archived skill through the same admission gates; a hub restore prepares exact consent and reruns held-out scoring."""
        def fork(self, spec: Facade.SkillLibraryForkRequest) -> Facade.SkillLibraryView:
            """The owner, or a person or agent on its own slip within its write Grant, forks a stored skill it can read under a new identity through the existing fork law; retained parent/version and hub ancestry remain inspectable."""
        @property
        def rules(self) -> "Oneiron._VaultSkillsRulesVerbs": ...
        @property
        def code_auto_install(self) -> "Oneiron._VaultSkillsCodeAutoInstallVerbs": ...
        @property
        def permissions(self) -> "Oneiron._VaultSkillsPermissionsVerbs": ...
        @property
        def optimize(self) -> "Oneiron._VaultSkillsOptimizeVerbs": ...
        @property
        def governance(self) -> "Oneiron._VaultSkillsGovernanceVerbs": ...
        def pack_receipt(self, spec: Facade.SkillPackReceiptRequest) -> Facade.SkillPackReceipt:
            """Reads a terminal pack receipt with its frozen loaded versions and actual-use attribution as the owner."""
        @property
        def outcomes(self) -> "Oneiron._VaultSkillsOutcomesVerbs": ...
        @property
        def attribution(self) -> "Oneiron._VaultSkillsAttributionVerbs": ...
    class _VaultSkillsRulesVerbs:
        def set(self, spec: Facade.SkillHashRuleRequest) -> Facade.HubConsentReceipt:
            """The owner sets or clears a known-bad canonical skill hash rule, independently of advisory scanner prose."""
    class _VaultSkillsCodeAutoInstallVerbs:
        def set(self, spec: Facade.SkillCodeAutoInstallRequest) -> Facade.HubConsentReceipt:
            """The owner sets the code auto-install switch through its existing consent gate; the switch grants no sandbox qualification."""
    class _VaultSkillsPermissionsVerbs:
        def approve(self, spec: Facade.HubSkillPermissionRequest) -> Facade.HubConsentReceipt:
            """The owner answers one imported skill permission ask at its exact hub source."""
    class _VaultSkillsOptimizeVerbs:
        def start(self, spec: Facade.SkillOptimizeStartRequest) -> Facade.SkillOptimizeStartReceipt:
            """The owner starts one skill_optimize attempt on the Dreamer queue; a named identity or alignment skill is excluded and never enqueued."""
        def result(self, spec: Facade.SkillOptimizeResultRequest) -> Facade.SkillOptimizeResultView:
            """Reads a started skill_optimize job, its drafted proposal, the incumbent, its governance and every held-out verdict on the proposal."""
        def propose(self, spec: Facade.SkillOptimizeProposeRequest) -> Facade.SkillOptimizeProposalReceipt:
            """Submits one explicit optimizer candidate against a fixed baseline version and a real drafting attempt; ordinary held-out admission still rules."""
        def measure(self, spec: Facade.SkillOptimizeMeasureRequest) -> Facade.SkillOptimizeMeasurement:
            """Judges held-out floors before any online slice, then measures the proposal on the effective goal with the registered judge and bounded live arms."""
        def score(self, spec: Facade.SkillOptimizeProposalRequest) -> Facade.SkillOptimizeResultView:
            """Rules on the submitted proposal through the existing held-out vector gate, floors and tradeoff ladder, without activating it."""
        def admit(self, spec: Facade.SkillOptimizeProposalRequest) -> Facade.SkillOptimizeResultView:
            """Admits only a standing gate acceptance and supersedes its incumbent atomically, with current body, evidence, tier, goal and owner checks."""
        @property
        def goal(self) -> "Oneiron._VaultSkillsOptimizeGoalVerbs": ...
        @property
        def preferences(self) -> "Oneiron._VaultSkillsOptimizePreferencesVerbs": ...
        @property
        def tradeoff_asks(self) -> "Oneiron._VaultSkillsOptimizeTradeoffAsksVerbs": ...
    class _VaultSkillsOptimizeGoalVerbs:
        def get(self, spec: Facade.SkillOptimizeGoalRequest) -> Facade.SkillOptimizeGoalView:
            """Reads the optimizer goal identity, effective axes, revision and joined project goal claim."""
        def bind(self, spec: Facade.SkillOptimizeGoalBindRequest) -> Facade.SkillOptimizeGoalRevision:
            """Joins a skill goal to the human project goal record, or unbinds with null; every join changes its admission revision."""
    class _VaultSkillsOptimizePreferencesVerbs:
        def get(self, spec: Facade.SkillOptimizeGoalRequest) -> Facade.SkillTradeoffPreferences | None:
            """Reads authored and learned goal tradeoff rules and the typed judgment band, without changing authority."""
        def set(self, spec: Facade.SkillOptimizePreferencesSetRequest) -> Facade.SkillOptimizeGoalRevision:
            """The responsible owner sets authored tradeoff rules and the typed judgment band, retaining learned picks and every admission clamp."""
    class _VaultSkillsOptimizeTradeoffAsksVerbs:
        def __call__(self, spec: Facade.EmptyRequest | None = None) -> list[Facade.SkillOptimizeTradeoffAskView]:
            """Lists the exact pending optimizer tradeoffs that have reached a role the caller holds, including bound typed judgment evidence."""
        def pick(self, spec: Facade.SkillOptimizeTradeoffPickRequest) -> Facade.SkillOptimizeResultView:
            """Approves or rejects the exact shown tradeoff; the attributed pick becomes a preference and a proposed project revision, never a Grant."""
    class _VaultSkillsGovernanceVerbs:
        def get(self, spec: Facade.HubSkillRequest) -> Facade.SkillGovernanceView:
            """Reads one skill governance tier as the owner, resolved fail-closed, and whether the automated edit loop may consider it."""
        def set(self, spec: Facade.SkillGovernanceSetRequest) -> Facade.SkillGovernanceView:
            """The owner marks or clears one skill governance tier; the mark changes no instruction content or version."""
    class _VaultSkillsOutcomesVerbs:
        def project(self, spec: Facade.SkillPackOutcomeRequest) -> Facade.SkillPackOutcomeProjection:
            """Projects the owner's anchored verdict through existing attributed pack outcomes; loading or calling alone never earns a reliability win."""
        def get(self, spec: Facade.SkillPackCreditRequest) -> Facade.LateCreditReceipt | None:
            """Reads the persisted anchored pack credit receipt, including its execution context, direct subjects and lineage shares, as the owner."""
    class _VaultSkillsAttributionVerbs:
        def settle(self, spec: Facade.ProposalDeltaSettleRequest) -> Facade.ProposalDeltaSettlement:
            """The owner settles one amended proposal: exact replacements are recorded, the delta is measured from those ops, hunks are judged and each share routes to its consumer."""
        def read(self, spec: Facade.ProposalDeltaReadRequest) -> Facade.ProposalDeltaRead:
            """The owner reads one proposal settlement by receipt: its measured delta, recorded ops, amendment evidence, judgment, preference notes and unclear rows."""
        @property
        def evidence(self) -> "Oneiron._VaultSkillsAttributionEvidenceVerbs": ...
        def project(self, spec: Facade.AttributionProjectRequest) -> Facade.AttributionProjection:
            """The owner runs one attribution pass over recorded evidence, plus the positive lane, returning the judgments and positive proposals it minted."""
        def judgments(self, spec: Facade.AttributionListRequest) -> Facade.AttributionJudgmentsView:
            """The owner reads every persisted attribution judgment in both lanes, the projector cursor and the unclear ledger."""
        def proposals(self, spec: Facade.AttributionListRequest) -> Facade.AttributionProposalsView:
            """The owner reads the pending skill edit proposals, preference proposals and positive skill proposals attribution has minted."""
        @property
        def positive(self) -> "Oneiron._VaultSkillsAttributionPositiveVerbs": ...
    class _VaultSkillsAttributionEvidenceVerbs:
        def record(self, spec: Facade.AttributionEvidenceRequest) -> Facade.AttributionEvidenceReceipt:
            """The owner records one attempt outcome as attribution evidence, grounded against its stamped pack receipt; recording never classifies it."""
    class _VaultSkillsAttributionPositiveVerbs:
        def retire(self, spec: Facade.PositiveRetireRequest) -> Facade.PositiveRetireReceipt:
            """The owner retires one positive skill proposal once the optimizer has drafted from it or declined it."""
    class _VaultSkillHubsVerbs:
        @property
        def default(self) -> "Oneiron._VaultSkillHubsDefaultVerbs": ...
        def put(self, spec: Facade.SkillHubPutRequest) -> Facade.SkillHubConfigured:
            """The owner registers or revises a hub source; hub trust never grants activation authority."""
        def get(self, spec: Facade.SkillHubRequest) -> Facade.SkillHubRecord:
            """Reads one configured hub as the owner."""
        @property
        def publishers(self) -> "Oneiron._VaultSkillHubsPublishersVerbs": ...
        @property
        def refs(self) -> "Oneiron._VaultSkillHubsRefsVerbs": ...
    class _VaultSkillHubsDefaultVerbs:
        def get(self, spec: Facade.EmptyRequest | None = None) -> Facade.DefaultSkillHub:
            """Reads the first hub identity, configured mirror endpoint and pinned skill-root ref; owner hub and ref setters configure that source."""
    class _VaultSkillHubsPublishersVerbs:
        def admit(self, spec: Facade.SkillPublisherRequest) -> Facade.SkillPublisherAdmission:
            """The owner admits a foreign publisher to offer candidates from one configured hub, and nothing else."""
        def revoke(self, spec: Facade.SkillPublisherRequest) -> Facade.HubConsentReceipt:
            """The owner revokes the exact offer-only publisher grant; foreign hooks recheck it before running."""
    class _VaultSkillHubsRefsVerbs:
        def get(self, spec: Facade.HubRefRequest) -> Facade.TrackedHubRef | None:
            """Reads one hub ref policy, pin and separate seen and trusted revisions as the owner."""
        def set(self, spec: Facade.HubRefSetRequest) -> Facade.TrackedHubRef:
            """The owner changes one hub ref policy and pin without fetching or trusting new bytes."""
    class _VaultPacksVerbs:
        def install(self, spec: Facade.HubImportRequest) -> Facade.PackPutReceipt:
            """The owner fetches a pinned hub pack as its foreign publisher; code stays Candidate and hooks wait for consent."""
        def sync(self, spec: Facade.HubPackRequest) -> Facade.PackPutReceipt:
            """The owner syncs a hub pack at its stored ref policy; wider hooks keep their old bindings until re-consent."""
        def get(self, spec: Facade.HubPackRequest) -> Facade.PackInstallReceipt | None:
            """Reads an installed pack and its exact source, pin, publisher and requested powers as the owner."""
        @property
        def hooks(self) -> "Oneiron._VaultPacksHooksVerbs": ...
        def put(self, spec: Facade.PackPutRequest) -> Facade.PackPutReceipt:
            """The owner installs a pack folder, or replaces the pack installed under its name, each file sent as text or as content_base64 bytes; the put is the consent for its hooks."""
        def preview(self, spec: Facade.PackPreviewRequest) -> Facade.PackImportPreview:
            """The owner previews a pack folder before vault.packs.put: the world its travelling agent would land in, with a please double-check notice when that world's current setting does not cover this machine; nothing is staged or written."""
        @property
        def connector(self) -> "Oneiron._VaultPacksConnectorVerbs": ...
        def remove(self, spec: Facade.PackRemoveRequest) -> Facade.PackInstallReceipt:
            """The owner removes an installed pack: it leaves the Active catalog and its hook bindings stop; a built-in goes back to its Candidate."""
        @property
        def sections(self) -> "Oneiron._VaultPacksSectionsVerbs": ...
        @property
        def setup(self) -> "Oneiron._VaultPacksSetupVerbs": ...
    class _VaultPacksHooksVerbs:
        def bind(self, spec: Facade.HubHookBindRequest) -> list[Facade.EntityId]:
            """The owner consents to the installed pack hook capabilities, including a widening update; publisher identity stays foreign."""
        def list(self, spec: Facade.EmptyRequest | None = None) -> list[Facade.HubHookBindingRow]:
            """Reads live pack hook bindings and their effective read grants as the owner, excluding revoked foreign publisher grants."""
        @property
        def grant(self) -> "Oneiron._VaultPacksHooksGrantVerbs": ...
        def qualify(self, spec: Facade.HubHookQualifyRequest) -> Facade.HubHookQualificationReceipt:
            """The owner qualifies a Candidate hub hook pack by real sandbox replay; qualification does not consent to wider hooks."""
    class _VaultPacksHooksGrantVerbs:
        def set(self, spec: Facade.HookGrantSetRequest) -> Facade.HookGrantView:
            """The owner sets or changes a live hook binding's read grant; outcomes still run as the hook's author. Returns the assigned grant."""
        def get(self, spec: Facade.HookGrantRequest) -> Facade.HookGrantView:
            """Reads a live hook binding's effective read grant as the owner: its manual assignment, or the author's ceiling when none was set."""
    class _VaultPacksConnectorVerbs:
        def prepare(self, spec: Facade.ConnectorPackPrepareRequest) -> Facade.ConnectorPackView:
            """Prepares an immutable connector pack admission, comparing the resolved declaration with the installed transport and drafting an ungranted slate."""
        def get(self, spec: Facade.ConnectorPackGetRequest) -> Facade.ConnectorPackView:
            """Reads a connector pack source, resolved manifest, advisory evidence, qualification and owner-stampable capability rows."""
        def qualify(self, spec: Facade.ConnectorPackQualifyRequest) -> Facade.ConnectorPackView:
            """Runs the real connector probes bound to the exact pack source and protocol; qualification grants nothing without the owner slate and actor grant."""
        def accept(self, spec: Facade.ConnectorPackAcceptRequest) -> Facade.ConnectorPackView:
            """Stamps the exact connector pack manifest and grant rows once, or revokes a row; qualification stays independent."""
        def update(self, spec: Facade.ConnectorPackUpdateRequest) -> Facade.ConnectorPackDelta:
            """Holds a connector pack at its new immutable source and protocol, carrying narrow rows and re-asking only for expanded capabilities."""
        @property
        def grants(self) -> "Oneiron._VaultPacksConnectorGrantsVerbs": ...
    class _VaultPacksConnectorGrantsVerbs:
        def get(self, spec: Facade.ConnectorPackGrantsGetRequest) -> Facade.ConnectorPackGrants:
            """Reads current per-capability authority for one actor on the reviewed connector pack source."""
        def put(self, spec: Facade.ConnectorPackGrantsPutRequest) -> Facade.ConnectorPackGrants:
            """Grants declared connector pack rows to one actor through the existing owner consent gate and installed endpoint."""
    class _VaultPacksSectionsVerbs:
        def propose(self, spec: Facade.PluginSectionProposeRequest) -> Facade.PluginSectionInstallOutcome:
            """The caller offers one typed plugin section manifest. A code-free section requesting no permission the caller lacks installs at once (vault.packs.sections.revoke undoes it); anything else waits for the owner as a proposed install claim."""
        def list(self, spec: Facade.PluginSectionListRequest) -> Facade.PluginSectionsView:
            """Plugin sections as they stand: one page of install offers awaiting the owner with their total and a cursor to the rest, admitted sections with their granted manifests, and the sections installed packs project."""
        def grant(self, spec: Facade.PluginSectionGrantRequest) -> Facade.PluginSectionGrant:
            """The owner grants exactly the reviewed plugin section install: the claim settles through its review handle and the section is admitted under that same consent."""
        def revoke(self, spec: Facade.PluginSectionRevokeRequest) -> Facade.PluginSectionRevoked:
            """The owner revokes a plugin section grant by retracting its install claim; the section and its advertised verbs leave the next board rebuild."""
        def suggest(self, spec: Facade.PluginSectionSuggestRequest) -> Facade.PluginSectionSuggestion:
            """Runs one workflow-pattern suggestion pass over a pinned hub on the caller's credential: a repeating pattern nominates at most one pack as an attributed proposal."""
        @property
        def suggestions(self) -> "Oneiron._VaultPacksSectionsSuggestionsVerbs": ...
    class _VaultPacksSectionsSuggestionsVerbs:
        def get(self, spec: Facade.EmptyRequest | None = None) -> Facade.PluginSuggestionsView:
            """The owner's plugin suggestion knob: whether workflow-pattern suggestion passes may run at all."""
        def set(self, spec: Facade.PluginSuggestionsSetRequest) -> Facade.PluginSuggestionsView:
            """The owner turns plugin suggestions on or off; off silences every later pass before any catalog is consulted."""
    class _VaultPacksSetupVerbs:
        def prepare(self, spec: Facade.PackSetupRequest) -> Facade.PackSetupReceipt:
            """The owner opens, or resumes, a pack's guided setup; opening grants nothing."""
        def get(self, spec: Facade.PackSetupRequest) -> Facade.PackSetupReceipt:
            """A pack's guided setup as it stands, for the owner."""
        def answer(self, spec: Facade.PackSetupAnswerRequest) -> Facade.PackSetupReceipt:
            """The owner's one typed answer or card action in a pack's guided setup; a credential value never passes here."""
        def verify(self, spec: Facade.PackSetupVerifyRequest) -> Facade.PackSetupReceipt:
            """Checks one pack connection with the engine's fixed read-only provider call for its declared check."""
    class _VaultProjectsVerbs:
        @property
        def goal(self) -> "Oneiron._VaultProjectsGoalVerbs": ...
        def propose(self, spec: Facade.ProjectProposalRequest) -> Facade.ProjectProposalCard:
            """The drafting agent proposes a project card on a source message; the card writes no project and confers no authority."""
        def proposals(self, spec: Facade.ProjectConversationRequest) -> list[Facade.ProjectCardRecord]:
            """The project cards shown in a conversation, each with its state."""
        def dismiss_card(self, spec: Facade.ProjectCardRequest) -> Facade.ProjectCardDismissal:
            """The card's person dismisses a project card so it never mints; false when it was dismissed already."""
        def confirm(self, spec: Facade.ProjectCardConfirmRequest) -> Facade.ProjectMintReceipt:
            """The owner's tap that confirms a host-held project card; only the host's own door can complete it."""
        @property
        def roster(self) -> "Oneiron._VaultProjectsRosterVerbs": ...
        def route_tradeoff(self, spec: Facade.ProjectTradeoffRouteRequest) -> Facade.TaskAskReceipt:
            """Asks the A/B tradeoff question pending on a skill proposal on a project TASK, as a visible turn in its home room."""
    class _VaultProjectsGoalVerbs:
        @property
        def intake(self) -> "Oneiron._VaultProjectsGoalIntakeVerbs": ...
        def get(self, spec: Facade.ProjectRefRequest) -> Facade.ProjectGoalView:
            """Reads the full effective goal record and its claim together; interview drafts and loop proposals never replace it."""
        def revisions(self, spec: Facade.ProjectRefRequest) -> list[Facade.ProjectGoalRevisionProposal]:
            """The learned goal preferences proposed for a project's goal in force and not dismissed, oldest first."""
        def dismiss(self, spec: Facade.ProjectGoalDismissRequest) -> Facade.ProjectGoalDismissReceipt:
            """The owner dismisses the proposal one tradeoff question made for a project's goal; false for an identical retry."""
    class _VaultProjectsGoalIntakeVerbs:
        def __call__(self, spec: Facade.ProjectRefRequest) -> Facade.ProjectGoalInterviewContext:
            """What a project's goal-intake interview starts from, for a member of its home room."""
        def complete(self, spec: Facade.ProjectGoalIntakeCompleteRequest) -> Facade.ProjectGoalIntakeReceipt:
            """Completes the witnessed human goal-intake interview with the full confirmed record; no agent proposal can write the effective goal."""
    class _VaultProjectsRosterVerbs:
        def write(self, spec: Facade.ProjectRosterWriteRequest) -> Facade.ProjectRosterWriteOutcome:
            """Writes an existing project's signed roster as the bound caller, filing joins for the newly seated subjects it stands for and an invitation for each unrelated person, who accepts through vault.rooms.consent."""
    class _VaultConnectorsVerbs:
        @property
        def proxy(self) -> "Oneiron._VaultConnectorsProxyVerbs": ...
        @property
        def slates(self) -> "Oneiron._VaultConnectorsSlatesVerbs": ...
        @property
        def subscriptions(self) -> "Oneiron._VaultConnectorsSubscriptionsVerbs": ...
        @property
        def calls(self) -> "Oneiron._VaultConnectorsCallsVerbs": ...
        @property
        def read_grants(self) -> "Oneiron._VaultConnectorsReadGrantsVerbs": ...
    class _VaultConnectorsProxyVerbs:
        def admit(self, spec: Facade.ProxyConnectorAdmitRequest) -> Facade.ProxyConnectorRegistration:
            """The owner admits the OpenAI memory proxy for one paired actor, stamping its read and remember slate and activating its connector key."""
        def revoke_write(self, spec: Facade.ProxyConnectorRevokeWriteRequest) -> Facade.ProxyConnectorRegistration:
            """The owner withdraws only the proxy remember grant at the reviewed key and slate revision; read access, stored memories and the connector remain intact."""
    class _VaultConnectorsSlatesVerbs:
        def redraft(self, spec: Facade.ConnectorSlateRedraftRequest) -> Facade.ConnectorSlateRedraftReply:
            """The owner asks the configured drafter to re-draft one connector grant slate: it proposes changed rows with rationale at the reviewed revision and stamps or grants nothing; with no drafter it answers unavailable."""
        def narrow(self, spec: Facade.ConnectorSlateNarrowRequest) -> Facade.ConnectorSlateNarrowView:
            """The holder of a connector key tightens rows or facets of what its own key's calls meet, with no stamp; it never widens or changes a shared catalog slate, and the owner's ruling on a row reverses it."""
        def scope_outcome(self, spec: Facade.ConnectorScopeOutcomeRequest) -> Facade.ConnectorScopeOutcomeView:
            """The owner rules on a held connector call's typed scope exceed, linked to the ask he ruled on: it folds once into that row's consent ramp and, once earned, drafts a proposed delta slate; nothing is stamped or granted."""
        def revision_offers(self, spec: Facade.ConnectorSlateRevisionOffersRequest) -> Facade.ConnectorSlateRevisionOffersView:
            """Lists the proposed connector slate revisions waiting on the owner: earned scope-exceed offers still standing and not held back, and issuer changes not yet accepted; listing activates nothing."""
        def defer_revision(self, spec: Facade.ConnectorSlateRevisionDeferRequest) -> Facade.ConnectorRevisionSnoozeView:
            """The owner holds a scope-exceed revision offer back (not now, or pinned manual) or unpins it, through the consent ramp's own answers; it never accepts the offer or mints a grant."""
        def accept_revision(self, spec: Facade.ConnectorSlateRevisionAcceptRequest) -> Facade.ConnectorSlateRevisionAcceptedView:
            """The owner stamps one proposed connector slate revision at the revision he reviewed, rechecked: a scope revision mints its widened grant; an issuer revision accepts the new issuer so the rows it held run again."""
        def reask_issuer(self, spec: Facade.ConnectorIssuerReaskRequest) -> Facade.ConnectorCredentialBindingView:
            """The owner records the issuer a catalog connector's credential slot answers for: the first is the baseline; another issuer holds only the keys and rows that depend on that slot and drafts their re-ask."""
    class _VaultConnectorsSubscriptionsVerbs:
        def put(self, spec: Facade.ChannelSubscriptionRequest) -> Facade.ChannelMessageSubscription:
            """The owner subscribes an agent to the messages a built-in channel (slack or line) routes to it, so each one wakes the agent to answer."""
        def list(self, spec: Facade.ChannelSubscriptionsRequest) -> Facade.ChannelSubscriptions:
            """An agent's connector event subscriptions, standing and revoked, for the owner."""
        def revoke(self, spec: Facade.ChannelSubscriptionRevokeRequest) -> Facade.ChannelSubscriptionRevoked:
            """The owner stops one connector event subscription; the agent's key for the channel stays."""
    class _VaultConnectorsCallsVerbs:
        def approve_once(self, spec: Facade.ConnectorCallApproveOnceRequest) -> Facade.ConsentActReceipt:
            """The owner approves once exactly one held connector call, by its call ref and the approve-once digest its current ask names; no standing grant is created and nothing is sent."""
    class _VaultConnectorsReadGrantsVerbs:
        def grant(self, spec: Facade.ConnectorWitnessReadGrantRequest) -> Facade.ConnectorWitnessReadGranted:
            """The owner grants one agent its witness-read grant over a connector conversation again, by agent and conversation; a revoked grant is issued anew at its same id, a missing one is issued, and a repeat on an active grant changes nothing."""
        def revoke(self, spec: Facade.ConnectorWitnessReadGrantRevokeRequest) -> Facade.ConnectorWitnessReadGrantRevoked:
            """The owner revokes one agent's witness-read grant over a connector conversation by its id; the agent stops reading the conversation's messages at once, no later witness issues the grant again, and a repeat changes nothing."""
    class _VaultAuthorityVerbs:
        def audit(self, spec: Facade.AuthorityAuditQuery) -> Facade.AuthorityAuditPage:
            """One page of the dated authority log audit, for the owner: grants, revokes and confirms. On a vault that adopted a checkpoint image a page can also carry cold, checkpoint-attested rows it does not store, with no clock or kind."""
        @property
        def history(self) -> "Oneiron._VaultAuthorityHistoryVerbs": ...
        @property
        def clock(self) -> "Oneiron._VaultAuthorityClockVerbs": ...
        @property
        def handoff_alarms(self) -> "Oneiron._VaultAuthorityHandoffAlarmsVerbs": ...
    class _VaultAuthorityHistoryVerbs:
        def export(self, spec: Facade.EmptyRequest | None = None) -> Facade.SignedAuthorityHistory:
            """Exports the full original signed authority history, including quarantined forks, as base64 envelopes for the owner. No signing secret leaves."""
        def import_(self, spec: Facade.SignedAuthorityHistory) -> Facade.AuthorityHistoryImported:
            """Imports original base64 signed authority envelopes atomically for the owner, preserving bytes and refolding locally. Invalid signatures, foreign genesis and missing parents write nothing."""
    class _VaultAuthorityClockVerbs:
        def repair(self, spec: Facade.EmptyRequest | None = None) -> Facade.AuthorityClockRepair:
            """Repairs a damaged authority clock floor for the owner from this vault's own observations, judged against the owner's proof in the repair's own writer. A whole floor, or one nothing here proves, is left as it is and the answer says so."""
    class _VaultAuthorityHandoffAlarmsVerbs:
        def __call__(self, spec: Facade.EmptyRequest | None = None) -> list[Facade.AuthorityHandoffAlarm]:
            """Every saved authority handoff fork alarm, for the owner."""
        def acknowledge(self, spec: Facade.HandoffAlarmRequest) -> Facade.AuthorityHandoffAlarm:
            """The owner acknowledges one saved handoff fork alarm."""
    class _VaultWireHealthVerbs:
        @property
        def thresholds(self) -> "Oneiron._VaultWireHealthThresholdsVerbs": ...
    class _VaultWireHealthThresholdsVerbs:
        def get(self, spec: Facade.EmptyRequest) -> Facade.WireThresholds:
            """The owner reads the serving host's per-verb and per-actor wire detection thresholds and their window; crossings ask a health question, never refuse for rate."""
        def set(self, spec: Facade.WireThresholds) -> Facade.WireThresholdsReceipt:
            """The owner replaces the serving host's positive wire detection thresholds and window, receiving the previous and installed policy without adding a rate refusal."""
    class _VaultSlimVerbs:
        def policy(self, spec: Facade.EmptyRequest) -> Facade.SlimIdlePolicy:
            """Reads the serving host idle policy: the long outbound wait, no exit on idle and lazy heap rebuild."""
        def state(self, spec: Facade.EmptyRequest) -> Facade.SlimStateSnapshot:
            """Observes FULL or SLIM atomically with this process id and the retained journaled resume pointer, without waking the vault."""
        def resume_step(self, spec: Facade.SlimResumeStepRequest) -> Facade.SavedResumeStep:
            """Reads a saved model checkpoint or outbound intent by its retained identity, including after FULL or restart, without reissuing it."""
        def drop_heavy(self, spec: Facade.SlimDropRequest) -> Facade.SlimDropReceipt:
            """Drops rebuildable heap in process and returns the completed engine transition, drop counts or typed refusal; one journaled outbound step is required."""
        def resume(self, spec: Facade.EmptyRequest) -> Facade.SlimResumeReceipt:
            """Resumes logical FULL in the same process and returns its completion receipt; indexes rebuild lazily and no saved outbound step is reissued."""
    class _VaultMeshVerbs:
        def path_receipts(self, spec: Facade.MeshPathReceiptsRequest) -> list[Facade.MeshPathReceipt]:
            """The newest path receipts this machine's paired-machine mesh left, newest first and bounded: direct or relayed, admitted, refused or failed, for the owner."""
        def identity(self, spec: Facade.EmptyRequest) -> Facade.MeshBindingIdentity:
            """This install's public mesh keys and both binding proofs, for the owner; no private key or grant is returned."""
        def bind_machine(self, spec: Facade.MeshMachineBinding) -> Facade.MeshMachineBound:
            """Bind a paired MACHINE's address and transport key using both possession proofs; the binding starts with no ALPN grants."""
        def set_alpn_grant(self, spec: Facade.MeshAlpnGrant) -> Facade.MeshAlpnGrant:
            """Allow or revoke one exact ALPN for a paired MACHINE and endpoint key, under the caller's own owner proof."""
        def revoke_machine(self, spec: Facade.MeshMachineRevokeRequest) -> Facade.MeshMachineRevoked:
            """Permanently revoke a MACHINE's mesh admission and all its ALPN grants; a new enrollment needs a new MACHINE and pairing."""
        def dial(self, spec: Facade.MeshDialRequest) -> Facade.MeshPathReceipt:
            """Dial an explicit mesh address with this install's real key, including before pairing; report admission and close without an application stream."""
    class _VaultInspectionVerbs:
        def resolve(self, spec: Facade.InspectionResolveRequest) -> Facade.InspectionResolved:
            """Resolves an inspection handle for the caller; unreadable, missing and wrong-kind targets all answer with no item."""
    class _VaultSharedVerbs:
        def propose_delete(self, spec: Facade.SharedVaultRequest) -> Facade.PendingAuthorityAct:
            """Starts a shared vault's delete_vault act, returned as a typed pending act."""
        def propose_transfer(self, spec: Facade.SharedTransferRequest) -> Facade.PendingAuthorityAct:
            """Starts a shared vault's transfer_ownership act: a live Owner hands the vault to another person."""
        def propose_remove_owner(self, spec: Facade.SharedRemoveOwnerRequest) -> Facade.PendingAuthorityAct:
            """Starts a shared vault's remove_owner act, with its export-first answer."""
        def execute(self, spec: Facade.SharedActRequest) -> Facade.ActAnswer[Facade.SharedActExecuted]:
            """A live Owner runs a matured shared-vault act and gets its receipt."""
        def receipt(self, spec: Facade.SharedReceiptRequest) -> Facade.SharedActExecutionReceipt:
            """One shared-act or membership receipt its reader was told about, by id."""
        def outcomes(self, spec: Facade.SharedVaultRequest) -> list[Facade.SharedActOutcome]:
            """The reader's own outcome notices for a shared vault."""
        def deletion(self, spec: Facade.EmptyRequest | None = None) -> Facade.SharedVaultDeletion | None:
            """The executed delete-the-vault act, if any."""
        def object(self, spec: Facade.SharedActRequest) -> Facade.PendingAuthorityAct:
            """A holder of a pending shared act's objector role objects inside its veto window."""
        def withdraw_objection(self, spec: Facade.SharedActRequest) -> Facade.PendingAuthorityAct:
            """The holder withdraws their objection; past the deadline the last withdrawal releases the act."""
        def started(self, spec: Facade.SharedVaultRequest) -> list[Facade.PendingActStarted]:
            """The caller's own notices of shared acts started in the vault."""
        def matured(self, spec: Facade.SharedVaultRequest) -> list[Facade.PendingActMatured]:
            """The caller's own notices of shared acts whose veto window has passed."""
        def erase_ask(self, spec: Facade.SharedEraseAskRequest) -> Facade.SharedEraseAsk:
            """A Member requests, or an Admin proposes, that the Owners erase a record; it erases nothing."""
        def erase_asks(self, spec: Facade.SharedVaultRequest) -> list[Facade.SharedEraseAsk]:
            """The erase asks the caller may see: every ask for an Owner, their own for anyone else."""
        def close_erase_ask(self, spec: Facade.SharedEraseAskCloseRequest) -> Facade.SharedEraseAsk:
            """An Owner closes an open erase ask, as erased (naming its erase act) or declined."""
        @property
        def policy(self) -> "Oneiron._VaultSharedPolicyVerbs": ...
    class _VaultSharedPolicyVerbs:
        def get(self, spec: Facade.SharedVaultRequest) -> Facade.SharedActPoliciesView:
            """A live Owner reads every shared-act policy row of a shared vault: the rows its kind ships, the vault's own rows, the row each act resolves to, and the policy_hash a change binds."""
        def propose(self, spec: Facade.SharedActPolicyProposeRequest) -> Facade.SharedActPolicyChange:
            """A live policy editor proposes one shared-act policy row change against the policy_hash they read; it applies only when every live editor approves it, and one no vetoes it."""
        def answer(self, spec: Facade.SharedActPolicyAnswerRequest) -> Facade.SharedActPolicyChange:
            """A live policy editor approves or vetoes a pending shared-act policy change under their own credential; the last approval of the live editor set writes the row."""
        def change(self, spec: Facade.SharedActPolicyChangeRequest) -> Facade.SharedActPolicyChange:
            """A live Owner reads one shared-act policy change: its row, approvals, veto, state and the live editors it still waits on."""
    class _VaultOrgAdminVerbs:
        def configure(self, spec: Facade.OrgAdminConfigureRequest) -> Facade.OrgAdminConfigured:
            """The owner fixes an organization's Admin identities and closed named-power set once; no root or private-vault power can be configured."""
        def powers(self, spec: Facade.OrgAdminPowersRequest) -> Facade.OrgAdminPowers:
            """The caller reads only the organization's fixed named Admin powers that their own credential carries."""
    class _VaultMembersVerbs:
        def reset_project_access(self, spec: Facade.SharedProjectAccessResetRequest) -> Facade.SharedProjectAccessReset:
            """An Admin resets only a non-root shared project's signed access roster through the existing project-proof gate; it never changes a personal root or grants an unsigned override."""
        def delegate(self, spec: Facade.FederationDelegateRequest) -> Facade.FederationMemberGrant:
            """A live parent Admin or Owner mints one explicit scope narrowing for a holder, bounded by policy and a server-clock expiry of at most 90 days; the Delegate cannot delegate onward."""
        def projection(self, spec: Facade.SharedMemberRequest) -> Facade.MemberProjection:
            """Read a member's visible role grants, scopes, expiry and person/relationship through the caller's own scoped read; relationship labels confer no additional authority."""
        def add(self, spec: Facade.SharedMemberAddRequest) -> Facade.SharedMemberInvited:
            """An Admin invites a live person into a shared vault at a non-root role; they join when they accept. Given the invitee's own device key, the host also mints the invitee a slip good only for this invitation while it is pending."""
        def invitation_slip(self, spec: Facade.InvitationSlipRequest) -> Facade.InvitationSlip:
            """An Admin mints a pending invitation's slip for the public key the invitee generated on their own device: a founding invitation's, or one whose slip was lost."""
        def change(self, spec: Facade.SharedMemberRoleRequest) -> Facade.SharedActExecutionReceipt:
            """An Admin assigns another non-root role to a member who is not an Owner."""
        def remove(self, spec: Facade.SharedMemberRequest) -> Facade.SharedActExecutionReceipt:
            """An Admin removes one member from a shared vault."""
        def leave(self, spec: Facade.SharedVaultRequest) -> Facade.SharedActExecutionReceipt:
            """A member leaves a shared vault under their own proof; an Owner leaves through remove_owner instead."""
        def invitations(self, spec: Facade.SharedVaultRequest) -> list[Facade.SharedInvitation]:
            """The caller's own pending invitations into a shared vault."""
        def accept(self, spec: Facade.SharedInvitationRequest) -> Facade.SharedActExecutionReceipt:
            """The invitee accepts their own invitation and joins the shared vault at its role."""
        def decline(self, spec: Facade.SharedInvitationRequest) -> Facade.SharedActExecutionReceipt:
            """The invitee declines their own invitation; nothing is granted."""
        def withdraw_invitation(self, spec: Facade.SharedInvitationWithdrawRequest) -> Facade.SharedActExecutionReceipt:
            """An Admin with the add_member power takes back a pending invitation."""
    class _VaultFederationVerbs:
        @property
        def coreference(self) -> "Oneiron._VaultFederationCoreferenceVerbs": ...
        @property
        def burst(self) -> "Oneiron._VaultFederationBurstVerbs": ...
        @property
        def connect(self) -> "Oneiron._VaultFederationConnectVerbs": ...
    class _VaultFederationCoreferenceVerbs:
        def link(self, spec: Facade.CoreferenceLinkRequest) -> Facade.CoreferenceLinkReceipt:
            """The owner atomically links two people with proposed or confirmed identity status, without pooling their claims or granting reads."""
        def confirm(self, spec: Facade.CoreferencePairRequest) -> Facade.CoreferenceLinkReceipt:
            """The owner atomically confirms cross-vault identity without changing either person or their claims."""
        def share_consent(self, spec: Facade.CoreferenceShareConsentRequest) -> Facade.CoreferenceShareConsentReceipt:
            """The owner consents to exporting an existing identity link into exactly one named federation pact."""
        def unlink(self, spec: Facade.CoreferencePairRequest) -> Facade.CoreferenceUnlinkReceipt:
            """The owner atomically removes both identity-link orientations and retracts link metadata while retaining the original claims."""
    class _VaultFederationBurstVerbs:
        def baseline(self, spec: Facade.FederationBurstPeerRequest) -> Facade.FederationBurstBaselineState:
            """The owner reads one peer's named or observed baseline, relative rate and streak, and current vault-size context."""
        @property
        def policy(self) -> "Oneiron._VaultFederationBurstPolicyVerbs": ...
        def ingress(self, spec: Facade.ConnectDelivery) -> Facade.FederationBurstReceipt:
            """The owner admits a peer host signed Connect delivery through current federation admission and receives its discriminated burst receipt."""
        def disposition(self, spec: Facade.FederationBurstReplayRequest) -> Facade.FederationBurstReceipt:
            """The owner reads an authenticated batch original disposition, named baseline context and current durable replay state."""
        @property
        def review(self) -> "Oneiron._VaultFederationBurstReviewVerbs": ...
        def replay(self, spec: Facade.FederationBurstReplayRequest) -> Facade.FederationBurstReceipt:
            """The owner retries one retained authenticated batch through its current grant and federation admission without another burst debit."""
    class _VaultFederationBurstPolicyVerbs:
        def __call__(self, spec: Facade.FederationBurstPeerRequest) -> Facade.FederationBurstPolicy:
            """The owner reads one grant-bound peer's relative-burst outcome policy."""
        def set(self, spec: Facade.FederationBurstPolicySetRequest) -> Facade.FederationBurstPolicy:
            """The owner sets a named baseline and allow, isolate-and-propose or defer routing for one peer without changing its grant."""
    class _VaultFederationBurstReviewVerbs:
        def __call__(self, spec: Facade.EmptyRequest) -> list[Facade.FederationBurstReviewBundle]:
            """The owner reads retained peer review bundles, coalesced once per peer and kept after replay or rejection."""
        def release(self, spec: Facade.FederationBurstReviewRequest) -> Facade.FederationBurstReviewReceipt:
            """The owner releases a bundle's burst hold for current-grant replay without importing evidence or widening authority."""
        def reject(self, spec: Facade.FederationBurstReviewRequest) -> Facade.FederationBurstReviewReceipt:
            """The owner rejects a bundle's pending batches while retaining its review evidence and terminal dispositions."""
    class _VaultFederationConnectVerbs:
        def identity(self, spec: Facade.EmptyRequest) -> Facade.ConnectIdentity:
            """The owner reads this vault identity and the host key used for reciprocal Connect consent."""
        @property
        def grants(self) -> "Oneiron._VaultFederationConnectGrantsVerbs": ...
        def offer(self, spec: Facade.OfferConnect) -> Facade.Offer:
            """The owner asks the host to sign one disclosed Connect half without activating it."""
        def accept(self, spec: Facade.AcceptConnect) -> Facade.ConnectAccepted:
            """The owner accepts the peer host signed Connect half and receives the matching host counter-half."""
        def narrow(self, spec: Facade.NarrowConnect) -> Facade.ConnectPactReceipt:
            """The owner narrows the current outbound scope without breaking the reciprocal relationship."""
        @property
        def rescope(self) -> "Oneiron._VaultFederationConnectRescopeVerbs": ...
        def disconnect(self, spec: Facade.ConnectPactRequest) -> Facade.ConnectDisconnected:
            """The owner unilaterally ends both directions of a pact without claiming to erase the peer retained copy."""
        def export(self, spec: Facade.ConnectExportRequest) -> Facade.ConnectDelivery:
            """The owner exports one grant-filtered named-world update signed by the host for its live pact and epoch."""
        def rejoin(self, spec: Facade.ConnectDelivery) -> Facade.ConnectRejoined:
            """The owner admits a peer host signed update through guest admission into the retained foreign-world vault."""
    class _VaultFederationConnectGrantsVerbs:
        def mint(self, spec: Facade.MintConnectGrant) -> Facade.ConnectGrant:
            """The owner mints an inert Connect guest grant inside the named local-world ceiling."""
    class _VaultFederationConnectRescopeVerbs:
        def offer(self, spec: Facade.RescopeConnect) -> Facade.RescopeOffer:
            """The owner discloses both directions at a new epoch and asks the host to sign a reciprocal re-scope proposal."""
        def accept(self, spec: Facade.AcceptRescopeConnect) -> Facade.ConnectRescoped:
            """The owner accepts the peer host signed re-scope and receives the matching signed counter-half."""
    class _VaultTrustedContactsVerbs:
        def name(self, spec: Facade.TrustedContactNameRequest) -> Facade.TrustedContact:
            """A live person names another live person of the vault as their trusted contact, reached on one outbound channel verb, with an ask-first dial; naming again replaces it and needs the contact's consent again."""
        def list(self, spec: Facade.TrustedContactsRequest) -> list[Facade.TrustedContact]:
            """A live person lists every trusted-contact relation they are a side of: those they named and those naming them, under their own credential."""
        def consent(self, spec: Facade.TrustedContactConsentRequest) -> Facade.TrustedContact:
            """The named contact, a live person under their own credential, accepts the naming version they were shown and attests they are an adult; the relation is live only after this."""
        def revoke(self, spec: Facade.TrustedContactRevokeRequest) -> Facade.TrustedContact:
            """Either side of a trusted-contact relation ends it under their own credential; no notice staged from it is sent after this returns, and its open asks close."""
        @property
        def dial(self) -> "Oneiron._VaultTrustedContactsDialVerbs": ...
        @property
        def tier(self) -> "Oneiron._VaultTrustedContactsTierVerbs": ...
        @property
        def concern(self) -> "Oneiron._VaultTrustedContactsConcernVerbs": ...
    class _VaultTrustedContactsDialVerbs:
        def set(self, spec: Facade.TrustedContactDialRequest) -> Facade.TrustedContact:
            """A person changes whether they are asked before their trusted contact is reached (ask_first or just_call); the contact's consent stands."""
    class _VaultTrustedContactsTierVerbs:
        def set(self, spec: Facade.TrustedContactTierRequest) -> Facade.TrustedContactTierSet:
            """The vault owner names the trusted-contact tier (concern or imminent) of one RouteToHelp policy row; a row never named is a concern."""
    class _VaultTrustedContactsConcernVerbs:
        def asks(self, spec: Facade.TrustedContactAsksRequest) -> list[Facade.TrustedContactAsk]:
            """A person reads their own open asks to reach a trusted contact, each raised by a RouteToHelp the policy gate settled."""
        def authorize(self, spec: Facade.TrustedContactAuthorizeRequest) -> Facade.TrustedContactAuthorization:
            """A person answers one of their own open asks, once: a yes stages the fact-of-concern notice (staged, not delivered) and returns the notices that tell the person and the model; a no or a superseded ask stages nothing."""
        def propose(self, spec: Facade.TrustedContactConcernRequest) -> Facade.TrustedContactConcernProposal:
            """The owner's policy gate reads one message the caller reads, fresh; a RouteToHelp asks the owner or stages a just-call notice, and the answer carries only the fact of concern, the gate receipt, open asks and notices."""
        def deliver(self, spec: Facade.TrustedContactDeliverRequest) -> Facade.TrustedContactDeliveryReceipt | None:
            """The caller sends the next staged fact-of-concern notice it is the stored sender of, as itself, through the consent-checked outbound dispatch; null when none is eligible, never another sender's notice."""
    class _VaultGuestsVerbs:
        def share(self, spec: Facade.GuestDocumentShareRequest) -> Facade.GuestDocumentEnvelope:
            """The owner shares a locally authored named-world document through its live guest grant as a filtered signed envelope bound to the pact epoch."""
        def export_envelope(self, spec: Facade.GuestDocumentShareRequest) -> Facade.GuestDocumentEnvelope:
            """The guest fetches its actual filtered signed document envelope under its own live grant-bound credential over HTTP or the held socket."""
        def reshare(self, spec: Facade.GuestDocumentShareRequest) -> Facade.GuestDocumentEnvelope:
            """The owner attempts a document re-share through the same local-world-only guest door; received foreign worlds and base are refused."""
        def revoke(self, spec: Facade.GuestRevokeRequest) -> Facade.GuestRevokeResponse: ...
        def mint_slip(self, spec: Facade.GuestSlipMintRequest) -> Facade.GuestSlipMinted:
            """The owner mints an Ask or active Connect guest capability slip bound to its live grant and the public key generated by the guest on their own device, with an optional signed comm cap (below vault, owners only)."""
    class _VaultSupportGrantsVerbs:
        def mint(self, spec: Facade.SupportGrantMintRequest) -> Facade.SupportGrantMintAnswer:
            """The owner mints our support person or agent a time-limited, revocable grant, bound to that party's own key, inside explicit bounds."""
        def list(self, spec: Facade.SupportGrantListRequest) -> Facade.SupportGrantList:
            """The owner lists the vault's support grants, newest first, with each one's bounds, deadline, status and revoke command."""
        def revoke(self, spec: Facade.SupportGrantRevokeRequest) -> Facade.SupportGrantRevokeAnswer:
            """The owner revokes one support grant; what support already read is not recalled."""
    class _VaultFilesVerbs:
        @property
        def sources(self) -> "Oneiron._VaultFilesSourcesVerbs": ...
    class _VaultFilesSourcesVerbs:
        def attach(self, spec: Facade.FilesSourceAttachRequest) -> Facade.FilesSourceAttachAnswer:
            """The owner attaches a folder of this host to its Files world, opting in on the first one: a world read on this install only, with no sealed copy. Its files land and its first rescan runs; the host's rescans keep it current."""
        def rescan(self, spec: Facade.FilesSourceRescanRequest) -> Facade.FilesRescanAnswer:
            """The owner rescans one Files source now, or every one: new files land, changed files supersede, files with no text are held by name, missing files retract."""
        def detach(self, spec: Facade.FilesSourceDetachRequest) -> Facade.FilesSourceDetachAnswer:
            """The owner detaches a Files source: no rescan reads its folder again and its ledger goes; the notes it landed stay."""
        def list(self, spec: Facade.FilesSourceListRequest) -> Facade.FilesSourceList:
            """The owner lists this install's Files world and every Files source, with each one's exclusions and ledger counts."""
        def files(self, spec: Facade.FilesSourceFilesRequest) -> Facade.FilesSourceFiles:
            """The owner reads one Files source's ledger: each file's path, readiness (text or name only, and why), revision and dates."""
    class _VaultResidenceVerbs:
        def mode(self, spec: Facade.ResidenceModeRequest) -> Facade.ResidenceModeAnswer:
            """Switches one of the owner's machines between opened and all residence; that machine's own sync connection applies it. A machine this host does not reach answers state queued, naming the directive."""
        def open(self, spec: Facade.ResidenceOpenRequest) -> Facade.ResidenceOpenAnswer:
            """Opens one item on the named machine and reports local or home residence; a NOTE includes typed text, its version and requested stable anchors. A machine this host does not reach answers state queued, naming the directive."""
        def index(self, spec: Facade.ResidenceMachineRequest) -> Facade.ResidenceIndexAnswer:
            """The thin index one of the owner's machines holds, window by window: what exists, never a body. A machine this host does not reach answers state queued, naming the directive."""
        def prune(self, spec: Facade.ResidencePruneRequest) -> Facade.ResidencePruneAnswer:
            """Drops the opened-item caches one of the owner's machines last touched before a time. A machine this host does not reach answers state queued, naming the directive."""
        def directives(self, spec: Facade.ResidenceDirectivesRequest) -> list[Facade.ResidenceDirectiveView]:
            """The owner reads the residence directives this replica holds and each machine's result as received here; a null result means not received here, not that the machine is idle."""
    class _VaultOffRecordVerbs:
        def start(self, spec: Facade.OffRecordStartRequest) -> Facade.OffRecordSessionView:
            """The vault's owner, or a person or agent who then manages it with the owner, enters an off-record session alone, off record or anonymous, under their own name for it, and answers the handle later calls name it by."""
        def status(self, spec: Facade.OffRecordSessionRequest) -> Facade.OffRecordSessionView:
            """The session's creator or the vault's owner reads one live off-record session: its mode, backend, entry time, promoted turns and whether it is closing; a room's member reads what their membership shows."""
        def witness(self, spec: Facade.OffRecordWitnessRequest) -> Facade.WitnessReceipt:
            """The session's creator or the vault's owner witnesses one turn into an off-record session, or a member into a room's; it stays in the room until promoted or dropped at close."""
        def discard(self, spec: Facade.OffRecordSessionRequest) -> Facade.OffRecordClosed:
            """The session's creator or the vault's owner closes an off-record session without saving it: its turns, writes, receipts and spilled outputs are dropped, and promoted turns stay."""
        def recall(self, spec: Facade.OffRecordRecallRequest) -> Facade.MemoryPack:
            """The session's creator or the vault's owner recalls over an off-record session and the vault together, on their own credential: rows the room holds and vault rows alike."""
        @property
        def notes(self) -> "Oneiron._VaultOffRecordNotesVerbs": ...
        @property
        def claims(self) -> "Oneiron._VaultOffRecordClaimsVerbs": ...
        @property
        def rooms(self) -> "Oneiron._VaultOffRecordRoomsVerbs": ...
    class _VaultOffRecordNotesVerbs:
        def create(self, spec: Facade.OffRecordNoteRequest) -> Facade.EntityRefReceipt:
            """The session's creator or the vault's owner writes one NOTE into an off-record session through its handle; it lands in the room, never in the vault, and close drops it."""
    class _VaultOffRecordClaimsVerbs:
        def upsert(self, spec: Facade.OffRecordClaimRequest) -> Facade.CommitReceipt:
            """The session's creator or the vault's owner admits one claim into an off-record session through its handle and the gate; it lands in the room beside the vault heads, and close drops it."""
    class _VaultOffRecordRoomsVerbs:
        def status(self, spec: Facade.OffRecordRoomRequest) -> Facade.OffRecordRoomView:
            """Reads a room's off-record notices and waiting save suggestions as the caller's membership shows them, without the talk."""
        def start(self, spec: Facade.OffRecordRoomStartRequest) -> Facade.OffRecordRoomView:
            """A person, or an agent within its Write Grant, starts an off-record stretch in a room they belong to, on their own credential."""
        def witness(self, spec: Facade.OffRecordRoomWitnessRequest) -> Facade.WitnessReceipt:
            """Witnesses a turn into a room's off-record stretch as the caller, under their live membership and the current saving grant."""
        def save(self, spec: Facade.OffRecordRoomRequest) -> Facade.OffRecordRoomSaved:
            """A holder of this vault's write grant saves the visible whole talk so far into this vault, on their own credential."""
        def save_from_here(self, spec: Facade.OffRecordRoomRequest) -> Facade.OffRecordRoomView:
            """A holder puts a room's stretch on record for later turns while their vault write grant and room membership stay live."""
        def export(self, spec: Facade.OffRecordRoomRequest) -> Facade.OffRecordRoomExport:
            """A person or an agent on its own slip exports only its visible room talk as a JSON attachment with a content-free notice; an Owner's export also writes an audit row and tells members of each private thread it holds that the Owner is not in."""
        def suggest_save(self, spec: Facade.OffRecordRoomRequest) -> Facade.OffRecordRoomView:
            """An agent suggests saving a room's off-record talk on a write or propose credential; nothing is saved until a holder confirms."""
        def confirm_save(self, spec: Facade.OffRecordRoomRequest) -> Facade.OffRecordRoomSaved:
            """A holder confirms the room's waiting save suggestions with their own save of the visible whole talk; refuses when none waits."""
        def decline_save(self, spec: Facade.OffRecordRoomRequest) -> Facade.OffRecordRoomView:
            """A holder declines the room's waiting save suggestions, posts a content-free notice and saves nothing; refuses when none waits."""
    class _VaultRecordsVerbs:
        def erase_preview(self, spec: Facade.RecordEraseRequest) -> Facade.RecordErasePreview:
            """What erasing one record would take: the brief grants it revokes, the records holding the same bytes and the LFS chunks it shares, with the digest erase_confirm takes back."""
        def erase_confirm(self, spec: Facade.RecordEraseConfirmRequest) -> Facade.ActAnswer[Facade.RecordEraseOutcome]:
            """Erase the record the caller previewed, once its preview still has the digest they confirmed; in a shared vault a held record starts its own erase act instead."""
        def erase_sweep(self, spec: Facade.RecordEraseSweepRequest) -> Facade.RecordEraseSweep | None:
            """Read a redaction receipt's recorded historical-sweep deadline and linked completion as the owner; never starts a sweep."""
    class _VaultResearchVerbs:
        def create_child(self, spec: Facade.ResearchChildWire) -> Facade.ResearchChildReceipt:
            """The owner enqueues an experiment child through ordinary agent dispatch under an unpruned campaign parent; record its actual candidate afterward with research.fork or research.weave."""
        @property
        def archive(self) -> "Oneiron._VaultResearchArchiveVerbs": ...
        def bind(self, spec: Facade.ResearchBindWire) -> Facade.ResearchBinding:
            """Binds an autoresearch campaign to its existing root attempt: its ruler, selection policy, cohort, budget share and prior ladder, once. The owner or the agent running that root calls it."""
        def fork(self, spec: Facade.ResearchForkWire) -> Facade.ExperimentNode:
            """Records a variation or debug child the campaign's controller enqueued under a measured or buggy parent."""
        def weave(self, spec: Facade.ResearchWeaveWire) -> Facade.ExperimentNode:
            """Records a crossover child of several parents whose candidate landed as a claim through the gate, once a held-out win turned merge crossover on."""
        def measure_search(self, spec: Facade.ResearchSearchWire) -> Facade.ExperimentNode:
            """Records a node's search-split evidence, its selection signal, once."""
        def measure_held_out(self, spec: Facade.ResearchHeldOutWire) -> Facade.ExperimentNode:
            """Records a node's held-out evidence, once; only the promotion basis reads it."""
        def evaluate_split(self, spec: Facade.CampaignSplitWire) -> Facade.CampaignSplitReport:
            """The owner scores one arm of a bound claim-authoring campaign on one split under its bound config; the blind taste questions go through the host's decision ladder, and the report is returned, not stored."""
        def mark_invalid(self, spec: Facade.ResearchInvalidWire) -> Facade.ExperimentNode:
            """Marks a node buggy: it stays as evidence and takes debug children."""
        def prune(self, spec: Facade.ResearchPruneWire) -> Facade.ExperimentNode:
            """Stops exploring a branch for a stated cause; its attempts, claims and outputs stay. A stop names the caller."""
        def select(self, spec: Facade.ResearchSelectWire) -> Facade.SelectionReceipt:
            """Runs one selection round through the trusted selection floor and records it; only the owner can say the goal is met."""
        def promotion_basis(self, spec: Facade.ResearchBasisWire) -> Facade.PromotionBasis:
            """Decides a candidate's held-out promotion basis against the incumbent, once."""
        def reserve_confirmation(self, spec: Facade.ResearchCandidateWire) -> Facade.EvalRelease:
            """Spends a Promote candidate's one sealed confirmation and releases the campaign's sealed cohort to the controller's referee, counted as a serving."""
        def promote(self, spec: Facade.ResearchPromoteWire) -> Facade.CampaignPromotionReceipt:
            """Settles a candidate on the sealed referee's scores of it and the incumbent: a strict win, a not-worse sufficiency card and, for a skill, the gate's accepted verdict make it the incumbent."""
        def reserve_work(self, spec: Facade.ResearchWorkWire) -> Facade.EntityId:
            """Reserves token work for the campaign on the RSI line under its share, and returns the reservation's id."""
        def settle_work(self, spec: Facade.ResearchSettleWire) -> Facade.ResearchReservation:
            """Settles a work reservation at its actual spend."""
        def refund_work(self, spec: Facade.ResearchRefundWire) -> Facade.ResearchReservation:
            """Refunds a work reservation nothing was spent on."""
        def reserve_exploration(self, spec: Facade.ResearchExplorationWire) -> Facade.EntityId:
            """Reserves exploration exposure for the campaign on its own exposure-denominated RSI line, independently of token work, and returns the reservation's id. Settle or refund it through settle_work and refund_work."""
        def budget(self, spec: Facade.ResearchArchiveWire) -> Facade.ResearchBudgetView:
            """Reads the campaign's lease, every reservation it holds or held with its settlement and soft-share overdraft receipt, and the vault RSI lines behind them, including the observable hold state."""
        def record_benchmark(self, spec: Facade.ResearchBenchmarkWire) -> Facade.SelectionBenchmark:
            """Records an estimator version's held-out selection benchmark against the DGM parent formula, once per version; a win of at least 30 cases lets its information gain rank parents."""
    class _VaultResearchArchiveVerbs:
        def __call__(self, spec: Facade.ResearchArchiveWire) -> Facade.ResearchArchive:
            """Reads the complete retained campaign record, including every pruned, buggy and woven candidate, original search and held-out evidence, selection rounds and promotion receipts, under the controller gate."""
        def install(self, spec: Facade.CampaignArchiveInstall) -> Facade.CampaignArchiveView:
            """Installs one immutable campaign output descriptor from a receipted Coach proposal under the current human goal; categorical axes and embedding clusters share the engine validator."""
        def record(self, spec: Facade.CampaignArchiveOutput) -> Facade.CampaignArchiveView:
            """Records original placement and quality receipts for one output revision; categorical judgment or pinned embedding placement competes only within its own cell."""
        def get(self, spec: Facade.CampaignArchiveRequest) -> Facade.CampaignArchiveRecord:
            """Reads the installed campaign output descriptor and every original placement and scoring receipt, including losing outputs, under the research controller gate."""
        def best(self, spec: Facade.CampaignArchiveRequest) -> Facade.CampaignArchiveView:
            """Rebuilds one best output per cell under the immutable descriptor revision and reports whether bunching warrants a new campaign proposal."""
        def repropose(self, spec: Facade.CampaignArchiveReproposal) -> Facade.CampaignArchiveView:
            """Installs a receipted descriptor proposal in a new bound campaign when the old archive is bunched; the old descriptor, goal and cell winners remain unchanged."""
        def coverage(self, spec: Facade.CampaignArchiveCoverage) -> Facade.CampaignArchiveAdmission:
            """Pins the incumbent and candidate replay output refs and projects the human goal coverage floor; promotion rechecks these receipts and rejects any lost incumbent cell."""
    class _VaultEvalsVerbs:
        def inventory(self, spec: Facade.EvalInventoryWire) -> Facade.EvalAuthoringInventory:
            """The owner reads the metadata-only eval-authoring inventory: real receipt families, grounded case candidates, date-cut cohorts and exposure counts. Pin its built_at and digest for cohort setup."""
        @property
        def cohorts(self) -> "Oneiron._VaultEvalsCohortsVerbs": ...
        def author_now(self, spec: Facade.EvalAuthorNowRequest) -> Facade.EvalAuthoringRef:
            """Queue the production Coach eval-authoring pass, coalescing with nightly work; the caller supplies no plan, skill provenance or lease."""
        @property
        def authoring(self) -> "Oneiron._VaultEvalsAuthoringVerbs": ...
        @property
        def families(self) -> "Oneiron._VaultEvalsFamiliesVerbs": ...
        @property
        def cases(self) -> "Oneiron._VaultEvalsCasesVerbs": ...
        def exposure(self, spec: Facade.EvalCohortRef) -> Facade.EvalExposureLedger:
            """Read a cohort's individual exposure ledger and independent candidate, query and promotion counts; unknown cohorts refuse."""
        def sufficiency(self, spec: Facade.SufficiencyInput) -> Facade.SufficiencyCard:
            """Compute the existing sufficiency card from explicit family-grouped measurements; unknown never approves, creates a label ask or deploys."""
        @property
        def labels(self) -> "Oneiron._VaultEvalsLabelsVerbs": ...
    class _VaultEvalsCohortsVerbs:
        def __call__(self, spec: Facade.EvalSeatRequest) -> list[Facade.EvalCohortView]:
            """Read date-cut cohorts, the fixed reference, retirement decisions, exposure counts and near-copy audits; similarity flags review only."""
        def setup(self, spec: Facade.EvalCohortSetup) -> Facade.EvalAuthoringReport:
            """The owner sets up sealed cohorts from a pinned real inventory through the existing family, case and audited cut doors. Reports refused decisions; never serves sealed content or fabricates labels or skill provenance."""
        def open(self, spec: Facade.EvalCohortOpenRequest) -> Facade.EvalRelease:
            """Count a candidate, query or promotion serving before releasing its sealed cohort in the same owner-validated transaction; retired cohorts refuse."""
    class _VaultEvalsAuthoringVerbs:
        def result(self, spec: Facade.EvalAuthoringRef) -> Facade.EvalAuthoringResult | None:
            """Read the eval-authoring host attempt's actual state and terminal error; a completed pass may author nothing."""
    class _VaultEvalsFamiliesVerbs:
        def __call__(self, spec: Facade.EvalSeatRequest) -> list[Facade.EvalFamilyView]:
            """Read a seat's family purposes, source roots, derivative lineage and dates, including retirement and training eligibility, without sealed labels."""
        def assign(self, spec: Facade.EvalFamilyAssignRequest) -> Facade.SourceFamily:
            """Assign source roots their fixed eval family and purpose before deriving cases; conflicting families, purposes or seats refuse."""
    class _VaultEvalsCasesVerbs:
        def __call__(self, spec: Facade.EvalCasesRequest) -> list[Facade.EvalCase]:
            """Read development or judge-audit eval cases; sealed confirmation refuses and retired cohorts read as development, never training."""
        def record(self, spec: Facade.EvalCaseDraft) -> Facade.EvalCase:
            """Record a receipt, repair, paraphrase, summary, translation, synthetic or rubric case through the shared family-inheritance guard; no labels are invented."""
    class _VaultEvalsLabelsVerbs:
        def blocked(self, spec: Facade.EvalBlockedLabelsRequest) -> list[Facade.EvalLabelAsk]:
            """Read only unanswered eval-label asks for this owner, optionally by seat or blocked decision, with scoped cases and quoted human minutes; create no standing label session."""
        def pick(self, spec: Facade.EvalLabelPickRequest) -> Facade.EvalCase:
            """Record either option of the responsible owner's existing eval-label ask once; the same pick repeats safely and a conflicting second pick refuses."""
    class _VaultRootsVerbs:
        @property
        def requests(self) -> "Oneiron._VaultRootsRequestsVerbs": ...
    class _VaultRootsRequestsVerbs:
        def cancel(self, spec: Facade.RootRequestCancelRequest) -> Facade.OwnerWorkReceipt:
            """The owner cancels one root request from any surface he is signed in on, ids only; the target applies it whenever it syncs. The receipt says cancelled, or that the target answered it first, which stands."""
    class _VaultCleanupVerbs:
        def run(self, spec: Facade.CleanupRunRequest) -> Facade.CleanupRunView:
            """The owner runs one archive-cleanup pass under the current posture; propose-first opens a proposal and archives nothing."""
        def review(self, spec: Facade.CleanupReviewRequest) -> Facade.CleanupReviewView:
            """The owner reviews one open cleanup proposal item by item with full disclosure: each slot's state, entity, kind, evidence, revision, accept effect and full content; erased, gone and unreadable slots stay as typed facts."""
        def decide(self, spec: Facade.CleanupDecideRequest) -> Facade.CleanupDecideView:
            """The owner decides one open cleanup proposal per item in one complete verdict, an accept or a reject for every slot; accepted slots archive as a whole accept does, rejected ones stay and are recorded as rejected."""
    class _VaultArchiveVerbs:
        @property
        def delete(self) -> "Oneiron._VaultArchiveDeleteVerbs": ...
    class _VaultArchiveDeleteVerbs:
        def preview(self, spec: Facade.ArchiveDeletePreviewRequest) -> Facade.ArchiveDeletePreviewView:
            """Previews explicit archived records under the caller's delete authority."""
        def confirm(self, spec: Facade.ArchiveDeleteConfirmRequest) -> Facade.ArchiveDeleteBatchResult:
            """Deletes explicit archived records under the caller's current delete authority and returns each receipt."""
    class _VaultUsageVerbs:
        @property
        def events(self) -> "Oneiron._VaultUsageEventsVerbs": ...
    class _VaultUsageEventsVerbs:
        def undecodable(self, spec: Facade.UsageRepairListRequest) -> Facade.UndecodableUsageList:
            """Lists the stored usage events of this server's metering scope that no longer decode, each by an opaque row ref, its byte length and the BLAKE3 hash of its bytes, for the owner or an agent whose own Grant names this verb."""
        def remove_undecodable(self, spec: Facade.UsageRepairRemoveRequest) -> Facade.UsageRepairReceipt:
            """Removes one listed undecodable usage event while it still holds the reviewed bytes and does not decode, and answers the receipt kept in that write, for the owner or an agent whose own Grant names this verb."""
    class _VaultLegalHoldsVerbs:
        def place(self, spec: Facade.LegalHoldPlaceRequest) -> Facade.LegalHold:
            """The owner places a customer legal hold on the named records or gate partitions."""
        def widen(self, spec: Facade.LegalHoldWidenRequest) -> Facade.LegalHold:
            """Adds targets to one of the owner's standing customer legal holds."""
        def list(self, spec: Facade.EmptyRequest | None = None) -> list[Facade.LegalHold]:
            """Every legal hold the owner may see."""
        def log(self, spec: Facade.EmptyRequest | None = None) -> list[Facade.LegalHoldEvent]:
            """The owner-visible legal hold log, oldest first."""
        def lift_and_erase(self, spec: Facade.LegalHoldLiftAndEraseRequest) -> Facade.LegalHoldLiftAndErased:
            """The owner's one confirm, bound to the state it showed, that lifts or narrows the customer holds on the named records, and on the claim-free gate partition when asked, and erases the records."""
    class _VaultCourtesyDeleteVerbs:
        def send(self, spec: Facade.CourtesyDeleteSendRequest) -> Facade.CourtesyDeleteSent:
            """The owner asks a former peer to drop what an ended pact delivered, and queues the signed ask for delivery."""
        def sent(self, spec: Facade.EmptyRequest | None = None) -> list[Facade.CourtesyDeleteSent]:
            """Every courtesy delete ask this vault sent, with its delivery status, for the owner."""
        def incoming(self, spec: Facade.EmptyRequest | None = None) -> list[Facade.CourtesyDeleteIncoming]:
            """Every courtesy delete ask a former peer sent, with each named world's stale stamp and the owner's answer."""
        def answer(self, spec: Facade.CourtesyDeleteAnswerRequest) -> Facade.CourtesyDeleteIncoming:
            """The owner answers one incoming courtesy delete ask from the menu, and sends the answer back when reply_to names where."""
    class _VaultEmbeddingSpacesVerbs:
        def list(self, spec: Facade.EmptyRequest | None = None) -> Facade.EmbeddingSpacesView:
            """Every declared embedding space, the text index, the space each kind slot reads, every move and the probe count per kind."""
        def declare(self, spec: Facade.EmbeddingSpaceDeclareRequest) -> Facade.EmbeddingSpacesView:
            """Declares or widens one embedding space: id, dimensions, accepts, query_towers and optional evidence floors."""
        def bind(self, spec: Facade.EmbeddingSpaceBindRequest) -> Facade.EmbeddingSpacesView:
            """Binds one kind slot to a declared space, or returns it to its default when no space is named."""
        def one_space(self, spec: Facade.EmbeddingSpaceRequest) -> Facade.EmbeddingSpacesView:
            """Binds every kind slot the space accepts, text included, to that one space."""
        def retire(self, spec: Facade.EmbeddingSpaceRequest) -> Facade.EmbeddingSpacesView:
            """Drops a declared space that no slot binds and no open move names, with its vector rows."""
        def move(self, spec: Facade.EmbeddingSpaceMoveRequest) -> Facade.SpaceMove:
            """Starts moving every kind slot the incumbent serves (the text index when none is named) to the candidate space."""
        def move_check(self, spec: Facade.EmbeddingSpaceCandidateRequest) -> Facade.EmbeddingSpaceMoveChecked:
            """Runs an embedding space move probes now through both spaces and acts on the reading; it can take minutes."""
        def move_approve(self, spec: Facade.EmbeddingSpaceCandidateRequest) -> Facade.EmbeddingSpacesView:
            """The owner says yes to a full candidate over a check that did not read not worse; it swaps in."""
        def move_undo(self, spec: Facade.EmbeddingSpaceCandidateRequest) -> Facade.EmbeddingSpacesView:
            """Binds a swapped-in move incumbent again."""
        def move_abandon(self, spec: Facade.EmbeddingSpaceCandidateRequest) -> Facade.EmbeddingSpacesView:
            """Ends an open embedding space move with no swap."""
        @property
        def probes(self) -> "Oneiron._VaultEmbeddingSpacesProbesVerbs": ...
    class _VaultEmbeddingSpacesProbesVerbs:
        def list(self, spec: Facade.EmptyRequest | None = None) -> Facade.EmbeddingSpaceProbes:
            """Every stored embedding space probe with its id."""
        def put(self, spec: Facade.EmbeddingSpaceProbePutRequest) -> Facade.EmbeddingSpaceProbe:
            """Stores one retrieval probe the owner or another model wrote: kind, a text query or a stored image or audio document as its query, family, targets and author."""
        def delete(self, spec: Facade.EmbeddingSpaceProbeDeleteRequest) -> Facade.EmbeddingSpaceProbeDeleted:
            """Removes one stored embedding space probe by its id."""
    class _VaultPolicyVerbs:
        @property
        def owner(self) -> "Oneiron._VaultPolicyOwnerVerbs": ...
        @property
        def outbound(self) -> "Oneiron._VaultPolicyOutboundVerbs": ...
        @property
        def relay(self) -> "Oneiron._VaultPolicyRelayVerbs": ...
    class _VaultPolicyOwnerVerbs:
        def get(self, spec: Facade.EmptyRequest | None = None) -> Facade.OwnerPolicyConfigurationView:
            """The owner reads the content-policy configuration, default manifest hash and effective off/on state."""
        def configure(self, spec: Facade.OwnerPolicyConfigureRequest) -> Facade.OwnerPolicyConfigurationReceipt:
            """The owner configures or toggles content policy against the current manifest hash without changing other policy tables."""
        @property
        def row(self) -> "Oneiron._VaultPolicyOwnerRowVerbs": ...
    class _VaultPolicyOwnerRowVerbs:
        def change(self, spec: Facade.PolicyRowChangeRequest) -> Facade.PolicyRowReceipt:
            """The owner adds, edits or removes a scoped content-policy row through its existing holder-governed writer and receives its change receipt."""
    class _VaultPolicyOutboundVerbs:
        def decide(self, spec: Facade.PolicyOutboundRequest) -> Facade.PolicyModelEnforcement:
            """Decide an outbound candidate under owner policy with system notices and hash-only receipts; Warn and Skipped preserve its exact bytes."""
    class _VaultPolicyRelayVerbs:
        def decide(self, spec: Facade.PolicyOutboundRequest) -> Facade.HostedRelayDecision:
            """Decide bytes carried by the host-bound attested relay under its own legal policy; each completed model decision leaves one content-free receipt, and outages halt with a service notice and local-model offer."""
    class _VaultConsentVerbs:
        def approve_once(self, spec: Facade.ApproveOnceRequest) -> Facade.ConsentActReceipt:
            """The owner approves exactly one engine-emitted effect digest; no standing grant is created."""
        def deny(self, spec: Facade.DenyConsentRequest) -> Facade.ConsentActReceipt:
            """The owner denies exactly one engine-emitted effect digest and records the refusal without granting authority."""
        def create_standing_grant(self, spec: Facade.CreateStandingGrantRequest) -> Facade.ConsentActReceipt:
            """The owner creates a bounded standing action or disclosure grant, with no stored expiry; a wider bound is a new decision."""
        def registry(self, spec: Facade.ConsentRegistryQuery) -> Facade.ConsentRegistry:
            """The owner reads the unified action and disclosure grant registry, including revoke commands and optionally revoked grants."""
        def failure_signals_held(self, spec: Facade.EmptyRequest | None = None) -> Facade.HeldFailureSignalBatchView | None:
            """Read the carried failure-signal batch's exact content and approval digest as the owner."""
        def revoke(self, spec: Facade.RevokeGrantRequest) -> Facade.ConsentActReceipt:
            """The owner immediately revokes a standing consent grant by the reference its receipt or registry emitted."""
        def bypass_grant_warning(self, spec: Facade.BypassGrantWarningRequest) -> Facade.BypassGrantWarningView:
            """The owner previews the exact actor, classes, envelope and project or thread of a scoped bypass; this warning grants nothing."""
        def create_bypass_grant(self, spec: Facade.CreateBypassGrantRequest) -> list[Facade.ConsentActReceipt]:
            """The owner explicitly acknowledges a scoped bypass warning and atomically creates one receipted standing bypass per class."""
        def active_bypass_grants(self, spec: Facade.ActiveBypassGrantsRequest) -> list[Facade.BypassActiveState]:
            """The owner reads live scoped bypass states and their complete bounds, newest first; vault.consent.revoke ends each grant."""
        def bypassed_effect_receipts(self, spec: Facade.BypassedEffectReceiptsRequest) -> list[Facade.BypassedEffectReceipt]:
            """The owner reads the existing Gate receipts for effects covered by one bypass grant, including after its revocation."""
        @property
        def graduation(self) -> "Oneiron._VaultConsentGraduationVerbs": ...
    class _VaultConsentGraduationVerbs:
        @property
        def policy(self) -> "Oneiron._VaultConsentGraduationPolicyVerbs": ...
        def stats(self, spec: Facade.GraduationScopeRequest) -> Facade.GraduationStats | None:
            """Reads one exact graduation scope outcome history and current consent posture."""
        def outcome(self, spec: Facade.GraduationOutcomeRequest) -> Facade.GraduationStats:
            """The owner records an untouched, amended or rejected proposal ruling, receipted and folded through the existing ramp."""
        def offers(self, spec: Facade.EmptyRequest) -> list[Facade.GraduationOffer]:
            """Reads earned, unsuppressed graduation offers with thresholds, streaks and before/after reach; reading grants nothing."""
        def answer(self, spec: Facade.GraduationAnswerRequest) -> Facade.GraduationAnswerReceipt:
            """The owner answers auto, not-now or manual_pinned; only auto mints the existing standing grant, and not-now resets the streak."""
        def trust_table(self, spec: Facade.EmptyRequest) -> list[Facade.GraduationTrustRow]:
            """Reads the owner trust table: scope, counts, effective threshold, snooze or manual pin, live grant and offer reach."""
        @property
        def settings(self) -> "Oneiron._VaultConsentGraduationSettingsVerbs": ...
        def demote(self, spec: Facade.GraduationDemoteRequest) -> Facade.GraduationChanged:
            """The owner demotes an exact scope to propose, revoking its live grant and recording the existing durable demotion receipt."""
    class _VaultConsentGraduationPolicyVerbs:
        def __call__(self, spec: Facade.GraduationPolicyRequest) -> Facade.GraduationPolicies:
            """Reads runtime consent-graduation policy rows and the effective row for an optional exact scope."""
        def set(self, spec: Facade.GraduationPolicySetRequest) -> Facade.GraduationChanged:
            """The owner sets a scope-pattern streak, posterior guard and two snooze backoffs; zero-second backoff is supported."""
        def clear(self, spec: Facade.GraduationPolicyClearRequest) -> Facade.GraduationChanged:
            """The owner clears one runtime graduation policy row; scopes fall back to the next matching policy."""
    class _VaultConsentGraduationSettingsVerbs:
        def unpin(self, spec: Facade.GraduationScopeRequest) -> Facade.GraduationChanged:
            """The owner reopens a pinned or snoozed graduation scope in settings; no grant is created."""
    class _VaultGateVerbs:
        @property
        def policy(self) -> "Oneiron._VaultGatePolicyVerbs": ...
        @property
        def checker(self) -> "Oneiron._VaultGateCheckerVerbs": ...
    class _VaultGatePolicyVerbs:
        def get(self, spec: Facade.PolicyManifestRead) -> Facade.PolicyManifestsView:
            """The owner reads Gate policy envelopes, actor ceilings, source permits and checker references, including inert contributions."""
        def put(self, spec: Facade.PolicyManifestPut) -> Facade.PolicyManifestReceipt:
            """The owner, or an Admin or Delegate holding the policy power, installs or edits typed Gate write axes, preserving other tables and meeting independently installed contributions."""
        def propose(self, spec: Facade.PolicyManifestPropose) -> Facade.PolicyManifestReceipt:
            """Propose a Gate policy under the caller's own authority; even a tighter contribution remains untrusted and inert."""
    class _VaultGateCheckerVerbs:
        def get(self, spec: Facade.EmptyRequest | None = None) -> Facade.GateCheckerView:
            """The owner reads the calibrated checker verdict role from the vault model manifest."""
        def set(self, spec: Facade.GateCheckerSet) -> Facade.GateCheckerReceipt:
            """The owner sets the calibrated checker model, slot, confidence floor and shadow or enforce mode without changing other model bindings."""
    class _VaultLearningVerbs:
        def read(self, spec: Facade.LearningReadRequest) -> Facade.LearningCellView:
            """The owner reads a measured learning cell, its explicit prior, derived UNTESTED mark, projector heads and anchored evidence; borrowed provenance stays separate from own runs."""
        def projection(self, spec: Facade.LearningProjectionRequest) -> Facade.LearningProjectionView:
            """The owner observes the stored projection receipt for an anchored attempt outcome; an absent receipt means projection has not committed, never a successful empty projection."""
    class _VaultSealVerbs:
        def confess(self, spec: Facade.AttemptConfession) -> Facade.SealReceiptView:
            """Confess an attempt's objectives without changing any score; named flaws and uncertainty create durable directed rechecks."""
        def audit(self, spec: Facade.SealAttemptRequest) -> Facade.SealReceiptView:
            """Draw a passing sealed attempt once at the current audit rate, saving the rate and selection before any checker runs."""
        def receipt(self, spec: Facade.SealAttemptRequest) -> Facade.SealReceiptView | None:
            """Read a sealed attempt, its stamped audit draw, directed and random check completions, weighted findings and separate honesty reward."""
        def pending(self, spec: Facade.SealPendingRequest) -> list[Facade.SealCheckRequest]:
            """Read pending directed rechecks and random audits, optionally for one attempt, without executing a checker."""
        def run(self, spec: Facade.SealRunRequest) -> Facade.SealRunReceipt:
            """Queue the existing Coach seal checker under its ordinary lease, Grant and budget; the returned job never grants extra authority."""
        def complete(self, spec: Facade.SealCompleteRequest) -> Facade.SealReceiptView:
            """Attest an independent external seal check as the owner; admit immutable findings and project them using the request's stamped rate."""
    class _VaultSettingsVerbs:
        @property
        def learning(self) -> "Oneiron._VaultSettingsLearningVerbs": ...
        @property
        def wake_policy(self) -> "Oneiron._VaultSettingsWakePolicyVerbs": ...
        @property
        def inference_defaults(self) -> "Oneiron._VaultSettingsInferenceDefaultsVerbs": ...
    class _VaultSettingsLearningVerbs:
        def __call__(self, spec: Facade.LearningSettingsRequest) -> Facade.LearningSettingsView:
            """The owner reads the learned-setting catalog, each knob's value now, and the owner's seed and pin rows at the vault, a project or a task type."""
        def put(self, spec: Facade.LearningSettingPut) -> Facade.LearningSettingsView:
            """The owner lays one seed or pin on a learned setting at the vault, a project or a task type, replacing the row of the same key, mode and scope."""
        def clear(self, spec: Facade.LearningSettingClear) -> Facade.LearningSettingsView:
            """The owner clears one learned-setting row of a key, mode and scope."""
    class _VaultSettingsWakePolicyVerbs:
        def set(self, spec: Facade.WakePolicySetRequest) -> Facade.PolicyActionOutcome:
            """The owner sets the dreamer's wake policy: the app's dreamer.wake_policy.set action, run as the caller under the owner's proof."""
    class _VaultSettingsInferenceDefaultsVerbs:
        def __call__(self, spec: Facade.EmptyRequest | None = None) -> Facade.PolicyActionOutcome:
            """Reads the per-purpose inference defaults: the app's inference.defaults.read action, which needs the caller's Auto ceiling."""
        def replace(self, spec: Facade.InferenceDefaultsReplaceRequest) -> Facade.PolicyActionOutcome:
            """Replaces the whole per-purpose inference default table: the app's inference.defaults.replace action, which needs the caller's Auto ceiling."""
    class _VaultSecretsVerbs:
        def lift_history(self, spec: Facade.SecretLiftRequest) -> Facade.SecretLiftStatus:
            """The owner reads the historical secret lift sweep: the run in progress, the last receipt and the open lift proposals by cause. With close, one proposal closes first with the owner's reason and a receipt; with start, a run is queued."""
    class _VaultWidenProposalsVerbs:
        def __call__(self, spec: Facade.WidenProposalsRequest) -> Facade.WidenProposalsView:
            """The owner lists the context-widen proposals agents raised, newest first, or only those pending, approved or declined."""
        def approve(self, spec: Facade.WidenProposalAnswer) -> Facade.WidenProposalView:
            """The owner, as the board above, approves one context-widen proposal: the parent's context widens and the child is enqueued."""
        def decline(self, spec: Facade.WidenProposalAnswer) -> Facade.WidenProposalView:
            """The owner, as the board above, declines one context-widen proposal for good; the decline stays on record."""
    class _VaultCraftCandidatesVerbs:
        def __call__(self, spec: Facade.CraftCandidatesRequest) -> Facade.CraftCandidatesView:
            """The owner lists the craft notes residents' dreaming proposed about themselves that wait on a verdict, newest first, or one resident's, each with the content hash an answer pins."""
        def answer(self, spec: Facade.CraftCandidateAnswer) -> Facade.CraftVerdictView:
            """The owner approves or rejects one craft candidate, bound to the content hash its card showed: an Approved or Rejected row supersedes it, with one receipt. The same answer again returns the first."""
    class _VaultLensesVerbs:
        def propose(self, spec: Facade.LensProposeRequest) -> Facade.LensProposalReceipt:
            """Stores one frozen compiled lens tree for a pack slot as this actor's proposal: a CODE kind=lens row born from a lens/intent NOTE that holds its prompt, with the trigger the caller names; it mounts only once the owner selects it."""
        def activate(self, spec: Facade.LensActivateRequest) -> Facade.LensActivationReceipt:
            """The owner selects a proposed lens revision for its pack slot."""
        def deactivate(self, spec: Facade.LensDeactivateRequest) -> Facade.LensActivationReceipt:
            """The owner clears a pack slot's selected lens; the pack, its skill and the proposal stay."""
        def list(self, spec: Facade.LensListRequest) -> Facade.LensListPage:
            """One page of the vault's lens proposals, each with its slot state from the owner's current selection. A credential narrowed to some worlds or facets sees only the proposals whose slot skill and pack source it reads, without their trees."""
        def select(self, spec: Facade.LensSelectRequest) -> Facade.LensSelection:
            """Selects a rendered atom or Unicode-scalar span under the caller's live key and holds its read handle on that card."""
        def resolve(self, spec: Facade.LensSelectionResolveRequest) -> Facade.LensSelectionResolved:
            """Re-proves a host-issued selection on the caller's held card and reads its source with its pinned cursor span."""
        @property
        def result_set(self) -> "Oneiron._VaultLensesResultSetVerbs": ...
        def default(self, spec: Facade.LensDefaultRequest) -> Facade.ScopedReadResult[Facade.LensFrameCard]:
            """Composes the default vault lens from the named sources, read under the caller's own scope, as a card. A server holds its frame for the card's events; an embedded handle holds none, so its events need a server."""
    class _VaultLensesResultSetVerbs:
        def action(self, spec: Facade.LensResultSetActionRequest) -> Facade.LensResultSetActionResult:
            """Re-proves the ticked rows or rendered predicate and their selected handles, then dispatches the declared result-set action through the caller's existing gate."""
    class _VaultDisclosureVerbs:
        def offer(self, spec: Facade.DisclosureOfferRequest) -> Facade.DisclosureOffered:
            """An agent files a clearance offer for one contact, waiting on the owner's answer until it lapses."""
        @property
        def ceiling(self) -> "Oneiron._VaultDisclosureCeilingVerbs": ...
        @property
        def reveals(self) -> "Oneiron._VaultDisclosureRevealsVerbs": ...
    class _VaultDisclosureCeilingVerbs:
        def get(self, spec: Facade.DisclosureCeilingRequest) -> Facade.DisclosureCeilingView:
            """Reads the owner registry dial for one model connection, optionally one data class."""
        def set(self, spec: Facade.DisclosureCeilingSet) -> Facade.DisclosureCeilingView:
            """The owner sets one connection or class disclosure ceiling; no read authority changes."""
        def clear(self, spec: Facade.DisclosureCeilingRequest) -> Facade.DisclosureCeilingView:
            """The owner clears one dial, restoring connection or actor-class inference."""
    class _VaultDisclosureRevealsVerbs:
        def __call__(self, spec: Facade.RevealAsksRequest) -> list[Facade.RevealAskView]:
            """The owner reads model-disclosure asks and receipts, including PERSON handles, without values."""
        def answer(self, spec: Facade.RevealAnswerRequest) -> Facade.RevealAnsweredView:
            """The owner approves once, approves standing, or denies the exact frozen reveal ask."""
    class _VaultSharesVerbs:
        def create(self, spec: Facade.ShareCreateRequest) -> Facade.ShareCreated:
            """The handle's actor issues a share: the brief, its recipient, the most the view may show and the text that travels."""
        def revoke(self, spec: Facade.ShareRevokeRequest) -> Facade.ShareRevokeReceipt: ...
        def view(self, spec: Facade.ShareViewRequest) -> Facade.ScopedReadResult[Facade.SharedBriefView | None]: ...
    class _VaultHooksVerbs:
        def replay(self, spec: Facade.HooksReplayRequest) -> Facade.HooksReplayPage:
            """The owner replays a fact hook over past facts on the hook sandbox, as a dry run where nothing lands, 256 entries a page; next_cursor continues to the rest."""
        @property
        def regen(self) -> "Oneiron._VaultHooksRegenVerbs": ...
    class _VaultHooksRegenVerbs:
        def due(self, spec: Facade.EmptyRequest | None = None) -> list[Facade.EntityId]:
            """List, as the authenticated owner, the hook bindings of the vault's own packs whose verb table or sandbox contract changed since their last good body passed, with no regen waiting. Runs no regen."""
        def get(self, spec: Facade.HookRegenBindingRequest) -> Facade.HookRegenView | None:
            """Read one hook binding's regen record as the authenticated owner: its last good body hash, contract stamp, intent and pending decision, with the candidate_hash an adoption names. Null for a binding bound under no record. Changes nothing."""
        def adopt(self, spec: Facade.HookRegenAdoptRequest) -> Facade.PackPutReceipt:
            """Adopt, as the authenticated owner and as their stamp, the regen candidate pending on one hook binding, named by the candidate_hash vault.hooks.regen.get shows. Answers the pack put receipt; only an installed put advances the record."""
    class _VaultArtifactsVerbs:
        def publish_approval(self, spec: Facade.ArtifactPublishRequest) -> Facade.ArtifactPublishApproval:
            """Computes the exact publication approval digest for the existing owner approve-once door; it grants nothing."""
        def publish(self, spec: Facade.ArtifactPublishRequest) -> Facade.ArtifactPublishView:
            """Publishes one immutable code fork or numbered blob export with an explicit audience through the existing Gate, returning its pointer and durable receipt ref."""
        def repoint(self, spec: Facade.ArtifactPublishRequest) -> Facade.ArtifactPublishView:
            """Repoints one artifact channel to an exact immutable export through the publication Gate; use a new publish id, and earlier receipts survive."""
        def pointer(self, spec: Facade.ArtifactPointerRequest) -> Facade.ArtifactPointer | None:
            """Reads the current artifact channel pin and audience under the owner credential; null when absent or withheld."""
        def unpublish(self, spec: Facade.ArtifactPointerRequest) -> Facade.ArtifactUnpublished:
            """Removes one artifact channel pointer without deleting its immutable export or earlier publication receipts."""
        def link_token(self, spec: Facade.EmptyRequest) -> Facade.ArtifactLinkToken:
            """Mints a serving-only link token and its digest tier; publication still requires a separate exact Gate authorization."""
        @property
        def live_preview(self) -> "Oneiron._VaultArtifactsLivePreviewVerbs": ...
        def view(self, request: Facade.ArtifactRefRequest) -> Facade.ArtifactView | None: ...
        def units(self, spec: Facade.ArtifactUnitsRequest) -> Facade.ArtifactUnitsView:
            """Inspects real DOCX blocks, XLSX cells and PPTX shapes in one version; other kinds explicitly report no annotation unit adapter."""
        @property
        def anchors(self) -> "Oneiron._VaultArtifactsAnchorsVerbs": ...
        @property
        def threads(self) -> "Oneiron._VaultArtifactsThreadsVerbs": ...
        def export(self, request: Facade.ArtifactExportRequest) -> Facade.ArtifactExportFile | None: ...
        def born_from(self, request: Facade.BornFromRequest) -> Facade.BornFromView: ...
        def proposals(self, request: Facade.ArtifactRefRequest) -> list[Facade.PendingProposalView]: ...
        def waits(self, request: Facade.ArtifactRefRequest) -> list[Facade.OrganWaitView]: ...
        def release_wait(self, request: Facade.ProposalSettleRequest) -> Facade.ReleasedWait: ...
        def review_slides(self, request: Facade.SlideReviewSubmit) -> Facade.ActAnswer[Facade.SlideReviewOutcome]: ...
        def ask(self, spec: Facade.ArtifactAskSubmit) -> Facade.ActAnswer[Facade.ArtifactAskOutcome]:
            """Asks one typed question over an artifact's sheet rows, paragraphs or folder items through the host's decision ladder and holds the answers as one proposal for Keep or Discard."""
        def admit(self, spec: Facade.ArtifactAdmitSubmit) -> Facade.ArtifactAskOutcome:
            """Admits the caller's own provider measurements for one artifact ask's units in place of the host ladder's, validating each decision and its provider-bound paired readings before holding the answers as one proposal for Keep or Discard."""
        def propose_outline(self, spec: Facade.DeckOutlineProposeRequest) -> Facade.DeckOutlineView:
            """Proposes a closed typed deck outline as a brief NOTE for the person to keep or decline."""
        def outline(self, spec: Facade.DeckOutlineRefRequest) -> Facade.DeckOutlineView:
            """Reads a typed deck outline, its current NOTE frontier, its keep and its freshness."""
        def keep_outline(self, spec: Facade.DeckOutlineSettleRequest) -> Facade.KeptOutline:
            """The owner keeps the exact outline frontier, freezing its version and content hash."""
        def decline_outline(self, spec: Facade.DeckOutlineSettleRequest) -> Facade.DeckOutlineDeclined:
            """The owner declines the exact outline frontier, clearing its keep and design directions."""
        def design_deck(self, spec: Facade.DeckDesignRequest) -> Facade.DeckDesignView:
            """Compiles one to three template directions from the exact fresh keep into validated plans or typed design decisions."""
        def create_deck(self, spec: Facade.DeckEmissionRequest) -> Facade.DeckEmissionOutcome:
            """Emits one checked deck from a fresh kept outline and a planned template, retaining born-from and unverified fit."""
        def inspect_deck(self, spec: Facade.DeckInspectRequest) -> Facade.DeckInspectionView:
            """Inspects one PPTX version for native edit targets and comment identities without minting ids."""
        def propose_deck(self, request: Facade.DeckProposeRequest) -> Facade.DeckProposeOutcome: ...
        def propose_output(self, request: Facade.NativeOutputRequest) -> Facade.PendingProposalView: ...
        def keep(self, request: Facade.ProposalSettleRequest) -> Facade.KeptProposal: ...
        def discard(self, request: Facade.ProposalSettleRequest) -> Facade.DiscardedProposal: ...
        def undo(self, request: Facade.ProposalSettleRequest) -> Facade.UndoneKeep: ...
        def create(self, spec: Facade.ArtifactCreateRequest) -> Facade.ArtifactView | None:
            """Creates an artifact with its first version, as the caller: a person's upload, or an agent's version naming its run."""
        def put(self, input: Facade.BlobArtifactInput) -> Facade.EntityRefReceipt:
            """Registers one blob artifact; its bytes ride vault.artifacts.append."""
        @property
        def body(self) -> "Oneiron._VaultArtifactsBodyVerbs": ...
        def append(self, input: Facade.AppendBlobVersionRequest) -> Facade.BlobVersionView:
            """Appends one version of bytes to a blob artifact's append-only chain."""
        def read(self, input: Facade.ReadBlobVersionRequest) -> Facade.BlobContent | None:
            """Reads one version of a blob artifact's bytes."""
    class _VaultArtifactsLivePreviewVerbs:
        def register(self, spec: Facade.ArtifactPreviewRegisterRequest) -> Facade.ArtifactPreviewView:
            """Opens a draft-labelled, owner-private live preview only for the exact process, port and lease already declared by the trusted session runtime."""
        def read(self, spec: Facade.ArtifactPreviewRequest) -> Facade.ArtifactPreviewView | None:
            """Reads a live draft endpoint and a caller-specific preview URL as the owner or a named invitee; uninvited callers are refused."""
        def close(self, spec: Facade.ArtifactPreviewRequest) -> Facade.ArtifactPreviewClosed:
            """Closes one owner-private preview lease, invalidating its old URLs, streams and upgrades without changing any published artifact pin."""
        def invite(self, spec: Facade.ArtifactPreviewInviteRequest) -> Facade.ArtifactPreviewInvitation:
            """Invites one named principal to a private live preview under the lease owner proof; no public audience is created."""
        def revoke_invite(self, spec: Facade.ArtifactPreviewInviteRequest) -> Facade.ArtifactPreviewInvitation:
            """Revokes one private preview invitation and its personal credentials, including active streams."""
        def share(self, spec: Facade.ArtifactPreviewRequest) -> Facade.ArtifactPreviewShare:
            """Mints a revocable sharing URL for one private live preview, replacing any earlier sharing URL; no artifact is published."""
        def revoke_share(self, spec: Facade.ArtifactPreviewRequest) -> Facade.ArtifactPreviewShare:
            """Revokes the private preview sharing URL and streams that used it while preserving separate owner and invitee credentials."""
    class _VaultArtifactsAnchorsVerbs:
        def pin(self, spec: Facade.AnnotationPinRequest) -> Facade.AnnotationAnchorView:
            """Pins an exact readable locator and quote in an artifact version; opening a thread makes the pin durable."""
    class _VaultArtifactsThreadsVerbs:
        def open(self, spec: Facade.AnnotationThreadOpenRequest) -> Facade.AnnotationThreadView:
            """Opens an anchored thread with its first comment as the caller, retaining its exact version, locator and quote."""
        def comment(self, spec: Facade.AnnotationCommentRequest) -> Facade.AnnotationCommentView:
            """Appends a comment as the caller; returns its first stored part, with every part available through threads.read."""
        def read(self, spec: Facade.AnnotationThreadRequest) -> Facade.AnnotationThreadView | None:
            """Reads a thread, its opening quote, current anchor, explicit pinned, mapped or drifted disposition, comments and assignment."""
        def list(self, spec: Facade.ArtifactRefRequest) -> list[Facade.AnnotationThreadView]:
            """Lists an artifact's readable threads with their opening pins, current anchors, drift, comments and assignments."""
        def assign(self, spec: Facade.AnnotationAssignRequest) -> Facade.AnnotationBriefView:
            """Assigns an anchored thread into a durable task brief with its anchor and transcript; an agent-definition assignee dispatches through the engine."""
        def state(self, spec: Facade.AnnotationStateRequest) -> Facade.AnnotationThreadView:
            """Opens or resolves a thread through its existing claim gate, preserving its anchor, comments and drift."""
    class _VaultArtifactsBodyVerbs:
        def import_(self, request: Facade.OfficeBodyImportRequest) -> Facade.OfficeBodyHead: ...
        def head(self, request: Facade.OfficeBodyArtifactRequest) -> Facade.OfficeBodyHead | None: ...
        def read(self, request: Facade.OfficeBodyReadRequest) -> Facade.OfficeBodyView: ...
        def commits(self, request: Facade.OfficeBodyCommitsRequest) -> list[Facade.OfficeBodyCommitView]: ...
        def edit(self, request: Facade.OfficeBodyEditRequest) -> Facade.OfficeBodyEdit: ...
        @property
        def fork(self) -> "Oneiron._VaultArtifactsBodyForkVerbs": ...
        @property
        def proposal(self) -> "Oneiron._VaultArtifactsBodyProposalVerbs": ...
        def export(self, request: Facade.OfficeBodyExportVerbRequest) -> Facade.OfficeBodyExportView: ...
        def preview(self, request: Facade.OfficeBodyPreviewRequest) -> Facade.XlsxPreview: ...
        @property
        def deck(self) -> "Oneiron._VaultArtifactsBodyDeckVerbs": ...
    class _VaultArtifactsBodyForkVerbs:
        def open(self, request: Facade.OfficeBodyForkOpenRequest) -> Facade.OfficeBodyFork: ...
        def edit(self, request: Facade.OfficeBodyForkEditRequest) -> Facade.OfficeBodyEdit: ...
        def diff(self, request: Facade.OfficeBodyForkRequest) -> Facade.OfficeBodyDiff: ...
        def merge(self, request: Facade.OfficeBodyForkMergeRequest) -> Facade.OfficeBodyDiff: ...
        def discard(self, request: Facade.OfficeBodyForkRequest) -> Facade.OfficeBodyFork: ...
    class _VaultArtifactsBodyProposalVerbs:
        def read(self, request: Facade.OfficeBodyProposalRequest) -> Facade.OfficeBodyProposal: ...
        def settle(self, request: Facade.OfficeBodyProposalSettleRequest) -> Facade.OfficeBodyProposal: ...
    class _VaultArtifactsBodyDeckVerbs:
        def review(self, request: Facade.OfficeBodyForkRequest) -> Facade.DeckReviewView: ...
        def merge(self, request: Facade.DeckForkMergeRequest) -> Facade.LandingReceipt: ...
        def export(self, request: Facade.DeckExportRequest) -> Facade.DeckExportView: ...
        def gate(self, request: Facade.DeckGateRequest) -> Facade.DeckGateView: ...
        def oracle(self, request: Facade.DeckOracleRequest) -> Facade.DeckGateView: ...
        def preview(self, request: Facade.DeckPreviewRequest) -> Facade.DeckPreview: ...
    class _VaultCodeVerbs:
        def diff(self, request: Facade.CodeDiffRequest) -> Facade.CodeDiffView | None: ...
        def blame(self, request: Facade.CodeStateRequest) -> Facade.CodeBlameView | None: ...
        def proposal_view(self, request: Facade.CodeProposalViewRequest) -> Facade.CodeProposalView | None: ...
        @property
        def symbols(self) -> "Oneiron._VaultCodeSymbolsVerbs": ...
        def proposal_submit(self, spec: Facade.CodeProposalSubmitRequest) -> Facade.CodeProposalSubmitted:
            """Stage one file change of a repository as a Proposed proposal with its retained base, under the owner's lens catalog or, with none, the vault's review policy. Owner only. Nothing is approved, queued or landed."""
        def conflict_record(self, spec: Facade.CodeConflictRecordRequest) -> Facade.CodeConflictView:
            """Record a real Git overlap between two stored one-file proposals at the same retained base, with both trees, paths and a linked reconciliation task. Owner only; neither branch moves."""
        def conflict_view(self, spec: Facade.CodeConflictViewRequest) -> Facade.CodeConflictHistory:
            """Read open repository conflicts and their durable resolution claims, including each reconciliation task. Owner only."""
        def proposal_resolve(self, spec: Facade.CodeProposalResolveRequest) -> Facade.CodeProposalSubmitted:
            """Stage a one-file resolution of an active repository conflict as another Proposed proposal, preserving its original proposals and reconciliation task. Owner only; nothing lands."""
        def proposal_review(self, spec: Facade.CodeProposalReviewRequest) -> Facade.CodeProposalSettlementView:
            """Record the authenticated owner's immutable critic opinion on one proposal lens. Independent reviewers only; this is no contract-check execution receipt."""
        def proposal_settle(self, spec: Facade.CodeProposalSettleRequest) -> Facade.CodeProposalSettlementView:
            """Approve or reject one code proposal as an independent owner, keeping a receipt. Its own catalog still needs unanimous critics; Approve satisfies the vault's review policy. Only the tested merge queue lands it."""
        def proposal_settlement(self, spec: Facade.CodeProposalSettlementRequest) -> Facade.CodeProposalSettlementView:
            """Read a code proposal's review decision receipt and execution lineage, including its conflict, original proposals, reconciliation task and resolution claim. Owner only."""
        def oplog(self, spec: Facade.CodeRepoRequest) -> Facade.CodeMutationLog:
            """Read the durable mutation log of one repository in sequence order: prepared, applied and failed mutations. Owner only. It is not a proposal queue and holds no pending proposal."""
        def model_heal_count(self, spec: Facade.CodeRunModelHealCountRequest) -> Facade.CodeRunModelHealCountView:
            """Read the tally this vault keeps of its own durable executor turns one model needed wire healing for, by full provider/name@revision id, zero when absent. Owner only. A routing signal, not a run correction receipt or repair policy."""
        def type_diagnostics(self, spec: Facade.CodeRunTypeDiagnosticsRequest) -> Facade.ProgramStepFeedbackRelease | None:
            """Read the type feedback of one code-mode program step by its check_ref as the owner, released whole: its check as it stands and every diagnostic; an MCP release hold gives it withheld, with no text. Never runs a program again."""
        @property
        def waits(self) -> "Oneiron._VaultCodeWaitsVerbs": ...
        def repo_diff(self, request: Facade.CodeRepoDiffRequest) -> Facade.CodeRepoDiffView | None: ...
        @property
        def export(self) -> "Oneiron._VaultCodeExportVerbs": ...
        def import_(self, spec: Facade.CodeRepoImportRequest) -> Facade.CodeRepoImportView:
            """Finalize an already-doored chosen Git commit into a complete mode-preserving snapshot and import manifest; optionally promote its exact checked baseline under the owner's selected manifest-review catalog. Owner only."""
        @property
        def repos(self) -> "Oneiron._VaultCodeReposVerbs": ...
        @property
        def forks(self) -> "Oneiron._VaultCodeForksVerbs": ...
        @property
        def imports(self) -> "Oneiron._VaultCodeImportsVerbs": ...
        @property
        def ingress(self) -> "Oneiron._VaultCodeIngressVerbs": ...
        @property
        def origin(self) -> "Oneiron._VaultCodeOriginVerbs": ...
        @property
        def checkout(self) -> "Oneiron._VaultCodeCheckoutVerbs": ...
        @property
        def views(self) -> "Oneiron._VaultCodeViewsVerbs": ...
        @property
        def cache(self) -> "Oneiron._VaultCodeCacheVerbs": ...
        @property
        def snapshots(self) -> "Oneiron._VaultCodeSnapshotsVerbs": ...
        @property
        def merge_queue(self) -> "Oneiron._VaultCodeMergeQueueVerbs": ...
        @property
        def checks(self) -> "Oneiron._VaultCodeChecksVerbs": ...
    class _VaultCodeSymbolsVerbs:
        def declare(self, spec: Facade.CodeSymbolsDeclareRequest) -> Facade.CodeSymbolsDeclared:
            """Declare the current repository symbols a task will touch, held by the caller until host time plus ttl_seconds. Owner only. An overlap waits behind the tasks it names, never refused; it grants no write, approval or landing."""
        def renew(self, spec: Facade.CodeSymbolsTaskRequest) -> Facade.CodeSymbolLeaseView:
            """Renew the live symbol declaration the caller holds for one task by its declared lifetime. Owner only."""
        def release(self, spec: Facade.CodeSymbolsTaskRequest) -> Facade.CodeSymbolsReleased:
            """Release the symbol declaration the caller holds for one task. Owner only. Keyed by task and holder with no epoch fence; it applies, approves and schedules nothing."""
        def definitions(self, spec: Facade.CodeSnapshotDefinitionsRequest) -> Facade.CodeSnapshotDefinitionsView:
            """Find Rust symbol definitions by exact name within one pinned code snapshot. Owner only. Definitions only: no calls, imports or refs relation, and no other language."""
    class _VaultCodeWaitsVerbs:
        def resolve(self, spec: Facade.CodeWaitResolveRequest) -> Facade.CodeWaitReceiptView:
            """Answer one sealed code consent wait as the authenticated owner, on the word the owner gave on its ask. First answer wins; the held effect meets its own current gate once. No raw reply, grant or consumption is taken."""
        def receipt(self, spec: Facade.CodeWaitReceiptRequest) -> Facade.CodeWaitReceiptView | None:
            """Read one code consent wait as the authenticated owner: its held effect, answer, settlement and replay consumption receipts. Never answers, resumes or sends. Null for an unknown, unsealed or withheld wait."""
    class _VaultCodeExportVerbs:
        def __call__(self, spec: Facade.CodeExportRequest) -> Facade.CodeExportResult:
            """Export one already-finalized and reviewed document revision through the existing origin publication protocol."""
        @property
        def preview(self) -> "Oneiron._VaultCodeExportPreviewVerbs": ...
    class _VaultCodeExportPreviewVerbs:
        def __call__(self, spec: Facade.CodeExportPreviewRequest) -> Facade.CodeExportPreviewAnswer:
            """Read the complete raw-byte and Git-mode delta for one explicit sealed export revision and ref expectation. Live owner or a caller under one covering Grant. Missing, withheld or masked sources return a typed hold; no export or ref is written."""
        def read(self, spec: Facade.CodeExportFileReadRequest) -> Facade.CodeExportFileReadAnswer:
            """Read the exact bytes and mode of one changed preview side by its recomputed handle. Live owner or a caller under one covering preview Grant. Missing, withheld or masked sources return a typed hold; no caller-selected host file is read."""
    class _VaultCodeReposVerbs:
        def get(self, spec: Facade.CodeRepoGetRequest) -> Facade.CodeRepoView | None:
            """Read the selected served code repository, immutable import and workbench links. Owner only. Does not discover a global directory or mutate work."""
    class _VaultCodeForksVerbs:
        def get(self, spec: Facade.CodeForkGetRequest) -> Facade.CodeForkView | None:
            """Read one durable code revision fork and its recorded base, proposals and document states. Owner only. A transient work view is not a persisted fork."""
    class _VaultCodeImportsVerbs:
        def create(self, spec: Facade.ExternalImportRequest) -> Facade.ExternalImportReceipt:
            """Fetch one exact outside source and send it through the existing authenticated Git door; retain source and receive links without approval or enqueue."""
        def get(self, spec: Facade.ExternalImportLookup) -> Facade.ExternalImportStatus | None:
            """Read one external import and its actual receive, aggregate candidate and checker work. Local only; never fetches, pushes or runs checks."""
    class _VaultCodeIngressVerbs:
        def get(self, spec: Facade.CodePushIngressGetRequest) -> Facade.CodePushIngressView | None:
            """Read one authenticated received ref and its recorded operations and candidate progress. Owner only. Pending matching does not change push acceptance."""
    class _VaultCodeOriginVerbs:
        def register(self, spec: Facade.OriginRegisterRequest) -> Facade.OriginRegistered:
            """Register a new empty served repository for authenticated Git and vault-LFS, with an explicit default branch; existing names are refused."""
        @property
        def mirror(self) -> "Oneiron._VaultCodeOriginMirrorVerbs": ...
        @property
        def publish(self) -> "Oneiron._VaultCodeOriginPublishVerbs": ...
        @property
        def authority(self) -> "Oneiron._VaultCodeOriginAuthorityVerbs": ...
        def publications(self, spec: Facade.OriginPublicationsRequest) -> Facade.OriginPublicationsView:
            """Read durable publication records for one served repository ref and commit without synthesizing a push acknowledgement."""
    class _VaultCodeOriginMirrorVerbs:
        def get(self, spec: Facade.OriginRepoRequest) -> Facade.OriginMirrorView:
            """Read one served repository's outbound mirror setup, cadence, sync strategy, pushed refs, last run and automatic push status (newest reviewed plan, review or reconcile holds, heads pending checks) as the owner."""
        def set(self, spec: Facade.OriginMirrorSetRequest) -> Facade.OriginMirrorTarget:
            """Set one served origin's HTTPS mirror, its custody-held origin:mirror-push token, cadence and sync strategy (ask_me, schedule or full_auto; ask_me unless named, the same URL keeps its own); the token binding is checked."""
        def strategy(self, spec: Facade.OriginMirrorStrategyRequest) -> Facade.OriginMirrorTarget:
            """Set one served origin mirror's sync strategy: ask_me sends nothing until an exact request is approved, schedule pushes every published ref on its cadence, full_auto each new green head at once; unsent automatic work pauses."""
        def clear(self, spec: Facade.OriginRepoRequest) -> Facade.OriginMirrorCleared:
            """Stop outbound mirroring of one served repository; the mirror retains its existing refs and bytes."""
        def push(self, spec: Facade.OriginRepoRequest) -> Facade.OriginMirrorRun:
            """Push one origin's published refs to its schedule or full_auto mirror now as a reviewed, leased plan (full_auto: green heads only), recording the real outcome; ask_me refuses publish_request_required. Refs are not LFS readiness."""
    class _VaultCodeOriginPublishVerbs:
        def request(self, spec: Facade.OriginPublishRequestInput) -> Facade.OriginPublishRequestView:
            """Ask to publish one exact commit to one branch of a served origin's mirror, once: the request leases the push on the branch tip an authenticated read saw and records a full-ancestry review of what it would expose."""
        def review(self, spec: Facade.OriginPublishReviewRequest) -> Facade.OriginPublishReviewView:
            """Read one page of an exact publish request's full-ancestry review: each commit the push would expose, with its parents, and every path, mode and object those commits introduce."""
        def get(self, spec: Facade.OriginPublishIdRequest) -> Facade.OriginPublishRequestView:
            """Read one exact publish request: its tuple, review digest, state, acts and the typed refusal that ended it, if one did."""
        def approve(self, spec: Facade.OriginPublishApproveRequest) -> Facade.OriginPublishRequestView:
            """Approve one pending exact publish request by naming its review digest, as the owner or under one Grant covering the branch and every reviewed path; no second approval is asked."""
        def execute(self, spec: Facade.OriginPublishIdRequest) -> Facade.OriginPublishRequestView:
            """Push one approved exact publish request's commit to its branch once, leased on the recorded tip; an unproven outcome settles from the mirror and is never sent again."""
        def cancel(self, spec: Facade.OriginPublishIdRequest) -> Facade.OriginPublishRequestView:
            """Cancel one pending or approved exact publish request; a request whose push is in flight or that already settled stays as it is."""
    class _VaultCodeOriginAuthorityVerbs:
        def get(self, spec: Facade.OriginRepoRequest) -> Facade.OriginAuthorityView:
            """Read one served origin authority and this host identity under the owner credential."""
        def set(self, spec: Facade.OriginAuthoritySetRequest) -> Facade.OriginAuthorityView:
            """Cut over one existing served origin under the owner proof and expected authority epoch."""
    class _VaultCodeCheckoutVerbs:
        def bind(self, spec: Facade.CheckoutDoorBindRequest) -> Facade.CheckoutDoorBinding:
            """Materialize an existing live owner checkout with lease-bound origin remotes and no upstream credential."""
        def claim(self, spec: Facade.CheckoutClaimInput) -> Facade.CheckoutLeaseView:
            """Claim the caller's checkout on an assigned task, with a bounded TTL and declared idempotence."""
        def get(self, spec: Facade.CheckoutGetInput) -> Facade.CheckoutLeaseView:
            """Read checkout custody and vault-clock expiry as a task party, without claiming or renewing it."""
        def renew(self, spec: Facade.CheckoutRenewInput) -> Facade.CheckoutLeaseView:
            """Renew the caller's still-live checkout under its exact holder and epoch fence."""
        def reclaim(self, spec: Facade.CheckoutReclaimInput) -> Facade.CheckoutLeaseView:
            """Reclaim an expired declared-idempotent build or verify checkout as an authorized successor at the named epoch."""
        def takeover(self, spec: Facade.CheckoutTakeoverInput) -> Facade.CheckoutLeaseView:
            """Explicitly take over a checkout as its task owner, including effect work, at the named epoch."""
        def publish(self, spec: Facade.CheckoutPublishInput) -> Facade.CheckoutPublished:
            """Publish a stored candidate result for checkout settlement under the caller's live epoch; this does not export a Git head."""
        def settle(self, spec: Facade.CheckoutSettleInput) -> Facade.CheckoutSettled:
            """Consume one published checkout result at its epoch as select, apply, release or discard; an identical retry returns its receipt."""
        def teardown(self, spec: Facade.CheckoutTeardownInput) -> Facade.CheckoutTornDown:
            """Collect the caller's checkout only with a matching durable pushed-head receipt and clear custody; retain dirty or uncertain trees."""
    class _VaultCodeViewsVerbs:
        def materialize(self, spec: Facade.CodeViewMaterializeRequest) -> Facade.CodeWorkingView:
            """Materialize a private linked working view from verified tested file frontiers in the authenticated owner account."""
        def get(self, spec: Facade.CodeViewRequest) -> Facade.CodeWorkingView:
            """Read one working view and its immutable tested base under the authenticated owner account."""
        def read(self, spec: Facade.CodeViewReadRequest) -> Facade.CodeViewFileBytes:
            """Read the current bytes of one selected input in the authenticated owner working view."""
        def action(self, spec: Facade.CodeViewActionRequest) -> Facade.CodeViewAction:
            """Freeze current view input identities and return the REAPI action digest with its exact command bytes and input root digest."""
        def build(self, spec: Facade.CodeViewBuildRequest) -> Facade.CodeCacheOutcome:
            """Run a pinned native owner build or verify leg, reusing clean account-local results and retaining secret-consuming exhaust as tainted."""
    class _VaultCodeCacheVerbs:
        def get(self, spec: Facade.CodeCacheReadRequest) -> Facade.CodeCacheOutcome:
            """Read one clean immutable account-local build result by action key without executing a command."""
        def reuse(self, spec: Facade.CodeViewBuildRequest) -> Facade.CodeCacheOutcome:
            """Reuse an authorized clean action result into another matching working view without dispatching a cold build."""
    class _VaultCodeSnapshotsVerbs:
        def ingest(self, spec: Facade.CodeSnapshotIngestRequest) -> Facade.CodeSnapshotView:
            """Import one committed Git tree, by an absolute folder on the serving host and a full 40-hex commit, as a custody-filtered snapshot. Owner only. It registers no repository, whitelist, membership or receipt."""
        def get(self, spec: Facade.CodeSnapshotRequest) -> Facade.CodeSnapshotView | None:
            """Read the file manifest of one code snapshot, pinned by its imported artifact and fork hash. Owner only. Files carry blob hashes, not document versions, and the scope key is an index key, not a grant."""
        def read(self, spec: Facade.CodeSnapshotReadRequest) -> Facade.CodeSnapshotPinnedFile | None:
            """Read one UTF-8 file and its SHA-256 from the frozen blobs of a pinned code snapshot, never from the folder on disk. Owner only."""
    class _VaultCodeMergeQueueVerbs:
        def enqueue(self, spec: Facade.MergeQueueEnqueueRequest) -> Facade.MergeQueueBatchView:
            """Queue stored repository proposals as one batch on the queue green commit, one to six per call, with no batching window. Owner only. The proposals keep their own bytes and reviews; nothing is checked or landed."""
        def stage(self, spec: Facade.MergeQueueBatchRequest) -> Facade.MergeQueueBatchView:
            """Materialize every nonempty subset of one queued batch as a journaled detached speculative worktree. Owner only. Head and green do not move."""
        def observe(self, spec: Facade.MergeQueueObserveRequest) -> Facade.MergeQueueObservation:
            """Read the queue head and green Git commits, the named batches in request order and the stored contract verdicts they name. Owner only. It never recovers or settles, and a verdict is no check execution receipt."""
        def requeue_survivors(self, spec: Facade.MergeQueueBatchRequest) -> Facade.MergeQueueRequeueView:
            """Queue the proposals a diagnosed red batch did not quarantine as a new batch, keeping the red batch and its quarantine. Owner only. No durable parent or child link is written."""
        def land_reviewed(self, spec: Facade.MergeQueueBatchRequest) -> Facade.MergeQueueBatchView:
            """Advance the fast-tested head by one ready batch through reviewed-stack admission alone. Owner only. Each proposal still needs the review it is held to and exact bytes and base; the owner proof approves nothing."""
        def settle_slow(self, spec: Facade.MergeQueueRepoRequest) -> Facade.MergeQueuePointersView:
            """Settle stored slow results in landing order: green advances past passing ones, and a red one rolls the ungreen suffix back. Owner only. The caller names no commit or result."""
        def recover(self, spec: Facade.MergeQueueRepoRequest) -> Facade.MergeQueuePointersView:
            """Reconcile an interrupted landing or rollback with its persisted mutation receipts. Owner only. Unreceipted divergence refuses; nothing is approved or rebased."""
        def init(self, spec: Facade.MergeQueueInitializeRequest) -> Facade.MergeQueueCheckWorkView:
            """Request owner-approved baseline checks and checked queue initialization from the plan pinned at baseline_commit. Retains missing configuration and work; never resets an existing queue."""
        def check(self, spec: Facade.MergeQueueCheckRequest) -> Facade.MergeQueueCheckWorkView:
            """Queue one fast or slow check on exact pinned inputs. Owner only. Excess checks wait; no pass, argv or output is accepted from the caller."""
        def diagnose(self, spec: Facade.MergeQueueDiagnoseRequest) -> Facade.MergeQueueCheckWorkView:
            """Request the frozen-plan fast checks needed for existing red-batch diagnosis, retaining proposals and the existing minimal quarantine. Owner only."""
        def check_status(self, spec: Facade.MergeQueueCheckStatusRequest) -> Facade.MergeQueueCheckWorkView:
            """Read the owner-requested checker work, configuration needs and receipt references, including initialization before a queue exists. Owner only."""
        @property
        def review_policy(self) -> "Oneiron._VaultCodeMergeQueueReviewPolicyVerbs": ...
        def export_green(self, spec: Facade.MergeQueueGreenExportRequest) -> Facade.CodeExportResult:
            """Export the current queue-issued tested revision through the existing reviewed origin export path. Owner only; no caller-supplied revision or check result."""
    class _VaultCodeMergeQueueReviewPolicyVerbs:
        def get(self, spec: Facade.EmptyRequest | None = None) -> Facade.QueueReviewPolicyView:
            """Read the vault's opt-in review policy for merge queue work and the mode inherited work is in: none set lands on green through the same checks; an unreadable row holds. A live Owner, or one covering Grant."""
        def set(self, spec: Facade.QueueReviewPolicySetRequest) -> Facade.QueueReviewPolicyView:
            """Set the vault's opt-in review policy for merge queue work, a lens catalog with overridable limits, or clear it with null. While set, work naming no catalog waits for critics or Approve. Owner, or one covering Grant."""
    class _VaultCodeChecksVerbs:
        def get(self, spec: Facade.CodeCheckReceiptRequest) -> Facade.CodeCheckReceiptView | None:
            """Read retained checker receipts for one inputs reference of the named work, including their generations, results and pinned evidence. Owner only. Never runs a check or accepts a pass."""
    class _VaultResultsVerbs:
        def status(self, spec: Facade.ResultRunRequest) -> Facade.ResultRunStatus:
            """The owner inspects retained result occurrences, incomplete body descriptors and recorded producing-run effects without entering the run."""
        def recover(self, spec: Facade.ResultRunRequest) -> Facade.ResultRunStatus:
            """The owner reopens retained result status after restart; it never resumes the producer or replays an effect to regenerate output."""
        def read(self, spec: Facade.ResultOccurrenceRequest) -> Facade.ResultReadView:
            """The owner reads one exact retained result occurrence card under its current taint and source-row fence, never by content authority alone."""
        def slice(self, spec: Facade.ResultSliceRequest) -> Facade.ResultSliceView:
            """The owner reads a typed byte or line range of one exact result occurrence, with bounded continuations and current taint withholding."""
    class _VaultAgentsVerbs:
        def create(self, spec: Facade.AgentDefinitionCreateRequest) -> Facade.AgentDefinitionView:
            """The owner creates an inert custom agent composition with an optional per-domain refusal dial, caller-derived authorship and existing fork/ceiling gates; no attempt is dispatched."""
        def get(self, spec: Facade.AgentDefinitionRequest) -> Facade.AgentDefinitionView:
            """The owner reads one saved agent composition, including its declared refusal dial, version and approval state."""
        def update(self, spec: Facade.AgentDefinitionUpdateRequest) -> Facade.AgentDefinitionView:
            """The owner edits the expected definition version and optional refusal dial through the existing immutable-field and ceiling gates; refusal decisions read the live dial."""
        @property
        def dreaming(self) -> "Oneiron._VaultAgentsDreamingVerbs": ...
        @property
        def grants(self) -> "Oneiron._VaultAgentsGrantsVerbs": ...
        def base(self, spec: Facade.EmptyRequest | None = None) -> Facade.BaseAgentList:
            """The owner reads the base agents' principal ids, the Coach's and the Dreamer's, which vault.agents.grants.mint takes as its agent."""
        @property
        def spawn(self) -> "Oneiron._VaultAgentsSpawnVerbs": ...
        def export_pack(self, request: Facade.AgentPackExportRequest) -> Facade.AgentPackExport: ...
    class _VaultAgentsDreamingVerbs:
        def get(self, spec: Facade.AgentDreamingRequest) -> Facade.AgentDreamingView:
            """The owner reads one agent's dreaming choice: its stored mode, the mode in force and its own dreaming model slot."""
        def set(self, spec: Facade.AgentDreamingSetRequest) -> Facade.AgentDreamingView:
            """The owner sets one agent's dreaming choice on the revision read: its own model, the vault weaver's, or off; sharing a model never shares its diary."""
    class _VaultAgentsGrantsVerbs:
        def mint(self, spec: Facade.AgentGrantMintRequest) -> Facade.AgentGrantMinted:
            """The owner grants one named agent an explicit verb list inside his exact scope, and optional repo bounds, until he revokes it or until the expiry he sets; a second mint adds a second grant."""
        def revoke(self, spec: Facade.AgentGrantRevokeRequest) -> Facade.AgentGrantRevoked:
            """The owner revokes one agent grant by its id; the agent stops counting it at once, and a repeat changes nothing."""
    class _VaultAgentsSpawnVerbs:
        def __call__(self, spec: Facade.SpawnIntentRequest) -> Facade.SpawnIntentReply:
            """The owner launches one reserved planned agent or team under an intent key on this host's planner: the type placed, the plan frozen at the root, then queued; the same key answers what it kept."""
        def get(self, spec: Facade.PlannedSpawnRead) -> Facade.PlannedSpawnObservation:
            """The owner reads one spawned agent's stored observations by its attempt: its type stamp and frozen plan, the team actually launched, its seat route, critic artifacts and receipt-backed learning."""
    class _VaultRepoVerbs:
        @property
        def git_push(self) -> "Oneiron._VaultRepoGitPushVerbs": ...
        @property
        def anchor(self) -> "Oneiron._VaultRepoAnchorVerbs": ...
        @property
        def snapshots(self) -> "Oneiron._VaultRepoSnapshotsVerbs": ...
        @property
        def symbols(self) -> "Oneiron._VaultRepoSymbolsVerbs": ...
        @property
        def views(self) -> "Oneiron._VaultRepoViewsVerbs": ...
        @property
        def merge_queue(self) -> "Oneiron._VaultRepoMergeQueueVerbs": ...
        @property
        def work(self) -> "Oneiron._VaultRepoWorkVerbs": ...
        def proposal_submit(self, spec: Facade.LiveRunRequest[Facade.RepoProposalSubmitInput]) -> Facade.RepoProposalSubmitOutput:
            """Keeps one whole-file change against the attached run's own work as an immutable Proposed proposal under the vault's review policy and a host-witnessed provenance; without that witness it holds typed, work kept."""
        @property
        def checkout(self) -> "Oneiron._VaultRepoCheckoutVerbs": ...
        def export(self, spec: Facade.LiveRunRequest[Facade.RepoExportInput]) -> Facade.RepoExportOutput:
            """Exports one finalized, promoted revision from the attached run's own checkout when one Grant lists publish over the revision's paths; otherwise it holds with a typed code. git_push never implies an export."""
    class _VaultRepoGitPushVerbs:
        def mint(self, spec: Facade.GitPushGrantMintInput) -> Facade.GitPushGrantMintOutput:
            """The owner grants one live person or agent raw git_push on explicitly named repos, each whole, until he revokes it or until the expiry he sets; a write grant never implies it."""
        def revoke(self, spec: Facade.GitPushGrantRevokeInput) -> Facade.GitPushGrantRevokeOutput:
            """The owner revokes one git_push Grant by its id; its holder's next push is refused at once, and a repeat changes nothing."""
    class _VaultRepoAnchorVerbs:
        def bind(self, spec: Facade.RepoAnchorBindInput) -> Facade.RepoAnchorBindOutput:
            """The owner binds one served repo to its CODE anchor in a live PROJECT he names, the anchor a git_push Grant, a run's repo bounds and a publish name it by; a repeat changes nothing."""
    class _VaultRepoSnapshotsVerbs:
        def get(self, spec: Facade.LiveRunRequest[Facade.RepoSnapshotsGetInput]) -> Facade.RepoSnapshotsGetOutput:
            """Reads one snapshot's manifest of a repo the Grant of this credential's attached live run admits, at the commit its full ref names now; the run, never the request, binds the actor, TASK and lease."""
        def read(self, spec: Facade.LiveRunRequest[Facade.RepoSnapshotsReadInput]) -> Facade.RepoSnapshotsReadOutput:
            """Reads one file of such a snapshot on a path the attached run's Grant reads."""
        def ingest(self, spec: Facade.LiveRunRequest[Facade.RepoSnapshotsIngestInput]) -> Facade.RepoSnapshotsIngestOutput:
            """Imports the commit an admitted repo's full ref names now, readable paths only, for the attached run."""
    class _VaultRepoSymbolsVerbs:
        def definitions(self, spec: Facade.LiveRunRequest[Facade.RepoSymbolsDefinitionsInput]) -> Facade.RepoSymbolsDefinitionsOutput:
            """Reads a snapshot's exact-name Rust definitions on paths the attached run's Grant reads."""
        def declare(self, spec: Facade.LiveRunRequest[Facade.RepoSymbolsDeclareInput]) -> Facade.RepoSymbolsDeclareOutput:
            """Declares current symbols of the attached run's own work on paths its Grant edits, for its TASK; an overlap waits, never refused."""
        def renew(self, spec: Facade.LiveRunRequest[Facade.RepoSymbolsRenewInput]) -> Facade.RepoSymbolsRenewOutput:
            """Extends the attached run's own symbol declaration by its declared lifetime."""
        def release(self, spec: Facade.LiveRunRequest[Facade.RepoSymbolsReleaseInput]) -> Facade.RepoSymbolsReleaseOutput:
            """Removes the attached run's own symbol declaration."""
    class _VaultRepoViewsVerbs:
        def get(self, spec: Facade.LiveRunRequest[Facade.RepoViewsGetInput]) -> Facade.RepoViewsGetOutput:
            """Reads the attached run's own work, as it was opened."""
        def read(self, spec: Facade.LiveRunRequest[Facade.RepoViewsReadInput]) -> Facade.RepoViewsReadOutput:
            """Reads one file of the attached run's own work."""
    class _VaultRepoMergeQueueVerbs:
        def observe(self, spec: Facade.LiveRunRequest[Facade.RepoMergeQueueObserveInput]) -> Facade.RepoMergeQueueObserveOutput:
            """Reads the merge queue the attached run's own work is pinned under, with its own entries and what each waits behind."""
        def enqueue(self, spec: Facade.LiveRunRequest[Facade.RepoMergeQueueEnqueueInput]) -> Facade.RepoMergeQueueEnqueueOutput:
            """Queues the attached run's own stored proposals of one work as one batch, under the declaration they were made under."""
    class _VaultRepoWorkVerbs:
        def open(self, spec: Facade.LiveRunRequest[Facade.RepoWorkOpenInput]) -> Facade.RepoWorkOpenOutput:
            """Opens a fresh private working set of an admitted repo at its queue's green commit for the attached run, readable paths only."""
    class _VaultRepoCheckoutVerbs:
        def bind(self, spec: Facade.LiveRunRequest[Facade.RepoCheckoutBindInput]) -> Facade.RepoCheckoutBindOutput:
            """Materializes the attached run's own live checkout lease of an admitted served repo, for its TASK, with its lease-route remote when a door base is named; no lease is minted and no host path is shown."""
    class _VaultStandingBlocksVerbs:
        def configure(self, spec: Facade.StandingBlockConfigureRequest) -> Facade.StandingBlockView:
            """The owner configures one agent's standing block in one world with its name and token floor; reopening the same pair answers the stored handle."""
        def reconfigure(self, spec: Facade.StandingBlockConfigureRequest) -> Facade.StandingBlockView:
            """The owner gives a configured standing block a new name and token floor; an unconfigured pair is refused, never implicitly opened."""
        def get(self, spec: Facade.StandingBlockRequest) -> Facade.StandingBlockView:
            """The owner reads one agent's configured standing block in one world: its handle, name and token floor."""
        def list(self, spec: Facade.StandingBlocksRequest) -> list[Facade.StandingBlockView]:
            """The owner lists every standing block configured for one agent, one per world, in world order."""
    class _VaultWorkflowsVerbs:
        def save(self, spec: Facade.WorkflowSaveRequest) -> Facade.WorkflowView:
            """The owner saves an ordered composition of live AGENT_DEF steps at a new WORKFLOW id at revision 1; an occupied id is refused and no attempt is dispatched."""
        def get(self, spec: Facade.WorkflowRequest) -> Facade.WorkflowView:
            """The owner reads one saved workflow, its steps, revision and fork lineage."""
        def update(self, spec: Facade.WorkflowUpdateRequest) -> Facade.WorkflowView:
            """The owner edits exactly the workflow revision they read; the door assigns the next revision and keeps fork lineage, and runs already admitted keep their captured steps."""
        def dispatch(self, spec: Facade.WorkflowDispatchRequest) -> Facade.WorkflowRunView:
            """The owner starts one root run of a saved workflow under a briefing through the ordinary dispatch admission for every step; each step's definition revision, scope and ceiling are captured, and a retried intent key returns the same run."""
        def dispatch_bound(self, spec: Facade.WorkflowPersonDispatchRequest) -> Facade.WorkflowRunView:
            """A member binds one run of a saved workflow to an idle standard TASK they own, as themselves, under funding terms they accepted: its root spend scope names them as payer, and a retried intent key with the same terms returns the same run."""
        def status(self, spec: Facade.WorkflowRunRequest) -> Facade.WorkflowRunView:
            """The owner reads one workflow run by its root attempt: the captured step definitions, the active step attempt and each settled step's attempt and result."""
    class _VaultTaskTypesVerbs:
        def pin(self, spec: Facade.TaskTypeTreePin) -> Facade.TaskTypeTreePinReceipt:
            """The owner stores an authored task-type tree on an open team-shape fork, as a candidate; the receipt says whether it is in force."""
        def get(self, spec: Facade.TaskTypeTreeRead) -> Facade.TaskTypeTreeReadReply:
            """The owner reads the task-type tree in force, or one kept tree version, for the vault or a project."""
    class _VaultTasksVerbs:
        @property
        def cancel(self) -> "Oneiron._VaultTasksCancelVerbs": ...
        @property
        def linear(self) -> "Oneiron._VaultTasksLinearVerbs": ...
    class _VaultTasksCancelVerbs:
        def force(self, spec: Facade.CancelForceRequest) -> Facade.CancelForceReceipt:
            """The owner force-stops every live branch of one TASK, unrefusably: each running attempt is cancelled, its live step stops, and the reply carries every branch's landing and cancellation receipts."""
    class _VaultTasksLinearVerbs:
        @property
        def mapping(self) -> "Oneiron._VaultTasksLinearMappingVerbs": ...
        def provenance(self, spec: Facade.LinearProvenanceRequest) -> Facade.LinearProvenancePage:
            """One TASK's stored Linear mirror events, newest first: webhook deliveries, sent pushes, mapping and title edits, with their external evidence and receipts."""
    class _VaultTasksLinearMappingVerbs:
        def __call__(self, spec: Facade.LinearMappingRequest) -> Facade.LinearMappingView:
            """One TASK's Linear issue mapping: its link, watermarks, unresolved conflicts, opt-out, mapping and dirty revisions, and its newest mirror events."""
        def edit(self, spec: Facade.LinearMappingEdit) -> Facade.LinearMappingEditReceipt:
            """Links, unlinks or mirrors again one TASK's Linear issue, by the TASK's owner at the mapping revision the caller read, under an intent key."""
    class _VaultRunsVerbs:
        @property
        def branches(self) -> "Oneiron._VaultRunsBranchesVerbs": ...
        def pause(self, spec: Facade.RunControlRequest) -> Facade.RunControlReceipt:
            """Pauses one queued or scheduled branch of a run by its attempt id: the vault owner pauses any branch, any other caller only a branch of a TASK it owns. A repeat answers already_paused; a running branch is not paused."""
        def resume(self, spec: Facade.RunControlRequest) -> Facade.RunControlReceipt:
            """Resumes one paused branch of a run by its attempt id: the vault owner resumes any branch, any other caller only a branch of a TASK it owns. A repeat answers already_resumed."""
        def step(self, spec: Facade.SettledStepRequest) -> Facade.SettledStepView | None:
            """Reads one committed model step of a Dreamer attempt by its job reference and step hash: the completion claim, the run identity it recorded and the stored response, without calling a model, spending a lease or admitting work."""
        def checkpoint(self, spec: Facade.CheckpointReadRequest) -> Facade.CheckpointView | None:
            """Reads one page of a code run's committed step checkpoints and the stored replies its parked calls resumed with, without attaching, resuming or dispatching the run."""
        def program(self, spec: Facade.ProgramRunRequest) -> Facade.ProgramRunView | None:
            """Reads where one of the caller's turn programs stands, or any program when the owner asks: its admission, queue tries, held park, code-run lifecycle and one page of its steps, without running, resuming or leasing it."""
        def program_step(self, spec: Facade.SettledProgramStepRequest) -> Facade.SettledProgramStepView | None:
            """Reads one settled step of a turn program's run and its exact result as far as the caller's credential reads it: a model step's terminal claim and stored response, a write's receipt, or a send's kept body."""
        def program_checkpoint(self, spec: Facade.ProgramCheckpointRequest) -> Facade.ProgramCheckpointView | None:
            """Reads the resume checkpoint of one of the caller's turn programs, or any when the owner asks: its head, frontier, a page of the settled calls its restarter answers and the wait it parked on, without running or resuming it."""
        @property
        def program_hold(self) -> "Oneiron._VaultRunsProgramHoldVerbs": ...
        def review(self, spec: Facade.RunReviewRequest) -> Facade.RunReview:
            """The owner reviews an explicit cross-kind set of existing changes, including child-job changes, with a content-bound review id and a derived explainer."""
        def settle(self, spec: Facade.RunSettleRequest) -> Facade.RunSettlement:
            """The owner approves or rejects the exact reviewed set through each kind's existing gate and keeps its ProposalOutcome and run revert handle."""
        def settlement(self, spec: Facade.RunSettlementRequest) -> Facade.RunSettlement:
            """The owner reads the durable cross-kind ProposalOutcome of one reviewed job and its revert handle."""
    class _VaultRunsBranchesVerbs:
        def get(self, spec: Facade.RunBranchesRequest) -> Facade.RunBranchesView:
            """The owner reads every branch of one TASK: its lifecycle state, run status, result, typed asks and signals, and its landing, saved partial-result (resume point) and cancellation receipts."""
    class _VaultRunsProgramHoldVerbs:
        def release(self, spec: Facade.ReleaseTurnProgramHoldRequest) -> Facade.ProgramHoldReleaseView:
            """The owner releases one held turn program's try against the exact hold he read: stop ends it and clears the hold, its run kept; resume queues the same try once its checkpoint, authority, pin and effects check out."""
    class _VaultConsultsVerbs:
        def get(self, spec: Facade.ConsultReadRequest) -> Facade.ConsultInspection:
            """The owner reads one consult TASK: its deadline and terminal register (how it ended, its result, the evidence or abstention reason, the ladder outcome and any counter TASK), as refs, never bodies."""
    class _VaultWorkspaceVerbs:
        def establish(self, spec: Facade.WorkspacePresetRequest) -> Facade.WorkspacePresetReceipt:
            """The caller establishes a workspace preset and companion policy through its existing owner or workspace-settings power; no member or companion is minted."""
        @property
        def members(self) -> "Oneiron._VaultWorkspaceMembersVerbs": ...
        def roster(self, spec: Facade.WorkspaceRosterRequest) -> list[Facade.WorkspaceRosterEntry]:
            """The owner reads the workspace house and companion roster with their actor, subject and facet refs."""
        @property
        def work_companion(self) -> "Oneiron._VaultWorkspaceWorkCompanionVerbs": ...
    class _VaultWorkspaceMembersVerbs:
        def onboard(self, spec: Facade.WorkspaceMemberOnboardRequest) -> Facade.MemberOnboardingOutcome:
            """A holder of the workspace AddMember power runs resumable member and companion onboarding. Bringing an existing companion requires the member's own caller proof; mailbox enrollment is separate."""
    class _VaultWorkspaceWorkCompanionVerbs:
        def get(self, spec: Facade.WorkspaceRefRequest) -> Facade.WorkCompanionPolicy:
            """A workspace's work_companion policy, readable by every member it governs."""
        def set(self, spec: Facade.WorkCompanionSetRequest) -> Facade.WorkCompanionPolicy:
            """The owner, or an Admin holding the workspace-settings power, sets a workspace's work_companion policy in person."""
    class _VaultCriticVerbs:
        def review(self, spec: Facade.CriticReviewSubmit) -> Facade.CriticReviewOutcome:
            """Reviews one document, design or proposed claim through the host's decision ladder, one lens at a time, and writes the verdict as the caller; nothing is applied to the target."""
    class _VaultRoomsVerbs:
        def list(self) -> list[Facade.RoomEntry]:
            """The caller's rooms its own grants admit; inside a room turn, only that room."""
        def messages(self, room_ref: str, after: str | None = None, limit: int | None = None, thread_ref: str | None = None) -> Facade.RoomPage:
            """One page of the turns in a room this reader may read; with thread_ref, of that one thread alone."""
        def participants(self, spec: Facade.ParticipantsRequest) -> Facade.ParticipantsPage:
            """One page of who took part in a room or one of its threads, each with its causes and whether it may take part now."""
        def render(self, room_ref: str) -> list[str]:
            """The standalone rendered view of a room's threads."""
        def find(self, room_ref: str, after: str | None = None, limit: int | None = None) -> Facade.RoomThreadPage:
            """One page of a room's threads."""
        def get(self, room_ref: str, turn_ref: str) -> Facade.RoomThread | None:
            """One thread of a room by its turn, even when every list omits it."""
        def trunk(self, room_ref: str, turn_ref: str) -> Facade.RoomTrunk:
            """One trunk turn of a room, with the completed TASK result headers that hang under it."""
        def reply_strips(self, spec: Facade.ReplyStripsRequest) -> Facade.ReplyStripsPage:
            """One page of a thread's quote replies, grouped by the message they quote, in reply order."""
        def claim(self, room_ref: str, turn_ref: str) -> Facade.RoomClaimOutcome:
            """Claims one turn addressed to the caller for it to answer: claimed, held by another, or not addressed."""
        def speak(self, spec: Facade.WitnessTurn) -> Facade.WitnessReceipt:
            """Speaks through the witness gate; on a new thread root, thread_audience explicitly limits readers to named room members, an audience later edited through vault.rooms.thread_audience.add and vault.rooms.thread_audience.remove."""
        @property
        def thread_audience(self) -> "Oneiron._VaultRoomsThreadAudienceVerbs": ...
        def private_threads(self, spec: Facade.RoomPrivateThreadsRequest) -> list[Facade.PrivateThreadMetadata]:
            """That a room's private threads exist: id, creator, created and last-active times, member count; never a name, members or words. The vault's Owner or an Admin, seated or not, or the companion agent of either may call it."""
        def thread_delete(self, spec: Facade.PrivateThreadDeleteRequest) -> Facade.PrivateThreadDeleteReceipt:
            """Deletes a private thread's root and its own messages on the room's delete rail; legal holds keep what they name. The vault's Owner, or an Admin while rooms.private_threads.admin_delete is on, may call it, seated or not."""
        @property
        def thread_join(self) -> "Oneiron._VaultRoomsThreadJoinVerbs": ...
        def join(self, spec: Facade.JoinRequest) -> Facade.JoinOutcome:
            """Files and decides a request to take part in a room or one of its threads."""
        def invite(self, spec: Facade.JoinRequest) -> Facade.JoinOutcome:
            """The vault's owner invites a person into an ordinary room: files her join with the owner's admission yes, which holds until she answers yes through vault.rooms.consent."""
        def consent(self, spec: Facade.ConsentAnswer) -> Facade.JoinOutcome:
            """One party's answer to a join that waits on it, after which the join is decided again."""
        @property
        def offer(self) -> "Oneiron._VaultRoomsOfferVerbs": ...
        def offers(self, spec: Facade.OffersRequest) -> Facade.OffersPage:
            """One page of the current offer cards in a room or one of its threads."""
        @property
        def host(self) -> "Oneiron._VaultRoomsHostVerbs": ...
        @property
        def upkeep(self) -> "Oneiron._VaultRoomsUpkeepVerbs": ...
        def sharing(self, spec: Facade.RoomRefRequest) -> Facade.RoomSharingView:
            """A room's effective sharing scope and why it is clamped, for a member of the room."""
    class _VaultRoomsThreadAudienceVerbs:
        def add(self, spec: Facade.ThreadAudienceAddRequest) -> Facade.ThreadAudienceReceipt:
            """Adds a room member to a private thread's audience, full or from_now. An Owner or Admin adding themselves, or an Admin adding from outside, adds from now; the Owner's full outside add opens full history, members told. Kept in base off record."""
        def open_full_history(self, spec: Facade.ThreadAudienceOpenFullHistoryRequest) -> Facade.ThreadAudienceReceipt:
            """Opens a private thread's whole history, turns before the caller's add included, to the vault's Owner inside its audience: a logged audience edit, every member told. The Owner alone may call it."""
        def remove(self, spec: Facade.ThreadAudienceRemoveRequest) -> Facade.ThreadAudienceReceipt:
            """Removes a person from a private thread's audience, ending every read of theirs there, its earlier turns too; its audience, the vault's Owner or an Admin may call it. An audience edit is structure: it persists in base even off record."""
    class _VaultRoomsThreadJoinVerbs:
        def request(self, spec: Facade.ThreadJoinRequest) -> Facade.ThreadJoinRequestView:
            """Asks to join a private thread by its exact root, for the caller itself; every member is asked, and a pending request is answered again. The vault's Owner or an Admin, as a person, or an agent may call it."""
        def requests(self, spec: Facade.ThreadJoinRequestsRequest) -> list[Facade.ThreadJoinRequestView]:
            """The requests to join a private thread pending now: each request, who asked and when; a member in its audience now may call it."""
        def approve(self, spec: Facade.ThreadJoinDecisionRequest) -> Facade.ThreadJoinRequestView:
            """Approves a pending request to join a private thread: the one who asked is added from now on, citing the request, and told; the first answer settles it and a later one answers how it settled. Any one member in its audience now may call it."""
        def deny(self, spec: Facade.ThreadJoinDecisionRequest) -> Facade.ThreadJoinRequestView:
            """Denies a pending request to join a private thread, and the one who asked is told; the first answer settles it and a later one answers how it settled. Any one member in its audience now may call it."""
    class _VaultRoomsOfferVerbs:
        def __call__(self, spec: Facade.OfferDraft) -> Facade.OfferCard:
            """Publishes an agent's offer card to join a room or one of its threads, with an optional fixed deadline for a room-wide card."""
        def answer(self, spec: Facade.OfferSettleOfferAnswerRequest) -> Facade.OfferSettlement:
            """The room's host answers an offer card: join, or not now."""
        def vote(self, spec: Facade.OfferVoteRequest) -> Facade.OfferCard:
            """Someone in the room casts an advisory join or not-now vote on an open room-wide offer card, which keeps it open; only the host's answer admits."""
        def reopen(self, spec: Facade.OfferReopenRequest) -> Facade.OfferCard:
            """The room's owner or delegated host reopens its aged-out room-wide offer card."""
    class _VaultRoomsHostVerbs:
        def __call__(self, spec: Facade.RoomHostRequest) -> Facade.RoomStanding:
            """Who hosts a room now, and the caller's own speaking role there."""
        def pin(self, spec: Facade.RoomHostPin) -> Facade.RoomStanding:
            """Pins an agent as a room's host, or clears the stored host, pin or handoff."""
        def hand(self, spec: Facade.RoomHostHand) -> Facade.RoomStanding:
            """The room's current host hands the hosting duty to another agent that may host."""
    class _VaultRoomsUpkeepVerbs:
        def pending(self, spec: Facade.RoomUpkeepPendingRequest) -> list[Facade.RoomUpkeepNudge]:
            """The room upkeep nudges addressed to the caller for rooms it hosts now, that its lane reads and no voice has used yet."""
        def voice(self, spec: Facade.RoomUpkeepVoiceRequest) -> Facade.RoomUpkeepVoiceReceipt:
            """The room's current host voices one upkeep nudge addressed to it as its own reply to the newest turn of the nudge's thread."""
    class _VaultConversationsVerbs:
        @property
        def turn(self) -> "Oneiron._VaultConversationsTurnVerbs": ...
        def create(self, spec: Facade.ConversationCreateInput) -> Facade.CoreEntityWriteReceipt:
            """Creates a conversation; a body naming members also authors its membership ledger, creator and role grants as the caller."""
        @property
        def turns(self) -> "Oneiron._VaultConversationsTurnsVerbs": ...
        @property
        def records(self) -> "Oneiron._VaultConversationsRecordsVerbs": ...
    class _VaultConversationsTurnVerbs:
        def continue_(self, spec: Facade.TurnActionRequest) -> Facade.TurnActionReceipt:
            """Queues generation that resumes an incomplete assistant reply from exactly its saved text."""
        def retry(self, spec: Facade.TurnActionRequest) -> Facade.TurnActionReceipt:
            """Queues a new answer to the user turn an assistant turn answered; the old reply stays."""
    class _VaultConversationsTurnsVerbs:
        def create(self, spec: Facade.ConversationTurnCreateInput) -> Facade.CoreEntityWriteReceipt:
            """Puts one TURN under a conversation, with its text index and checked ChildOf edge, in one batch; the host lands the turn once."""
    class _VaultConversationsRecordsVerbs:
        def append(self, spec: Facade.DagRecordAppendInput) -> Facade.DagRecordAppendReceipt:
            """Appends one TURN to a conversation's DAG, bylined the caller, with its topology in one transaction; the host lands the turn once."""
    class _VaultModelsVerbs:
        @property
        def manifest(self) -> "Oneiron._VaultModelsManifestVerbs": ...
        @property
        def oneironer(self) -> "Oneiron._VaultModelsOneironerVerbs": ...
        @property
        def routes(self) -> "Oneiron._VaultModelsRoutesVerbs": ...
        @property
        def roles(self) -> "Oneiron._VaultModelsRolesVerbs": ...
        @property
        def catalog(self) -> "Oneiron._VaultModelsCatalogVerbs": ...
        @property
        def trials(self) -> "Oneiron._VaultModelsTrialsVerbs": ...
        @property
        def bindings(self) -> "Oneiron._VaultModelsBindingsVerbs": ...
    class _VaultModelsManifestVerbs:
        def read(self, spec: Facade.EmptyRequest) -> Facade.ModelManifest | None:
            """Reads the owner-pinned v2 model manifest, or none when no manifest is configured."""
        def replace(self, spec: Facade.ModelManifestReplace) -> Facade.ModelManifest:
            """Replaces the v2 model manifest under the owner proof, preserving the teacher-probe guard and atomically clearing resident route overrides."""
    class _VaultModelsOneironerVerbs:
        def bind(self, spec: Facade.OneironerBind) -> Facade.ModelManifest:
            """Binds the Oneironer this server has loaded as the on-device extraction_encoder in the current v2 model manifest under the owner proof, keeping every other binding and clearing resident route overrides."""
    class _VaultModelsRoutesVerbs:
        def read(self, spec: Facade.ModelRouteRead) -> Facade.ModelRouteView:
            """Reads one independent model slot route with its manifest pin and effective resident narrowing."""
        def replace(self, spec: Facade.ModelRouteReplace) -> Facade.ModelRouteView:
            """Replaces one model slot route within its manifest pin without changing any other slot or role binding."""
    class _VaultModelsRolesVerbs:
        def read(self, spec: Facade.ModelRoleRead) -> Facade.ModelRoleReceipt:
            """Reads one resolved role binding with its revision-pinned model, slot, route, provider and registered catalog fingerprint; grants no execution authority."""
        def invoke(self, spec: Facade.ModelRoleInvoke) -> Facade.ModelRoleInvocation:
            """Invokes a pinned model role through the configured generative, retrieval-embedder or extraction-encoder door and returns its typed output and resolved-model receipt."""
    class _VaultModelsCatalogVerbs:
        def refresh(self, spec: Facade.ModelCatalogRefresh) -> Facade.ModelCatalogRevision:
            """Refreshes priced model catalog rows and external-score diffs under an immutable revision; changes no role binding."""
        def get(self, spec: Facade.ModelCatalogGet) -> Facade.ModelCatalogRevision:
            """Reads a pinned model catalog revision with its prices, backend offers and score evidence."""
        def diff(self, spec: Facade.ModelCatalogDiffRequest) -> Facade.ModelCatalogDiff:
            """Diffs two immutable model catalog revisions, including prices, scores and retired offers."""
    class _VaultModelsTrialsVerbs:
        def nominate(self, spec: Facade.ModelTrialNominate) -> Facade.ModelTrialView:
            """Nominates a question-specific held-out trial at a catalog revision using the caller own labels; external scores grant no authority."""
        def get(self, spec: Facade.ModelTrialRef) -> Facade.ModelTrialView:
            """Reads a retained held-out trial, its catalog revision, independent labels, measured cost and how many of its paid arms are read or unknown."""
        def approve(self, spec: Facade.ModelTrialRef) -> Facade.ModelTrialView:
            """Approves exploration for a held-out model trial only; leaves its role binding unchanged."""
        def run(self, spec: Facade.ModelTrialRef) -> Facade.ModelTrialView:
            """Runs the pinned arms not yet sent through decide and normal leases on the original held-out frontier, keeping each billed read before the next send; a rerun resumes unsent arms, never an arm of unknown outcome."""
        def complete(self, spec: Facade.ModelTrialComplete) -> Facade.ModelTrialView:
            """Completes a measured model trial with a sufficiency card bound to its exact set and measurements; only produces an offer."""
    class _VaultModelsBindingsVerbs:
        def propose(self, spec: Facade.ModelBindingPropose) -> Facade.ModelBindingProposal:
            """Proposes a role model change from a completed held-out trial offer, an explicitly unknown one included for the owner to review, retaining catalog revision and real trial cost without activating it."""
        def get(self, spec: Facade.ModelBindingProposalRef) -> Facade.ModelBindingProposal:
            """Reads an owner-reviewed model role-binding proposal and its pinned trial evidence."""
        def read(self, spec: Facade.ModelBindingRead) -> Facade.ModelBinding:
            """Reads the currently active manifest binding for a model role."""
        def accept(self, spec: Facade.ModelBindingAccept) -> Facade.ModelBindingProposal:
            """Accepts a pending model role-binding proposal as the owner after transaction-local incumbent, catalog and trial checks."""
        def deny(self, spec: Facade.ModelBindingProposalRef) -> Facade.ModelBindingProposal:
            """Denies a pending model role-binding proposal as the owner without changing the incumbent manifest binding."""
    class _VaultVoicesVerbs:
        @property
        def packs(self) -> "Oneiron._VaultVoicesPacksVerbs": ...
        def render_consent(self, spec: Facade.VoiceRenderConsentRequest) -> Facade.VoiceRenderConsentReceipt:
            """A person records the render decision on their own voice, or a designed voice's creator on that voice with no basis: a grant names the farthest locality its refs reach; a withdrawal drops each target clone. It joins the render history."""
        @property
        def targets(self) -> "Oneiron._VaultVoicesTargetsVerbs": ...
        def inspect(self, spec: Facade.VoiceBankInspectRequest) -> Facade.VoiceBankInspection:
            """A voice's subject, or a designed voice's creator, inspects that voice as the bank holds it for one configured hosted target: identity, pack metadata without audio, the current render decision and the target's current clone."""
        def lineage(self, spec: Facade.VoiceRenderLineageRequest) -> list[Facade.VoiceRenderEventView]:
            """A voice's subject, or a designed voice's creator, reads that voice's render history: every render decision recorded for it, in order, with the target clones each dropped. Metadata only, with no provider call."""
    class _VaultVoicesPacksVerbs:
        def put(self, spec: Facade.VoiceBankPackPutRequest) -> Facade.VoiceBankPackReceipt:
            """A person banks one immutable reference pack of their own voice, or a designed voice's creator of that voice: the first source pack makes its identity, a captured pack cites the subject's current render grant, and a retry is a no-op."""
    class _VaultVoicesTargetsVerbs:
        def provision(self, spec: Facade.VoiceTargetProvisionRequest) -> Facade.VoiceTargetReceipt:
            """The caller's own voice, a person's or a designed voice its creator made, cloned at a configured hosted target from its banked refs, or that target's current clone. The render consent must reach the target's locality first."""
        def evict(self, spec: Facade.VoiceTargetEvictRequest) -> Facade.VoiceTargetEvictReceipt:
            """A voice's subject, or a designed voice's creator, drops a target's clone of that voice, deleted at its vendor best effort. The identity and its packs stay."""
    class _VaultGraphVerbs:
        def ask(self, spec: Facade.GraphAskRequest) -> Facade.GraphAskOutcome: ...
        def admit(self, spec: Facade.GraphAdmitRequest) -> Facade.GraphAskOutcome:
            """Admits the caller's own provider measurement for one graph unit in place of the host ladder's, validating the whole decision and its provider-bound paired readings before landing it as a proposed claim private to the caller."""
    class _VaultQuestionsVerbs:
        def create(self, spec: Facade.QuestionCreateRequest) -> Facade.QuestionRecord: ...
        def edit(self, spec: Facade.QuestionEditRequest) -> Facade.QuestionRecord: ...
        def pause(self, spec: Facade.QuestionPauseRequest) -> Facade.QuestionPaused: ...
        def backfill(self, spec: Facade.QuestionBackfillRequest) -> Facade.ScheduledBackfill: ...
        def read(self, spec: Facade.QuestionReadRequest) -> Facade.QuestionRecord | None: ...
        def answers(self, spec: Facade.QuestionAnswersRequest) -> Facade.QuestionAnswersReply:
            """Reads every graph answer and artifact ask of the caller's standing question, across its versions, as one bare list; a cursor opts into pages, an empty one reading the first and each next_cursor the next, page_size bounding each."""
        def refresh(self, spec: Facade.QuestionRefreshRequest) -> list[Facade.QuestionAnswer]:
            """Refreshes the caller's standing question by hand, now, over every unit or artifact its current version covers, on the host's ladder as the standing pump answers it."""
        @property
        def outcomes(self) -> "Oneiron._VaultQuestionsOutcomesVerbs": ...
        def schedule(self, spec: Facade.QuestionScheduleRequest) -> Facade.QuestionScheduleHead | None:
            """Reads the caller's standing question scheduling head: its current version, paused state, last refresh and any failed-refresh hold."""
    class _VaultQuestionsOutcomesVerbs:
        def __call__(self, spec: Facade.QuestionOutcomesRequest) -> Facade.QuestionOutcomes:
            """Reads the caller's standing question outcome labels and calibration pairs, each pairing an answer prediction and probability with its mapped label."""
        def project(self, spec: Facade.QuestionOutcomesProjectRequest) -> Facade.QuestionOutcomesProjected:
            """Projects the caller's standing question bound outcomes over current facts, idempotently binding each admissible fact in an answer horizon as its label."""
    class _VaultDecisionsVerbs:
        @property
        def bands(self) -> "Oneiron._VaultDecisionsBandsVerbs": ...
        @property
        def asks(self) -> "Oneiron._VaultDecisionsAsksVerbs": ...
    class _VaultDecisionsBandsVerbs:
        def read(self, spec: Facade.DecisionBandReadRequest) -> Facade.LearnedBand:
            """The owner reads a question version's effective band on the running host; an unlearned row stays shadow at the supplied seed and version zero."""
        def learn(self, spec: Facade.DecisionBandLearnRequest) -> Facade.LearnedBand:
            """The owner declares a question version's learned band in shadow mode on the running host, advancing its band version for that reversibility."""
        def enforce(self, spec: Facade.DecisionBandEnforceRequest) -> Facade.LearnedBand:
            """The owner enforces an already learned question-version and reversibility band on the running host without widening any decision dial or authority."""
    class _VaultDecisionsAsksVerbs:
        def answer(self, spec: Facade.DecisionAskAnswerRequest) -> Facade.DecisionAsk: ...
        def climb(self, spec: Facade.DecisionAskClimbRequest) -> Facade.ResolvedRole | None: ...
    class _VaultBookingVerbs:
        def availability(self, spec: Facade.BookingAvailabilityRequest) -> Facade.BookingOperationResponse:
            """Lists ranked public slots on a live published booking page as the caller, through the shared booking admission and solver without exposing busy sources."""
        def book(self, spec: Facade.BookingBookRequest) -> Facade.BookingOperationResponse:
            """Holds or confirms a real slot on a live published booking page as the caller, through the shared admission and home-node lifecycle with opaque session-bound tokens."""
        def reschedule(self, spec: Facade.BookingRescheduleRequest) -> Facade.BookingOperationResponse:
            """Moves a booking on a live published page using its reschedule token, preserving EVENT and UID and replaying without another passport revision."""
        def cancel(self, spec: Facade.BookingCancelRequest) -> Facade.BookingOperationResponse:
            """Cancels a booking on a live published page using its cancel token, preserving EVENT and UID and replaying without another passport revision."""
        def constraint_turn(self, spec: Facade.BookingConstraintTurnRequest) -> Facade.BookingConstraintTurnResponse:
            """Parses one scheduling constraint on a live published booking page as the caller, returning public slot controls, an email continuation or a deflect; this never holds or confirms a booking."""
        def page_token(self, spec: Facade.BookingPageTokenRequest) -> Facade.BookingPageTokenResponse:
            """The owner discovers the opaque token for an existing configured booking page; this does not publish the page or grant booking authority."""
    class _VaultCalendarVerbs:
        @property
        def passports(self) -> "Oneiron._VaultCalendarPassportsVerbs": ...
        def create(self, spec: Facade.CalendarEventCreateRequest) -> Facade.CalendarEventCreated:
            """Creates a native or evidence-linked dreamer EVENT as the caller, with atomic projector-recorded origin and engine-stamped recorded time."""
        @property
        def ics(self) -> "Oneiron._VaultCalendarIcsVerbs": ...
        def occurrences(self, spec: Facade.CalendarOccurrencesRequest) -> Facade.ScopedReadResult[list[Facade.CalendarOccurrenceView]]:
            """Expands an admitted stored master inside an inclusive UTC window under the caller's read scope, preserving UID and original-start identities and masking detached exceptions."""
        @property
        def instances(self) -> "Oneiron._VaultCalendarInstancesVerbs": ...
        def read(self, spec: Facade.CalendarReadRequest) -> Facade.ScopedReadResult[Facade.CalendarEventView | None]:
            """Reads one calendar EVENT under the caller's scoped read, with its mandatory narrowing receipt."""
        def search(self, spec: Facade.CalendarSearchRequest) -> Facade.ScopedReadResult[list[Facade.CalendarEventView]]:
            """Searches calendar EVENTs by calendar, inclusive UTC range and name under the caller's scoped read, with its mandatory narrowing receipt."""
        def freebusy(self, spec: Facade.CalendarFreebusyRequest) -> Facade.ScopedReadResult[Facade.CalendarFreebusyDto]:
            """Projects source-redacted busy occupancy over an inclusive UTC range under the caller's scoped read, as half-open intervals with a mandatory narrowing receipt."""
        def prep(self, spec: Facade.CalendarMeetingRequest) -> Facade.ScopedReadResult[Facade.PrepPack | None]:
            """Builds a fresh caller-scoped meeting PrepPack with commitments first and a 250-word ceiling, or deliberately returns no pack."""
        def event_outcome(self, spec: Facade.CalendarMeetingRequest) -> Facade.ScopedReadResult[Facade.CalendarEventOutcome | None]:
            """Reads the caller-visible meeting outcome and its recorded basis; silence projects to unknown and never to held or no_show."""
        @property
        def check_in(self) -> "Oneiron._VaultCalendarCheckInVerbs": ...
        @property
        def outcome_policy(self) -> "Oneiron._VaultCalendarOutcomePolicyVerbs": ...
        @property
        def transcript(self) -> "Oneiron._VaultCalendarTranscriptVerbs": ...
    class _VaultCalendarPassportsVerbs:
        def read(self, spec: Facade.CalendarPassportReadRequest) -> Facade.ScopedReadResult[Facade.CalendarPassportRevision | None]:
            """Reads the admitted passport head for one EVENT, system and UID through the caller scoped-read gate, including sequence, semantic hash, direction and presence."""
        def history(self, spec: Facade.CalendarPassportReadRequest) -> Facade.ScopedReadResult[list[Facade.CalendarPassportRevision]]:
            """Reads recorded passport revisions oldest first for one EVENT, system and UID, retaining explicit approval and lifecycle under the caller recorded-read gate."""
    class _VaultCalendarIcsVerbs:
        def import_(self, spec: Facade.CalendarIcsImportRequest) -> Facade.CalendarIcsImportReceipt:
            """The owner imports one exact uploaded ICS version through the existing UID diff and imported-claim gate; the receipt exposes pending claim refs without granting consent."""
    class _VaultCalendarInstancesVerbs:
        def move(self, spec: Facade.CalendarInstanceMoveRequest) -> Facade.CalendarIcsImportReceipt:
            """The owner applies one uploaded detached-instance amendment matching its UID, original start and new interval, through the import gate without changing other instances."""
    class _VaultCalendarCheckInVerbs:
        def due(self, spec: Facade.CalendarMeetingRequest) -> Facade.ScopedReadResult[Facade.CalendarCheckInDue | None]:
            """Observes whether a meeting check-in is due under owner proof, live evidence and the engine clock, without advancing time or recording an outcome."""
        def answer(self, spec: Facade.CalendarCheckInRequest) -> Facade.CalendarCheckInReceipt:
            """The owner answers a due check-in as held, no_show or rescheduled; the caller cannot assert machine evidence or replace it."""
    class _VaultCalendarOutcomePolicyVerbs:
        def get(self, spec: Facade.EmptyRequest | None = None) -> Facade.CalendarOutcomePolicy:
            """Reads the owner-configured post-meeting grace policy, including the default 1800 seconds when no override exists."""
        def set(self, spec: Facade.CalendarOutcomePolicy) -> Facade.CalendarOutcomePolicy:
            """Sets the post-meeting grace in real seconds under owner proof, without changing event times or minting attendance evidence."""
    class _VaultCalendarTranscriptVerbs:
        def ingest(self, spec: Facade.TranscriptFileDropInput) -> Facade.TranscriptIngestOutcome:
            """Ingests verified uploaded UTF-8 transcript bytes as a closed SESSION with ordered TURNs; an optional meeting link earns a machine outcome through the caller gate."""
    class _VaultWritesVerbs:
        @property
        def critical_confirm(self) -> "Oneiron._VaultWritesCriticalConfirmVerbs": ...
        def pending(self, input: Facade.ReceiptsRequest) -> list[Facade.PendingWrite]:
            """Gated writes parked for consent, newest first."""
    class _VaultWritesCriticalConfirmVerbs:
        def pending(self, spec: Facade.CriticalWriteConfirmPendingRequest) -> Facade.CriticalWriteConfirmPending | None:
            """The owner reads a candidate's exact critical confirmation, with its nonce, effect digest, policy frontier and deadline."""
        def clear(self, spec: Facade.CriticalWriteConfirmRequest) -> Facade.CriticalWriteConfirmSettlement:
            """The owner clears exactly the nonce and frontier-bound critical claim confirmation and receives its fold-verified signed receipt."""
        def decline(self, spec: Facade.CriticalWriteConfirmRequest) -> Facade.CriticalWriteConfirmSettlement:
            """The owner declines exactly the nonce and frontier-bound critical claim confirmation and receives its fold-verified signed receipt."""
        def receipt(self, spec: Facade.CriticalWriteConfirmReceiptRequest) -> Facade.CriticalWriteConfirmReceipt:
            """The owner reads a critical confirmation's existing signed authority receipt without settling or rewriting the claim."""
    class _VaultRefsVerbs:
        def resolve(self, spec: Facade.ResolveRecordRefRequest) -> Facade.ScopedReadResult[Facade.RecordRefPreview]:
            """The bounded preview of one record ref, read through the caller's own scope; unreadable and missing look the same."""
        def links(self, spec: Facade.RecordLinksRequest) -> Facade.RecordLinks:
            """A text, the texts a read surface returned, or a turn's readable messages, as typed spans whose record links resolve under the caller's own read."""
    class _VaultVectorsVerbs:
        def put(self, spec: Facade.VectorPutRequest) -> Facade.VectorPutReceipt:
            """Supplies one full-width vector for a readable record as the authenticated owner; the existing write gate checks model, transform, width, revision staging and graph updates atomically."""
    class _VaultStructuralVerbs:
        def put(self, input: Facade.StructuralPutInput) -> Facade.EntityRefReceipt:
            """Puts one structural record with its text-index fields and outgoing edges, in one atomic batch; claims go through commit."""
    class _VaultHabitsVerbs:
        def checkin(self, input: Facade.HabitCheckinInput) -> Facade.EntityRefReceipt:
            """Appends one immutable check-in under a Habit TASK."""
    class _VaultProductivityVerbs:
        def create(self, spec: Facade.ProductivityCreateRequest) -> Facade.EntityRefReceipt:
            """Creates one inert Goal, Milestone or Habit TASK under an optional checked parent; an illegal nesting refuses the whole write."""
        def tree(self, spec: Facade.ProductivityTreeRequest) -> Facade.ScopedReadResult[Facade.ProductivityTree | None]:
            """The role-labelled TASK tree under one root, read through the caller's lane, with each Habit's derived streak counters."""
    class _VaultEsignVerbs:
        def create(self, spec: Facade.EsignCreateRequest) -> Facade.EsignDraftView:
            """Drafts a signing document on PDF artifacts the caller already holds, as the caller; sending it is its own gated act."""
        def get(self, spec: Facade.EsignGetRequest) -> Facade.EsignDocumentView:
            """Reads one signing document as its trail folds: its status, recipients, filled fields and its hash-chained audit trail, with its delivery receipts. A trail that does not read answers trail unreadable with its error, its receipts still listed."""
        @property
        def links(self) -> "Oneiron._VaultEsignLinksVerbs": ...
        def send_for_signature(self, spec: Facade.EsignDispatchRequest) -> Facade.EsignDispatchView:
            """Sends a drafted signing document to its recipients through the outbound gate, as the caller; an agent sends only within its principal envelope."""
        @property
        def notices(self) -> "Oneiron._VaultEsignNoticesVerbs": ...
        def remind(self, spec: Facade.EsignDispatchRequest) -> Facade.EsignDispatchView:
            """Reminds the recipients whose turn it is to sign a pending document, through the outbound gate, as the caller."""
        def void(self, spec: Facade.EsignVoidRequest) -> Facade.EsignDispatchView:
            """Withdraws a drafted or pending signing document unsealed and tells its recipients why, through the outbound gate, as the caller."""
        @property
        def signing(self) -> "Oneiron._VaultEsignSigningVerbs": ...
        @property
        def seal(self) -> "Oneiron._VaultEsignSealVerbs": ...
    class _VaultEsignLinksVerbs:
        def issue(self, spec: Facade.EsignLinksIssueRequest) -> Facade.EsignLinksView:
            """The vault owner mints the signing links of a drafted document and receives each new one once, to deliver to its recipient."""
    class _VaultEsignNoticesVerbs:
        def dispatch(self, spec: Facade.EsignNoticesDispatchRequest) -> Facade.EsignNoticesDispatchView:
            """Dispatches the due transition notices of one signing document recorded for the caller through the email send gate, as the caller."""
    class _VaultEsignSigningVerbs:
        def act(self, spec: Facade.EsignSigningRequest) -> Facade.SigningOutcome:
            """One recipient ceremony act under the signing capability in the body: load the page, save a field, complete with consent, or reject; an agent caller makes Complete an automated sign act."""
        def pdf(self, spec: Facade.EsignSigningPdfRequest) -> Facade.EsignSigningPdfView:
            """One ceremony item under its signing capability, as base64 PDF bytes: the pinned original while signing, the hash-checked sealed output after sealing."""
        def image(self, spec: Facade.EsignSigningImageRequest) -> Facade.EsignSigningImageView:
            """Stores one signature image bound to the signing capability recipient and answers the ref a signature field value names."""
        def signature(self, spec: Facade.EsignSigningSignatureRequest) -> Facade.EsignSigningSignatureView:
            """Reads back one stored signature image under the signing capability that uploaded it, as base64 bytes."""
    class _VaultEsignSealVerbs:
        def get(self, spec: Facade.EsignSealGetRequest) -> Facade.EsignSealView:
            """Where one signing document seal task stands: its folded status, every seal attempt receipt, its sealed manifest once sealed, and its delivery receipts. A trail that does not read answers trail unreadable with its error."""
    class _VaultConsolidationVerbs:
        def enqueue(self, spec: Facade.ConsolidationEnqueueRequest) -> Facade.DreamerAttemptRef:
            """Enqueues one consolidation attempt and returns its durable job reference."""
        def status(self, spec: Facade.ConsolidationStatusRequest) -> Facade.DreamerAttemptView | None:
            """Reads the status of one consolidation attempt by its durable job reference."""
        @property
        def wake(self) -> "Oneiron._VaultConsolidationWakeVerbs": ...
        @property
        def home(self) -> "Oneiron._VaultConsolidationHomeVerbs": ...
        def lineage(self, spec: Facade.ConsolidationLineageRequest) -> Facade.ConsolidationLineageView | None:
            """The owner reads one consolidation job's retry chain back to its root and a page of its committed step refs, without resuming, leasing or calling a model."""
        def promote(self, spec: Facade.ConsolidationPromoteRequest) -> Facade.ConsolidationPromotion:
            """Promotes typed generated candidates in an admitted Dreamer attempt through its host-stamped writer and checker, returning retained evidence and refusals."""
        def pin(self, spec: Facade.ConsolidationPinRequest) -> Facade.ConsolidationRootAccounting:
            """Pins reference-only evidence for six-axis consolidation buckets at one owner-scoped ledger revision. Hashes, lineage taint and source eligibility are derived by the root, never accepted from children."""
        def frontier(self, spec: Facade.ConsolidationFrontierRequest) -> Facade.ConsolidationRootAccounting:
            """Records immutable child judgements and reference sets against an existing root pin, in any completion order, and accounts source-plus-hash corroboration without merging projects. Does not settle claims."""
        def accounting(self, spec: Facade.ConsolidationAccountingRequest) -> Facade.ConsolidationRootAccounting:
            """Reads the original root revision, source hashes, ancestor and edge provenance taint, zero-signal exclusions and per-bucket corroboration accounting under current owner read authority."""
        def evidence(self, spec: Facade.ConsolidationEvidenceRequest) -> Facade.ScopedReadResult[list[Facade.ConsolidationEvidenceSource]]:
            """Reads exact generated-claim evidence, source lineage and separate consolidation, corroboration and effector-evidence eligibility as the owner."""
    class _VaultConsolidationWakeVerbs:
        def status(self, spec: Facade.ConsolidationWakeStatusRequest) -> Facade.DreamerWakeView | None:
            """Reads one page of a consolidation wake pass observation by attempt or wake reference: its clock and ceiling, admitted attempts, each model call with its lease, the Checkpoint parks it cut and the pass as it runs now."""
    class _VaultConsolidationHomeVerbs:
        def get(self, spec: Facade.EmptyRequest | None = None) -> Facade.ConsolidationHomeView:
            """The owner reads the elected MACRO home this node's runner holds, the host's last candidate set it elected over, his home pick and this install's own sync client id, without electing, minting or waking anything."""
        def pick(self, spec: Facade.ConsolidationHomePickRequest) -> Facade.ConsolidationHomePickReceipt:
            """The owner picks or clears the node that runs his vault's MACRO consolidation: a signed act every linked machine folds, recorded even for a node unknown here; a stale seen revision refuses. It re-elects this home and moves no job or lease."""
    class _VaultSieveVerbs:
        @property
        def evidence(self) -> "Oneiron._VaultSieveEvidenceVerbs": ...
        def cadence(self, spec: Facade.WakeCadenceRequest) -> Facade.WakeCadenceView:
            """Read the shared Dreamer/Coach wake policy, the production scheduler cadence receipt and pending recipe evidence ranges; do not tick, enqueue or call a model."""
        @property
        def settlements(self) -> "Oneiron._VaultSieveSettlementsVerbs": ...
        def queue(self, spec: Facade.SievePageRequest) -> Facade.SieveQueuePage:
            """The owner reads one ordered page of the sieve interest queue: span handles, source and range refs, kind, score and the rungs still owed."""
        def retained(self, spec: Facade.SievePageRequest) -> Facade.SieveRetainedPage:
            """The owner reads the sieve retained original span readings, which spending never removes, for a later weave over evidence."""
        def receipts(self, spec: Facade.SievePageRequest) -> Facade.SieveReceiptsPage:
            """The owner reads consumed-span receipts: each span nightly spending consumed once, its source ref and the attempt that spent it."""
        @property
        def policy(self) -> "Oneiron._VaultSievePolicyVerbs": ...
        @property
        def recipe_policy(self) -> "Oneiron._VaultSieveRecipePolicyVerbs": ...
        @property
        def lease(self) -> "Oneiron._VaultSieveLeaseVerbs": ...
    class _VaultSieveEvidenceVerbs:
        def __call__(self, spec: Facade.SieveEvidenceRequest) -> Facade.SieveEvidenceView:
            """Read the original TURN identity, sieve reading digest, evidence cursor and owed/continuing state as the owner."""
        def replay(self, spec: Facade.SieveEvidenceRequest) -> Facade.SieveEvidenceView:
            """Replay the same stored TURN through its owed sieve read under the owner proof; preserve every ingress identity and let the existing digest check decide whether evidence changed."""
    class _VaultSieveSettlementsVerbs:
        def __call__(self, spec: Facade.WakeSettlementsRequest) -> Facade.WakeSettlementsPage:
            """Page shared-scheduler root receipts and all Dreamer/Coach descendants, including exact conclusion identities, authority receipts, terminal states and durable parks."""
        def get(self, spec: Facade.WakeSettlementRequest) -> Facade.WakeSettlementView | None:
            """Read one shared-scheduler root and its complete descendant settlement; a completed dispatcher never implies its children completed."""
    class _VaultSievePolicyVerbs:
        def __call__(self, spec: Facade.SievePolicyRequest) -> Facade.SievePolicy:
            """The owner reads the sieve policy row: how much one pass reads, each kind interest, rule confidences and the uncertain band."""
        def set(self, spec: Facade.SievePolicySetRequest) -> Facade.SievePolicy:
            """The owner replaces the sieve policy row; the new row scores spans read after it and queued spans keep the score they were given."""
    class _VaultSieveRecipePolicyVerbs:
        def __call__(self, spec: Facade.SievePolicyRequest) -> Facade.WakeRecipePolicy:
            """The owner reads the wake recipe policy row: per-receipt span and child budgets, rung retry and the sampled audit settings."""
        def set(self, spec: Facade.SieveRecipePolicySetRequest) -> Facade.WakeRecipePolicy:
            """The owner replaces the wake recipe policy row; unspent interest stays queued and only later receipts spend under the new budgets."""
    class _VaultSieveLeaseVerbs:
        def __call__(self, spec: Facade.SieveLeaseRequest) -> Facade.SieveLeaseView:
            """The owner reads one wake-budget lease counter without creating it: total, remaining and reserved units by its budget id."""
        def refill(self, spec: Facade.SieveLeaseRefillRequest) -> Facade.SieveLeaseView:
            """The owner refills one wake-budget lease to a replacement total; spent and reserved units keep their claim and replay adds nothing twice."""
    class _VaultFreeTimeVerbs:
        @property
        def policy(self) -> "Oneiron._VaultFreeTimePolicyVerbs": ...
        def cycles(self, spec: Facade.FreeTimeCyclesRequest) -> Facade.FreeTimeCyclesPage:
            """The owner reads one agent's free-time cycles a page at a time, newest first: each cycle's state, period and floor from its item receipts, with the cursor of the next page."""
        def cycle(self, spec: Facade.FreeTimeCycleRequest) -> Facade.FreeTimeCycleView | None:
            """The owner reads one free-time cycle: its state, the floor and whether every item receipt read, the agent's short note, each item's receipt, and the spend records by label with their own completeness. Never the agent's diary."""
    class _VaultFreeTimePolicyVerbs:
        def get(self, spec: Facade.FreeTimePolicyRequest) -> Facade.FreeTimePolicyView:
            """The owner reads one agent's free-time policy with its revision: the total one cycle may spend, its daily clock in an IANA zone and any pinned split, or disabled when none is set."""
        def set(self, spec: Facade.FreeTimePolicySetRequest) -> Facade.FreeTimePolicyView:
            """The owner sets one agent's free-time policy at the revision it read, or clears it with no policy; a clear ends the open cycle and the agent goes back to its nightly dreaming."""
    class _VaultMemoryVerbs:
        @property
        def signal_extraction(self) -> "Oneiron._VaultMemorySignalExtractionVerbs": ...
    class _VaultMemorySignalExtractionVerbs:
        def __call__(self, spec: Facade.SignalExtractionRequest) -> Facade.SignalExtractionTicket:
            """Queues typed extraction of witnessed turns on the configured production Dreamer role; returns durable partition job refs, never caller-authored candidates."""
        def result(self, spec: Facade.SignalExtractionResultRequest) -> Facade.SignalExtractionResult | None:
            """Reads extraction completion, accepted claims, generated prospective queries and parent-verified source ranges and MESSAGE revisions as the owner may read them."""
    class _VaultChannelIdentitiesVerbs:
        def provision(self, spec: Facade.ChannelIdentityProvisionRequest) -> Facade.ChannelIdentityLifecycleReceipt:
            """Provision an engine-held channel address, handle or shared presence through the existing lifecycle gate."""
        def bind(self, spec: Facade.ChannelIdentityBindRequest) -> Facade.ChannelIdentityLifecycleReceipt:
            """Bind a requested identity or an existing delegated account with transaction-verified custody."""
        def fulfill(self, spec: Facade.ChannelIdentityRequest) -> Facade.ChannelIdentityLifecycleReceipt:
            """Record owner-confirmed fulfillment of a pending channel identity; delegated custody is revalidated."""
        def rotate(self, spec: Facade.ChannelIdentityRequest) -> Facade.ChannelIdentityLifecycleReceipt:
            """Rotate an engine-held channel identity through its lifecycle gate; delegated accounts cannot rotate."""
        def release(self, spec: Facade.ChannelIdentityReleaseRequest) -> Facade.ChannelIdentityLifecycleReceipt:
            """Release a channel identity through its lifecycle gate, retaining engine-held addresses under the never-recycle rule."""
        def route_inbound(self, spec: Facade.ChannelIdentityRequest) -> Facade.ChannelIdentityLifecycleReceipt:
            """Read and receipt the gated inbound routing disposition of a channel identity, including retirement holds."""
        def get(self, spec: Facade.ChannelIdentityRequest) -> Facade.ChannelIdentityView:
            """Read live channel identity facts, custody, lifecycle and outbound capability without granting permission to send."""
        @property
        def selection(self) -> "Oneiron._VaultChannelIdentitiesSelectionVerbs": ...
        def select(self, spec: Facade.ChannelSelectionRequest) -> Facade.ChannelSelectionView:
            """Select a live channel identity under relationship rules, retaining an existing thread passport mask."""
        @property
        def passports(self) -> "Oneiron._VaultChannelIdentitiesPassportsVerbs": ...
    class _VaultChannelIdentitiesSelectionVerbs:
        def rules(self, spec: Facade.EmptyRequest) -> Facade.ChannelIdentitySelectionRuleSet:
            """Read the compiled relationship selection law and authenticated writer provenance."""
        def update(self, spec: Facade.ChannelSelectionUpdateRequest) -> Facade.ChannelIdentitySelectionRuleSet:
            """Amend relationship selection rules at an expected revision as the authenticated owner or an authorized agent writer."""
    class _VaultChannelIdentitiesPassportsVerbs:
        def get(self, spec: Facade.ThreadPassportRequest) -> Facade.ThreadPassportLookup:
            """Read one receiving identity and Message-ID passport through the caller credential."""
        def list(self, spec: Facade.ThreadPassportsRequest) -> Facade.ThreadPassportsView:
            """Read canonical thread passports and the sticky identity, actor and facet mask."""
    class _VaultDeliveryWindowVerbs:
        @property
        def policy(self) -> "Oneiron._VaultDeliveryWindowPolicyVerbs": ...
        def evaluate(self, spec: Facade.DeliveryWindowEvaluateRequest) -> Facade.DeliveryWindowPreview:
            """Preview live delivery-window policy with the engine evaluator; the preview does not authorize or release an effect."""
    class _VaultDeliveryWindowPolicyVerbs:
        def put(self, spec: Facade.DeliveryWindowPolicyPutRequest) -> Facade.CommitReceipt:
            """The owner writes one typed interrupt-only delivery-window policy through the gated claim writer."""
        def list(self, spec: Facade.DeliveryWindowPolicyRequest) -> Facade.DeliveryWindowPolicies:
            """Read typed delivery-window policy rows with approval, source, lifecycle and validity provenance."""
        def retract(self, spec: Facade.DeliveryWindowPolicyRetractRequest) -> Facade.CommitReceipt:
            """The owner retracts a delivery-window policy through the existing claim lifecycle door."""
    class _VaultSummariesVerbs:
        def create(self, request: Facade.SummaryCreateRequest) -> Facade.SummaryQueued:
            """Declares a readable source scope; only the configured Dreamer writes and source-links the SUMMARY birth."""
        def read(self, request: Facade.SummaryReadRequest) -> Facade.ScopedReadResult[Facade.SummaryReadView | None]:
            """Reads SUMMARY text, keep, derivation, covers and stable edit anchors in one caller-scoped snapshot."""
        def status(self, request: Facade.SummaryStatusRequest) -> Facade.ScopeSummaryStatus:
            """Reads the calling principal's own summary declaration and its retained completion or failure."""
        def keep(self, request: Facade.SummaryKeepRequest) -> Facade.SummaryKeepResult:
            """Edits the SUMMARY keep memo at the exact frontier read, under the caller's owner proof or entity-bound text grant."""
        def edit(self, request: Facade.SummaryEditRequest) -> Facade.SummaryProposalView:
            """Applies attributed anchored SUMMARY edits through existing grants; ungranted edits remain a typed review proposal."""
        def patch(self, request: Facade.SummaryPatchRequest) -> Facade.SummaryMutationResult:
            """Applies generated anchored SUMMARY operations after a keep fence and source admission; durable receipts name the sources read."""
        def regenerate(self, request: Facade.SummaryRegenerateRequest) -> Facade.SummaryMutationResult:
            """Retains generated SUMMARY text as a source-linked rewrite fork after reading keep; no head moves without explicit switch."""
        @property
        def proposals(self) -> "Oneiron._VaultSummariesProposalsVerbs": ...
    class _VaultSummariesProposalsVerbs:
        def read(self, request: Facade.SummaryProposalRequest) -> Facade.SummaryProposalView:
            """Reads a SUMMARY proposal's fork provenance, retained text and durable receipts only when every member is readable."""
        def merge(self, request: Facade.SummaryProposalRequest) -> Facade.SummaryProposalView:
            """Merges the complete SUMMARY proposal under existing entity grants, preserving concurrent head edits and durable receipts."""
        def switch(self, request: Facade.SummaryProposalRequest) -> Facade.SummaryProposalView:
            """Explicitly switches the complete SUMMARY proposal under existing entity grants; a stale causal base refuses the entire set."""
        def reject(self, request: Facade.SummaryProposalRequest) -> Facade.SummaryProposalView:
            """Rejects the complete SUMMARY proposal under existing entity grants, dropping pending fork text without moving live heads."""
    class _VaultNotesVerbs:
        def bless_brief_kind(self, input: Facade.EmptyRequest) -> Facade.BriefKindStamp:
            """A verified person stamps the brief kind policy seed; it grants no sharing or extraction authority."""
        def author_brief(self, input: Facade.AuthorBriefRequest) -> Facade.EntityRefReceipt:
            """Authors markdown with supporting claim citations, capturing source NOTE pins and rechecking their live read authority in the brief write transaction."""
        def follow_citation(self, spec: Facade.BriefCitationFollowRequest) -> Facade.ScopedReadResult[Facade.SharedBriefCitation | None]:
            """Follows returned share and claim references under the caller live read scope; revocation stops resolution and hidden citations disclose no quote or lifecycle."""
        def create(self, input: Facade.CreateNoteRequest) -> Facade.EntityRefReceipt:
            """Creates a NOTE of a registered kind, its first authored text as its birth."""
        def author_take(self, input: Facade.AuthorTakeRequest) -> Facade.EntityRefReceipt:
            """Appends an opinion/take NOTE about a subject or claim, attributed to the bound caller without changing the target."""
        def from_entity(self, input: Facade.CreateNoteFromEntityRequest) -> Facade.EntityRefReceipt:
            """Creates a NOTE of a registered kind from an existing entity."""
        def read(self, input: Facade.NoteReadRequest) -> Facade.ScopedReadResult[Facade.NoteReadView | None]:
            """Reads live NOTE text or one retained NoteVersion, acquiring stable edit anchors in the same scoped snapshot."""
        def history(self, input: Facade.NoteAccessRequest) -> Facade.ScopedReadResult[Facade.NoteHistoryView | None]:
            """Reads authenticated NOTE operation identities and actors with the retained history boundary; hidden or purged history is never invented."""
        def fork(self, input: Facade.NoteForkRequest) -> Facade.NoteForkView:
            """Forks one NOTE at the exact live-head version the caller read, retaining its edits or rewrite without moving the live head."""
        @property
        def forks(self) -> "Oneiron._VaultNotesForksVerbs": ...
        @property
        def proposals(self) -> "Oneiron._VaultNotesProposalsVerbs": ...
        def version_tree(self, input: Facade.NoteAccessRequest) -> Facade.ScopedReadResult[Facade.NoteVersionTree | None]:
            """Reads NOTE birth, current version, fork parent and frontier links, proposal membership, verdicts and durable head-move receipts."""
        def history_purge(self, spec: Facade.NoteHistoryPurgeRequest) -> Facade.NoteHistoryPurgeOutcome:
            """The owner explicitly erases a NOTE's safe history, or opens its shared-vault erase veto window; no grant names this action."""
        def history_purge_execute(self, spec: Facade.NoteHistoryPurgeExecuteRequest) -> Facade.NoteHistoryPurgeReceipt:
            """Executes the exact history erase this owner started after its veto window closes without objection; retries return its durable receipt."""
        def history_purge_receipts(self, spec: Facade.NoteHistoryPurgeRequest) -> list[Facade.NoteHistoryPurgeReceipt]:
            """The owner reads a NOTE's durable history-purge receipts, including each requested and retained causal frontier."""
        @property
        def editor(self) -> "Oneiron._VaultNotesEditorVerbs": ...
        def edit(self, input: Facade.EditNoteRequest) -> Facade.NoteEditOutcome:
            """Edits one NOTE in a transaction-local document; a rejected edit leaves nothing pending."""
        def seal(self, request: Facade.NoteRefRequest) -> Facade.NoteSeal: ...
        def lifecycle(self, request: Facade.NoteRefRequest) -> Facade.NoteLifecycleView: ...
        def set_overrides(self, request: Facade.SetNoteOverridesRequest) -> Facade.NoteDefaultsView: ...
        def defaults(self, request: Facade.NoteRefRequest) -> Facade.NoteDefaultsView: ...
    class _VaultNotesForksVerbs:
        def read(self, input: Facade.NoteForkReadRequest) -> Facade.ScopedReadResult[Facade.NoteForkView | None]:
            """Reads a NOTE fork and its retained pending text through the same scoped, reason-logged read as the live NOTE."""
    class _VaultNotesProposalsVerbs:
        def open(self, input: Facade.NoteProposalOpenRequest) -> Facade.NoteProposalView:
            """Opens one explicit set of NOTE forks with its shared explainer; the engine routes each member under the caller's own existing grants."""
        def read(self, input: Facade.NoteProposalRequest) -> Facade.NoteProposalView:
            """Reads an entire NOTE proposal set, its pending fork text, explainer and head-move receipts only when every member is readable."""
        def merge(self, input: Facade.NoteProposalRequest) -> Facade.NoteProposalView:
            """Accepts the complete NOTE proposal set by merge under the caller's existing NOTE grants, retaining concurrent head edits and durable receipts."""
        def switch(self, input: Facade.NoteProposalRequest) -> Facade.NoteProposalView:
            """Accepts the complete NOTE proposal set by explicit switch under the caller's existing NOTE grants, recording every head move."""
        def reject(self, input: Facade.NoteProposalRequest) -> Facade.NoteProposalView:
            """Rejects the complete NOTE proposal set under the caller's existing NOTE grants, dropping pending text without changing live heads."""
    class _VaultNotesEditorVerbs:
        def bind(self, spec: Facade.NoteAccessRequest) -> Facade.ScopedReadResult[Facade.NoteEditorBinding | None]:
            """Binds a live NOTE editor to the caller and returns its typed text and base version; close the binding when the editor leaves."""
        def close(self, spec: Facade.NoteEditorCloseRequest) -> Facade.NoteEditorClosed:
            """Closes one live NOTE editor held by this caller; a binding id alone grants no authority."""
    class _FeedbackVerbs:
        def preview(self, spec: Facade.FeedbackPreviewRequest) -> Facade.FeedbackSubjectPreview:
            """The owner previews the exact feedback bundle one report issue would send to its publisher: its subject, digest, destination and approval."""
        def send(self, spec: Facade.FeedbackSendSubjectRequest) -> Facade.FeedbackSubjectSent:
            """The owner sends exactly the previewed feedback bundle for one report issue to its publisher, once, through the ordinary outbound gate."""
    class _SelfVerbs:
        @property
        def focus(self) -> "Oneiron._SelfFocusVerbs": ...
        @property
        def memory(self) -> "Oneiron._SelfMemoryVerbs": ...
        @property
        def standing(self) -> "Oneiron._SelfStandingVerbs": ...
        @property
        def identity(self) -> "Oneiron._SelfIdentityVerbs": ...
        @property
        def inbox(self) -> "Oneiron._SelfInboxVerbs": ...
        def message(self, spec: Facade.MessagePersonRequest) -> Facade.MessagePersonReceipt:
            """Sends one message to a person in the Direct room the caller's person and theirs share, making the room on first use."""
        @property
        def grants(self) -> "Oneiron._SelfGrantsVerbs": ...
        @property
        def budget(self) -> "Oneiron._SelfBudgetVerbs": ...
        @property
        def credential(self) -> "Oneiron._SelfCredentialVerbs": ...
        @property
        def admission(self) -> "Oneiron._SelfAdmissionVerbs": ...
        @property
        def saved_query(self) -> "Oneiron._SelfSavedQueryVerbs": ...
        @property
        def off_record(self) -> "Oneiron._SelfOffRecordVerbs": ...
        @property
        def consent(self) -> "Oneiron._SelfConsentVerbs": ...
        def use(self, spec: Facade.SecretUseRequest) -> Facade.SecretUseAnswer:
            """Hands a secret to one trusted operation by its handle, under the owner's binding; answers what the operation got back, never the value."""
        @property
        def secrets(self) -> "Oneiron._SelfSecretsVerbs": ...
        @property
        def skills(self) -> "Oneiron._SelfSkillsVerbs": ...
        @property
        def decisions(self) -> "Oneiron._SelfDecisionsVerbs": ...
        @property
        def run(self) -> "Oneiron._SelfRunVerbs": ...
        @property
        def folds(self) -> "Oneiron._SelfFoldsVerbs": ...
        def history(self, spec: Facade.FoldHistoryRequest) -> Facade.FoldHistory:
            """Reads checkpointed raw steps and landed fold and epoch boundaries of the attached run; a cleared ask alone never proves compaction settled."""
        @property
        def browser(self) -> "Oneiron._SelfBrowserVerbs": ...
        def fold(self, spec: Facade.FoldMarkRequest) -> Facade.FoldReply[Facade.FoldMarked]:
            """Marks a span of the attached run as pending; compaction leaves its raw steps untouched until a batch lands."""
        def compact(self, spec: Facade.FoldCompactRequest) -> Facade.FoldReply[Facade.FoldCompactAsked]:
            """Asks the attached run to fold its pending marks in one batch at its next step boundary; read self.history for landed folds and epochs."""
        def unfold(self, spec: Facade.FoldUnfoldRequest) -> Facade.FoldReply[Facade.FoldUnfolded]:
            """Appends a fold of the attached run after its current tail, without replacing the earlier stub."""
        def report_blocked(self, spec: Facade.LiveRunRequest[Facade.ReportBlockedInput]) -> Facade.ReportBlockedOutput:
            """Files this credential's attached agent run's own blocked report: a closed category and its detail as the fenced, untrusted leaf of a witnessed receipt for the Coach's Issues job; it grants nothing and completes no task."""
        @property
        def agents(self) -> "Oneiron._SelfAgentsVerbs": ...
        @property
        def leader(self) -> "Oneiron._SelfLeaderVerbs": ...
    class _SelfFocusVerbs:
        def wakes(self, spec: Facade.LiveRunRequest[Facade.BoardWakeRequest]) -> Facade.BoardWakeReply:
            """Takes every wake queued for the attached run's board STREAM connection, each re-read under this credential at delivery."""
        @property
        def scratchpad(self) -> "Oneiron._SelfFocusScratchpadVerbs": ...
        def refresh(self, spec: Facade.LiveRunRequest[Facade.BoardRefreshRequest]) -> Facade.BoardFrameReply:
            """Re-renders the attached run's context board as one STREAM frame, at the frame epoch the caller last saw."""
        def subscribe(self, spec: Facade.LiveRunRequest[Facade.BoardSubscriptionRequest]) -> Facade.BoardSubscriptionReply:
            """Subscribes the attached run's board STREAM connection to the named scopes, inside its credential ceiling."""
        def unsubscribe(self, spec: Facade.LiveRunRequest[Facade.BoardSubscriptionRequest]) -> Facade.BoardSubscriptionReply:
            """Unsubscribes the attached run's board STREAM connection from the named scopes."""
    class _SelfFocusScratchpadVerbs:
        def recall(self, spec: Facade.ScratchpadRecallRequest) -> Facade.ScratchpadRecallReply:
            """Searches the bound actor's whole session scratchpad, live or sealed, for the lines holding every query word, folded lines in full."""
        def append(self, spec: Facade.ScratchpadAppendRequest) -> Facade.ScratchpadWriteReply:
            """Appends one line, with an optional keep or scratch mark and pin, to the bound actor's session scratchpad; the session's first line opens the pad, and a sealed pad is refused."""
        def seal(self, spec: Facade.ScratchpadSealRequest) -> Facade.ScratchpadWriteReply:
            """Seals the bound actor's session scratchpad, ending the run's pad; a session with no pad answers no pad."""
    class _SelfMemoryVerbs:
        @property
        def diary(self) -> "Oneiron._SelfMemoryDiaryVerbs": ...
    class _SelfMemoryDiaryVerbs:
        def __call__(self, spec: Facade.DiaryEntryRequest) -> Facade.DiaryEntryReceipt:
            """Writes one private entry in the bound actor's own diary, as an actor-private NOTE."""
        def reads(self, spec: Facade.DiaryReadsRequest) -> Facade.DiaryReadsView:
            """This agent's diary read log: who read its diary and why, newest first, and the reasons its review holds."""
        def review(self, spec: Facade.DiaryReviewAnswer) -> Facade.DiaryReadRequest:
            """This agent's yes or no to a reader's reason for reading its diary; only the diary's own agent answers."""
        def query(self, spec: Facade.DiaryQueryRequest) -> Facade.DiaryQueryOutcome:
            """Reads an agent's diary under the caller's diary.read grants, stating a reason the agent sees in its read log."""
    class _SelfStandingVerbs:
        def get(self, spec: Facade.OwnStandingBlockRequest) -> Facade.StandingBlockView:
            """This agent's configured standing block in one world: its handle, name and token floor."""
        def list(self, spec: Facade.EmptyRequest | None = None) -> list[Facade.StandingBlockView]:
            """Every standing block configured for this agent, one per world, in world order."""
        def edit(self, spec: Facade.StandingBlockEditRequest) -> Facade.StandingBlockEditReceipt:
            """This agent proposes one persona field's new text for its standing block, as a Generated claim its gate settles; compiled text is never edited."""
    class _SelfIdentityVerbs:
        def answer(self, spec: Facade.IdentityAnswerEvidenceRequest) -> Facade.IdentitySettled:
            """The owner answers an identity choice with supporting evidence refs; the original mention and verified owner resolution provenance are retained atomically."""
        def settle(self, spec: Facade.IdentityActNowRequest) -> Facade.IdentityActNow:
            """Before acting on a person known only by a name, settles who that name is from its newest saved mention, or opens an ask."""
    class _SelfInboxVerbs:
        def list(self, spec: Facade.InboxListRequest) -> Facade.NotificationPage:
            """Lists one page of notifications delivered to the bound actor, without marking them."""
        def mark(self, spec: Facade.InboxMarkRequest) -> Facade.NotificationRow:
            """Marks one delivered notification seen or acknowledged for the bound actor."""
        @property
        def concern(self) -> "Oneiron._SelfInboxConcernVerbs": ...
        def lens(self, spec: Facade.InboxLensRequest) -> Facade.InboxLensPage:
            """Reads the bound actor's own identity inbox slice in impact order, with optional identity filtering and concern groups; not a delivered-notification page."""
    class _SelfInboxConcernVerbs:
        def __call__(self, spec: Facade.ConcernCardRequest) -> Facade.AgentHealthCardView: ...
        def outcome(self, spec: Facade.ConcernOutcomeRequest) -> Facade.ConcernCardSummary: ...
        def move(self, spec: Facade.ConcernMoveRequest) -> Facade.ConcernMoveOutcome: ...
    class _SelfGrantsVerbs:
        def ask(self, spec: Facade.GrantAskRequest) -> Facade.GrantAskReceipt:
            """Asks a person or agent for access on the caller's behalf; the request itself grants nothing, and the vault owner or the authorized asked person or agent answers it."""
        def answer(self, spec: Facade.GrantAnswerRequest) -> Facade.GrantAnswered:
            """The vault owner, or the person or agent an access request asks, approves or denies one pending request on their own proof; an asked member approves up to what their own credential may delegate, and the rest stays pending for the owner."""
    class _SelfBudgetVerbs:
        def __call__(self, spec: Facade.SelfBudgetRequest) -> Facade.AgentBudgetView:
            """The caller's own dispatched attempt: its persisted spend allowance, landing reserve, checkpoint and saved hold, without substituting a token meter for money."""
        def land(self, spec: Facade.BudgetLandRequest) -> Facade.PartialResultHold:
            """The worker parks its own dispatched attempt at its budget hold with its lease fence and exact checkpoint; the same run keeps its partial results and resumes later."""
    class _SelfCredentialVerbs:
        def attenuate(self, spec: Facade.CredentialAttenuationRequest) -> Facade.CredentialAttenuated:
            """Appends a holder-signed caveat to the caller's own slip, optionally transferring it to a recipient public key. Existing caveats and live parent authority remain binding; no actor or grant is minted."""
    class _SelfAdmissionVerbs:
        def status(self, spec: Facade.AdmissionStatusRequest) -> Facade.AdmissionReceipt | None:
            """Reads the durable queued, held or terminal receipt of one typed call under its invocation id, as its own actor; never submits or replays work."""
        def receipts(self, spec: Facade.AdmissionReceiptsRequest) -> list[Facade.AdmissionReceipt]:
            """Reconciles an exact authored set of invocation ids against the caller actor durable admission receipts in one snapshot, without duplicate outcomes or replay."""
    class _SelfSavedQueryVerbs:
        def create(self, spec: Facade.SavedQueryCreateRequest) -> Facade.SavedQueryRecordView:
            """Creates a saved query (scope, stage-1 filter, stage-2 matcher and evaluation policy) owned by the caller."""
        def read(self, spec: Facade.SavedQueryReadRequest) -> Facade.SavedQueryReadResult:
            """One saved query the caller owns; a query absent or not the caller's reads as not found."""
        def update(self, spec: Facade.SavedQueryUpdateRequest) -> Facade.SavedQueryRecordView:
            """Replaces a saved query's scope, filter, matcher and evaluation policy whole under a definition-version check; it is how the owner accepts a pack-drift repair for a paused query, and a valid replacement resumes it."""
        def archive(self, spec: Facade.SavedQueryArchiveRequest) -> Facade.SavedQueryRecordView:
            """Archives a saved query under a definition-version check: it stays readable and is never evaluated again."""
        def members(self, spec: Facade.SavedQueryMembersRequest) -> Facade.SavedQueryMembershipPageView:
            """One cursor-bounded page of the membership this saved query derived, entered and exited causes preserved."""
        def evaluate(self, spec: Facade.SavedQueryEvaluateRequest) -> Facade.SavedQueryEvaluationReceipt:
            """Evaluates a saved query the caller owns now, bounded by its per-wake caps, with one verdict and memo receipt per visited entity."""
    class _SelfOffRecordVerbs:
        def execute(self, spec: Facade.OffRecordExecuteRequest) -> Facade.OffRecordExecuted:
            """The session's creator or the vault's owner runs one entry of a durable code-mode run bound to an off-record session; its rows and spilled outputs stay in the room until close."""
    class _SelfConsentVerbs:
        @property
        def graduation(self) -> "Oneiron._SelfConsentGraduationVerbs": ...
    class _SelfConsentGraduationVerbs:
        def demote(self, spec: Facade.GraduationScopeRequest) -> Facade.GraduationChanged:
            """The bound actor transparently gives up only its own ramp scope authority, with the existing durable demotion receipt."""
    class _SelfSecretsVerbs:
        def materialize(self, spec: Facade.LiveRunRequest[Facade.SecretGrantMintRequest]) -> Facade.SecretGrantView:
            """Mints a value-free grant on a secret for this credential's attached run, to one purpose: an operation or connector (door), a host destination (leased) or a declared file (local); the answer never holds the value."""
        def renew(self, spec: Facade.LiveRunRequest[Facade.SecretGrantRenewRequest]) -> Facade.SecretGrantView:
            """Renews a grant the attached run holds: a fresh grant at the secret's current generation in its place, never a longer life for bytes already handed out."""
        def teardown(self, spec: Facade.LiveRunRequest[Facade.SecretGrantTeardownRequest]) -> Facade.SecretGrantView:
            """Tears down a grant the attached run holds, whatever its state: revokes it and its lease, removes its file or clears its destination, and says what the cleanup found."""
        def use(self, spec: Facade.LiveRunRequest[Facade.SecretGrantUseRequest]) -> Facade.SecretUseAnswer:
            """Hands the secret a door grant redeems to one trusted operation or connector call, for the attached run; a grant minted before a rotation refuses until renewed, and the answer never holds the value."""
    class _SelfSkillsVerbs:
        def save(self, spec: Facade.SkillSaveRequest) -> Facade.SkillAuthoringReceipt:
            """An agent saves a skill it wrote, SKILL.md and scripts together; it lands as a proposed candidate and nothing activates it."""
        def fork(self, spec: Facade.SkillForkRequest) -> Facade.SkillAuthoringReceipt:
            """An agent forks a stored skill under its own identity, keeping its import ancestry."""
        def callables(self, spec: Facade.EmptyRequest | None = None) -> list[Facade.CallableCardView]:
            """Every loadable callable helper skill and its call contract: what it takes and returns."""
        def call(self, spec: Facade.LiveRunRequest[Facade.SkillCallInput]) -> Any:
            """Runs a callable skill on this credential's attached leased run with its existing sandbox and gates; the result follows the stored return contract, while anchored outcomes settle separately."""
    class _SelfDecisionsVerbs:
        def asks(self, spec: Facade.EmptyRequest | None = None) -> list[Facade.DecisionAsk]: ...
    class _SelfRunVerbs:
        def attach(self, spec: Facade.RunAttachRequest) -> Facade.RunAttached:
            """Attaches the caller's own credential to its leased live run and returns the handle required by the public fold and history calls."""
    class _SelfFoldsVerbs:
        def __call__(self, spec: Facade.FoldRunRequest) -> Facade.FoldReply[Facade.FoldList]:
            """Lists the attached run's landed folds, pending marks and outstanding compact ask."""
        def describe(self, spec: Facade.FoldUnfoldRequest) -> Facade.FoldReply[Facade.FoldDescription]:
            """Reads one pending mark or landed fold of the attached run, with its Generated stub, source ids and retained result handles."""
    class _SelfBrowserVerbs:
        def open(self, spec: Facade.LiveRunRequest[Facade.OpenInput]) -> Facade.BrowserObservationPage:
            """Opens a URL in the attached run's own browser session and observes the page whole, in pages read on with observe and next; site_skills hold the exact-origin skills of the page it landed on, and site_skill_notes say why none loaded."""
        def observe(self, spec: Facade.LiveRunRequest[Facade.ObserveInput]) -> Facade.BrowserObservationPage:
            """Observes the attached run's page as an edit of the base it names or the caller's last whole read, else whole (or with full), paged via observe and next, each page keeping its open's site_skills; acts follow new tabs; secrets show as handles."""
        def find(self, spec: Facade.LiveRunRequest[Facade.FindInput]) -> Facade.BrowserFindOutput:
            """Finds the page rows whose role and name match, each with its live ref and its locator, in pages: an answer with next goes on, and find with that cursor reads the next page."""
        def click(self, spec: Facade.LiveRunRequest[Facade.ClickInput]) -> Facade.BrowserObservationPage:
            """Clicks one page target by live ref or locator and observes the result as an edit of the caller's base; a ref whose node is gone acts on its locator's row as rebound; a long observation comes in pages, read on with observe and next."""
        def click_at(self, spec: Facade.LiveRunRequest[Facade.PointInput]) -> Facade.BrowserObservationPage:
            """Clicks a point of a held screenshot, mapped onto the viewport, and observes the result as an ordered edit of the caller's base; a long page's observation comes in pages, read on with observe and its next cursor."""
        def type(self, spec: Facade.LiveRunRequest[Facade.TypeInput]) -> Facade.BrowserObservationPage:
            """Types text, or the value a run-bound secret handle names, into one page target by live ref or locator, observing the result as an edit of the caller's base; a gone ref acts on its locator's row as rebound; long observations page."""
        def select(self, spec: Facade.LiveRunRequest[Facade.SelectInput]) -> Facade.BrowserObservationPage:
            """Picks the option of a select element by live ref or locator, by its label, text or value, and observes the result as an edit of the caller's base; a long observation comes in pages, read on with observe and its next cursor."""
        def wait_for(self, spec: Facade.LiveRunRequest[Facade.WaitForInput]) -> Facade.BrowserWaitForOutput:
            """Waits until a page row its live refs or locators name, or else a row matching a role and name, is there; a ref whose node is gone matches its locator's row, listed in rebindings; many rows come in pages, read on with find and next."""
        def expect(self, spec: Facade.LiveRunRequest[Facade.ExpectInput]) -> Facade.BrowserExpectOutput:
            """Checks that a page row, by live ref or locator, is present or absent, and holds a given value or, compared unread, the secret a run-bound handle names; a ref whose node is gone is checked on its locator's row and listed in rebindings."""
        def screenshot(self, spec: Facade.LiveRunRequest[Facade.ScreenshotInput]) -> Facade.BrowserScreenshotOutput:
            """Takes a screenshot the session holds, by image ref and never captioned, under its own capture_id; with since_capture, unchanged_from names that earlier capture when this one is the same masked PNG taken in the same scope."""
        def view(self, spec: Facade.LiveRunRequest[Facade.ViewInput]) -> Facade.BrowserImageOutput:
            """Reads back a held image by its ref."""
        def crop(self, spec: Facade.LiveRunRequest[Facade.CropInput]) -> Facade.BrowserImageOutput:
            """Crops a held image to a rectangle."""
        def zoom(self, spec: Facade.LiveRunRequest[Facade.ZoomInput]) -> Facade.BrowserImageOutput:
            """Zooms into a rectangle of a held image."""
        def batch(self, spec: Facade.LiveRunRequest[Facade.BatchInput]) -> Facade.BrowserBatchOutput:
            """Runs one batched browser program for a subgoal in the attached run's browser; fill types supplied, reference, template or checked written text (receipt text_source, text_ref); a failing or no_progress stop returns a failed_receipt."""
        @property
        def library(self) -> "Oneiron._SelfBrowserLibraryVerbs": ...
        @property
        def demonstration(self) -> "Oneiron._SelfBrowserDemonstrationVerbs": ...
        def handover(self, spec: Facade.LiveRunRequest[Facade.HandoverInput]) -> Facade.BrowserHandoverOutput:
            """Asks a person to take the browser over, saying why (to sign in or pay); until they hand it back, browser verbs refuse browser_taken_over and the answer after carries the record. With demonstrate: true the handback returns their span's draft."""
        def switch_engine(self, spec: Facade.LiveRunRequest[Facade.SwitchEngineInput]) -> Facade.BrowserSwitchEngineOutput:
            """Moves the run browser to the other engine (lightpanda or chromium) when a page does not work on this one, as after a click_no_effect fact; carries the URL, cookies, storage and scroll, and records the switch. Nothing switches by itself."""
    class _SelfBrowserLibraryVerbs:
        def find(self, spec: Facade.LiveRunRequest[Facade.LibraryFindInput]) -> Facade.BrowserLibraryFindOutput:
            """The replay library's programs for a site, url or run's page, and apart its site skills' seed candidates (exact origin); type_ref keeps one task type. Cards: type_ref, runs, failures, recent pass/miss/repair, strict_misses, held_out, seed."""
        def draft(self, spec: Facade.LiveRunRequest[Facade.DraftInput]) -> Facade.BrowserLibraryDraftOutput:
            """Drafts a proposal from the attached run's browser receipts on its open origin, no model, replay or filing: steps, slot_candidates, secrets as slots, gaps; it ends before a send, pay, publish, destructive or unknown press unless past_press."""
        def propose(self, spec: Facade.LiveRunRequest[Facade.ProposeInput]) -> Facade.BrowserLibraryProposeOutput:
            """Offers a solved run's program, or a seed candidate (its checked program and provenance win, args stay yours), to the run's library, secrets as slots; it joins once a no-model fresh-guest replay meets its postcondition; supersedes retires."""
        def retire(self, spec: Facade.LiveRunRequest[Facade.LibraryRetireInput]) -> Facade.BrowserLibraryRetireOutput:
            """Takes a program out of the replay library of the attached run's browser session for every later run, and returns the card it had."""
        def retired(self, spec: Facade.LiveRunRequest[Facade.LibraryRetiredInput]) -> Facade.BrowserLibraryRetiredOutput:
            """The programs retires took out of the replay library for a site, or for the attached run's open page's site, the newest first, each with when and why."""
        def run(self, spec: Facade.LiveRunRequest[Facade.LibraryRunInput]) -> Facade.BrowserLibraryRunOutput:
            """Runs a replay library program in the attached run's browser, strict (rules only; a model step or fill generation asks up at zero tokens) or assisted; receipts name fill text_source; no_progress hands up; 3 strict misses retire it drift."""
    class _SelfBrowserDemonstrationVerbs:
        def start(self, spec: Facade.LiveRunRequest[Facade.DemonstrationStartInput]) -> Facade.BrowserDemonstrationStartOutput:
            """Starts recording a demonstration in the attached run's Chromium browser: page acts become replay steps, secret text never leaves the page; returns its id, or the running one with already_running."""
        def stop(self, spec: Facade.LiveRunRequest[Facade.DemonstrationStopInput]) -> Facade.BrowserDemonstrationStopOutput:
            """Stops a demonstration in the attached run's browser, or takes one that ended, once: recorded steps, named gaps, stop_cause, and an unfiled draft for the subgoal and postcondition given."""
    class _SelfAgentsVerbs:
        def spawn(self, spec: Facade.LiveRunRequest[Facade.AgentSpawnInput]) -> Facade.AgentSpawnOutput:
            """Spawns a child under the leased parent attached to this credential; spec states the need, work and narrowing, never the parent identity."""
    class _SelfLeaderVerbs:
        def split(self, spec: Facade.LiveRunRequest[Facade.LeaderSplitInput]) -> Facade.LeaderSplitOutput:
            """Splits the attached leader run into a subproject inside its own TASK wrapper; spec may name only the child leader and a narrower scope."""
    class _TasksVerbs:
        def create(self, spec: Facade.TaskCreateRequest) -> Facade.TaskCreateReceipt:
            """Mints one TASK and its realizing attempt when the actor's ceiling permits, or parks it as a proposal; an intent key with a typed brief posts it through the task highway, and may bind an agent TASK to a library program (`context.workflow`)."""
        def wave(self, spec: Facade.TaskWaveRequest) -> Facade.TaskWaveReceipt:
            """Cuts an epic TASK into a wave of TASKs through a planner agent, as one planning attempt: under the asking run's own lease, or the owner's root wave."""
        def update(self, spec: Facade.TaskUpdateRequest) -> Facade.TaskUpdateReceipt:
            """Reports task progress, blocked work or a durable result through the task highway; without a report, acknowledges a failed TASK. A revised workflow binding reaches only later tries."""
        def accept(self, spec: Facade.TaskAccept) -> Facade.TaskCallReceipt:
            """Accepts one TASK addressed to the caller through the task highway under the caller's intent key; the attempt handle it answers fences the caller's reports."""
        def redo(self, spec: Facade.TaskRedo) -> Facade.TaskCallReceipt:
            """Posts a new TASK and its try from one TASK's current brief, assignee, spec, label and parent through the task highway, under the caller's intent key; the redone TASK, its result and its receipts are never written."""
        def answer(self, handle: Facade.TaskAskHandle, word: Facade.TaskAskWord) -> Facade.TaskAskAnswer:
            """Admits one person's word on an ask; the word is evidence, never approval."""
        def outcomes(self, handle: Facade.TaskAskHandle) -> list[Facade.CalibrationPair]:
            """Owner-scoped calibration pairs for an ask: each prediction against the outcome it was bound to."""
        def refuse(self, spec: Facade.LiveRunRequest[Facade.TaskRefuseInput]) -> Facade.TaskRefuseOutput:
            """Applies this credential's attached agent run refusal dial to its own TASK, with a durable reason; the live lease supplies the actor and TASK and the engine owns replay."""
    class _AiVerbs:
        @property
        def chat(self) -> "Oneiron._AiChatVerbs": ...
        @property
        def steps(self) -> "Oneiron._AiStepsVerbs": ...
        @property
        def streams(self) -> "Oneiron._AiStreamsVerbs": ...
        def reply(self, spec: Facade.AiReplyRequest) -> Facade.AiReply:
            """Generate one context-bearing reply from the caller's scoped conversation, standing prefix and reader profile through an exact configured model; return durable emit-context receipt refs."""
        @property
        def voice(self) -> "Oneiron._AiVoiceVerbs": ...
        def anonymous_chat(self, spec: Facade.AnonymousChatRequest) -> Facade.AnonymousChatResponse:
            """One standalone memory-free turn on the house configuration or a plain model, with ephemeral policy notices; use the HTTP SDK, not a recorded MCP or code-mode call."""
        def options(self, spec: Facade.AiOptionsRequest) -> Facade.AiOptions:
            """The model rows the caller could call now: where each runs, what it takes, its price and rates, and what its meter has left."""
        def image(self, spec: Facade.AiCallRequest) -> Facade.AiAnswer:
            """One image out of the host's image model; reference images make it an edit."""
        def speech(self, spec: Facade.AiCallRequest) -> Facade.AiAnswer:
            """Speech audio out of text, from the host's speech model."""
        def transcribe(self, spec: Facade.AiCallRequest) -> Facade.AiAnswer:
            """Text out of speech audio, from the host's transcription model."""
        def embed(self, spec: Facade.AiCallRequest) -> Facade.AiAnswer:
            """One embedding vector per input text, from the host's embedding model."""
        @property
        def video(self) -> "Oneiron._AiVideoVerbs": ...
        def verdict(self, spec: Facade.AiVerdictRequest) -> Facade.AiVerdict:
            """The caller's own typed question through the host's decision ladder: yes or no, one of its options, a score in the caller's range, or a box or point in an image, answered with a probability and a decision receipt."""
    class _AiChatVerbs:
        def completions(self, spec: Facade.ChatCompletionRequest) -> Facade.ChatCompletionResponse:
            """Recalls scoped memory, injects it as data, forwards a buffered OpenAI chat call and proposes the exchange under the paired connector's own ceiling."""
    class _AiStepsVerbs:
        def submit(self, spec: Facade.ModelStepSubmit) -> Facade.ModelStepReceipt:
            """Submit or resume one owner-bound durable model step with declared transport attempts (past the retry schedule its last interval paces), deterministic fallback and a schema-validated JSON result."""
        def receipt(self, spec: Facade.ModelStepReceiptRequest) -> Facade.ModelStepReceipt:
            """Read the owner-bound model-step checkpoints and persisted terminal result without calling a model or spending another lease; after an owner erase only the receipt metadata and an erased result remain."""
    class _AiStreamsVerbs:
        def open(self, spec: Facade.ModelStreamOpen) -> Facade.ModelStreamOpened:
            """Open one owner-bound shared model stream under a stable key: a single admitted producer starts (or the standing stream answers), and a replay never starts a second one."""
        def subscribe(self, spec: Facade.ModelStreamSubscribe) -> Facade.ModelStreamSubscribed:
            """Attach before or after open to the caller's shared model stream, without starting a producer; replay every typed part event from the first under an independently detachable handle."""
        def events(self, spec: Facade.ModelStreamEventsRequest) -> Facade.ModelStreamEvents:
            """Drain one subscription's queued typed LlmStreamEvents (part-correlated text, reasoning, tool and image deltas, then Done) without blocking; closed once the producer ended and the queue is empty."""
        def detach(self, spec: Facade.ModelStreamDetach) -> Facade.ModelStreamDetached:
            """Detach only this subscription from the shared model stream; the producer and every other subscriber continue."""
        def abort(self, spec: Facade.ModelStreamAbort) -> Facade.ModelStreamTerminal:
            """Abort the caller's shared model stream with actual usage: subscribers receive the cancelled Done of the parts completed so far, recorded as the one durable terminal."""
        def terminal(self, spec: Facade.ModelStreamTerminalRequest) -> Facade.ModelStreamTerminal:
            """Read the one durable terminal of the caller's model stream by key (its ordered ContentParts, usage and finish reason, or its recorded failure) after any restart, without calling a model."""
    class _AiVoiceVerbs:
        @property
        def asr(self) -> "Oneiron._AiVoiceAsrVerbs": ...
        def start(self, spec: Facade.LiveVoiceStartRequest) -> Facade.LiveVoiceSession:
            """Opens an owner-bound live media session on the configured voice routes, using the caller credential, room audience and existing budget gates."""
        def audio(self, spec: Facade.LiveVoiceAudioRequest) -> Facade.LiveVoiceProcessed:
            """Feeds one utterance of PCM16LE with client VAD to the live voice host; sustained speech retires old output through the shared cancellation path."""
        def events(self, spec: Facade.LiveVoiceEventsRequest) -> Facade.LiveVoiceEvents:
            """Reads ordered utterance and epoch events, PCM, flushes, playout stops, safeguard receipts and notices; advancing the cursor releases consumed events."""
        def ack(self, spec: Facade.LiveVoiceAckRequest) -> Facade.LiveVoiceProcessed:
            """Acknowledges the exact playout-end or playout-stop event of one session epoch after client playback or flush has completed."""
        def usage(self, spec: Facade.LiveVoiceUsageRequest) -> Facade.LiveVoiceUsage:
            """Observes actual voice-brain run settlements and a terminal boundary after producer teardown, epoch retirement, TTS cancel and client playout acknowledgment."""
        def tool(self, spec: Facade.LiveVoiceToolRequest) -> Facade.LiveVoiceToolReply:
            """Calls a connector under the caller grant and carries its delivered result, marked foreign, into the next voice utterance for parallel sentence safeguards."""
        def end(self, spec: Facade.LiveVoiceSessionRequest) -> Facade.LiveVoiceProcessed:
            """Ends live voice through the shared cancellation path; keeps the session available for final playout acknowledgment and usage observation."""
        def close(self, spec: Facade.LiveVoiceSessionRequest) -> Facade.LiveVoiceProcessed:
            """Ends and releases a live voice session and its retained events; read terminal usage and acknowledge playout before closing."""
    class _AiVoiceAsrVerbs:
        def open(self, spec: Facade.AsrOpenRequest) -> Facade.AsrSession:
            """Opens one credential-bound utterance for host-enriched ASR speculative recall, with fixed scope, at most four fires and a call-mode deadline."""
        def hypothesis(self, spec: Facade.AsrHypothesisRequest) -> Facade.AsrHypothesisReceipt:
            """Observes an ASR hypothesis and host enrichment; returns the engine signature-change decision, actual fire budget, scoped candidates and a per-fire receipt."""
        def finalize(self, spec: Facade.AsrHypothesisRequest) -> Facade.AsrFinalReceipt:
            """Consumes an ASR utterance, promoting its compatible last fire with receipt linkage or running one full finalize pass with warm-fill and honest partial reporting."""
        def close(self, spec: Facade.AsrCloseRequest) -> Facade.AsrClosed:
            """Closes an unfinished ASR utterance under its opening credential and releases its warm candidates without a final retrieval."""
    class _AiVideoVerbs:
        def __call__(self, spec: Facade.AiCallRequest) -> Facade.AiVideoTicket:
            """Starts a video render as a provider job and answers with its ticket."""
        def poll(self, spec: Facade.AiVideoJobRequest) -> Facade.AiVideoJob:
            """Where a video job stands; a finished one answers with its clip on every poll until ai.video.cancel deletes it."""
        def cancel(self, spec: Facade.AiVideoJobRequest) -> Facade.AiVideoCancelled:
            """Stops a video job at its provider."""
    class _RevealVerbs:
        def __call__(self, spec: Facade.RevealRequest) -> Facade.RevealPending:
            """Asks for a custody or PERSON handle's value for the model, by its handle and why; answers a pending reveal that reveal.wait collects."""
        def wait(self, spec: Facade.RevealWaitRequest) -> Facade.RevealWaitAnswer:
            """Where a reveal stands: pending, denied, expired or granted; the first granted answer carries the value, later ones the receipt."""
        def describe(self, spec: Facade.RevealDescribeRequest) -> Facade.RevealHandleCard:
            """What a custody or PERSON handle names, where it was found and what a reveal of it would do now; never the value."""
    class _HostVerbs:
        def compact(self, spec: Facade.HostCompactRequest) -> Facade.HostCompactResult:
            """Compacts a conversation window on the configured cheap backend, preserving add-only hook pins through the existing gate and keyframe mint."""
        def wake(self, spec: Facade.HostWakeRequest) -> Facade.HostWakeResult:
            """Schedules the host wake through its typed trigger; pre-hook Skip keeps its reason and Timer includes the engine maintenance lanes."""
        @property
        def budget(self) -> "Oneiron._HostBudgetVerbs": ...
    class _HostBudgetVerbs:
        def hit(self, spec: Facade.HostBudgetHitRequest) -> Facade.HostBudgetHitResult:
            """Notifies a spent durable budget seat under Suspend, retaining the original line, root payer, cap and accounting for hook follow-up work."""
    class _GraphFsVerbs:
        def readdir(self, spec: Facade.GraphFsPathRequest) -> Facade.GraphFsDirectoryView:
            """List one directory at the mounted reference under the caller read gate, with a sealed continuation."""
        def read_file(self, spec: Facade.GraphFsPathRequest) -> Facade.GraphFsOutput:
            """Read a bounded page of file bytes at the mounted reference, with its encoding and sealed continuation."""
        def read_link(self, spec: Facade.GraphFsLinkRequest) -> Facade.GraphFsLinkView:
            """Resolve a visible graph link at the mounted reference without following a host filesystem link."""
        def ls(self, spec: Facade.GraphFsLsRequest) -> Facade.GraphFsOutput:
            """List names at the mounted reference, using the live temporal index when requested."""
        def find(self, spec: Facade.GraphFsFindRequest) -> Facade.GraphFsOutput:
            """Walk visible paths at the mounted reference, or push a live newer-than query into the temporal index."""
        def grep(self, spec: Facade.GraphFsGrepRequest) -> Facade.GraphFsOutput:
            """Search visible mounted file bytes, using the live claim text index for supported recursive patterns."""
        def cat(self, spec: Facade.GraphFsPathRequest) -> Facade.GraphFsOutput:
            """Read a bounded page of mounted file bytes as UTF-8 or base64 without changing its reference."""
        def head(self, spec: Facade.GraphFsHeadRequest) -> Facade.GraphFsOutput:
            """Read the first requested lines at the mounted reference with bounded output and a sealed continuation."""
        def wc(self, spec: Facade.GraphFsLinkRequest) -> Facade.GraphFsOutput:
            """Count lines, words and bytes of a visible file at the mounted reference."""
    class _ConnectorVerbs:
        def list(self, spec: Facade.ConnectorListRequest) -> list[Facade.ConnectorEntry]:
            """Every live catalogued connector whose name or summary matches the query."""
        def status(self, spec: Facade.ConnectorNameRequest) -> Facade.ConnectorView | None:
            """One catalogued connector by name, removed ones included."""
        def call(self, spec: Facade.ConnectorCallRequest) -> Facade.ActAnswer[Facade.ConnectorCallReply]:
            """Calls one tool of one catalogued connector under the caller's own grant and gate; the tool's reply comes back as foreign data."""
        def schema(self, spec: Facade.ConnectorSchemaRequest) -> Facade.ConnectorSchemaReply:
            """One catalogued connector tool's approved input schema, as the caller's own grant resolves it."""
        def call_status(self, spec: Facade.ConnectorCallStatusRequest) -> Facade.ConnectorCallStatus:
            """Where one connector.call stands, by the call_ref its held, pending_delivery or awaiting_input reply named: pending, the questions it waits on, or its settled reply. Only its caller and the vault's owner read it."""
        @property
        def outbound(self) -> "Oneiron._ConnectorOutboundVerbs": ...
        def answer(self, spec: Facade.ConnectorAnswerRequest) -> Facade.ConnectorCallReply:
            """Answers the questions one of the caller's own connector calls waits on, by the handle its awaiting_input reply named, under that call's grant and principal; the connector's next questions or its result come back as foreign data."""
    class _ConnectorOutboundVerbs:
        def schedule(self, spec: Facade.OutboundScheduleRequest) -> Facade.OutboundIntentReceipt:
            """Schedules one send through a granted outbound connector, gated and held for delivery."""
    class _CalendarVerbs:
        def invite(self, spec: Facade.CalendarInviteSurfaceInput) -> Facade.OutboundIntentReceipt:
            """Schedules an iMIP REQUEST or CANCEL through the caller-bound outbound gate, preserving UID, SEQUENCE, vault-only hygiene and delivery dedupe."""
        @property
        def ics(self) -> "Oneiron._CalendarIcsVerbs": ...
        @property
        def connector(self) -> "Oneiron._CalendarConnectorVerbs": ...
        @property
        def imip(self) -> "Oneiron._CalendarImipVerbs": ...
    class _CalendarIcsVerbs:
        def configure(self, spec: Facade.CalendarIcsFeedConfigureRequest) -> Facade.CalendarIcsFeedRegistration:
            """Installs one owner-authorized secret-ref ICS feed per system with the existing bounded poll cadence; configuration grants no import consent."""
        def poll(self, spec: Facade.CalendarIcsFeedRequest) -> Facade.CalendarIcsPollCompletion:
            """Fetches the installed ICS feed through secret custody and the existing imported-claim gate, returning a durable completion barrier and cursor; failed or truncated fetches never mean absence."""
        def status(self, spec: Facade.CalendarIcsFeedRequest) -> Facade.CalendarIcsFeedStatus | None:
            """Reads the installed ICS configuration, real cursor and last public poll completion under owner proof, never the secret URL."""
    class _CalendarConnectorVerbs:
        def configure(self, spec: Facade.CalendarConnectorConfigureRequest) -> Facade.CalendarConnectorRegistration:
            """Installs one CalDAV seat under owner proof, with a custody reference, discovery endpoint and nonzero bounded poll cadence."""
        def get(self, spec: Facade.CalendarConnectorRequest) -> Facade.CalendarConnectorRegistration | None:
            """Reads a configured CalDAV seat, its real provider cursor, kill switch and last sync observation under owner proof."""
        def pull(self, spec: Facade.CalendarConnectorRequest) -> Facade.CalendarSyncOutcome:
            """Pulls the configured CalDAV seat through the existing import gate and echo law, returning the real cursor and sync counters under owner proof."""
        def write(self, spec: Facade.CalendarConnectorWriteRequest) -> Facade.RemoteWriteReceipt:
            """Writes a readable EVENT to the owner-installed CalDAV seat through the durable conditional-write outbox, never a blind overwrite."""
        def kill(self, spec: Facade.CalendarConnectorKillRequest) -> Facade.CalendarConnectorRegistration:
            """Kills a CalDAV seat under owner proof, revoking its advertised verbs and stopping further polling and writes without erasing calendar evidence."""
    class _CalendarImipVerbs:
        def configure(self, spec: Facade.CalendarImipTransportConfig) -> Facade.CalendarImipTransportConfig:
            """Installs the host iMIP mail submission endpoint and custody name under owner proof; this configuration grants no invite consent or sending identity."""
        def get(self, spec: Facade.EmptyRequest | None = None) -> Facade.CalendarImipTransportConfig | None:
            """Reads the installed host iMIP submission endpoint and custody name under owner proof, never its credential value."""

# END GENERATED FACADE VERBS
```
