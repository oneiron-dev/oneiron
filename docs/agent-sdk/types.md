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

/** Retrieval effort dial. `high`, `xhigh` and `max` need a budget lease and return `LEASE_REQUIRED` without one. */
export type Effort = "light" | "medium" | "high" | "xhigh" | "max"

/** Rendered pack formats; these are the engine's exact tokens. */
export type PackFormat = "json" | "yaml" | "toon" | "md" | "txt"

/** Recall scoping: narrowing only; unset is the vault floor. */
export type RecallScope = {
  worldRef?: string
  facet?: string
}

/** Options for {@link Oneiron.recall}. */
export type RecallOptions = {
  /** Defaults to `medium`. */
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
  partial: boolean
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

from .agent_verbs import TasksVerbs, RoomsVerbs
import os
from typing import Any, Literal, NotRequired, TypedDict

__all__ = ["Oneiron", "OneironError"]

WitnessAuthor = Literal["user", "companion", "system"]
Effort = Literal["light", "medium", "high", "xhigh", "max"]
PackFormat = Literal["json", "yaml", "toon", "md", "txt"]

class WitnessMessage(TypedDict):
    id: NotRequired[str]
    author: WitnessAuthor
    message_type: str
    content: str
    metadata: NotRequired[dict[str, Any] | None]
    is_visible: NotRequired[bool]
    order: int

class WitnessTurn(TypedDict):
    conversation_ref: str
    turn_ref: NotRequired[str | None]
    messages: list[WitnessMessage]
    # Unix seconds; omitted is stamped at the call boundary.
    occurred_at: NotRequired[int]

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

class MemoryProvenance(TypedDict):
    source: str
    source_revision_ids: list[str]
    evidence_turn_ids: list[str]

class MemoryItem(TypedDict):
    short_id: str
    kind: str
    predicate: str | None
    value_text: str
    confidence: float
    hedge_bucket: str
    provenance: MemoryProvenance
    world: str | None
    facet: str | None
    salience: float | None

class ScopeHonesty(TypedDict):
    out_of_scope_worlds: list[str]

class RetrievalMeta(TypedDict):
    partial: bool
    sparse: bool | None
    total_candidates: int
    claims_returned: int
    deep_pending: bool | None

class MemoryPack(TypedDict):
    items: list[MemoryItem]
    scope_honesty: ScopeHonesty
    retrieval_meta: RetrievalMeta
    # Always equal to the engine's MEMORY_PACK_VERSION, and to this package's major.
    pack_version: int
    rendered: str | None

class FacadeReceipt(TypedDict):
    receipt_ref: str
    outcome: str
    created_at: int
    reason_codes: list[str]
    actor_class: str
    actor_ref: str | None
    content_kind: str
    claim_ref: str | None


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

class TasksOverflow(TypedDict):
    known_omitted_rows: int
    source_exhausted: bool

class TasksSectionDescription(TypedDict):
    kind: Literal["tasks_section"]
    rows: list[dict[str, Any]]
    overflow: TasksOverflow | None

class TaskCardDescription(TypedDict):
    kind: Literal["task_card"]
    lines: list[str]

TaskDescription = TasksSectionDescription | TaskCardDescription

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

class OneironError(RuntimeError):
    code: str
    message: str
    suggestions: tuple[str, ...]
    def __init__(self, code: str, message: str, suggestions: list[str]) -> None: ...

class Oneiron:
    tasks: TasksVerbs
    rooms: RoomsVerbs
    @classmethod
    def open(
        cls,
        path: str | os.PathLike[str] | None = None,
        *,
        dimensions: int | None = None,
    ) -> "Oneiron": ...
    @classmethod
    def connect(cls, url: str, key: str) -> "Oneiron": ...
    @classmethod
    def pair(cls, link: str) -> tuple["Oneiron", str]: ...
    def as_actor(self, actor_key: str) -> "Oneiron": ...
# BEGIN GENERATED FACADE VERBS
    def cancel(self, task_ref: str) -> TaskCancelReceipt: ...
    def describe(self, task_ref: str | None = None) -> TaskDescription: ...
    def witness(self, turn: WitnessTurn) -> WitnessReceipt: ...
    def claim_upsert(self, claim: ClaimInput) -> CommitReceipt: ...
    def recall(self, query: str, *, effort: Effort = 'medium', scope: RecallScope | None = None, limit: int = 10, format: PackFormat | None = None) -> MemoryPack: ...
    def receipts(self, limit: int = 100) -> list[FacadeReceipt]: ...
    def key_value_get(self, request: KeyValueAddress) -> KeyValueItem | None: ...
    def key_value_put(self, request: KeyValuePut) -> KeyValuePutReceipt: ...
    def key_value_delete(self, request: KeyValueAddress) -> KeyValueDeleteReceipt: ...
    def key_value_search(self, request: KeyValueSearch) -> list[KeyValueItem]: ...
    def key_value_namespaces(self, request: KeyValueNamespaces) -> list[list[str]]: ...
    def can(self, request: TaskCanAskRequest) -> TaskAskPreflight: ...
    def peek(self, request: TaskAskHandle) -> list[TaskAskPersonEvidence]: ...

# END GENERATED FACADE VERBS
```
