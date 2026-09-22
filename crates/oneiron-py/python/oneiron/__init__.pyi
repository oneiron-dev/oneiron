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
    def as_actor(self, actor_key: str) -> "Oneiron": ...
    # BEGIN GENERATED FACADE VERBS
    def witness(self, turn: WitnessTurn) -> WitnessReceipt: ...
    def claim_upsert(self, claim: ClaimInput) -> CommitReceipt: ...
    def recall(
        self,
        query: str,
        *,
        effort: Effort = "medium",
        scope: RecallScope | None = None,
        limit: int = 10,
        format: PackFormat | None = None,
    ) -> MemoryPack: ...
    def receipts(self, limit: int = 100) -> list[FacadeReceipt]: ...
    def key_value_get(self, request: KeyValueAddress) -> KeyValueItem | None: ...
    def key_value_put(self, request: KeyValuePut) -> KeyValuePutReceipt: ...
    def key_value_delete(self, request: KeyValueAddress) -> KeyValueDeleteReceipt: ...
    def key_value_search(self, request: KeyValueSearch) -> list[KeyValueItem]: ...
    def key_value_namespaces(self, request: KeyValueNamespaces) -> list[list[str]]: ...

# END GENERATED FACADE VERBS
