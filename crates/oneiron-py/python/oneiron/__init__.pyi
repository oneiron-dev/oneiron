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
from ._facade_verbs import _FacadeVerbs

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
    # The records this reply names as cited or created, judged by the engine under the writer's own read; omitted asserts nothing.
    assertions: NotRequired[Facade.WitnessAssertions]

class WitnessReceipt(TypedDict):
    turn_short_id: str
    message_short_ids: list[str]
    # Always begins `witness:`.
    receipt_ref: str
    # What the wake this turn owes its actor's armed programs came to; None
    # when it owes none.
    wake_outcome: NotRequired[Facade.TurnProgramWakeOutcome | None]

class ClaimInput(TypedDict):
    id: NotRequired[str]
    predicate: str
    subject_ref: str
    value: Any
    confidence: float
    source: str
    world_ref: NotRequired[str | None]
    relationship_ref: NotRequired[list[str] | None]
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
    narrowing: Facade.ScopedReadReceipt
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
# context for a model round trip only; empty when absent. `stream`
# (FIX 11399): the profile the answer is framed in; a patch-profile caller
# takes the card's refinement beside a local action's `$state`.
LensFrameEventRequest = TypedDict(
    "LensFrameEventRequest",
    {
        "event": Facade.GeneratedUiActionEvent,
        "idempotencyKey": str,
        "selectedContext": NotRequired[list[str]],
        "stream": NotRequired[Facade.GeneratedUiStreamProfile],
    },
)
LensFrameLocalReply = TypedDict(
    "LensFrameLocalReply",
    {
        "$state": Facade.GeneratedUiStateSnapshot,
        "refinement": NotRequired[Facade.GeneratedUiSegment | None],
    },
)
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
    # What keeps the install's checkpoint signing seed at rest, as the owner is told it.
    assurance: Literal["hardware", "platform", "software", "process"]
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

class ExportReceipt(TypedDict):
    # The archive manifest's format: "archive" or "okf".
    format: str
    # The archive's length in bytes.
    bytes: int
    # BLAKE3 of the archive, lowercase hex.
    digest: str
    # Each world the owner's own export carries that his recipient choice
    # would keep from where it goes, and why (owner ruling 1-EXPORT = B).
    notices: NotRequired[list[Facade.WorldRecipientNotice]]
    # Each other member's personal mailbox the owner's own export left out,
    # and why (fix list row 15416).
    mailbox_notices: NotRequired[list[Facade.MailboxExportNotice]]

class NativeLimitQuestion(TypedDict):
    # The [limits] row key that asked.
    row: str
    # What the row stood at for the work, exact.
    bound: int
    # What the work measured, exact.
    measured: int

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
    # The refusal's stable reason codes, in its producer's order (FIX 7398).
    reason_codes: tuple[str, ...] | None
    legal_hold: Facade.LegalHoldNotice | None
    room_join_hold: Facade.RoomJoinHold | None
    def __init__(
        self,
        code: str,
        message: str,
        suggestions: list[str],
        wrong_root: dict[str, str] | None = None,
        hook: dict[str, Any] | None = None,
        retry_after: int | None = None,
        resets_at: list[int] | None = None,
        reason_codes: list[str] | None = None,
        legal_hold: Facade.LegalHoldNotice | None = None,
        room_join_hold: Facade.RoomJoinHold | None = None,
    ) -> None: ...

class Oneiron(_FacadeVerbs):
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
        hold_checkpoint_root_signer: bool | None = None,
    ) -> HostRootOpened:
        """open, then this install's machine profile from the vault's host root secret's exact bytes (FIX 5342)."""
    @classmethod
    def connect(cls, url: str, key: str) -> "Oneiron": ...
    @classmethod
    def pair(cls, link: str) -> Paired: ...
    def as_actor(self, actor_key: str) -> "Oneiron": ...
    def in_room_turn(self, room_ref: str) -> "Oneiron": ...
    def in_off_record_session(self, session_ref: str) -> "Oneiron": ...
    def with_read_credential(self, credential: str) -> "Oneiron": ...
    def last_receipt_ref(self) -> str | None: ...
    def last_hook_notice(self) -> str | None: ...
    def native_limit_questions(self) -> list[NativeLimitQuestion] | None:
        """The engine-limit crossings this client's own vault kept; None on a remote, attached, or rebound view."""
    def retry(self, pending: OneironError, verb: str, input: Any) -> Any:
        """Resends a PENDING_ASK call under its invocation; the reply is the verb's shared wire JSON."""
    def lens_frame_event(self, card_id: str, request: LensFrameEventRequest) -> LensFrameEventReply:
        """Sends one event on a lens card the connected server rendered; embedded raises BAD_REQUEST."""
    def close_lens_frame(self, card_id: str) -> CloseLensFrameReply:
        """Closes a lens card the connected server rendered and frees its frame."""
    def export_to(
        self, path: str | os.PathLike[str], format: str | None = None
    ) -> ExportReceipt:
        """Exports the whole vault into the file at ``path``; answers its receipt."""
    @staticmethod
    def vault_secrets_custody_seal(
        view: Facade.SecretCustodyViewReply,
        change: str,
        holder: str | None,
        recipients: list[str],
        body: bytes,
    ) -> Facade.SecretCustodySubmitRequest:
        """Seals a custody register or rotate on the caller's own side; answers the custody.submit input."""
