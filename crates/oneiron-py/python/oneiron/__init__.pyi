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
    # A new project room thread root's audience; fixed once set.
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

class MemoryItem(TypedDict):
    short_id: str
    source_revision_ref: NotRequired[str]
    kind: str
    predicate: str | None
    value_text: str
    confidence: float
    hedge_bucket: str
    provenance: MemoryProvenance
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
    short_id: NotRequired[str]
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

class MemoryPack(TypedDict):
    items: list[MemoryItem]
    scope_honesty: ScopeHonesty
    retrieval_meta: RetrievalMeta
    # Always equal to the engine's MEMORY_PACK_VERSION, and to this package's major.
    pack_version: int
    rendered: str | None

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

# OF-181: a host-rendered lens card's event and close. These keep the wire's
# camelCase keys: they are the server route's bodies, not snake_case DTOs.
LensFrameEventRequest = TypedDict(
    "LensFrameEventRequest",
    {"event": Facade.GeneratedUiActionEvent, "idempotencyKey": str},
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

class OneironError(RuntimeError):
    code: str
    message: str
    suggestions: tuple[str, ...]
    wrong_root: dict[str, str] | None
    # The verb hook's stop; on PENDING_ASK `{"status": "pending", "invocation", "ask"}`.
    hook: dict[str, Any] | None
    def __init__(
        self,
        code: str,
        message: str,
        suggestions: list[str],
        wrong_root: dict[str, str] | None = None,
        hook: dict[str, Any] | None = None,
    ) -> None: ...

class Oneiron:
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
    def report(self, spec: Facade.ReportRequest) -> Facade.ReportReceipt:
        """Files one feedback report on a skill or run: its subject, category and evidence; the host supplies the actor."""
    @property
    def self(self) -> "Oneiron._SelfVerbs": ...
    @property
    def vault(self) -> "Oneiron._VaultVerbs": ...
    def cancel(self, task_ref: str) -> TaskCancelReceipt: ...
    def steer(self, spec: Facade.SteerRequest) -> Facade.SteerReceipt:
        """The TASK's spawner nudges its live run; a resend with the same key answers the first receipt."""
    def describe(self, task_ref: str | None = None) -> TaskDescription: ...
    @property
    def tasks(self) -> "Oneiron._TasksVerbs": ...
    @property
    def reveal(self) -> "Oneiron._RevealVerbs": ...
    def can(self, request: TaskCanAskRequest) -> TaskAskPreflight: ...
    def peek(self, request: TaskAskHandle) -> list[TaskAskPersonEvidence]: ...
    @overload
    def ask(self, spec_or_who: Facade.TaskAskRequest) -> Facade.TaskAskReceipt: ...
    @overload
    def ask(self, spec_or_who: str | list[str] | set[str] | tuple[str, ...] | dict[str, Any] | None, what: dict[str, Any], until: int | None = None, default: str = "ask_me") -> Facade.TaskAskReceipt: ...
    def wait(self, handle: Facade.TaskAskHandle, step_key: str = "sdk.wait") -> Facade.TaskAskWait:
        """Waits on an ask at a step with no other work: pending, changed, ready with its result, or a park for code mode."""
    @property
    def ai(self) -> "Oneiron._AiVerbs": ...
    @property
    def connector(self) -> "Oneiron._ConnectorVerbs": ...
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
        def off_record(self) -> "Oneiron._SelfOffRecordVerbs": ...
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
        @property
        def agents(self) -> "Oneiron._SelfAgentsVerbs": ...
        @property
        def leader(self) -> "Oneiron._SelfLeaderVerbs": ...
    class _SelfFocusVerbs:
        @property
        def scratchpad(self) -> "Oneiron._SelfFocusScratchpadVerbs": ...
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
        def answer(self, spec: Facade.IdentityAnswerRequest) -> Facade.IdentitySettled:
            """A vault owner's tap on an identity choice card: who a person named in their conversations is."""
        def settle(self, spec: Facade.IdentityActNowRequest) -> Facade.IdentityActNow:
            """Before acting on a person known only by a name, settles who that name is from its newest saved mention, or opens an ask."""
    class _SelfInboxVerbs:
        def list(self, spec: Facade.InboxListRequest) -> Facade.NotificationPage:
            """Lists one page of notifications delivered to the bound actor, without marking them."""
        def mark(self, spec: Facade.InboxMarkRequest) -> Facade.NotificationRow:
            """Marks one delivered notification seen or acknowledged for the bound actor."""
        @property
        def concern(self) -> "Oneiron._SelfInboxConcernVerbs": ...
    class _SelfInboxConcernVerbs:
        def __call__(self, spec: Facade.ConcernCardRequest) -> Facade.AgentHealthCardView: ...
        def outcome(self, spec: Facade.ConcernOutcomeRequest) -> Facade.ConcernCardSummary: ...
        def move(self, spec: Facade.ConcernMoveRequest) -> Facade.ConcernMoveOutcome: ...
    class _SelfGrantsVerbs:
        def ask(self, spec: Facade.GrantAskRequest) -> Facade.GrantAskReceipt:
            """Asks a person for access on the caller's behalf; the request grants nothing until the vault owner approves it."""
    class _SelfBudgetVerbs:
        def __call__(self, spec: Facade.SelfBudgetRequest) -> Facade.AgentBudgetView:
            """The caller's own dispatched attempt: its persisted spend allowance, landing reserve, checkpoint and saved hold, without substituting a token meter for money."""
        def land(self, spec: Facade.BudgetLandRequest) -> Facade.PartialResultHold:
            """The worker parks its own dispatched attempt at its budget hold with its lease fence and exact checkpoint; the same run keeps its partial results and resumes later."""
    class _SelfCredentialVerbs:
        def attenuate(self, spec: Facade.CredentialAttenuationRequest) -> Facade.CredentialAttenuated:
            """Appends a holder-signed caveat to the caller's own slip, optionally transferring it to a recipient public key. Existing caveats and live parent authority remain binding; no actor or grant is minted."""
    class _SelfOffRecordVerbs:
        def execute(self, spec: Facade.OffRecordExecuteRequest) -> Facade.OffRecordExecuted:
            """The session's creator or the vault's owner runs one entry of a durable code-mode run bound to an off-record session; its rows and spilled outputs stay in the room until close."""
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
        def open(self, spec: Facade.LiveRunRequest[Facade.OpenInput]) -> Facade.ObservationPage:
            """Opens a URL in the attached run's own browser session and observes the page; a long page's observation comes in pages, read on with observe and its next cursor."""
        def observe(self, spec: Facade.LiveRunRequest[Facade.ObserveInput]) -> Facade.ObservationPage:
            """Observes the current page of the attached run's browser session, in pages read on with observe and an answer's next cursor; the verbs follow a tab an act opens, or a closed tab's opener, and name the move as switched."""
        def find(self, spec: Facade.LiveRunRequest[Facade.FindInput]) -> Facade.FindOutput:
            """Finds the page rows whose role and name match, in pages: an answer with next goes on, and find with that cursor reads the next page."""
        def click(self, spec: Facade.LiveRunRequest[Facade.ClickInput]) -> Facade.ObservationPage:
            """Clicks one page target and observes the result; a long page's observation comes in pages, read on with observe and its next cursor."""
        def click_at(self, spec: Facade.LiveRunRequest[Facade.PointInput]) -> Facade.ObservationPage:
            """Clicks a point of a held screenshot, mapped onto the viewport; a long page's observation comes in pages, read on with observe and its next cursor."""
        def type(self, spec: Facade.LiveRunRequest[Facade.TypeInput]) -> Facade.ObservationPage:
            """Types text into one page target and observes the result; a long page's observation comes in pages, read on with observe and its next cursor."""
        def select(self, spec: Facade.LiveRunRequest[Facade.SelectInput]) -> Facade.ObservationPage:
            """Picks the option of a select element by its label, text or value; a long page's observation comes in pages, read on with observe and its next cursor."""
        def wait_for(self, spec: Facade.LiveRunRequest[Facade.WaitForInput]) -> Facade.WaitForOutput:
            """Waits until a page row its refs name, or else some row matching a role and name, is there; many rows come in pages, read on with find and its next cursor."""
        def expect(self, spec: Facade.LiveRunRequest[Facade.ExpectInput]) -> Facade.ExpectOutput:
            """Checks that a page row is present or absent, and holds a given value."""
        def screenshot(self, spec: Facade.LiveRunRequest[Facade.ScreenshotInput]) -> Facade.ScreenshotOutput:
            """Takes a screenshot the session holds, by image ref and never captioned."""
        def view(self, spec: Facade.LiveRunRequest[Facade.ViewInput]) -> Facade.ImageOutput:
            """Reads back a held image by its ref."""
        def crop(self, spec: Facade.LiveRunRequest[Facade.CropInput]) -> Facade.ImageOutput:
            """Crops a held image to a rectangle."""
        def zoom(self, spec: Facade.LiveRunRequest[Facade.ZoomInput]) -> Facade.ImageOutput:
            """Zooms into a rectangle of a held image."""
        def batch(self, spec: Facade.LiveRunRequest[Facade.BatchInput]) -> Facade.BatchOutput:
            """Runs one batched program of browser steps for a subgoal, stopping at the first step that fails; a long last observation comes in pages, read on with observe and the batch's next cursor."""
        def handover(self, spec: Facade.LiveRunRequest[Facade.HandoverInput]) -> Facade.HandoverOutput:
            """Asks a person to take the browser over, saying why (to sign in or pay inside the same page); until they hand it back, every browser verb refuses browser_taken_over, and the answer after carries the takeover's record."""
    class _SelfAgentsVerbs:
        def spawn(self, spec: Facade.LiveRunRequest[Facade.AgentSpawnInput]) -> Facade.AgentSpawnOutput:
            """Spawns a child under the leased parent attached to this credential; spec states the need, work and narrowing, never the parent identity."""
    class _SelfLeaderVerbs:
        def split(self, spec: Facade.LiveRunRequest[Facade.LeaderSplitInput]) -> Facade.LeaderSplitOutput:
            """Splits the attached leader run into a subproject inside its own TASK wrapper; spec may name only the child leader and a narrower scope."""
    class _VaultVerbs:
        @property
        def people(self) -> "Oneiron._VaultPeopleVerbs": ...
        @property
        def shape(self) -> "Oneiron._VaultShapeVerbs": ...
        @property
        def fanout(self) -> "Oneiron._VaultFanoutVerbs": ...
        @property
        def budgets(self) -> "Oneiron._VaultBudgetsVerbs": ...
        def witness(self, turn: WitnessTurn) -> WitnessReceipt: ...
        @property
        def claims(self) -> "Oneiron._VaultClaimsVerbs": ...
        def recall(self, query: str, *, effort: Effort = 'medium', scope: RecallScope | None = None, limit: int = 10, format: PackFormat | None = None, as_of: int | None = None, deadline_ms: int | None = None, media: RecallMedia | None = None, query_affect: QueryAffect | None = None) -> MemoryPack: ...
        @property
        def retrieval(self) -> "Oneiron._VaultRetrievalVerbs": ...
        @property
        def affect(self) -> "Oneiron._VaultAffectVerbs": ...
        @property
        def tagging(self) -> "Oneiron._VaultTaggingVerbs": ...
        @property
        def export(self) -> "Oneiron._VaultExportVerbs": ...
        @property
        def scope(self) -> "Oneiron._VaultScopeVerbs": ...
        @property
        def receipts(self) -> "Oneiron._VaultReceiptsVerbs": ...
        @property
        def images(self) -> "Oneiron._VaultImagesVerbs": ...
        @property
        def explain(self) -> "Oneiron._VaultExplainVerbs": ...
        @property
        def kv(self) -> "Oneiron._VaultKvVerbs": ...
        @property
        def campaign(self) -> "Oneiron._VaultCampaignVerbs": ...
        @property
        def weave(self) -> "Oneiron._VaultWeaveVerbs": ...
        @property
        def skill_hubs(self) -> "Oneiron._VaultSkillHubsVerbs": ...
        @property
        def packs(self) -> "Oneiron._VaultPacksVerbs": ...
        @property
        def skills(self) -> "Oneiron._VaultSkillsVerbs": ...
        @property
        def connectors(self) -> "Oneiron._VaultConnectorsVerbs": ...
        @property
        def authority(self) -> "Oneiron._VaultAuthorityVerbs": ...
        @property
        def slim(self) -> "Oneiron._VaultSlimVerbs": ...
        @property
        def mesh(self) -> "Oneiron._VaultMeshVerbs": ...
        @property
        def inspection(self) -> "Oneiron._VaultInspectionVerbs": ...
        @property
        def shared(self) -> "Oneiron._VaultSharedVerbs": ...
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
        def cleanup(self) -> "Oneiron._VaultCleanupVerbs": ...
        @property
        def entities(self) -> "Oneiron._VaultEntitiesVerbs": ...
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
        def projects(self) -> "Oneiron._VaultProjectsVerbs": ...
        @property
        def conversations(self) -> "Oneiron._VaultConversationsVerbs": ...
        @property
        def messages(self) -> "Oneiron._VaultMessagesVerbs": ...
        @property
        def companions(self) -> "Oneiron._VaultCompanionsVerbs": ...
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
        def search(self) -> "Oneiron._VaultSearchVerbs": ...
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
            """Commits up to 256 core entity puts atomically, at the grade of the credential that sent them; an embedded handle commits below owner grade."""
        @property
        def consolidation(self) -> "Oneiron._VaultConsolidationVerbs": ...
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
    class _VaultPeopleVerbs:
        def list(self, spec: Facade.PeopleListRequest) -> Facade.PeoplePage:
            """One page of the people the caller reads, in handle order."""
        def get(self, spec: Facade.PersonRequest) -> Facade.PersonRow:
            """One person the vault knows, by their pr handle."""
    class _VaultShapeVerbs:
        def read(self, spec: Facade.EmptyRequest | None = None) -> Facade.ShapeRead:
            """The vault's stored seed and its live setup plane held as one document (ARCH-0070); a free read."""
        def plan(self, spec: Facade.ShapePlanRequest) -> Facade.ShapePlan:
            """The difference between a seed, or the stored one, and the vault, item by item at a pinned frontier; a free read that writes nothing."""
        def apply(self, spec: Facade.ShapeApplyRequest) -> Facade.ShapeApplyReceipt:
            """Lands a shape plan one item at a time through the vault's named doors, or resumes its apply; a widening lands only on the owner's word for that item."""
    class _VaultFanoutVerbs:
        def spawn(self, spec: Facade.LiveRunRequest[Facade.FanoutBatchInput]) -> Facade.FanoutBatchView:
            """Admits input-order child slots under this credential's attached live run, through the frozen fan-out approval gate and one shared parent spend tree."""
        def slots(self, spec: Facade.FanoutLaunchRequest) -> Facade.FanoutBatchView | None:
            """Reads a batch launch in input slot order, with child errors, results, reservations, settled spend and released holds from its shared parent lease tree."""
        def launch(self, spec: Facade.FanoutLaunchRequest) -> Facade.FanoutLaunchView | None:
            """One held or launched fan-out by its launch ref, with the statement frozen before it launched; readable by the vault owner, its creator, or a live lead/board holder of its project, anything else reads as none."""
        def resume(self, spec: Facade.FanoutResumeRequest) -> Facade.FanoutLaunchView:
            """The owner rules on a held fan-out launch by the digest they saw: approve once, approve and remember under a cap, or deny, which keeps the hold visible."""
        def resume_as(self, spec: Facade.FanoutResumeRequest) -> Facade.FanoutLaunchView:
            """A live lead or board holder of a held fan-out launch's project rules on it by the digest they saw: approve once, or deny, which keeps the hold visible; only the owner may remember."""
        def ack(self, spec: Facade.FanoutAckRequest) -> Facade.FanoutLaunchView:
            """The owner acknowledges the width check of a fan-out that already went out, once or remembered under a cap; nothing was held, so nothing is denied."""
    class _VaultBudgetsVerbs:
        @property
        def lease(self) -> "Oneiron._VaultBudgetsLeaseVerbs": ...
        @property
        def hold(self) -> "Oneiron._VaultBudgetsHoldVerbs": ...
        def local(self, spec: Facade.LocalRunnerBudgetRequest) -> Facade.LocalRunnerBudgetView:
            """The owner observes a device-local runner budget counter without creating it, including absence after an owner restore."""
        def settlements(self, spec: Facade.RunSettlementsRequest) -> Facade.RunSettlementsView:
            """The owner reads a served run's persisted physical-rung settlement receipts, with reservation, settled units and stamped cost when priced."""
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
        def weights(self) -> "Oneiron._VaultRetrievalWeightsVerbs": ...
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
    class _VaultRetrievalWeightsVerbs:
        def get(self, spec: Facade.EmptyRequest | None = None) -> Facade.RetrievalWeightsView:
            """The owner reads effective affect, arousal, community and semantic-edge VAD priors with the trusted manifest hash."""
        def configure(self, spec: Facade.RetrievalWeightsConfigureRequest) -> Facade.RetrievalWeightsReceipt:
            """The owner sets independent retrieval priors against the current manifest hash; zero disables each prior without changing confidence or authority."""
    class _VaultRetrievalOutcomesVerbs:
        def put(self, spec: Facade.RetrievalOutcome) -> list[Facade.RetrievalOutcomeRecord]:
            """The owner attaches an explicit observation to one local serving run; raw reward stays telemetry, never a gated training label."""
        def end(self, spec: Facade.RetrievalEndOutcome) -> list[Facade.RetrievalRunEvidence]:
            """The owner records a gate-attributed turn outcome for its exact contributing retrievalRunIds; the engine validates the links and shapes the reward."""
    class _VaultAffectVerbs:
        @property
        def annotations(self) -> "Oneiron._VaultAffectAnnotationsVerbs": ...
        @property
        def claims(self) -> "Oneiron._VaultAffectClaimsVerbs": ...
    class _VaultAffectAnnotationsVerbs:
        def put(self, spec: Facade.AffectAnnotationPut) -> Facade.CommitReceipt:
            """Writes one sourced TURN VAD annotation through ordinary scoped claim admission and the caller credential; the receipt states its approval."""
    class _VaultAffectClaimsVerbs:
        def consolidate(self, spec: Facade.AffectClaimConsolidateRequest) -> Facade.AffectClaimConsolidation:
            """The owner consolidates a claim from stored TURN VAD evidence, updating only derived affect state and semantic-edge VAD through the existing engine transaction."""
    class _VaultTaggingVerbs:
        def status(self, spec: Facade.TaggingTurnRequest) -> Facade.TaggingStatusView:
            """Reads one turn tagging marker as pending retrying settled or failed, with the configured checkpoint, serving model, live marker and failure reason."""
        def tags(self, spec: Facade.TaggingTurnRequest) -> Facade.TaggingTagsView:
            """Reads the tags saved for one turn: mention spans and targets, coreference, mood, PII and other labels, and the derivation that made them."""
        def history(self, spec: Facade.TaggingTurnRequest) -> Facade.TaggingHistoryView:
            """Reads one turn recorded tagging traces oldest first: each attempt, checkpoint, model, try number and saved shadowed skipped or failed outcome."""
        def mentions(self, spec: Facade.TaggingMentionsRequest) -> Facade.TaggingMentionsView:
            """Reads the saved tagger mentions naming one entity, bounded by limit and each served only while its turn reads for the caller."""
    class _VaultExportVerbs:
        def __call__(self, format: PackFormat | None = None) -> dict[str, Any]: ...
        def scoped(self, spec: Facade.ScopedExportRequest) -> Facade.ScopedExport:
            """Exports rows selected under the caller credential and named channel, preserving the engine export fences and provenance withholding."""
    class _VaultScopeVerbs:
        def ceiling(self, spec: Facade.EmptyRequest | None = None) -> Facade.CredentialCeiling:
            """Reads the caller credential ceiling as a typed ceiling, never as a record position."""
    class _VaultReceiptsVerbs:
        def __call__(self, limit: int = 100, kinds: list[str] | None = None) -> list[FacadeReceipt]: ...
        def get(self, spec: Facade.CallReceiptRequest) -> Facade.CallReceipt | None:
            """One call receipt by ref, readable by its own actor or the vault's live owner; anything else reads as none."""
        def context(self, spec: Facade.CallReceiptRequest) -> Facade.ContextEmitReceipt | None:
            """Read the frozen context of one actual reply emit, as its actor or the live vault owner; never rebuild the assembly."""
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
        def program(self) -> "Oneiron._VaultCampaignProgramVerbs": ...
    class _VaultCampaignProgramVerbs:
        def create(self, spec: Facade.CreateCampaignProgramRequest) -> Facade.CampaignProgramRecord:
            """Creates a campaign program (ordered steps and an optional saved-query audience) under a campaign the caller owns."""
        def read(self, spec: Facade.CampaignProgramReadRequest) -> Facade.CampaignProgramReadResult:
            """One campaign program under a campaign the caller owns, with whether its audience gets automatic intake now."""
        def update(self, spec: Facade.UpdateCampaignProgramRequest) -> Facade.CampaignProgramRecord:
            """Replaces a campaign program's name, steps and audience whole under a version check; work queued at a dropped step stops."""
        def archive(self, spec: Facade.ArchiveCampaignProgramRequest) -> Facade.CampaignProgramRecord:
            """Archives a campaign program: it stays readable, enrolls no one, and its queued enrollment work stops."""
    class _VaultWeaveVerbs:
        def report(self, spec: Facade.WeaveReportRequest) -> Facade.WeaveReportView:
            """The live weave report for the bound actor, read through its own scope and the vault's weave policy for its role."""
        def digest(self, spec: Facade.WeaveDigestRequest) -> Facade.WeaveDigestView | None:
            """One of the bound actor's saved weave digests, or the newest, under the current read policy. Its lens is a card; a server holds its frame for the card's events, an embedded handle holds none."""
        def lens(self, spec: Facade.WeaveReportRequest) -> Facade.LensFrameCard:
            """Renders the caller's live weave report through the weave-report skill on the server's model, as a card whose wrong controls are its declared actions; the server holds its frame for the card's events."""
        @property
        def link(self) -> "Oneiron._VaultWeaveLinkVerbs": ...
        @property
        def owner(self) -> "Oneiron._VaultWeaveOwnerVerbs": ...
        @property
        def item(self) -> "Oneiron._VaultWeaveItemVerbs": ...
    class _VaultWeaveLinkVerbs:
        def wrong(self, spec: Facade.WeaveWrongLinkRequest) -> Facade.WeaveLinkCorrectionView:
            """A person labels a link in their own lens as wrong; the label teaches the loops and the link stays."""
    class _VaultWeaveOwnerVerbs:
        @property
        def link(self) -> "Oneiron._VaultWeaveOwnerLinkVerbs": ...
        @property
        def item(self) -> "Oneiron._VaultWeaveOwnerItemVerbs": ...
    class _VaultWeaveOwnerLinkVerbs:
        def wrong(self, spec: Facade.WeaveWrongLinkRequest) -> Facade.WeaveLinkCorrectionView:
            """The owner labels a link in the owner lens as wrong, under the owner's own credential; the label teaches the loops and the link stays."""
    class _VaultWeaveOwnerItemVerbs:
        def wrong(self, spec: Facade.WeaveWrongItemRequest) -> Facade.WeaveItemCorrectionView:
            """The owner labels a claim, project or budget item in the owner lens as wrong, under the owner's own credential; the label teaches the loops and the record stays."""
    class _VaultWeaveItemVerbs:
        def wrong(self, spec: Facade.WeaveWrongItemRequest) -> Facade.WeaveItemCorrectionView:
            """A person labels a claim, project or budget item in their own lens as wrong; the label teaches the loops and the record stays."""
    class _VaultSkillHubsVerbs:
        def put(self, spec: Facade.SkillHubPutRequest) -> Facade.SkillHubConfigured:
            """The owner registers or revises a hub source; hub trust never grants activation authority."""
        def get(self, spec: Facade.SkillHubRequest) -> Facade.SkillHubRecord:
            """Reads one configured hub as the owner."""
        @property
        def publishers(self) -> "Oneiron._VaultSkillHubsPublishersVerbs": ...
        @property
        def refs(self) -> "Oneiron._VaultSkillHubsRefsVerbs": ...
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
            """The owner installs a pack folder, or replaces the pack installed under its name; the put is the consent for its hooks."""
        @property
        def connector(self) -> "Oneiron._VaultPacksConnectorVerbs": ...
        def remove(self, spec: Facade.PackRemoveRequest) -> Facade.PackInstallReceipt:
            """The owner removes an installed pack: it leaves the Active catalog and its hook bindings stop; a built-in goes back to its Candidate."""
        @property
        def setup(self) -> "Oneiron._VaultPacksSetupVerbs": ...
    class _VaultPacksHooksVerbs:
        def bind(self, spec: Facade.HubHookBindRequest) -> list[Facade.EntityId]:
            """The owner consents to the installed pack hook capabilities, including a widening update; publisher identity stays foreign."""
        def list(self, spec: Facade.EmptyRequest | None = None) -> list[Facade.HubHookBindingRow]:
            """Reads live pack hook bindings as the owner, excluding revoked foreign publisher grants."""
        def qualify(self, spec: Facade.HubHookQualifyRequest) -> Facade.HubHookQualificationReceipt:
            """The owner qualifies a Candidate hub hook pack by real sandbox replay; qualification does not consent to wider hooks."""
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
    class _VaultPacksSetupVerbs:
        def prepare(self, spec: Facade.PackSetupRequest) -> Facade.PackSetupReceipt:
            """The owner opens, or resumes, a pack's guided setup; opening grants nothing."""
        def get(self, spec: Facade.PackSetupRequest) -> Facade.PackSetupReceipt:
            """A pack's guided setup as it stands, for the owner."""
        def answer(self, spec: Facade.PackSetupAnswerRequest) -> Facade.PackSetupReceipt:
            """The owner's one typed answer or card action in a pack's guided setup; a credential value never passes here."""
        def verify(self, spec: Facade.PackSetupVerifyRequest) -> Facade.PackSetupReceipt:
            """Checks one pack connection with the engine's fixed read-only provider call for its declared check."""
    class _VaultSkillsVerbs:
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
            """The owner forks a stored skill under a new identity through the existing fork law; retained parent/version and hub ancestry remain inspectable."""
        @property
        def rules(self) -> "Oneiron._VaultSkillsRulesVerbs": ...
        @property
        def code_auto_install(self) -> "Oneiron._VaultSkillsCodeAutoInstallVerbs": ...
        @property
        def permissions(self) -> "Oneiron._VaultSkillsPermissionsVerbs": ...
        def pack_receipt(self, spec: Facade.SkillPackReceiptRequest) -> Facade.SkillPackReceipt:
            """Reads a terminal pack receipt with its frozen loaded versions and actual-use attribution as the owner."""
        @property
        def outcomes(self) -> "Oneiron._VaultSkillsOutcomesVerbs": ...
    class _VaultSkillsRulesVerbs:
        def set(self, spec: Facade.SkillHashRuleRequest) -> Facade.HubConsentReceipt:
            """The owner sets or clears a known-bad canonical skill hash rule, independently of advisory scanner prose."""
    class _VaultSkillsCodeAutoInstallVerbs:
        def set(self, spec: Facade.SkillCodeAutoInstallRequest) -> Facade.HubConsentReceipt:
            """The owner sets the code auto-install switch through its existing consent gate; the switch grants no sandbox qualification."""
    class _VaultSkillsPermissionsVerbs:
        def approve(self, spec: Facade.HubSkillPermissionRequest) -> Facade.HubConsentReceipt:
            """The owner answers one imported skill permission ask at its exact hub source."""
    class _VaultSkillsOutcomesVerbs:
        def project(self, spec: Facade.SkillPackOutcomeRequest) -> Facade.SkillPackOutcomeProjection:
            """Projects the owner's anchored verdict through existing attributed pack outcomes; loading or calling alone never earns a reliability win."""
        def get(self, spec: Facade.SkillPackCreditRequest) -> Facade.LateCreditReceipt | None:
            """Reads the persisted anchored pack credit receipt, including its execution context, direct subjects and lineage shares, as the owner."""
    class _VaultConnectorsVerbs:
        @property
        def subscriptions(self) -> "Oneiron._VaultConnectorsSubscriptionsVerbs": ...
    class _VaultConnectorsSubscriptionsVerbs:
        def put(self, spec: Facade.ChannelSubscriptionRequest) -> Facade.ChannelMessageSubscription:
            """The owner subscribes an agent to the messages a built-in channel (slack or line) routes to it, so each one wakes the agent to answer."""
        def list(self, spec: Facade.ChannelSubscriptionsRequest) -> Facade.ChannelSubscriptions:
            """An agent's connector event subscriptions, standing and revoked, for the owner."""
        def revoke(self, spec: Facade.ChannelSubscriptionRevokeRequest) -> Facade.ChannelSubscriptionRevoked:
            """The owner stops one connector event subscription; the agent's key for the channel stays."""
    class _VaultAuthorityVerbs:
        def audit(self, spec: Facade.AuthorityAuditQuery) -> Facade.AuthorityAuditPage:
            """One page of the dated authority log audit, for the owner: grants, revokes and confirms. On a vault that adopted a checkpoint image a page can also carry cold, checkpoint-attested rows it does not store, with no clock or kind."""
        @property
        def history(self) -> "Oneiron._VaultAuthorityHistoryVerbs": ...
        @property
        def handoff_alarms(self) -> "Oneiron._VaultAuthorityHandoffAlarmsVerbs": ...
    class _VaultAuthorityHistoryVerbs:
        def export(self, spec: Facade.EmptyRequest | None = None) -> Facade.SignedAuthorityHistory:
            """Exports the full original signed authority history, including quarantined forks, as base64 envelopes for the owner. No signing secret leaves."""
        def import_(self, spec: Facade.SignedAuthorityHistory) -> Facade.AuthorityHistoryImported:
            """Imports original base64 signed authority envelopes atomically for the owner, preserving bytes and refolding locally. Invalid signatures, foreign genesis and missing parents write nothing."""
    class _VaultAuthorityHandoffAlarmsVerbs:
        def __call__(self, spec: Facade.EmptyRequest | None = None) -> list[Facade.AuthorityHandoffAlarm]:
            """Every saved authority handoff fork alarm, for the owner."""
        def acknowledge(self, spec: Facade.HandoffAlarmRequest) -> Facade.AuthorityHandoffAlarm:
            """The owner acknowledges one saved handoff fork alarm."""
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
        def execute(self, spec: Facade.SharedActRequest) -> Facade.SharedActExecuted:
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
    class _VaultMembersVerbs:
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
            """The vault owner names another live person of the vault as their trusted contact, reached on one outbound channel verb, with an ask-first dial; naming again replaces it and needs the contact's consent again."""
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
            """The vault owner changes whether they are asked before their trusted contact is reached (ask_first or just_call); the contact's consent stands."""
    class _VaultTrustedContactsTierVerbs:
        def set(self, spec: Facade.TrustedContactTierRequest) -> Facade.TrustedContactTierSet:
            """The vault owner names the trusted-contact tier (concern or imminent) of one RouteToHelp policy row; a row never named is a concern."""
    class _VaultTrustedContactsConcernVerbs:
        def asks(self, spec: Facade.TrustedContactAsksRequest) -> list[Facade.TrustedContactAsk]:
            """The vault owner reads their open asks to reach a trusted contact, each raised by a RouteToHelp the policy gate settled."""
        def authorize(self, spec: Facade.TrustedContactAuthorizeRequest) -> Facade.TrustedContactAuthorization:
            """The vault owner answers one open ask, once: a yes stages the fact-of-concern notice (staged, not delivered) and returns the notices that tell the person and the model; a no or a superseded ask stages nothing."""
        def propose(self, spec: Facade.TrustedContactConcernRequest) -> Facade.TrustedContactConcernProposal:
            """The owner's policy gate reads one message the caller reads, fresh; a RouteToHelp asks the owner or stages a just-call notice, and the answer carries only the fact of concern, the gate receipt, open asks and notices."""
        def deliver(self, spec: Facade.TrustedContactDeliverRequest) -> Facade.TrustedContactDeliveryReceipt | None:
            """The caller sends the next staged fact-of-concern notice it is the stored sender of, as itself, through the consent-checked outbound dispatch; null when none is eligible, never another sender's notice."""
    class _VaultGuestsVerbs:
        def revoke(self, spec: Facade.GuestRevokeRequest) -> Facade.GuestRevokeResponse: ...
        def mint_slip(self, spec: Facade.GuestSlipMintRequest) -> Facade.GuestSlipMinted:
            """The owner mints an ask guest's capability slip, bound to its grant, for the public key the guest generated on their own device."""
    class _VaultSupportGrantsVerbs:
        def mint(self, spec: Facade.SupportGrantMintRequest) -> Facade.SupportGrantMintAnswer:
            """The owner mints our support person or agent a time-limited, revocable grant, bound to that party's own key, inside explicit bounds."""
        def list(self, spec: Facade.SupportGrantListRequest) -> Facade.SupportGrantList:
            """The owner lists the vault's support grants, newest first, with each one's bounds, deadline, status and revoke command."""
        def revoke(self, spec: Facade.SupportGrantRevokeRequest) -> Facade.SupportGrantRevokeAnswer:
            """The owner revokes one support grant; what support already read is not recalled."""
    class _VaultResidenceVerbs:
        def mode(self, spec: Facade.ResidenceModeRequest) -> Facade.ResidenceModeAnswer:
            """Switches one of the owner's machines between opened and all residence; that machine's own sync connection applies it. A machine this host does not reach answers state queued, naming the directive."""
        def open(self, spec: Facade.ResidenceOpenRequest) -> Facade.ResidenceOpenAnswer:
            """Opens one item on the named machine and reports local or home residence; a NOTE includes typed text, its version and requested stable anchors. A machine this host does not reach answers state queued, naming the directive."""
        def index(self, spec: Facade.ResidenceMachineRequest) -> Facade.ResidenceIndexAnswer:
            """The thin index one of the owner's machines holds, window by window: what exists, never a body. A machine this host does not reach answers state queued, naming the directive."""
        def prune(self, spec: Facade.ResidencePruneRequest) -> Facade.ResidencePruneAnswer:
            """Drops the opened-item caches one of the owner's machines last touched before a time. A machine this host does not reach answers state queued, naming the directive."""
    class _VaultOffRecordVerbs:
        def start(self, spec: Facade.OffRecordStartRequest) -> Facade.OffRecordSessionView:
            """The vault's owner, or a person or agent who then manages it with the owner, enters an off-record session alone, off record or anonymous; nothing of it reaches the vault unless the owner promotes or saves it."""
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
    class _VaultOffRecordNotesVerbs:
        def create(self, spec: Facade.OffRecordNoteRequest) -> Facade.EntityRefReceipt:
            """The session's creator or the vault's owner writes one NOTE into an off-record session through its handle; it lands in the room, never in the vault, and close drops it."""
    class _VaultOffRecordClaimsVerbs:
        def upsert(self, spec: Facade.OffRecordClaimRequest) -> Facade.CommitReceipt:
            """The session's creator or the vault's owner admits one claim into an off-record session through its handle and the gate; it lands in the room beside the vault heads, and close drops it."""
    class _VaultRecordsVerbs:
        def erase_preview(self, spec: Facade.RecordEraseRequest) -> Facade.RecordErasePreview:
            """What erasing one record would take: the brief grants it revokes, the records holding the same bytes and the LFS chunks it shares, with the digest erase_confirm takes back."""
        def erase_confirm(self, spec: Facade.RecordEraseConfirmRequest) -> Facade.RecordEraseOutcome:
            """Erase the record the caller previewed, once its preview still has the digest they confirmed; in a shared vault a held record starts its own erase act instead."""
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
    class _VaultEvalsCohortsVerbs:
        def setup(self, spec: Facade.EvalCohortSetup) -> Facade.EvalAuthoringReport:
            """The owner sets up sealed cohorts from a pinned real inventory through the existing family, case and audited cut doors. Reports refused decisions; never serves sealed content or fabricates labels or skill provenance."""
    class _VaultCleanupVerbs:
        def run(self, spec: Facade.CleanupRunRequest) -> Facade.CleanupRunView:
            """The owner runs one archive-cleanup pass under the current posture; propose-first opens a proposal and archives nothing."""
    class _VaultEntitiesVerbs:
        def mention(self, spec: Facade.EntityMentionRequest) -> Facade.EntityResolutionWaterfallDecision:
            """The owner resolves an evidence-backed mention through the existing waterfall, restoring its selected archived record in place and never minting a duplicate."""
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
            """The owner's one confirm that lifts or narrows the customer holds on the named records and erases them."""
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
            """Stores one retrieval probe the owner or another model wrote: kind, query, family, targets and author."""
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
            """Decide bytes carried by the host-bound attested relay under its own legal policy; outages halt with a service notice and local-model offer."""
    class _VaultConsentVerbs:
        def approve_once(self, spec: Facade.ApproveOnceRequest) -> Facade.ConsentActReceipt:
            """The owner approves exactly one engine-emitted effect digest; no standing grant is created."""
        def deny(self, spec: Facade.DenyConsentRequest) -> Facade.ConsentActReceipt:
            """The owner denies exactly one engine-emitted effect digest and records the refusal without granting authority."""
        def create_standing_grant(self, spec: Facade.CreateStandingGrantRequest) -> Facade.ConsentActReceipt:
            """The owner creates a bounded standing action or disclosure grant, with no stored expiry; a wider bound is a new decision."""
        def registry(self, spec: Facade.ConsentRegistryQuery) -> Facade.ConsentRegistry:
            """The owner reads the unified action and disclosure grant registry, including revoke commands and optionally revoked grants."""
        def revoke(self, spec: Facade.RevokeGrantRequest) -> Facade.ConsentActReceipt:
            """The owner immediately revokes a standing consent grant by the reference its receipt or registry emitted."""
    class _VaultGateVerbs:
        @property
        def policy(self) -> "Oneiron._VaultGatePolicyVerbs": ...
        @property
        def checker(self) -> "Oneiron._VaultGateCheckerVerbs": ...
    class _VaultGatePolicyVerbs:
        def get(self, spec: Facade.PolicyManifestRead) -> Facade.PolicyManifestsView:
            """The owner reads Gate policy envelopes, actor ceilings, source permits and checker references, including inert contributions."""
        def put(self, spec: Facade.PolicyManifestPut) -> Facade.PolicyManifestReceipt:
            """The owner installs or edits typed Gate write axes, preserving other tables and meeting independently installed contributions."""
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
            """Stores one frozen compiled lens tree for a pack slot as this actor's proposal; it mounts only once the owner selects it."""
        def activate(self, spec: Facade.LensActivateRequest) -> Facade.LensActivationReceipt:
            """The owner selects a proposed lens revision for its pack slot."""
        def deactivate(self, spec: Facade.LensDeactivateRequest) -> Facade.LensActivationReceipt:
            """The owner clears a pack slot's selected lens; the pack, its skill and the proposal stay."""
        def list(self, spec: Facade.LensListRequest) -> Facade.LensListPage:
            """One page of the vault's lens proposals, each with its slot state from the owner's current selection. A credential narrowed to some worlds or facets sees only the proposals whose slot skill and pack source it reads, without their trees."""
        def default(self, spec: Facade.LensDefaultRequest) -> Facade.ScopedReadResult[Facade.LensFrameCard]:
            """Composes the default vault lens from the named sources, read under the caller's own scope, as a card. A server holds its frame for the card's events; an embedded handle holds none, so its events need a server."""
    class _VaultDisclosureVerbs:
        def offer(self, spec: Facade.DisclosureOfferRequest) -> Facade.DisclosureOffered:
            """An agent files a clearance offer for one contact, waiting on the owner's answer until it lapses."""
    class _VaultSharesVerbs:
        def create(self, spec: Facade.ShareCreateRequest) -> Facade.ShareCreated:
            """The handle's actor issues a share: the brief, its recipient, the most the view may show and the text that travels."""
        def revoke(self, spec: Facade.ShareRevokeRequest) -> Facade.ShareRevokeReceipt: ...
        def view(self, spec: Facade.ShareViewRequest) -> Facade.ScopedReadResult[Facade.SharedBriefView | None]: ...
    class _VaultHooksVerbs:
        def replay(self, spec: Facade.HooksReplayRequest) -> list[Facade.HookReplayRow]:
            """The owner replays a fact hook over past facts on the hook sandbox, as a dry run where nothing lands."""
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
        def review_slides(self, request: Facade.SlideReviewSubmit) -> Facade.SlideReviewOutcome: ...
        def ask(self, spec: Facade.ArtifactAskSubmit) -> Facade.ArtifactAskOutcome:
            """Asks one typed question over an artifact's sheet rows, paragraphs or folder items through the host's decision ladder and holds the answers as one proposal for Keep or Discard."""
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
            """Stage one file change of a repository as a Proposed proposal with its retained base, under the review lens catalog the owner sends. Owner only. The engine mints the proposal id; nothing is approved, queued or landed."""
        def oplog(self, spec: Facade.CodeRepoRequest) -> Facade.CodeMutationLog:
            """Read the durable mutation log of one repository in sequence order: prepared, applied and failed mutations. Owner only. It is not a proposal queue and holds no pending proposal."""
        def model_heal_count(self, spec: Facade.CodeRunModelHealCountRequest) -> Facade.CodeRunModelHealCountView:
            """Read the tally this vault keeps of its own durable executor turns one model needed wire healing for, by full provider/name@revision id, zero when absent. Owner only. A routing signal, not a run correction receipt or repair policy."""
        @property
        def waits(self) -> "Oneiron._VaultCodeWaitsVerbs": ...
        def repo_diff(self, request: Facade.CodeRepoDiffRequest) -> Facade.CodeRepoDiffView | None: ...
        def export(self, spec: Facade.CodeExportRequest) -> Facade.CodeExportResult:
            """Export one already-finalized and reviewed document revision through the existing origin publication protocol."""
        @property
        def origin(self) -> "Oneiron._VaultCodeOriginVerbs": ...
        @property
        def checkout(self) -> "Oneiron._VaultCodeCheckoutVerbs": ...
        @property
        def snapshots(self) -> "Oneiron._VaultCodeSnapshotsVerbs": ...
        @property
        def merge_queue(self) -> "Oneiron._VaultCodeMergeQueueVerbs": ...
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
    class _VaultCodeOriginVerbs:
        @property
        def authority(self) -> "Oneiron._VaultCodeOriginAuthorityVerbs": ...
        def publications(self, spec: Facade.OriginPublicationsRequest) -> Facade.OriginPublicationsView:
            """Read durable publication records for one served repository ref and commit without synthesizing a push acknowledgement."""
    class _VaultCodeOriginAuthorityVerbs:
        def get(self, spec: Facade.OriginRepoRequest) -> Facade.OriginAuthorityView:
            """Read one served origin authority and this host identity under the owner credential."""
        def set(self, spec: Facade.OriginAuthoritySetRequest) -> Facade.OriginAuthorityView:
            """Cut over one existing served origin under the owner proof and expected authority epoch."""
    class _VaultCodeCheckoutVerbs:
        def bind(self, spec: Facade.CheckoutDoorBindRequest) -> Facade.CheckoutDoorBinding:
            """Materialize an existing live owner checkout with lease-bound origin remotes and no upstream credential."""
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
            """Advance the fast-tested head by one ready batch through reviewed-stack admission alone. Owner only. Each proposal still needs unanimous critic approval and exact bytes and base; the owner proof approves nothing."""
        def settle_slow(self, spec: Facade.MergeQueueRepoRequest) -> Facade.MergeQueuePointersView:
            """Settle stored slow results in landing order: green advances past passing ones, and a red one rolls the ungreen suffix back. Owner only. The caller names no commit or result."""
        def recover(self, spec: Facade.MergeQueueRepoRequest) -> Facade.MergeQueuePointersView:
            """Reconcile an interrupted landing or rollback with its persisted mutation receipts. Owner only. Unreceipted divergence refuses; nothing is approved or rebased."""
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
        def spawn(self) -> "Oneiron._VaultAgentsSpawnVerbs": ...
        def export_pack(self, request: Facade.AgentPackExportRequest) -> Facade.AgentPackExport: ...
    class _VaultAgentsDreamingVerbs:
        def get(self, spec: Facade.AgentDreamingRequest) -> Facade.AgentDreamingView:
            """The owner reads one agent's dreaming choice: its stored mode, the mode in force and its own dreaming model slot."""
        def set(self, spec: Facade.AgentDreamingSetRequest) -> Facade.AgentDreamingView:
            """The owner sets one agent's dreaming choice on the revision read: its own model, the vault weaver's, or off; sharing a model never shares its diary."""
    class _VaultAgentsSpawnVerbs:
        def get(self, spec: Facade.PlannedSpawnRead) -> Facade.PlannedSpawnObservation:
            """The owner reads one spawned agent's stored observations by its attempt: its type stamp and frozen plan, the team actually launched, its seat route, critic artifacts and receipt-backed learning."""
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
        def status(self, spec: Facade.WorkflowRunRequest) -> Facade.WorkflowRunView:
            """The owner reads one workflow run by its root attempt: the captured step definitions, the active step attempt and each settled step's attempt and result."""
    class _VaultTaskTypesVerbs:
        def pin(self, spec: Facade.TaskTypeTreePin) -> Facade.TaskTypeTreePinReceipt:
            """The owner stores an authored task-type tree on an open team-shape fork, as a candidate; the receipt says whether it is in force."""
        def get(self, spec: Facade.TaskTypeTreeRead) -> Facade.TaskTypeTreeReadReply:
            """The owner reads the task-type tree in force, or one kept tree version, for the vault or a project."""
    class _VaultTasksVerbs:
        def cancel_force(self, spec: Facade.CancelForceRequest) -> Facade.CancelForceReceipt:
            """The owner force-stops every live branch of one TASK, unrefusably: each running attempt is cancelled, its live step stops, and the reply carries every branch's landing and cancellation receipts."""
        @property
        def linear(self) -> "Oneiron._VaultTasksLinearVerbs": ...
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
    class _VaultRunsBranchesVerbs:
        def get(self, spec: Facade.RunBranchesRequest) -> Facade.RunBranchesView:
            """The owner reads every branch of one TASK: its lifecycle state, run status, result, typed asks and signals, and its landing, saved partial-result (resume point) and cancellation receipts."""
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
        def messages(self, room_ref: str, after: str | None = None, limit: int | None = None) -> Facade.RoomPage:
            """One page of the turns in a room this reader may read."""
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
            """Speaks through the witness gate; on a new thread root, thread_audience explicitly limits readers to named room members and cannot be changed later."""
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
        def sharing(self, spec: Facade.RoomRefRequest) -> Facade.RoomSharingView:
            """A room's effective sharing scope and why it is clamped, for a member of the room."""
    class _VaultRoomsOfferVerbs:
        def __call__(self, spec: Facade.OfferDraft) -> Facade.OfferCard:
            """Publishes an agent's offer card to join a room or one of its threads, with an optional fixed deadline for a room-wide card."""
        def answer(self, spec: Facade.OfferAnswerRequest) -> Facade.OfferSettlement:
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
    class _VaultProjectsVerbs:
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
        @property
        def goal(self) -> "Oneiron._VaultProjectsGoalVerbs": ...
        def route_tradeoff(self, spec: Facade.ProjectTradeoffRouteRequest) -> Facade.TaskAskReceipt:
            """Asks the A/B tradeoff question pending on a skill proposal on a project TASK, as a visible turn in its home room."""
    class _VaultProjectsRosterVerbs:
        def write(self, spec: Facade.ProjectRosterWriteRequest) -> Facade.ProjectRosterWriteOutcome:
            """Writes an existing project's signed roster as the bound caller, filing joins for the newly seated subjects it stands for and an invitation for each unrelated person, who accepts through vault.rooms.consent."""
    class _VaultProjectsGoalVerbs:
        def intake(self, spec: Facade.ProjectRefRequest) -> Facade.ProjectGoalInterviewContext:
            """What a project's goal-intake interview starts from, for a member of its home room."""
        def revisions(self, spec: Facade.ProjectRefRequest) -> list[Facade.ProjectGoalRevisionProposal]:
            """The learned goal preferences proposed for a project's goal in force and not dismissed, oldest first."""
        def dismiss(self, spec: Facade.ProjectGoalDismissRequest) -> Facade.ProjectGoalDismissReceipt:
            """The owner dismisses the proposal one tradeoff question made for a project's goal; false for an identical retry."""
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
    class _VaultMessagesVerbs:
        def react(self, spec: Facade.MessageReactionRequest) -> Facade.MessageReactionReceipt:
            """Puts or removes the caller's own reaction on a message or turn; an owner-grade host also brings a provider's reaction as connector ingress."""
    class _VaultCompanionsVerbs:
        @property
        def sharing(self) -> "Oneiron._VaultCompanionsSharingVerbs": ...
    class _VaultCompanionsSharingVerbs:
        def get(self, spec: Facade.CompanionSharingRequest) -> Facade.CompanionSharingView:
            """One contact's clearance in a companion's source vault, for the principal who controls that vault."""
        def set(self, spec: Facade.CompanionSharingSetRequest) -> Facade.CompanionSharingView:
            """The owner's standing yes to one frozen clearance offer for a companion's contact."""
    class _VaultVoicesVerbs:
        @property
        def packs(self) -> "Oneiron._VaultVoicesPacksVerbs": ...
        def render_consent(self, spec: Facade.VoiceRenderConsentRequest) -> Facade.VoiceRenderConsentReceipt:
            """The owner records their render decision on their own voice: a grant names the farthest locality its refs may reach; a withdrawal drops each target clone, deleted at its vendor best effort, and keeps the packs."""
        @property
        def targets(self) -> "Oneiron._VaultVoicesTargetsVerbs": ...
        def inspect(self, spec: Facade.VoiceBankInspectRequest) -> Facade.VoiceBankInspection:
            """The owner inspects their own voice as the bank holds it for one configured hosted target: identity, pack metadata without audio or transcripts, the current render decision and the target's current clone."""
    class _VaultVoicesPacksVerbs:
        def put(self, spec: Facade.VoiceBankPackPutRequest) -> Facade.VoiceBankPackReceipt:
            """The owner banks one immutable reference pack of their own voice: the first captured or designed pack makes its identity, a captured pack cites their current render grant, and a retry of the same pack is a no-op."""
    class _VaultVoicesTargetsVerbs:
        def provision(self, spec: Facade.VoiceTargetProvisionRequest) -> Facade.VoiceTargetReceipt:
            """The owner's own voice cloned at a configured hosted target from its banked refs, or that target's current clone. The render consent must reach the target's locality before any provider call."""
        def evict(self, spec: Facade.VoiceTargetEvictRequest) -> Facade.VoiceTargetEvictReceipt:
            """The owner drops a target's clone of their own voice, deleted at its vendor best effort. The identity and its packs stay."""
    class _VaultGraphVerbs:
        def ask(self, spec: Facade.GraphAskRequest) -> Facade.GraphAskOutcome: ...
    class _VaultQuestionsVerbs:
        def create(self, spec: Facade.QuestionCreateRequest) -> Facade.QuestionRecord: ...
        def edit(self, spec: Facade.QuestionEditRequest) -> Facade.QuestionRecord: ...
        def pause(self, spec: Facade.QuestionPauseRequest) -> Facade.QuestionPaused: ...
        def backfill(self, spec: Facade.QuestionBackfillRequest) -> Facade.ScheduledBackfill: ...
        def read(self, spec: Facade.QuestionReadRequest) -> Facade.QuestionRecord | None: ...
        def answers(self, spec: Facade.QuestionAnswersRequest) -> list[Facade.QuestionAnswer]: ...
        def refresh(self, spec: Facade.QuestionRefreshRequest) -> list[Facade.AnswerRecord]:
            """Refreshes the caller's standing question by hand, now, over every unit its current version covers, on the host's ladder as the standing pump answers it."""
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
        def constraint_turn(self, spec: Facade.BookingConstraintTurnRequest) -> Facade.BookingConstraintTurnResponse:
            """Parses one scheduling constraint on a live published booking page as the caller, returning public slot controls, an email continuation or a deflect; this never holds or confirms a booking."""
        def page_token(self, spec: Facade.BookingPageTokenRequest) -> Facade.BookingPageTokenResponse:
            """The owner discovers the opaque token for an existing configured booking page; this does not publish the page or grant booking authority."""
    class _VaultCalendarVerbs:
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
        @property
        def transcript(self) -> "Oneiron._VaultCalendarTranscriptVerbs": ...
    class _VaultCalendarIcsVerbs:
        def import_(self, spec: Facade.CalendarIcsImportRequest) -> Facade.CalendarIcsImportReceipt:
            """The owner imports one exact uploaded ICS version through the existing UID diff and imported-claim gate; the receipt exposes pending claim refs without granting consent."""
    class _VaultCalendarInstancesVerbs:
        def move(self, spec: Facade.CalendarInstanceMoveRequest) -> Facade.CalendarIcsImportReceipt:
            """The owner applies one uploaded detached-instance amendment matching its UID, original start and new interval, through the import gate without changing other instances."""
    class _VaultCalendarTranscriptVerbs:
        def ingest(self, spec: Facade.TranscriptFileDropInput) -> Facade.TranscriptIngestOutcome:
            """Ingests an uploaded UTF-8 transcript as the caller, retaining source labels and atomically closing its SESSION with ordered TURNs and extraction wake receipts."""
    class _VaultWritesVerbs:
        def pending(self, input: Facade.ReceiptsRequest) -> list[Facade.PendingWrite]:
            """Gated writes parked for consent, newest first."""
    class _VaultRefsVerbs:
        def resolve(self, spec: Facade.ResolveRecordRefRequest) -> Facade.ScopedReadResult[Facade.RecordRefPreview]:
            """The bounded preview of one record ref, read through the caller's own scope; unreadable and missing look the same."""
        def links(self, spec: Facade.RecordLinksRequest) -> Facade.RecordLinks:
            """A text, the texts a read surface returned, or a turn's readable messages, as typed spans whose record links resolve under the caller's own read."""
    class _VaultSearchVerbs:
        def hybrid(self, input: Facade.HybridSearchRequest) -> Facade.ScopedReadResult[list[Facade.HybridSearchHit]]:
            """Searches explicit vector, text, phonetic, temporal and PPR channels under the caller read ceiling, with optional fixed-time blend replay and per-hit score evidence."""
        def temporal(self, input: Facade.TemporalSearchRequest) -> Facade.ScopedReadResult[Facade.TemporalSearchResult]:
            """Searches occurrence, learning or both temporal anchors under the caller's read ceiling, with sigma, adaptive widening, hard outer ranges, admitted dates and the effective request sigma and rounds."""
        def bm25(self, input: Facade.QueryBm25Request) -> Facade.ScopedReadResult[list[Facade.LexicalHit]]:
            """BM25 text search over the engine index; surfaceable claims only."""
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
            """Reads one signing document as its trail folds: its status, recipients, filled fields and its hash-chained audit trail."""
        @property
        def links(self) -> "Oneiron._VaultEsignLinksVerbs": ...
        def send_for_signature(self, spec: Facade.EsignDispatchRequest) -> Facade.EsignDispatchView:
            """Sends a drafted signing document to its recipients through the outbound gate, as the caller; an agent sends only within its principal envelope."""
        def remind(self, spec: Facade.EsignDispatchRequest) -> Facade.EsignDispatchView:
            """Reminds the recipients whose turn it is to sign a pending document, through the outbound gate, as the caller."""
        def void(self, spec: Facade.EsignVoidRequest) -> Facade.EsignDispatchView:
            """Withdraws a drafted or pending signing document unsealed and tells its recipients why, through the outbound gate, as the caller."""
    class _VaultEsignLinksVerbs:
        def issue(self, spec: Facade.EsignLinksIssueRequest) -> Facade.EsignLinksView:
            """The vault owner mints the signing links of a drafted document and receives each new one once, to deliver to its recipient."""
    class _VaultConsolidationVerbs:
        def enqueue(self, spec: Facade.ConsolidationEnqueueRequest) -> Facade.DreamerAttemptRef:
            """Enqueues one consolidation attempt and returns its durable job reference."""
        def status(self, spec: Facade.ConsolidationStatusRequest) -> Facade.DreamerAttemptView | None:
            """Reads the status of one consolidation attempt by its durable job reference."""
        def promote(self, spec: Facade.ConsolidationPromoteRequest) -> Facade.ConsolidationPromotion:
            """Promotes typed generated candidates in an admitted Dreamer attempt through its host-stamped writer and checker, returning retained evidence and refusals."""
        def evidence(self, spec: Facade.ConsolidationEvidenceRequest) -> Facade.ScopedReadResult[list[Facade.ConsolidationEvidenceSource]]:
            """Reads exact generated-claim evidence, source lineage and separate consolidation, corroboration and effector-evidence eligibility as the owner."""
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
    class _TasksVerbs:
        def create(self, spec: Facade.TaskCreateRequest) -> Facade.TaskCreateReceipt:
            """Mints one TASK and its realizing attempt when the actor's ceiling permits, or parks it as a proposal; an intent key with a typed brief posts it through the task highway."""
        def wave(self, spec: Facade.TaskWaveRequest) -> Facade.TaskWaveReceipt:
            """Cuts an epic TASK into a wave of TASKs through a planner agent, as one planning attempt: under the asking run's own lease, or the owner's root wave."""
        def update(self, spec: Facade.TaskUpdateRequest) -> Facade.TaskUpdateReceipt:
            """Reports task progress, blocked work or a durable result through the task highway; without a report, acknowledges a failed TASK."""
        def accept(self, spec: Facade.TaskAccept) -> Facade.TaskCallReceipt:
            """Accepts one TASK addressed to the caller through the task highway under the caller's intent key; the attempt handle it answers fences the caller's reports."""
        def answer(self, handle: Facade.TaskAskHandle, word: Facade.TaskAskWord) -> Facade.TaskAskAnswer:
            """Admits one person's word on an ask; the word is evidence, never approval."""
        def outcomes(self, handle: Facade.TaskAskHandle) -> list[Facade.CalibrationPair]:
            """Owner-scoped calibration pairs for an ask: each prediction against the outcome it was bound to."""
        def refuse(self, spec: Facade.LiveRunRequest[Facade.TaskRefuseInput]) -> Facade.TaskRefuseOutput:
            """Applies this credential's attached agent run refusal dial to its own TASK, with a durable reason; the live lease supplies the actor and TASK and the engine owns replay."""
    class _RevealVerbs:
        def __call__(self, spec: Facade.RevealRequest) -> Facade.RevealPending:
            """Asks for a secret's value for the model, by its handle and why; answers a pending reveal that reveal.wait collects."""
        def wait(self, spec: Facade.RevealWaitRequest) -> Facade.RevealWaitAnswer:
            """Where a reveal stands: pending, denied, expired or granted; the first granted answer carries the value, later ones the receipt."""
        def describe(self, spec: Facade.RevealDescribeRequest) -> Facade.RevealHandleCard:
            """What a secret handle names, where it was found and what a reveal of it would do now; never the value."""
    class _AiVerbs:
        @property
        def steps(self) -> "Oneiron._AiStepsVerbs": ...
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
    class _AiStepsVerbs:
        def submit(self, spec: Facade.ModelStepSubmit) -> Facade.ModelStepReceipt:
            """Submit or resume one owner-bound durable model step with declared transport attempts, deterministic fallback and a schema-validated JSON result."""
        def receipt(self, spec: Facade.ModelStepReceiptRequest) -> Facade.ModelStepReceipt:
            """Read the owner-bound model-step checkpoints and persisted terminal result without calling a model or spending another lease."""
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
    class _ConnectorVerbs:
        def list(self, spec: Facade.ConnectorListRequest) -> list[Facade.ConnectorEntry]:
            """Every live catalogued connector whose name or summary matches the query."""
        def status(self, spec: Facade.ConnectorNameRequest) -> Facade.ConnectorView | None:
            """One catalogued connector by name, removed ones included."""
        def call(self, spec: Facade.ConnectorCallRequest) -> Facade.ConnectorCallReply:
            """Calls one tool of one catalogued connector under the caller's own grant and gate; the tool's reply comes back as foreign data."""
        def schema(self, spec: Facade.ConnectorSchemaRequest) -> Facade.ConnectorSchemaReply:
            """One catalogued connector tool's approved input schema, as the caller's own grant resolves it."""
        def call_status(self, spec: Facade.ConnectorCallStatusRequest) -> Facade.ConnectorCallStatus:
            """Where one held connector.call stands, by the call_ref its held or pending_delivery reply named: still pending, or the reply it settled with. Only the actor that made the call and the vault's owner read it."""
        @property
        def outbound(self) -> "Oneiron._ConnectorOutboundVerbs": ...
    class _ConnectorOutboundVerbs:
        def schedule(self, spec: Facade.OutboundScheduleRequest) -> Facade.OutboundIntentReceipt:
            """Schedules one send through a granted outbound connector, gated and held for delivery."""

# END GENERATED FACADE VERBS
