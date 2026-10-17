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

__all__ = ["Oneiron", "OneironError"]

WitnessAuthor = Literal["user", "companion", "system"]
Effort = Literal["light", "medium", "high", "xhigh", "max", "call"]
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
    kinds: NotRequired[list[str] | None]

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
    wrong_root: dict[str, str] | None
    def __init__(
        self,
        code: str,
        message: str,
        suggestions: list[str],
        wrong_root: dict[str, str] | None = None,
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
    def pair(cls, link: str) -> tuple["Oneiron", str]: ...
    def as_actor(self, actor_key: str) -> "Oneiron": ...
    def in_room_turn(self, room_ref: str) -> "Oneiron": ...
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
        def memory(self) -> "Oneiron._SelfMemoryVerbs": ...
        @property
        def identity(self) -> "Oneiron._SelfIdentityVerbs": ...
        def message(self, spec: Facade.MessagePersonRequest) -> Facade.MessagePersonReceipt:
            """Sends one message to a person in the Direct room the caller's person and theirs share, making the room on first use."""
        @property
        def grants(self) -> "Oneiron._SelfGrantsVerbs": ...
        @property
        def skills(self) -> "Oneiron._SelfSkillsVerbs": ...
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
    class _SelfIdentityVerbs:
        def answer(self, spec: Facade.IdentityAnswerRequest) -> Facade.IdentitySettled:
            """A vault owner's tap on an identity choice card: who a person named in their conversations is."""
        def settle(self, spec: Facade.IdentityActNowRequest) -> Facade.IdentityActNow:
            """Before acting on a person known only by a name, settles who that name is from its newest saved mention, or opens an ask."""
    class _SelfGrantsVerbs:
        def ask(self, spec: Facade.GrantAskRequest) -> Facade.GrantAskReceipt:
            """Asks a person for access on the caller's behalf; the request grants nothing until the vault owner approves it."""
    class _SelfSkillsVerbs:
        def save(self, spec: Facade.SkillSaveRequest) -> Facade.SkillAuthoringReceipt:
            """An agent saves a skill it wrote, SKILL.md and scripts together; it lands as a proposed candidate and nothing activates it."""
        def fork(self, spec: Facade.SkillForkRequest) -> Facade.SkillAuthoringReceipt:
            """An agent forks a stored skill under its own identity, keeping its import ancestry."""
        def callables(self, spec: Facade.EmptyRequest | None = None) -> list[Facade.CallableCardView]:
            """Every loadable callable helper skill and its call contract: what it takes and returns."""
    class _VaultVerbs:
        @property
        def people(self) -> "Oneiron._VaultPeopleVerbs": ...
        def witness(self, turn: WitnessTurn) -> WitnessReceipt: ...
        @property
        def claims(self) -> "Oneiron._VaultClaimsVerbs": ...
        def recall(self, query: str, *, effort: Effort = 'medium', scope: RecallScope | None = None, limit: int = 10, format: PackFormat | None = None, as_of: int | None = None, deadline_ms: int | None = None) -> MemoryPack: ...
        def export(self, format: PackFormat | None = None) -> dict[str, Any]: ...
        @property
        def receipts(self) -> "Oneiron._VaultReceiptsVerbs": ...
        @property
        def images(self) -> "Oneiron._VaultImagesVerbs": ...
        @property
        def kv(self) -> "Oneiron._VaultKvVerbs": ...
        @property
        def weave(self) -> "Oneiron._VaultWeaveVerbs": ...
        @property
        def packs(self) -> "Oneiron._VaultPacksVerbs": ...
        @property
        def authority(self) -> "Oneiron._VaultAuthorityVerbs": ...
        @property
        def inspection(self) -> "Oneiron._VaultInspectionVerbs": ...
        @property
        def shared(self) -> "Oneiron._VaultSharedVerbs": ...
        @property
        def members(self) -> "Oneiron._VaultMembersVerbs": ...
        @property
        def guests(self) -> "Oneiron._VaultGuestsVerbs": ...
        @property
        def legal_holds(self) -> "Oneiron._VaultLegalHoldsVerbs": ...
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
        def rooms(self) -> "Oneiron._VaultRoomsVerbs": ...
        @property
        def projects(self) -> "Oneiron._VaultProjectsVerbs": ...
        @property
        def conversations(self) -> "Oneiron._VaultConversationsVerbs": ...
        @property
        def companions(self) -> "Oneiron._VaultCompanionsVerbs": ...
        @property
        def workspace(self) -> "Oneiron._VaultWorkspaceVerbs": ...
        @property
        def graph(self) -> "Oneiron._VaultGraphVerbs": ...
        @property
        def questions(self) -> "Oneiron._VaultQuestionsVerbs": ...
        def commit(self, input: Facade.CommitRequest) -> list[Facade.CommitReceipt]:
            """Commits claims through the gate, each element decided on its own; rejected elements come back rejected and do not persist."""
        def remember(self, input: Facade.ClaimInput) -> Facade.CommitReceipt:
            """Commits one claim through the gate, the same as vault.claims.upsert."""
        def forget(self, input: Facade.ForgetRequest) -> list[Facade.CommitReceipt]:
            """Retracts claims by exact claim or by subject and predicate; never a hard delete."""
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
        def notes(self) -> "Oneiron._VaultNotesVerbs": ...
    class _VaultPeopleVerbs:
        def list(self, spec: Facade.PeopleListRequest) -> Facade.PeoplePage:
            """One page of the people the caller reads, in handle order."""
        def get(self, spec: Facade.PersonRequest) -> Facade.PersonRow:
            """One person the vault knows, by their pr handle."""
    class _VaultClaimsVerbs:
        def upsert(self, claim: ClaimInput) -> CommitReceipt: ...
        def retract(self, input: Facade.ClaimRefRequest) -> Facade.CommitReceipt:
            """Retracts one active claim: a deliberate withdrawal that preserves the record."""
        def list(self, input: Facade.ClaimListFilter) -> Facade.ScopedReadResult[list[Facade.ClaimView]]:
            """Lists claims by subject, predicate and lifecycle, with the read's narrowing receipt."""
        def history(self, input: Facade.ClaimRefRequest) -> Facade.ScopedReadResult[list[Facade.ClaimView]]:
            """The supersession timeline of one claim, oldest first, with the read's narrowing receipt."""
        def admit(self, input: Facade.AdmitImportedClaimInput) -> Facade.CommitReceipt:
            """Admits one imported-evidence claim through its ingest source's trust ceiling; the gate still decides."""
    class _VaultReceiptsVerbs:
        def __call__(self, limit: int = 100) -> list[FacadeReceipt]: ...
        def get(self, spec: Facade.CallReceiptRequest) -> Facade.CallReceipt | None:
            """One call receipt by ref, readable by its own actor or the vault's live owner; anything else reads as none."""
    class _VaultImagesVerbs:
        def view(self, request: Facade.ImageViewRequest) -> Facade.PulledImage: ...
    class _VaultKvVerbs:
        def get(self, request: KeyValueAddress) -> KeyValueItem | None: ...
        def put(self, request: KeyValuePut) -> KeyValuePutReceipt: ...
        def delete(self, request: KeyValueAddress) -> KeyValueDeleteReceipt: ...
        def search(self, request: KeyValueSearch) -> list[KeyValueItem]: ...
        def namespaces(self, request: KeyValueNamespaces) -> list[list[str]]: ...
    class _VaultWeaveVerbs:
        def report(self, spec: Facade.WeaveReportRequest) -> Facade.WeaveReportView:
            """The live weave report for the bound actor, read through its own scope and the vault's weave policy for its role."""
        def digest(self, spec: Facade.WeaveDigestRequest) -> Facade.WeaveDigestView | None:
            """One of the bound actor's saved weave digests, or the newest, under the current read policy."""
        def lens(self, spec: Facade.WeaveReportRequest) -> Facade.GeneratedLens: ...
        @property
        def link(self) -> "Oneiron._VaultWeaveLinkVerbs": ...
    class _VaultWeaveLinkVerbs:
        def wrong(self, spec: Facade.WeaveWrongLinkRequest) -> Facade.WeaveLinkCorrectionView:
            """A person labels a link in their own lens as wrong; the label teaches the loops and the link stays."""
    class _VaultPacksVerbs:
        def put(self, spec: Facade.PackPutRequest) -> Facade.PackPutReceipt:
            """The owner installs a pack folder, or replaces the pack installed under its name; the put is the consent for its hooks."""
        @property
        def setup(self) -> "Oneiron._VaultPacksSetupVerbs": ...
    class _VaultPacksSetupVerbs:
        def prepare(self, spec: Facade.PackSetupRequest) -> Facade.PackSetupReceipt:
            """The owner opens, or resumes, a pack's guided setup; opening grants nothing."""
        def get(self, spec: Facade.PackSetupRequest) -> Facade.PackSetupReceipt:
            """A pack's guided setup as it stands, for the owner."""
        def answer(self, spec: Facade.PackSetupAnswerRequest) -> Facade.PackSetupReceipt:
            """The owner's one typed answer or card action in a pack's guided setup; a credential value never passes here."""
        def verify(self, spec: Facade.PackSetupVerifyRequest) -> Facade.PackSetupReceipt:
            """Checks one pack connection with the engine's fixed read-only provider call for its declared check."""
    class _VaultAuthorityVerbs:
        def audit(self, spec: Facade.AuthorityAuditQuery) -> Facade.AuthorityAuditPage:
            """One page of the dated authority log audit: grants, revokes and confirms, for the owner."""
        @property
        def handoff_alarms(self) -> "Oneiron._VaultAuthorityHandoffAlarmsVerbs": ...
    class _VaultAuthorityHandoffAlarmsVerbs:
        def __call__(self, spec: Facade.EmptyRequest | None = None) -> list[Facade.AuthorityHandoffAlarm]:
            """Every saved authority handoff fork alarm, for the owner."""
        def acknowledge(self, spec: Facade.HandoffAlarmRequest) -> Facade.AuthorityHandoffAlarm:
            """The owner acknowledges one saved handoff fork alarm."""
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
    class _VaultMembersVerbs:
        def add(self, spec: Facade.SharedMemberAddRequest) -> Facade.SharedActExecutionReceipt:
            """An Admin adds a live person to a shared vault at a non-root role."""
        def change(self, spec: Facade.SharedMemberRoleRequest) -> Facade.SharedActExecutionReceipt:
            """An Admin assigns another non-root role to a member who is not an Owner."""
        def remove(self, spec: Facade.SharedMemberRequest) -> Facade.SharedActExecutionReceipt:
            """An Admin removes one member from a shared vault."""
        def leave(self, spec: Facade.SharedVaultRequest) -> Facade.SharedActExecutionReceipt:
            """A member leaves a shared vault under their own proof; an Owner leaves through remove_owner instead."""
    class _VaultGuestsVerbs:
        def revoke(self, spec: Facade.GuestRevokeRequest) -> Facade.GuestRevokeResponse: ...
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
    class _VaultLensesVerbs:
        def propose(self, spec: Facade.LensProposeRequest) -> Facade.LensProposalReceipt:
            """Stores one frozen compiled lens tree for a pack slot as this actor's proposal; it mounts only once the owner selects it."""
        def activate(self, spec: Facade.LensActivateRequest) -> Facade.LensActivationReceipt:
            """The owner selects a proposed lens revision for its pack slot."""
        def deactivate(self, spec: Facade.LensDeactivateRequest) -> Facade.LensActivationReceipt:
            """The owner clears a pack slot's selected lens; the pack, its skill and the proposal stay."""
        def list(self, spec: Facade.LensListRequest) -> Facade.LensListPage:
            """One page of the vault's lens proposals, each with its slot state from the owner's current selection."""
        def default(self, spec: Facade.LensDefaultRequest) -> Facade.ScopedReadResult[Facade.GeneratedLens]:
            """Composes the default vault lens from the named sources, read under the caller's own scope."""
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
        def view(self, request: Facade.ArtifactRefRequest) -> Facade.ArtifactView | None: ...
        def export(self, request: Facade.ArtifactExportRequest) -> Facade.ArtifactExportFile | None: ...
        def born_from(self, request: Facade.BornFromRequest) -> Facade.BornFromView: ...
        def proposals(self, request: Facade.ArtifactRefRequest) -> list[Facade.PendingProposalView]: ...
        def waits(self, request: Facade.ArtifactRefRequest) -> list[Facade.OrganWaitView]: ...
        def release_wait(self, request: Facade.ProposalSettleRequest) -> Facade.ReleasedWait: ...
        def review_slides(self, request: Facade.SlideReviewSubmit) -> Facade.SlideReviewOutcome: ...
        def propose_deck(self, request: Facade.DeckProposeRequest) -> Facade.DeckProposeOutcome: ...
        def propose_output(self, request: Facade.NativeOutputRequest) -> Facade.PendingProposalView: ...
        def keep(self, request: Facade.ProposalSettleRequest) -> Facade.KeptProposal: ...
        def discard(self, request: Facade.ProposalSettleRequest) -> Facade.DiscardedProposal: ...
        def undo(self, request: Facade.ProposalSettleRequest) -> Facade.UndoneKeep: ...
        def put(self, input: Facade.BlobArtifactInput) -> Facade.EntityRefReceipt:
            """Registers one blob artifact; its bytes ride vault.artifacts.append."""
        def append(self, input: Facade.AppendBlobVersionRequest) -> Facade.BlobVersionView:
            """Appends one version of bytes to a blob artifact's append-only chain."""
        def read(self, input: Facade.ReadBlobVersionRequest) -> Facade.BlobContent | None:
            """Reads one version of a blob artifact's bytes."""
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
            """Speaks one turn into the current room turn's room, through the normal witness gate."""
        def join(self, spec: Facade.JoinRequest) -> Facade.JoinOutcome:
            """Files and decides a request to take part in a room or one of its threads."""
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
            """Publishes an agent's offer card to join a room or one of its threads."""
        def answer(self, spec: Facade.OfferAnswerRequest) -> Facade.OfferSettlement:
            """The room's host answers an offer card: join, or not now."""
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
        def goal(self) -> "Oneiron._VaultProjectsGoalVerbs": ...
        def route_tradeoff(self, spec: Facade.ProjectTradeoffRouteRequest) -> Facade.TaskAskReceipt:
            """Asks the A/B tradeoff question pending on a skill proposal on a project TASK, as a visible turn in its home room."""
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
    class _VaultConversationsTurnVerbs:
        def continue_(self, spec: Facade.TurnActionRequest) -> Facade.TurnActionReceipt:
            """Queues generation that resumes an incomplete assistant reply from exactly its saved text."""
        def retry(self, spec: Facade.TurnActionRequest) -> Facade.TurnActionReceipt:
            """Queues a new answer to the user turn an assistant turn answered; the old reply stays."""
    class _VaultCompanionsVerbs:
        @property
        def sharing(self) -> "Oneiron._VaultCompanionsSharingVerbs": ...
    class _VaultCompanionsSharingVerbs:
        def get(self, spec: Facade.CompanionSharingRequest) -> Facade.CompanionSharingView:
            """One contact's clearance in a companion's source vault, for the principal who controls that vault."""
        def set(self, spec: Facade.CompanionSharingSetRequest) -> Facade.CompanionSharingView:
            """The owner's standing yes to one frozen clearance offer for a companion's contact."""
    class _VaultWorkspaceVerbs:
        @property
        def work_companion(self) -> "Oneiron._VaultWorkspaceWorkCompanionVerbs": ...
    class _VaultWorkspaceWorkCompanionVerbs:
        def get(self, spec: Facade.WorkspaceRefRequest) -> Facade.WorkCompanionPolicy:
            """A workspace's work_companion policy, readable by every member it governs."""
        def set(self, spec: Facade.WorkCompanionSetRequest) -> Facade.WorkCompanionPolicy:
            """The owner sets a workspace's work_companion policy in person."""
    class _VaultGraphVerbs:
        def ask(self, spec: Facade.GraphAskRequest) -> Facade.GraphAskOutcome: ...
    class _VaultQuestionsVerbs:
        def create(self, spec: Facade.QuestionCreateRequest) -> Facade.QuestionRecord: ...
        def edit(self, spec: Facade.QuestionEditRequest) -> Facade.QuestionRecord: ...
        def pause(self, spec: Facade.QuestionPauseRequest) -> Facade.QuestionPaused: ...
        def read(self, spec: Facade.QuestionReadRequest) -> Facade.QuestionRecord | None: ...
        def answers(self, spec: Facade.QuestionAnswersRequest) -> list[Facade.AnswerRecord]: ...
    class _VaultWritesVerbs:
        def pending(self, input: Facade.ReceiptsRequest) -> list[Facade.PendingWrite]:
            """Gated writes parked for consent, newest first."""
    class _VaultRefsVerbs:
        def resolve(self, spec: Facade.ResolveRecordRefRequest) -> Facade.ScopedReadResult[Facade.RecordRefPreview]:
            """The bounded preview of one record ref, read through the caller's own scope; unreadable and missing look the same."""
        def links(self, spec: Facade.RecordLinksRequest) -> Facade.RecordLinks:
            """A text, or a turn's readable messages, as typed spans whose record links resolve under the caller's own read."""
    class _VaultSearchVerbs:
        def bm25(self, input: Facade.QueryBm25Request) -> Facade.ScopedReadResult[list[Facade.LexicalHit]]:
            """BM25 text search over the engine index; surfaceable claims only."""
    class _VaultStructuralVerbs:
        def put(self, input: Facade.StructuralPutInput) -> Facade.EntityRefReceipt:
            """Puts one structural record with its text-index fields and outgoing edges, in one atomic batch; claims go through commit."""
    class _VaultHabitsVerbs:
        def checkin(self, input: Facade.HabitCheckinInput) -> Facade.EntityRefReceipt:
            """Appends one immutable check-in under a Habit TASK."""
    class _VaultNotesVerbs:
        def create(self, input: Facade.CreateNoteRequest) -> Facade.EntityRefReceipt:
            """Creates a NOTE of a registered kind, its first authored text as its birth."""
        def from_entity(self, input: Facade.CreateNoteFromEntityRequest) -> Facade.EntityRefReceipt:
            """Creates a NOTE of a registered kind from an existing entity."""
        def edit(self, input: Facade.EditNoteRequest) -> Facade.NoteEditOutcome:
            """Edits one NOTE in a transaction-local document; a rejected edit leaves nothing pending."""
    class _TasksVerbs:
        def create(self, spec: Facade.TaskCreateRequest) -> Facade.TaskCreateReceipt:
            """Mints one TASK and its realizing attempt when the actor's ceiling permits, or parks it as a proposal."""
        def update(self, spec: Facade.TaskRequest) -> Facade.TaskUpdateReceipt:
            """Records the owner's acknowledgement of a failed TASK; any other task stays as it was."""
        def answer(self, handle: Facade.TaskAskHandle, word: Facade.TaskAskWord) -> Facade.TaskAskAnswer:
            """Admits one person's word on an ask; the word is evidence, never approval."""
        def outcomes(self, handle: Facade.TaskAskHandle) -> list[Facade.CalibrationPair]:
            """Owner-scoped calibration pairs for an ask: each prediction against the outcome it was bound to."""
    class _AiVerbs:
        def options(self, spec: Facade.AiOptionsRequest) -> Facade.AiOptions:
            """The model rows an ai call could use: where each runs, what it takes, its rates, and what the media meter has left."""
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
            """The caller's own typed question through the host's decision ladder, answered with a probability and a decision receipt."""
    class _AiVideoVerbs:
        def __call__(self, spec: Facade.AiCallRequest) -> Facade.AiVideoTicket:
            """Starts a video render as a provider job and answers with its ticket."""
        def poll(self, spec: Facade.AiVideoJobRequest) -> Facade.AiVideoJob:
            """Where a video job stands; a finished one answers with its clip, once."""
        def cancel(self, spec: Facade.AiVideoJobRequest) -> Facade.AiVideoCancelled:
            """Stops a video job at its provider."""
    class _ConnectorVerbs:
        def list(self, spec: Facade.ConnectorListRequest) -> list[Facade.ConnectorEntry]:
            """Every live catalogued connector whose name or summary matches the query."""
        def status(self, spec: Facade.ConnectorNameRequest) -> Facade.ConnectorView | None:
            """One catalogued connector by name, removed ones included."""
        @property
        def outbound(self) -> "Oneiron._ConnectorOutboundVerbs": ...
    class _ConnectorOutboundVerbs:
        def schedule(self, spec: Facade.OutboundScheduleRequest) -> Facade.OutboundIntentReceipt:
            """Schedules one send through a granted outbound connector, gated and held for delivery."""

# END GENERATED FACADE VERBS
