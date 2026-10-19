//! BRIDGE-01 (ONE-1454): transport-agnostic memory facade.
//!
//! The single write door for app-tier callers (ONE-WIRE-1 W1/W3, ONE-WIRE-2
//! S1/S3/S7/S8): every verb here rides EXISTING engine machinery — the gated
//! claim-candidate path, `BatchBuilder` structural puts, the named deletion
//! verbs, the blob-artifact store — and never bypasses
//! `check_claim_policy_for_write`. Bindings (napi, HTTP) lift this surface
//! verbatim; the facade is authored once, engine-side.
//!
//! Vocabulary (S1): short-id refs (`"ms3:a1"`) or 32-hex entity ids in,
//! typed DTOs out. No type bytes, no raw MessagePack on this surface.
//!
//! Approval policy (design §4.2): the facade REQUESTS `auto` only for
//! `user_stated`/`observed` claims whose scope carries no explicit
//! `sensitivity` key; everything else is submitted `proposed`. The gate
//! remains the enforcer: when it refuses an `auto` request
//! (`GateWriteRejected`), the facade resubmits the same claim `proposed`, so
//! writes park as pending consents instead of vanishing.
//!
//! One concern per file: `error` owns the error vocabulary, `support`
//! owns [`Memory`] itself plus the shared actor-verification and wire
//! plumbing, and each verb family lives in the file named for it. This
//! module re-exports the whole surface, so `crate::memory::X` paths are
//! unchanged from the flat-file era.

pub mod affect;
mod answer_boundary;
mod archive_purge;
mod artifact_hosting_doors;
mod asset_doors;
mod asset_resolve;
mod authorship;
mod critical_confirm;
pub use critical_confirm::{
    CriticalWriteConfirmAnswer, CriticalWriteConfirmPending, CriticalWriteConfirmPendingRequest,
    CriticalWriteConfirmReceipt, CriticalWriteConfirmReceiptRequest, CriticalWriteConfirmRequest,
    CriticalWriteConfirmSettlement,
};
mod birth_position;
mod booking;
mod claim_admission;
mod claim_conflict;
mod claim_stale;
pub mod clustering;
pub mod commitment_doors;
mod conflict_settle;
pub mod consolidation;
pub mod consolidation_frontier;
pub mod coping_doors;
mod diagnostics;
mod diary_read;
mod dreamer_revert;
mod people_verbs;
pub mod run_review;
mod skill_authoring;
pub mod wellness_doors;
pub(crate) use booking::booking_error;
pub(crate) use outbound::facade_error_from_outbound_dispatch;
pub(crate) use outbound::parse_job_ref;
pub(crate) mod booking_publication;
mod campaign;
mod campaign_actions;
pub mod caps;
pub mod channel_doors;
mod chat;
pub mod checkout_doors;
mod claims;
pub mod code_doors;
pub mod code_run_doors;
pub mod code_view_doors;
pub mod code_wait_doors;
pub mod codebase_doors;
mod conversation_list;
mod credential_key;
mod dreamer;
mod entity_delete;
mod entity_erase;
pub mod erase_sweep;
mod export;
mod expression_preference;
pub mod extraction;
pub mod foreign_code;
pub mod graph_fs_doors;
pub mod hook_regen_doors;
mod inspection;
mod key_value;
mod lifted_view;
mod locality;
mod machine_write;
pub mod merge_queue_doors;
mod message_result;
mod note_tombstone;
mod notes;
pub mod origin_doors;
mod outbound;
mod owner_door;
mod presented_credential;
mod read_lane;
mod read_selection;
mod reads;
mod recall;
mod report;
mod result_attachment;
pub mod result_doors;
mod room_turn;
mod scoped_export;
mod search_hybrid;
mod search_temporal;
mod search_vector;
mod session_writes;
mod shape_doors;
mod signal_extraction;
mod structural;
mod subscriptions;
mod support;
mod transcript;
mod web_fetch;
mod witness;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_regressions;

pub use answer_boundary::AnswerAdmission;
pub use archive_purge::{ArchivePurgeEntry, ArchivePurgePreview};
pub use asset_doors::{AssetIngestReceipt, AssetIngestRequest, AssetResolveRequest, AssetResolved};
pub use asset_resolve::{
    AssetConsumer, HydratedAsset, IMAGE_FULL, ImageHandle, ImagePick, ImageViewRequest,
    LandedImage, PixelRegion, PulledImage, ResolvedAsset, ServedAssetForm, hydrated_asset,
    pull_image, resolve_audio_ref, resolve_image_ref,
};
pub(crate) use asset_resolve::{asset_audio_in_lane, asset_image_in_lane};
pub use authorship::MemoryAuthoringAction;
pub(crate) use authorship::{
    claim_author, explicit_claim_override_in_txn, guard_existing_claim_in_txn,
    require_claim_self_grant_in_txn,
};
pub use booking::EmergencyInstructionInput;
pub use chat::{
    ChatAbstentionReason, ChatComposeRequest, ChatComposer, ChatDepth, ChatOptions, ChatResponse,
    ChatScope, ComposedChatAnswer,
};
pub use claim_admission::{
    AllRelationships, ClaimRelationships, ClaimScope, ScopedClaimInput, ScopedCommitRequest,
};
pub(crate) use claim_conflict::claim_conflict_ruling_gate_refs_in_txn;
pub use claim_conflict::{
    ClaimConflictBundle, ClaimConflictMember, ClaimConflictQuestion, ClaimConflictReceipt,
};
pub use claim_stale::{
    ClaimDemoteActionInput, ClaimDemoteRequest, ClaimDemoteView, ClaimFilteredListRequest,
    ClaimFilteredReadRequest, ReadFilterInput,
};
pub use claims::{
    ClaimChangeVerdict, ClaimInput, ClaimProposalReview, ClaimProposalReviewRequest,
    ClaimSettleDecision, ClaimSettleRequest, ClaimSettlement, ClaimSettlementAnswer,
    ClaimSettlementReason, ClaimSettlementRevert, ClaimSettlementVerdict, CommitOutcome,
    CommitReceipt, DeleteReceipt, MULTI_CARDINALITY_PREDICATES, MemoryReceipt, PendingWrite,
    RecordRefusal, RefusalReason, SafeDeleteReason,
};
pub use conversation_list::{ConversationListFilter, ConversationListPage, ConversationListRow};
pub use diagnostics::{
    BlockedReportView, CoachInspectRequest, CoachInspectionView, CoachProposalView,
    CoachWorkingSetView, DiagnosticEventView, DiagnosticsGetRequest, DiagnosticsListRequest,
};
pub use diary_read::{
    DIARY_READ_VERB, DiaryAgentRead, DiaryEntry, DiaryEntryAdmission, DiaryReadGate, DiaryReadHold,
    DiaryReadOutcome, DiaryReadReceipt, DiaryReadRecord, DiaryReadRequest, DiaryReadsRequest,
    DiaryReadsView, DiaryReviewAnswer, DiaryReviewState,
};
pub use diary_read::{DiaryReader, DiaryReaderList, SealedPadReader};
pub use dreamer::{
    ConsolidationAttemptInput, DreamerAttemptRef, DreamerAttemptView, DreamerParkCauseView,
    DreamerParkedAttemptView,
};
pub use entity_erase::{
    EntityEraseOutcome, EraseOptions, EraseReason, SameBytesHold, SameBytesOutcome,
};
pub use export::{
    EXPORT_TARGET_ARCHIVE, EXPORT_TARGET_OKF, ExportOptions, ExportReceipt, MemoryExport,
    MemoryExportReceipt,
};
pub use expression_preference::{
    ExpressionPreferenceInput, ExpressionPreferenceReceipt, ExpressionPreferenceView,
};
pub use key_value::{
    KeyValueAddress, KeyValueDeleteReceipt, KeyValueItem, KeyValueNamespaces, KeyValuePut,
    KeyValuePutReceipt, KeyValueSearch,
};
pub use locality::ProducerRows;
pub use oneiron_contracts::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_BUDGET_SPENT, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INTERNAL,
    MEMORY_CODE_INVALID_STATE, MEMORY_CODE_LEASE_REQUIRED, MEMORY_CODE_MODEL_UNAVAILABLE,
    MEMORY_CODE_NOT_FOUND, MEMORY_CODE_OFF_RECORD_SESSION_DOOR, MEMORY_CODE_OWNER_BINDING_REQUIRED,
    MEMORY_CODE_PENDING_ASK, MEMORY_CODE_VAULT_LOCKED_SINGLE_WRITER, MEMORY_CODE_WRONG_ROOT,
    MemoryError, MemoryGateDenial, MemoryPolicyDenial, MemoryPolicyExceptionProposal, MemoryResult,
    MemoryWrongRoot,
};
pub use people_verbs::{
    GrantAskReceipt, GrantAskRequest, GrantAskScope, MessagePersonReceipt, MessagePersonRequest,
    PEOPLE_PAGE_SIZE, PeopleListRequest, PeoplePage, PersonRequest,
};
pub use signal_extraction::{
    ProspectiveQueryHint, SignalExtractionClaim, SignalExtractionMessage, SignalExtractionRequest,
    SignalExtractionResult, SignalExtractionResultRequest, SignalExtractionSource,
    SignalExtractionTicket,
};
// OF-063: a write that names a record its writer cannot resolve is refused
// with this code; hover and open resolve a typed record ref through the lens.
pub use crate::lens::{
    LinkedText, ProseSpan, RecordLinks, RecordLinksRequest, RecordRef, RecordRefPreview,
    ResolveRecordRefRequest,
};
// FIX 2222: a host credential where no host acts as a person.
pub use oneiron_contracts::memory::MEMORY_CODE_HOST_ACTION_REFUSED;
pub use oneiron_contracts::memory::MEMORY_CODE_IDENTITY_UNSETTLED;
pub use oneiron_contracts::memory::MEMORY_CODE_INVENTED_REFERENCE;
// WILL-PLAN L13 row 03: a room's whole off-record stretch, which no
// consent record admits a session row to manage.
pub use oneiron_contracts::memory::MEMORY_CODE_ROOM_MANAGEMENT;
pub use outbound::{
    BRIDGE_OUTBOUND_ATTEMPT_KIND, CALENDAR_INVITE_OUTBOUND_CHANNEL, CALENDAR_INVITE_OUTBOUND_VERB,
    CalendarFreebusyDto, CalendarFreebusyIntervalDto, CalendarInviteSurfaceInput,
    CalendarInviteSurfaceMethod, OutboundDraftInput, OutboundIntentReceipt,
    OutboundScheduleContext,
};
pub use read_selection::RecallWorlds;
pub use reads::{ClaimListFilter, ClaimView, LexicalHit, NeighborHit, NeighborOpts};
pub(crate) use recall::check_recall_request;
pub use recall::{
    CONTAINER_KINDS, CitedMessage, DEFAULT_CALL_MODE_DEADLINE, Effort, MEMORY_PACK_VERSION,
    MemoryItem, MemoryPack, MemoryProvenance, MemoryStaleStamp, RecallEffort, RecallRerank,
    RecallRerankHost, RecallScope, RerankDocument, RerankEgress, RerankReport, RerankScores,
    RerankSkip, RetrievalMeta, ScopeHonesty, resolve_recall_dial,
};
pub use result_attachment::{
    MESSAGE_RESULT_METADATA_KEY, MessageResultAttachment, MessageResultSource,
};
pub use room_turn::RoomTurnHandle;
pub use scoped_export::{
    ChannelCeiling, CredentialCeiling, ExportChannel, RecordPosition, RecordPositionRequest,
    RecordSelector, ScopeAxisInput, ScopeSensitivityBand, ScopeSensitivityInput, ScopedExport,
    ScopedExportRecord, ScopedExportRequest,
};
pub use search_hybrid::{
    HybridPprQuery, HybridRankReplay, HybridSearchHit, HybridSearchRequest, HybridTemporalQuery,
};
pub use search_temporal::{
    TemporalSearchHit, TemporalSearchRange, TemporalSearchRequest, TemporalSearchResult,
};
pub use search_vector::{
    VectorPutReceipt, VectorPutRequest, VectorSearchConfig, VectorSearchHit, VectorSearchLane,
    VectorSearchRequest, VectorSearchResult,
};
pub use skill_authoring::SkillAuthoringReceipt;
pub(crate) use skill_authoring::{skill_author_in_txn, skill_author_proof_is_live_in_txn};
pub(crate) use structural::append_agent_diary_in_txn;
pub use structural::{
    AdmitImportedClaimInput, BlobArtifactInput, BlobVersionView, EntityRefReceipt, EntityView,
    HabitCheckinInput, ProductivityCreateRequest, ProductivityCreateRole, ProductivityNode,
    ProductivityRole, ProductivityTree, ProductivityTreeRequest, StructuralEdgeSpec,
    StructuralPutInput, TextIndexField,
};
pub use subscriptions::{MemorySubscriptionOwner, ScopedView};
pub use support::{HostWriteOrigin, Memory, RewriteAdmit, parse_actor_key, resolve_entity_ref};
pub use transcript::{
    MAX_TRANSCRIPT_PAGE_TURNS, TranscriptMessage, TranscriptPage, TranscriptTurn,
};
pub use witness::{
    AppendToStreamRequest, BeginMessageStreamRequest, CancelStreamRequest, CommitMessageRequest,
    MessageBirth, MessageCancelKind, MessageCancelReason, MessageCommitOptions,
    MessageCustomCancel, MessageCustomCancelKind, MessageDocumentState, MessageDurability,
    MessageDurabilityRequest, MessageStreamMode, MessageStreamOptions, MessageStreamRequest,
};
pub use witness::{
    DEFAULT_MESSAGE_STREAM_IDLE_MS, MAX_MESSAGE_STREAM_BYTES, MessageCompletion,
    MessageStreamError, MessageStreamHandle, MessageStreamPartial, MessageStreamPolicy,
    MessageStreamPump, MessageStreamReceipt, MessageStreamResult, MessageWriteMode, StreamCadence,
    StreamCancelReason, StreamFinality, StreamFinalityReason, StreamSyncVisibility,
};
pub(crate) use witness::{
    MessageStreamRuntime, erase_stream_seeds_in_txn, message_completion_in_txn,
    message_stream_finality_in_txn,
};
pub use witness::{WitnessAssertions, WitnessAuthor, WitnessMessage, WitnessReceipt, WitnessTurn};

pub(crate) use booking_publication::verify_public_booking_owner_in_txn;
pub(crate) use credential_key::{actor_is_vault_owner_in_txn, owner_exemption_holds_in_txn};
pub(crate) use support::{
    facade_provenance, hard_deleted_refusal, verify_actor_binding, verify_actor_binding_in_txn,
    verify_deletion_authority_in_txn, verify_owner_actor_binding_in_txn,
};
pub(crate) use witness::{
    IMPORTED_SOURCE_KEY, ImportedTurnStamp, guard_import_stamp, turn_admits_message_bodies,
    witness_message_body,
};
pub(crate) use witness::{
    next_witness_message_order, sole_edge_target, taken_witness_message_order,
    witness_message_order,
};

// Read-version, revision-change, and publication types are available under
// the existing memory namespace; no additional crate-root surface is required.
pub use crate::gate::LiveQueryTrackerLimits;
pub use crate::vault::entity_revision::{EntityRevisionChange, IndexedPublication};
pub use crate::vault::{
    IndexedRefreshReport, IndexedRevisionEmbedder, IndexedRevisionInput, PinnedCitation, ReadMode,
    ResolvedCitation, RevisionRef,
};
