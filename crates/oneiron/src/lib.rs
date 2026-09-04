use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(test)]
thread_local! {
    static PANIC_ON_UNIX_SECONDS_NOW: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

pub mod access_grant;
pub mod actor_claims;
pub mod affect;
pub mod agent_def;
pub mod agent_dispatch;
pub mod agent_run_status;
pub mod analyzer;
pub mod anchored_annotation;
pub mod artifact_hosting;
pub mod attempt_queue;
pub mod authority;
pub mod batch;
pub mod blob_artifact;
pub(crate) mod bm25;
pub mod board_verb;
pub mod booking;
pub mod calendar;
pub mod campaign;
pub mod channel_identity;
pub mod channel_identity_lifecycle;
pub mod channel_identity_manifest;
pub mod channel_identity_provider;
pub mod channel_identity_selection;
pub mod checkout;
pub mod claim;
pub mod cluster;
pub mod code_artifact;
pub mod code_memory;
pub mod code_revision;
pub mod code_run;
pub mod code_sandbox;
pub mod code_symbol;
pub mod codebase;
pub mod comm;
pub mod commitment;
pub mod commitment_ledger;
pub mod commitment_lifecycle;
pub mod commitment_schedule;
pub mod commitment_wake;
pub mod compaction;
pub mod companion;
pub mod config;
pub mod connector_key;
// DEC-0006 unified consent-mode: the pinned import path is `oneiron::consent::ActorBound`.
pub mod consent;
pub mod consent_graduation;
pub mod consult_ladder;
pub mod context_board;
pub mod context_pack;
pub mod context_projection;
pub mod counterparty_contact;
pub(crate) mod credential_door;
pub mod critic;
pub mod deletion;
pub mod delivery_window;
pub mod disclosure;
pub(crate) mod distance;
pub mod dreamer_consolidation;
pub mod dreamer_plugin_suggest;
pub mod dreamer_promotion;
pub mod dreamer_runner;
pub mod dreamer_tournament;
pub mod dreamer_wake;
pub mod edge;
pub mod edit_distance;
pub mod edit_roundtrip;
pub mod edit_settle;
pub mod eiri;
pub mod embed;
pub mod engine_executor;
pub mod entity_id;
pub mod error;
pub mod extraction_eval;
pub mod failure_ladder;
pub mod fanout_auto;
pub mod federation;
pub(crate) mod fusion;
pub(crate) mod gate;
pub mod genui;
pub mod git_wire;
pub mod graph_fs;
pub mod habit;
pub(crate) mod hnsw;
pub mod human_task;
pub(crate) mod identity;
pub mod identity_redirect;
pub mod identity_reputation;
pub mod identity_topology;
pub mod inbox;
pub mod ingest;
pub mod interlocutor;
pub mod lens;
pub(crate) mod limits;
pub mod linear_sync;
pub mod linkedin_connector;
pub mod llm;
pub mod maintain;
pub mod memory;
pub mod note;
pub mod off_record;
pub mod origin;
pub mod outbound;
pub(crate) mod outbound_chokepoint;
pub mod outbound_consent;
pub mod outbound_grant;
pub mod outbound_intent_ledger;
pub(crate) mod overlay_db;
pub mod persona_snapshot;
pub mod pipeline;
pub mod policy_model;
pub(crate) mod ppr;
pub mod prompt;
pub mod provenance;
pub mod provider_confidence;
pub mod psych_profile;
pub mod query_expansion;
pub mod receipt;
pub mod recovery;
pub mod registry;
pub mod repo_mutation;
pub mod rerank;
pub mod run_tree;
pub mod saved_query;
pub mod secret_custody;
pub mod secret_lease;
pub mod secret_manifest;
pub mod secret_snapshot;
pub mod serialize;
pub mod session_lifecycle;
pub(crate) mod session_overlay;
pub mod settings;
pub mod skill;
pub mod skill_attribution;
pub mod skill_convert;
pub mod skill_hub;
pub mod skill_optimize;
pub mod skill_reliability;
pub mod skill_scan;
pub mod speculative;
pub mod store;
pub mod surface_event;
pub(crate) mod sweep;
#[cfg(feature = "sync")]
pub mod sync;
pub mod task_authority;
pub mod task_verb;
pub mod temporal;
pub mod thread_lens;
pub mod tokenizer;
mod vault;
// VOX-02 voice identity: consent log, enrollment, and local roster matching.
pub mod voice_identity;
pub mod voice_segment;
pub mod wave_orchestration;
pub mod web_fetch;
pub mod write_envelope;

// Root re-export surface (curated). A name lives here only when a downstream
// consumer imports it at the crate root — plus `Error`, pinned by the docs
// contract, and the signature closure: a type a public signature exposes (an
// argument, return, or `pub`-field type of a root item) whose own module is
// not `pub` must stay nameable here. Everything else stays reachable
// module-qualified (`oneiron::<module>::Name`); nothing was removed from the
// module tree.
pub use crate::access_grant::AccessGrant;
pub use crate::affect::{Vad, VadAnnotation, VadAnnotationSource};
pub use crate::agent_dispatch::{DispatchHealer, HealerSlot, HealerSlotOutcome};
pub use crate::artifact_hosting::{
    ArtifactPointerChannel, ArtifactServedFile, ArtifactSnapshotSelector, artifact_hex,
    parse_codebase_fork_hash_hex,
};
pub use crate::attempt_queue::{
    AttemptId, AttemptInterventionEffect, AttemptInterventionKind, AttemptQueue, InterveneAttempt,
};
pub use crate::batch::BatchBuilder;
// Kept by the compiler, not by a consumer: `bm25` and `gate` are non-`pub` modules,
// so dropping these would make their own items `unreachable_pub` (denied workspace-wide).
// `Bm25Formula` is signature-kept: public `Bm25RankProfile::with_formula` takes it.
pub use crate::bm25::{
    Bm25DiagnosticCounter, Bm25DiagnosticKind, Bm25DiagnosticsSnapshot, Bm25Formula,
    bm25_diagnostics_snapshot,
};
pub use crate::calendar::{
    CALENDAR_INVITE_CHANNEL, CALENDAR_INVITE_VERB, CalendarEventView, CalendarInviteConsentBasis,
    CalendarInviteMethod, CalendarInviteMimePart, CalendarInvitePayload, CalendarRangeDto,
    CalendarReadRequest, CalendarSearchRequest, CalendarSel, ImipEmitRequest, emit_imip_ics,
    persist_imip_blob,
};
pub use crate::channel_identity_provider::{
    ChannelIdentityProviderAdapter, ChannelIdentityProviderInbound, DevEmailIdentityAdapter,
    DevEmailIdentityAdapterConfig, EmailProviderInbound,
};
pub use crate::channel_identity_selection::{
    ChannelIdentityCandidate, ChannelIdentityFace, ChannelIdentitySelectionDecision,
    ChannelIdentitySelectionError, ChannelIdentitySelectionPatch, ChannelIdentitySelectionQuery,
    ChannelIdentitySelectionRule, ChannelIdentitySelectionRuleSet, ChannelIdentitySelectionWriter,
    ChannelIdentityThreadPin, RelationshipContext, SelectionRuleScope, SelectionRuleWriterKind,
    resolve_channel_identity_selection,
};
pub use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    ExpressionKeigo, ExpressionPreferenceKind, ExpressionPreferenceOrigin,
    ExpressionPreferenceValue, ExpressionRegister,
};
pub use crate::codebase::{
    CODEBASE_CONTENT_HASH_LEN, CODEBASE_FORK_HASH_LEN, CODEBASE_SCOPE_KEY_LEN, CodebaseFileEntry,
    CodebaseSnapshot, RepoRef,
};
pub use crate::commitment::FulfillmentSource;
pub use crate::commitment_lifecycle::{
    BriefFulfillmentReport, CommitmentCloseResult, FULFILLMENT_PROPOSAL_SCHEMA_VERSION,
    LapseSweepReport, PREDICATE_COMMITMENT_FULFILLMENT_PROPOSAL, fulfill_commitment_from,
    fulfill_commitments_for_brief, lapse_overdue_commitments, link_brief_fulfillment,
    propose_commitment_fulfilled, release_commitment_with_close, supersede_commitment_with_close,
};
pub use crate::commitment_wake::{
    ApprovedCommitmentWake, CommitmentWakeDue, CommitmentWakeEvent, CommitmentWakeExecutor,
    CommitmentWakeFireOutcome, CommitmentWakePhase, CommitmentWakeProposalDraft,
    CommitmentWakeProposalPlanner, CommitmentWakeProposalSkip, CommitmentWakeSkip,
    approved_commitment_wake, commitment_wake_proposal_claim_id, decode_commitment_wake_event,
    encode_commitment_wake_event, fire_due_commitment_wake, schedule_approved_commitment_wake,
};
pub use crate::compaction::{
    COMPACTION_PACKET_SCHEMA_VERSION, CompactionPacket, CompactionPayloadKind,
    CompactionSnapshotRef, ValidatedCompactionPacket, admit_compaction_packet,
};
pub use crate::companion::{
    CompanionExportClassification, CompanionExpression, CompanionExpressionRegister,
    CompanionProvenance, CompanionRecord, CompanionRecordKind, CompanionScope,
    CompanionScopeResolutionSource, CompanionSubject, CompanionTaskKind, EndCompanionRelationship,
    EnqueueCompanionTaskOutcome, companion_value_from_json, companion_value_to_json,
};
pub use crate::config::{HnswConfig, VaultConfig};
pub use crate::context_pack::{
    ContextEntity, ContextPack, ContextPackBuilder, ContextPackRetrievalBudget, EmptyContext,
    EmptyReason, FieldProfile, PackFormat, PackStats, PackTokenStats, TokenAllocation,
};
pub use crate::deletion::{
    DeleteReason, HydratedShortIdDeletion, HydratedShortIdDeletionReason,
    HydratedShortIdDeletionSource, MemoryOperationKind, MemoryTimeline, MemoryTimelineRecordState,
    NamedMemoryVerb,
};
pub use crate::delivery_window::DeliveryWindowApnsInterruptionLevel;
pub use crate::disclosure::{DisclosureAssembly, DisclosureContext};
pub use crate::dreamer_consolidation::{
    ConsolidationExecutor, ConsolidationSink, plan_partitions, read_watermark, scan_dirty_turns,
};
#[cfg(feature = "sync")]
pub use crate::dreamer_runner::DreamerAttemptProgressProducer;
pub use crate::dreamer_runner::{
    DEFAULT_DREAMER_CHILD_RESERVE_UNITS, DREAMER_CONSOLIDATION_MACRO_ATTEMPT_KIND,
    DREAMER_CONSOLIDATION_MESO_ATTEMPT_KIND, DREAMER_CONSOLIDATION_MICRO_ATTEMPT_KIND,
    DreamerAdmittedAttempt, DreamerBudgetReserveOutcome, DreamerClaimAuthoringStrategy,
    DreamerConsolidationScope, DreamerHomeNodeCandidate, DreamerRunnerStore,
    EnqueueDreamerAttemptOutcome, EnqueueDreamerConsolidationAttempt, ReserveDreamerBudget,
};
pub use crate::dreamer_wake::{
    DREAMER_EXECUTOR_ERROR_PARK_REASON, DREAMER_GRACEFUL_WRAP_WINDOW_MS,
    DREAMER_WAKE_PASS_WALL_CLOCK_CEILING_MS, DreamerAttemptExecution, DreamerAttemptExecutor,
    DreamerWakeDriver, RunWakePass, WakeAttemptContext, WakeCancellation, WakeMilestoneAuthor,
    WakePassDeadline, WakePassReport, WakePassStop, WakeTrigger,
};
pub use crate::edge::{EdgeActorClass, EdgeInfo, EdgeKind};
pub use crate::eiri::{
    EIRI_CONTEXT_VERSION_V4, EiriCompanionAssembly, EiriMemoryBoard, EiriMemoryBoardBudget,
    EiriSessionRagState, NotificationItem, ResumeBudget, ResumeBundle, SessionContext,
    UnprocessedItem,
};
pub use crate::entity_id::{EntityId, parse_presentation_id};
pub use crate::error::{CompactionPacketError, Error, ErrorKind, Result};
#[cfg(feature = "sync")]
pub use crate::error::{SyncConfigField, SyncEngineContext, SyncProtocolValidation};
pub use crate::failure_ladder::{
    DEFAULT_MAX_CONSECUTIVE_TRANSIENTS, FailureClass, FailureEscalationMode, FailureLadder,
    FailureLadderOutcome, FailureScope, FailureScopePolicy, HealerCase, HealerRepairRoute,
    RetryLineagePathology, SurfacedFailure,
};
pub use crate::federation::FederationGrantScope;
pub use crate::gate::{
    CRITICAL_WRITE_CONFIRM_TIMEOUT_SECS, CriticalWriteConfirmBinding,
    CriticalWriteConfirmResolution, GATE_BUNDLE_CONTENT_KIND, GATE_BUNDLE_OUTCOME_APPROVED,
    GATE_BUNDLE_OUTCOME_DECLINED, GATE_BUNDLE_REASON_APPROVED, GATE_BUNDLE_REASON_DECLINED,
    GATE_REASON_ALLOW_CRITICAL_CONFIRM_ATTACHED, GATE_REASON_CRITICAL_CONFIRM_DECLINED,
    GATE_REASON_CRITICAL_CONFIRM_TIMEOUT,
};
pub use crate::genui::{
    FailureDiagnosisState, HealerQaEntryRef, HealerQaFeed, SURFACED_FAILURE_CARD_SCHEMA_VERSION,
    SurfacedFailureCard,
};
pub use crate::interlocutor::{
    InterlocutorPartyInput, InterlocutorResolutionInput, InterlocutorSet, InterlocutorStamp,
};
pub use crate::linear_sync::{
    LinearChangePage, LinearChangeSource, LinearEgress, LinearFieldConflict, LinearIssueChange,
    LinearIssueRef, LinearMirrorReceipt, LinearMirrorStatus, LinearPullReceipt, LinearSyncAdapter,
    LinearSyncDirection, LinearSyncError, LinearSyncResult, LinearTaskStore, MirroredTaskFields,
    TaskIssueLink, TaskMirrorSnapshot, WaveResult, linear_operation_id,
};
pub use crate::llm::{
    BudgetExhaustionPolicy, BudgetGuard, BudgetLease, CallClass, CallEnvelope, CallPurpose,
    ContentPart, DeterministicFallback, FatalLlmError, FinishReason, ImageContent, LlmBackend,
    LlmCapability, LlmCatalogEntry, LlmError, LlmGenerateFuture, LlmInputUsage, LlmMessage,
    LlmMessageRole, LlmOutputUsage, LlmRequest, LlmResponse, LlmResult, LlmStream, LlmStreamEvent,
    LlmStreamResult, LlmToolSpec, LlmUsage, ModelId, ModelLocality, ModelTierRef,
    PinnedConfigViolation, PinnedModelConfig, ResponseFormat, RetryableLlmError, TierPrecedence,
    UnsupportedCapability,
};
pub use crate::memory::{
    AdmitImportedClaimInput, BlobArtifactInput, CalendarInviteSurfaceInput,
    CalendarInviteSurfaceMethod, ChatAbstentionReason, ChatComposeRequest, ChatComposer, ChatDepth,
    ChatOptions, ChatResponse, ChatScope, ClaimInput, ClaimListFilter, ClaimView, CommitReceipt,
    CompanionRecordInput, ComposedChatAnswer, ConsolidationAttemptInput, Effort, EntityRefReceipt,
    EntityView, ExpressionPreferenceInput, HabitCheckinInput, MEMORY_CODE_BAD_REQUEST,
    MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INTERNAL, MEMORY_CODE_INVALID_STATE, MEMORY_CODE_NOT_FOUND,
    MEMORY_PACK_VERSION, Memory, MemoryError, NeighborOpts, OutboundDraftInput, RecallScope,
    SafeDeleteReason, StructuralEdgeSpec, StructuralPutInput, TextIndexField, WitnessAuthor,
    WitnessMessage, WitnessTurn, parse_actor_key,
};
pub use crate::outbound::{
    COMMON_OUTBOUND_VERB_KINDS, OUTBOUND_CAPABILITY_MANIFEST_VERSION, OUTBOUND_VERB_FIELD_CONTRACT,
    OutboundCapabilityManifest, OutboundVerbContract, UnsupportedOutboundCapability,
    outbound_capability_manifest, outbound_capability_manifests, outbound_verb_contract,
    unsupported_outbound_connector,
};
pub use crate::pipeline::{PipelineBuilder, ScoredEntity, Signal};
pub use crate::psych_profile::{
    PsychProfile, PsychProfileSnapshotStatus, PsychProfileStaleReason, PsychProfileState,
};
pub use crate::repo_mutation::{
    REPO_PROVENANCE_NOTES_REF, export_repo_provenance_git_note, repo_commit_for_provenance_claim,
    repo_commit_provenance,
};
pub use crate::run_tree::{
    GATE_CONSENT_BUNDLE_DOMAIN, GATE_CONSENT_BUNDLE_FALLBACK_LABEL,
    GATE_CONSENT_BUNDLE_SCHEMA_VERSION, GateConsentBundle, GateConsentBundleAction,
    GateConsentBundleMember, GateConsentBundleReceipt, RunTree, RunTreeAdapter, RunTreeEvent,
    RunTreeEventKind, RunTreeNode, RunTreeRepair, RunTreeStatus,
};
pub use crate::session_lifecycle::{
    EndedSession, SessionClosePredicate, SessionEndWake, SessionMintOutcome,
};
pub use crate::skill::{SKILL_RECORD_BODY_KEYS, SkillGovernanceTier};
pub use crate::store::{
    RetrievalRunId, RetrievalScoreBreakdown, RetrievalScoreComponent, RetrievalSignal,
    RetrievalTrace, RetrievalTraceChannelRecord, RetrievalTraceForkHash, RetrievalTraceStage,
    RetrievalTraceStageRecord,
};
pub use crate::surface_event::{
    InboundSurfaceEventInput, InboundSurfaceRejectionReason, InboundSurfaceRouteOutcome,
    InboundSurfaceRouteReceipt, SurfaceCounterpartyStamp, SurfaceEventAck, SurfaceEventAction,
    SurfaceEventAdmission, SurfaceEventHandoffState, SurfaceEventHandoffStatus, SurfaceEventSource,
    SurfaceInteractionKind, SurfaceSourceApp,
};
pub use crate::task_authority::{
    TASK_AUTHORITY_FACT_SCHEMA_VERSION, TASK_AUTHORITY_FACT_SUBKIND, TaskAuthorityFact,
    TaskAuthorityFactKind, TaskAuthorityState,
};
pub use crate::temporal::TimeRange;
pub use crate::tokenizer::{DEFAULT_CONTEXT_PACK_TOKENIZER_ID, count_context_pack_tokens};
// Beyond the two consumer-kept names, the rest are signature-kept: `Vault`'s
// public `doctor`, `text_index_status`, and `as_actor` return them directly
// or through the doctor report's `pub` fields, and `vault` is not `pub`.
pub use crate::vault::{
    ActorBound, HydratedShortId, TextIndexStatus, Vault, VaultDoctorDbManifestReport,
    VaultDoctorHnswRecordState, VaultDoctorHnswReport, VaultDoctorReport,
};
pub use crate::web_fetch::{
    CrawlCompletion, CrawlPageBudget, CrawlPageFailure, CrawlRequest, CrawlResult, CrawlScope,
    DEFAULT_MIN_EXTRACTED_CONTENT_BYTES, FetchResult, FirecrawlRenderer, HeadlessDocument,
    HeadlessRenderer, MinExtractedContentBytes, NativeHeadlessRenderer, NativeReadabilityRenderer,
    RenderedPage, Renderer, RendererAttemptFailure, RendererError, RendererErrorKind, RendererKind,
    RendererResult, WEB_FETCH_CONTENT_HASH_DOMAIN, WebFetchError, WebFetchResult, WebFetcher,
};

pub use crate::wave_orchestration::{
    BlockedByEdgeWrite, PlannedTask, ValidatedWavePlan, WaveOrchestrator, WavePlan,
    WavePlanReceipt, WavePlanRequest, WavePlanner, WaveTaskPort, WaveTaskWrite,
    blocked_by_edge_write,
};
pub use crate::write_envelope::{ClaimCandidate, WriteActor, WriteEnvelope, WriteProvenance};

pub(crate) fn unix_seconds_now() -> u64 {
    #[cfg(test)]
    PANIC_ON_UNIX_SECONDS_NOW.with(|panic_on_call| {
        assert!(
            !panic_on_call.get(),
            "unix_seconds_now must not be called by this path",
        );
    });
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

#[cfg(test)]
pub(crate) fn panic_on_unix_seconds_now_for_current_thread(enabled: bool) {
    PANIC_ON_UNIX_SECONDS_NOW.with(|panic_on_call| panic_on_call.set(enabled));
}

pub(crate) fn le_bytes_to_f32_vec(bytes: &[u8], dimensions: usize) -> Result<Vec<f32>> {
    crate::store::decode_vector_row(bytes, dimensions)
}

#[cfg(test)]
mod branch_store_oracle;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod tests_bug;

/// M8 forward test oracle (path-opener ONE-1685): contract-level red tests
/// for ONE-1687 / ONE-1689 / ONE-1690 / ONE-1691, each behind
/// `#[ignore = "armed by ONE-XXXX"]`. Arming tickets remove the ignore and
/// adapt signatures — the asserts are never weakened.
#[cfg(test)]
mod m8_forward_oracle;

#[cfg(test)]
pub(crate) mod test_util {
    //! Shared test helpers. Centralized to avoid drift between per-module
    //! copies of `open_test_vault`, seed-id, policy-manifest, and config
    //! fixtures.
    //!
    //! Config carve-out: [`embedding_test_config`] is the canonical
    //! embedding-enabled config. A module keeps a LOCAL `test_config()` only
    //! when its values genuinely diverge (map size, dimensions, embedding
    //! model, HNSW params); a copy that is value-identical to the shared
    //! helper is a drift hazard and must route through it.
    use crate::batch::ENTITY_METADATA_HEADER_LEN;
    use crate::config::VaultConfig;
    use crate::entity_id::EntityId;
    use crate::error::Error;
    use crate::registry::ENTITY_TYPE_POLICY_MANIFEST;
    use crate::store::Store;
    use crate::temporal::TimeRange;
    use crate::vault::Vault;

    /// Id bytes pinned by production code. `entity` refuses them so a generic
    /// fixture can never alias a system identity. Any byte NOT listed here is
    /// safe for test seeds. A new production id pin must be added to this list
    /// in the same change that mints it.
    ///
    /// - `0x00`, `0xFF`: reserved sentinels (`entity_id::is_reserved_entity_id_bytes`)
    /// - `0x11`: dreamer consolidation probe actor
    /// - `0x42`: code-run replay canonical request actor
    /// - `0x47`: gate local-write actor ref
    /// - `0xA1..=0xA6`: seeded system-agent row/actor ids (canonical manifest).
    ///   ONE-1709's `sys.team_lead` row is deliberately NOT a repeated byte
    ///   (`aaaa…aaaa1709`): every free byte in the roster's `0xA*` range was
    ///   already in `[seed; 16]` fixture use, and a non-repeating id is
    ///   unreachable from that whole class of seed.
    /// - `0xD7`: default policy manifest id
    /// - `0xE1`: first-party connector actor id
    pub(crate) const PINNED_ID_BYTES: [u8; 13] = [
        0x00, 0x11, 0x42, 0x47, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xD7, 0xE1, 0xFF,
    ];

    /// Canonical test entity id: `[seed; 16]`.
    ///
    /// Panics when `seed` is production-pinned (see [`PINNED_ID_BYTES`]) —
    /// including `entity(0)`, whose bytes are the reserved zero sentinel.
    /// Tests that *intend* a pinned identity must construct it explicitly
    /// (a seeded roster row id resolved through
    /// `Vault::get_seeded_agent_definition_by_logical_id`,
    /// `crate::gate::default_policy_manifest_id()`, or
    /// `EntityId::from_bytes` with an intent comment), never through this
    /// helper.
    pub(crate) fn entity(seed: u8) -> EntityId {
        assert!(
            !PINNED_ID_BYTES.contains(&seed),
            "test seed {seed:#04x} collides with a production-pinned id byte; \
             pick a byte outside PINNED_ID_BYTES or construct the pinned id explicitly"
        );
        EntityId::from_bytes([seed; 16]).expect("non-pinned seed byte forms a valid entity id")
    }

    /// Raw stored-entity record: the 25-byte metadata header (type byte,
    /// occurred start/end, learned_at — all big-endian u64s, per the
    /// `batch::ENTITY_*_OFFSET` layout) followed by `body`.
    pub(crate) fn entity_record(
        entity_type: u8,
        occurred: TimeRange,
        learned_at: u64,
        body: &[u8],
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + body.len());
        out.push(entity_type);
        out.extend_from_slice(&occurred.start.to_be_bytes());
        out.extend_from_slice(&occurred.end.to_be_bytes());
        out.extend_from_slice(&learned_at.to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    /// Stores `data` as a policy-manifest entity at `id` via a raw store put
    /// (occurred `1..1`, learned_at `1`), bypassing the batch write path.
    /// Seeding the *default* manifest slot must pass
    /// `crate::gate::default_policy_manifest_id()` so the intent is explicit.
    /// The `graph_fs` test copy deliberately stays local: it exercises the
    /// real `apply_ops` write path instead of a raw put.
    pub(crate) fn put_policy_manifest_bytes(
        vault: &Vault,
        id: EntityId,
        data: &[u8],
    ) -> crate::Result<()> {
        let payload = entity_record(
            ENTITY_TYPE_POLICY_MANIFEST,
            TimeRange { start: 1, end: 1 },
            1,
            data,
        );
        vault.with_write_txn(|wtxn| {
            vault.store.entities.put(wtxn, id.as_bytes(), &payload)?;
            let type_key = Store::encode_type_key(ENTITY_TYPE_POLICY_MANIFEST, &id);
            vault.store.type_index.put(wtxn, &type_key, &[])?;
            Ok(())
        })
    }

    /// Canonical embedding-enabled test config: 16 MiB map, 4 dimensions,
    /// `test/model@v1` embedding model, 16 readers. Everything else is the
    /// `VaultConfig::device()` preset — HNSW and text-analyzer defaults
    /// included, so do NOT re-assign defaults here.
    pub(crate) fn embedding_test_config() -> VaultConfig {
        let mut config = VaultConfig::device();
        config.map_size = 16 * 1024 * 1024;
        config.dimensions = 4;
        config.embedding_model = Some("test/model@v1".to_owned());
        config.max_readers = 16;
        config
    }

    /// Opens a temporary vault with the supplied config. Returns the
    /// `TempDir` so callers keep the directory alive for the vault's lifetime.
    pub(crate) fn open_test_vault_with(cfg: VaultConfig) -> (tempfile::TempDir, Vault) {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::open(dir.path(), cfg).expect("open vault");
        clear_default_policy_manifest_for_legacy_tests(&vault);
        (dir, vault)
    }

    /// Asserts `error` is the Gate secret-scan denial: [`Error::GateWriteRejected`]
    /// with outcome `"deny"` and reason codes exactly
    /// `["gate.secret_scan.detected", expected_reason]`. Call sites pass the
    /// expected leaf reason explicitly (e.g. `"gate.secret_scan.github_token"`)
    /// so the asserted detector is visible at the test.
    pub(crate) fn assert_secret_scan_rejected(error: Error, expected_reason: &'static str) {
        match error {
            Error::GateWriteRejected {
                outcome,
                reason_codes,
            } => {
                assert_eq!(outcome, "deny");
                assert_eq!(
                    reason_codes.as_slice(),
                    &["gate.secret_scan.detected", expected_reason]
                );
            }
            other => panic!("expected GateWriteRejected, got {other:?}"),
        }
    }

    fn clear_default_policy_manifest_for_legacy_tests(vault: &Vault) {
        let id = crate::gate::default_policy_manifest_id().expect("default policy manifest id");
        vault
            .with_write_txn(|wtxn| {
                crate::batch::deindex_entity_for_test(&vault.store, wtxn, &id)?;
                Ok(())
            })
            .expect("clear default policy manifest for legacy test fixture");
    }
}
