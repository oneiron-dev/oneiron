use std::time::{SystemTime, UNIX_EPOCH};

pub mod access_grant;
pub mod affect;
pub mod analyzer;
pub mod authority;
pub mod batch;
pub(crate) mod bm25;
pub mod channel_identity;
pub mod channel_identity_lifecycle;
pub mod channel_identity_manifest;
pub mod claim;
pub mod code_artifact;
pub mod code_revision;
pub mod code_run;
pub mod code_sandbox;
pub mod code_symbol;
pub mod codebase;
pub mod context_pack;
pub mod counterparty_contact;
pub mod critic;
pub mod deletion;
pub(crate) mod distance;
pub mod dreamer_runner;
pub mod embed;
pub mod error;
pub mod federation;
pub(crate) mod fusion;
pub(crate) mod gate;
pub mod graph_fs;
pub(crate) mod hnsw;
pub(crate) mod identity;
pub mod identity_reputation;
pub mod ingest;
pub mod job_queue;
pub mod lens;
pub(crate) mod limits;
pub mod llm;
pub mod maintain;
pub mod outbound;
pub mod pipeline;
pub(crate) mod ppr;
pub mod provenance;
pub mod receipt;
pub mod recovery;
pub mod repo_mutation;
pub mod run_tree;
pub mod serialize;
pub mod settings;
pub mod skill;
pub mod store;
pub mod surface_event;
pub(crate) mod sweep;
#[cfg(feature = "sync")]
pub mod sync;
pub mod tokenizer;
pub mod types;
mod vault;

pub use crate::access_grant::{
    ACCESS_GRANT_BODY_KEYS, ACCESS_GRANT_SCHEMA_VERSION, AccessGrant, AccessGrantCapability,
    AccessGrantScope, AccessGrantStatus, decode_access_grant_body, encode_access_grant_body,
};
pub use crate::affect::coping::{
    COPING_OUTCOME_PREDICATE, CopingOutcomeRecord, CopingOutcomeUpdate, CopingOutcomeValue,
    CopingStrategy, coping_delta_successful, coping_outcome_claim_candidate, coping_outcome_value,
    decode_coping_outcome_claim, decode_coping_outcome_value,
};
pub use crate::affect::{
    AFFECT_TRIGGER_PREDICATE, AffectTriggerValue, CLAIM_VAD_REAPPRAISAL_PREDICATE,
    ClaimVadConsolidation, ClaimVadReappraisal, ClaimVadTurnEvidence, VadDelta,
    affect_trigger_claim_candidate, affect_trigger_value, decode_affect_trigger_claim,
    decode_affect_trigger_value,
};
pub use crate::analyzer::{
    ANALYZER_VERSION, AnalyzerAssetManifest, AnalyzerChannel, AnalyzerContext, AnalyzerManifest,
    AnalyzerMode, LangPolicy, LanguageHint, NormalizationPolicy, Token, TokenKind,
};
pub use crate::authority::{
    AUTHORITY_FORK_ALARM_KIND, AUTHORITY_LOG_SCHEMA_VERSION, AUTHORITY_TRANSCRIPT_DOMAIN,
    AuthorityAttestation, AuthorityConfirmAction, AuthorityConfirmKind, AuthorityEntryHash,
    AuthorityFold, AuthorityFoldIssue, AuthorityFork, AuthorityForkAlarm, AuthorityForkStatus,
    AuthorityKey, AuthorityLogEntry, AuthorityOp, AuthorityPendingWiden, AuthoritySignature,
    AuthoritySignatureSuite, AuthorityTier, AuthorityVaultId, DEFAULT_PENDING_WIDEN_DELAY_SECS,
    DeviceAuthority, FoldedDevice, MAX_DEFAULT_PENDING_WIDEN_DELAY_SECS,
    MIN_DEFAULT_PENDING_WIDEN_DELAY_SECS, ROLE_ADMIN, ROLE_AGENT, ROLE_CLOUD, ROLE_OWNER,
    ROLE_RECOVERY, authority_entry_hash, authority_transcript, decode_authority_log_entry_body,
    encode_authority_log_entry_body, fold_authority_log, fold_authority_log_with_seen_times,
    genesis_vault_id, validate_authority_log_entry_body_bytes, verify_authority_signature,
};
pub use crate::batch::{BatchBuilder, TxnBatchBuilder};
pub use crate::bm25::{
    Bm25DiagnosticCounter, Bm25DiagnosticKind, Bm25DiagnosticsSnapshot, Bm25Formula,
    bm25_diagnostics_snapshot,
};
pub use crate::channel_identity::{
    CHANNEL_IDENTITY_BODY_KEYS, CHANNEL_IDENTITY_CLAIM_PREDICATES,
    CHANNEL_IDENTITY_MIN_QUARANTINE_SECS, CHANNEL_IDENTITY_SCHEMA_VERSION, ChannelIdentity,
    ChannelIdentityBinding, ChannelIdentityFulfillment, ChannelIdentityShape, ChannelIdentityState,
    PREDICATE_CHANNEL_IDENTITY_ADDRESS_OR_HANDLE, PREDICATE_CHANNEL_IDENTITY_BINDING_SCOPE,
    PREDICATE_CHANNEL_IDENTITY_BINDING_TARGET, PREDICATE_CHANNEL_IDENTITY_CHANNEL,
    PREDICATE_CHANNEL_IDENTITY_MANIFEST_REF, PREDICATE_CHANNEL_IDENTITY_PENDING_FULFILLMENT,
    PREDICATE_CHANNEL_IDENTITY_QUARANTINE_UNTIL, PREDICATE_CHANNEL_IDENTITY_REPUTATION_REF,
    PREDICATE_CHANNEL_IDENTITY_SHAPE, PREDICATE_CHANNEL_IDENTITY_STATE,
    PREDICATE_CHANNEL_IDENTITY_STATE_CHANGED_AT, decode_channel_identity_body,
    encode_channel_identity_body,
};
pub use crate::channel_identity_lifecycle::{
    BindIntent, ChannelIdentityFulfillmentInput, ChannelIdentityLifecycleActor,
    ChannelIdentityLifecycleGate, ChannelIdentityLifecycleIntent,
    ChannelIdentityLifecyclePolicyRisk, ChannelIdentityLifecycleRequest,
    ChannelIdentityLifecycleResult, ChannelIdentityLifecycleVerb, ProvisionIntent, ReleaseIntent,
    RotateIntent, RouteInboundIntent,
};
pub use crate::channel_identity_manifest::{
    CHANNEL_IDENTITY_CAPABILITY_MATRIX_VERSION, ChannelIdentityCapabilityMatrix,
    ChannelIdentityDisclosureClass, ChannelIdentityManifest, ChannelIdentityManifestError,
    ChannelIdentityMintability, ChannelIdentityPolicyRisk, ChannelIdentityReceiveCapabilities,
    ChannelIdentityReputationSignal, channel_identity_capability_matrix, channel_identity_manifest,
    channel_identity_manifests, parse_channel_identity_capability_matrix,
};
pub use crate::claim::{
    CLAIM_BODY_KEYS, ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource,
    ClaimSubject, MAX_PREDICATE_BYTES, PREDICATE_CONFLICT_OPEN, PREDICATE_CONFLICT_RESOLVED,
    RESERVED_PREDICATE_NAMESPACE,
};
pub use crate::code_artifact::{
    CODE_ARTIFACT_BODY_KEYS, CODE_ARTIFACT_REPO_REF_MAX_BYTES, CODE_ARTIFACT_SUMMARY_HASH_LEN,
    CODE_ARTIFACT_SUMMARY_PROMPT_MAX_BYTES, CodeArtifactBody, decode_code_artifact_body,
    encode_code_artifact_body,
};
pub use crate::code_revision::{
    CODE_REVISION_FORK_KEYS, CODE_REVISION_RECORD_KEYS, CodeRevision, CodeRevisionFork,
    CodeRevisionKind, decode_code_revision, decode_code_revision_fork, encode_code_revision,
    encode_code_revision_fork,
};
pub use crate::code_run::{
    HostSelfDispatcher, SelfAskHumanCall, SelfCall, SelfDispatchOutcome, SelfDispatcher,
    SelfDurableWait, SelfDurableWaitReason, SelfEffect, SelfFixtureEffectCall,
    SelfMemoryEdgeWriteResult, SelfMemoryPutClaimCall, SelfMemoryPutEdgeCall, SelfMemorySearchCall,
    SelfMemorySearchResult, SelfMemorySupersedeClaimCall, SelfMemoryWriteFixtureCall,
    SelfMemoryWriteResult,
};
pub use crate::code_sandbox::{
    FakeSandboxAdapter, PLAIN_JS_HOST_VERB_DTS, SANDBOX_JS_COMPONENT_NAME, SANDBOX_MNT_ROOT,
    SANDBOX_OUTPUTS_ROOT, SANDBOX_SKILLS_ROOT, SANDBOX_UPLOADS_ROOT, SANDBOX_WIT_WORLD_NAME,
    SANDBOX_WORKSPACE_ROOT, SandboxBoundaryAdapter, SandboxBoundaryContract, SandboxClaimProposal,
    SandboxComponentBoundary, SandboxCredentialCall, SandboxCredentialEffect,
    SandboxCredentialHandle, SandboxCredentialOperation, SandboxCredentialOutcome, SandboxFileRead,
    SandboxFileWriteProposal, SandboxGuestLanguage, SandboxGuestRuntime, SandboxGuestTier,
    SandboxImportClass, SandboxLinkedImport, SandboxMount, SandboxMountTable, SandboxProposalDelta,
    SandboxProposalKind, SandboxProposalWrite, SandboxReadFile, SandboxVirtualPath,
};
pub use crate::code_symbol::{
    CODE_SYMBOL_CHUNK_KEYS, CODE_SYMBOL_ENTITY_BODY_KEYS, CODE_SYMBOL_FINGERPRINT_LEN,
    CODE_SYMBOL_KIND_MAX_BYTES, CODE_SYMBOL_MANIFEST_BODY_KEYS, CODE_SYMBOL_MANIFEST_MAX_CHUNKS,
    CODE_SYMBOL_MANIFEST_MAX_SYMBOLS, CODE_SYMBOL_NAME_MAX_BYTES, CODE_SYMBOL_REVISION_KEYS,
    CODE_SYMBOL_SOURCE_SESSION_MAX_BYTES, CODE_SYMBOL_TEXT_HASH_LEN, CodeChunk, CodeEmbeddingInput,
    CodeEmbeddingVector, CodeSymbolBlame, CodeSymbolDefinition, CodeSymbolGraph,
    CodeSymbolGraphEdge, CodeSymbolManifest, CodeSymbolRevision, CodeSymbolSource,
    code_symbol_entity_id, decode_code_symbol_manifest, derive_code_chunks_from_text_diff,
    derive_code_embedding_inputs_from_text_diff, derive_code_symbol_graph_from_sources,
    derive_symbol_fingerprint, embed_code_chunks, encode_code_symbol_manifest,
};
pub use crate::codebase::{
    CODEBASE_COMMIT_HASH_HEX_LEN, CODEBASE_CONTENT_HASH_LEN, CODEBASE_FILE_ENTRY_KEYS,
    CODEBASE_FILE_PATH_MAX_BYTES, CODEBASE_FORK_HASH_LEN, CODEBASE_PROJECT_ID_MAX_BYTES,
    CODEBASE_REPO_REF_MAX_BYTES, CODEBASE_SCOPE_KEY_LEN, CODEBASE_SNAPSHOT_BODY_KEYS,
    CODEBASE_SNAPSHOT_MAX_FILES, CodebaseFileEntry, CodebaseForkHash, CodebaseScopeKey,
    CodebaseSnapshot, RepoIngestConfig, RepoIngestResult, RepoRef, decode_codebase_snapshot,
    encode_codebase_snapshot,
};
pub use crate::context_pack::{ContextPackBuilder, SerializedContextPack};
pub use crate::counterparty_contact::{
    COUNTERPARTY_CONTACT_BODY_KEYS, COUNTERPARTY_CONTACT_CLAIM_PREDICATES,
    COUNTERPARTY_CONTACT_SCHEMA_VERSION, CounterpartyContactRecord, CounterpartyContactStatus,
    CounterpartyFirstTouch, CounterpartyOptOut, CounterpartyOptOutReason,
    PREDICATE_COUNTERPARTY_CONTACT_COUNTERPARTY, PREDICATE_COUNTERPARTY_CONTACT_CREATED_AT,
    PREDICATE_COUNTERPARTY_CONTACT_FIRST_TOUCH, PREDICATE_COUNTERPARTY_CONTACT_IDENTITY_REF,
    PREDICATE_COUNTERPARTY_CONTACT_NOTES, PREDICATE_COUNTERPARTY_CONTACT_OPT_OUT,
    PREDICATE_COUNTERPARTY_CONTACT_PROMO_CONSENT, PREDICATE_COUNTERPARTY_CONTACT_REVOKED_AT,
    PREDICATE_COUNTERPARTY_CONTACT_STATUS, PREDICATE_COUNTERPARTY_CONTACT_UPDATED_AT,
    decode_counterparty_contact_body, encode_counterparty_contact_body,
};
pub use crate::critic::{
    CRITIC_LENS_CATALOG_SCHEMA_VERSION, CRITIC_RELIABILITY_CLAIM_SCHEMA_VERSION,
    CRITIC_RELIABILITY_PREDICATE_PREFIX, CRITIQUE_ARTIFACT_SCHEMA_VERSION, CriticLens,
    CriticReliability, CritiqueArtifact, CritiqueArtifactStore, CritiqueProvenance,
    CritiqueSeverity, CritiqueTriage, CritiqueTriageScores, CritiqueVerdict, LensCatalog,
    OF366_SEED_LENS_CATALOG_JSON, ReliabilityOutcomeEvent, ReliabilityOutcomeSource,
    critic_reliability_claim_body, critic_reliability_predicate, triage_critiques,
    triage_critiques_with_exploration,
};
pub use crate::deletion::{
    DecodedTombstoneValue, DeleteEntityOutcome, DeleteReason, TOMBSTONE_VALUE_LEGACY_LEN,
    TOMBSTONE_VALUE_V2_LEN, TombstoneReason, TombstoneValueV2, decode_tombstone_value,
};
pub use crate::dreamer_runner::{
    AbortDreamerBudgetReservation, AdmitDreamerConsolidationJob, AdmitDreamerJob,
    CompleteDreamerJob, CompleteDreamerJobOutcome, DEFAULT_DREAMER_CHILD_RESERVE_UNITS,
    DREAMER_CONSOLIDATION_MACRO_JOB_KIND, DREAMER_CONSOLIDATION_MESO_JOB_KIND,
    DREAMER_CONSOLIDATION_MICRO_JOB_KIND, DREAMER_HOME_NODE_DESIGNATION_KEYS,
    DREAMER_HOME_NODE_DESIGNATION_SCHEMA_VERSION, DREAMER_JOB_PAYLOAD_KEYS,
    DREAMER_JOB_PAYLOAD_SCHEMA_VERSION, DREAMER_MILESTONE_PREDICATE, DREAMER_MILESTONE_VALUE_KEYS,
    DREAMER_MILESTONE_VALUE_SCHEMA_VERSION, DREAMER_RUNNER_JOB_KIND, DreamerAdmissionOutcome,
    DreamerAdmittedJob, DreamerBudgetRecord, DreamerBudgetReservation, DreamerBudgetReserveOutcome,
    DreamerBudgetSettlement, DreamerBudgetSettlementOutcome, DreamerConsolidationAdmissionOutcome,
    DreamerConsolidationScope, DreamerDurableMilestone, DreamerHomeNodeCandidate,
    DreamerHomeNodeClass, DreamerHomeNodeDesignation, DreamerJobPayload, DreamerJobProgressState,
    DreamerJobStatus, DreamerMilestoneClaim, DreamerMilestoneKind, DreamerParkedJobRecord,
    DreamerReservedBudget, DreamerRunTreeRecord, DreamerRunnerStore, DreamerWakeBudgetConfig,
    EnqueueDreamerConsolidationJob, EnqueueDreamerJob, EnqueueDreamerJobOutcome, FailDreamerJob,
    FailDreamerJobOutcome, ParkDreamerJob, ReserveDreamerBudget, SettleDreamerBudget,
    decode_dreamer_job_payload, encode_dreamer_job_payload,
};
#[cfg(feature = "sync")]
pub use crate::dreamer_runner::{
    DREAMER_JOB_PROGRESS_KEY_PREFIX, DREAMER_JOB_PROGRESS_TERMINAL_RETENTION_MS,
    DREAMER_JOB_PROGRESS_THROTTLE_MS, DREAMER_JOB_PROGRESS_VALUE_SCHEMA_VERSION,
    DreamerJobProgressProducer, DreamerJobProgressSnapshot, DreamerJobProgressSource,
    DreamerJobProgressUpdate, DreamerProgressed, dreamer_job_progress_key,
};
#[cfg(feature = "sync")]
pub use crate::embed::{
    DEFAULT_PENDING_EMBEDDING_LEASE_MS, PendingEmbeddingReconcileReport, PendingEmbeddingReconciler,
};
pub use crate::embed::{
    EMBED_PRIORITY_BACKFILL, EMBED_PRIORITY_DEVICE, EMBED_PRIORITY_SERVER,
    EMBED_PRIORITY_SURFACED_HOT, Embedder, EmbedderLocality, PendingEmbeddingInput,
};
pub use crate::error::{Error, ErrorKind, Result};
pub use crate::federation::{
    FEDERATION_GRANT_BODY_KEYS, FEDERATION_GRANT_SCHEMA_VERSION, FederationGrant,
    FederationGrantPreset, FederationGrantRole, FederationGrantScope, decode_federation_grant_body,
    encode_federation_grant_body,
};
pub use crate::graph_fs::{
    GRAPH_FS_COREUTILS_DEFAULT_RESULT_CAP, GRAPH_FS_COREUTILS_MAX_RESULT_CAP,
    GRAPH_FS_DEFAULT_MAX_ENTRIES, GRAPH_FS_DEFAULT_PAGE_BYTE_CAP, GRAPH_FS_HOST_IMPORTS,
    GRAPH_FS_MAX_PAGE_BYTE_CAP, GRAPH_FS_MAX_PAGE_ENTRIES, GRAPH_FS_MIN_PAGE_BYTE_CAP,
    GRAPH_FS_MORE_ENTRY, GRAPH_FS_PROJECTION_VERSION, GraphFsCommandOutput,
    GraphFsCoreutilsDecision, GraphFsCoreutilsVerb, GraphFsEntry, GraphFsEntryKind, GraphFsFile,
    GraphFsMount, GraphFsOptions, GraphFsPage, GraphFsResolver,
};
pub use crate::identity_reputation::{
    CONSTRAINED_REPUTATION_DAILY_CAP, DEGRADED_REPUTATION_DAILY_CAP, EmailReputationWebhookSignal,
    IDENTITY_REPUTATION_CLAIM_PREDICATES, IDENTITY_REPUTATION_SCHEMA_VERSION,
    IdentityAttestationTier, IdentityReputation, IdentityReputationSignal,
    IdentityReputationStatus, IdentitySendRateClamp, IdentityWarmupStage,
    PREDICATE_IDENTITY_REPUTATION_ATTESTATION_TIER, PREDICATE_IDENTITY_REPUTATION_BOUNCE_RATE,
    PREDICATE_IDENTITY_REPUTATION_COMPLAINT_RATE, PREDICATE_IDENTITY_REPUTATION_ROTATE_PROPOSAL,
    PREDICATE_IDENTITY_REPUTATION_SPAM_LABEL_OBSERVATIONS,
    PREDICATE_IDENTITY_REPUTATION_UPDATED_AT, PREDICATE_IDENTITY_REPUTATION_WARMUP_STAGE,
    WARMUP_COLD_DAILY_CAP, WARMUP_WARMING_DAILY_CAP, is_identity_reputation_claim_predicate,
};
pub use crate::ingest::{
    INGEST_SOURCE_REGISTRY, IngestError, IngestHarnessConfig, IngestResult, IngestSource,
    IngestSourceConfig, IngestSourceFormat, IngestSourceRegistration, IngestSourceRegistry,
    IngestTrustCeiling, JSONL_TRANSCRIPT_SOURCE_ID, JsonlTranscriptSource,
    KNOWN_INGEST_HARNESS_CONFIG, NormalizedIngestBatch, NormalizedIngestClaim,
    NormalizedIngestRecord,
};
pub use crate::job_queue::{
    ClaimJob, ClaimOutcome, CleanupJobLeases, CompleteJob, CompleteOutcome, EnqueueJob,
    EnqueueOutcome, FailJob, FailOutcome, InterveneJob, InterveneOutcome, JobEvent, JobId,
    JobInterventionEffect, JobInterventionKind, JobQueue, JobQueueCleanupMetricsSnapshot,
    JobQueueCleanupReport, JobQueueRetryReason, JobQueueRetryReasonCount, JobRecord, JobState,
    RetryJob, RetryOutcome, job_queue_cleanup_metrics_snapshot,
};
pub use crate::lens::{
    AnswerSheetAtom, AsofScrubberAtom, ButtonControl, ClaimLineAtom, CollectionAtom, FiniteF64,
    GENERATED_LENS_ATOM_KINDS, GeneratedLens, GraphEdge, GraphNode, InspectorAtom,
    LENS_ATOM_KIT_VERSION, LedgerCell, LedgerRowAtom, LensActingPrincipalKind, LensApprovedAction,
    LensApprovedActionArg, LensAtom, LensAtomId, LensBackingRefId, LensBackingRefToken,
    LensBackingTarget, LensBackingTargetKind, LensExecutionBoundary, LensGateWriteChokepoint,
    LensHandleName, LensHandleRef, LensHandleRole, LensHostBackingRef, LensHostImport,
    LensHostMediatedWrite, LensNode, LensPrincipalBinding, LensRenderFrame, LensRenderId,
    LensStatus, LensText, MetaLineAtom, NeighborhoodGraphAtom, PackLineAtom, PostmarkAtom,
    QuickFilterAtom, ReceiptAtom, SealAtom, SealLevel, SectionAtom, SegmentedControl,
    SelectControl, SelfUiAction, SelfUiActionId, SelfUiControl, SelfUiControlId, SelfUiOption,
    SelfUiOptionValue, SelfUiValue, SliderControl, StatusDotAtom, TextInputControl,
    ThreadEntryAtom, ThrobberAtom, ToggleControl, TwoClocksAtom, VadBadge, VoiceLineAtom,
};
pub use crate::llm::{
    BUDGET_LAND_PROMPT_TEMPLATE, BUDGET_LAND_PROMPT_TEMPLATE_ID,
    BUDGET_OWNER_DIGEST_PROMPT_TEMPLATE, BUDGET_OWNER_DIGEST_PROMPT_TEMPLATE_ID,
    BUDGET_PLAN_PROMPT_TEMPLATE, BUDGET_PLAN_PROMPT_TEMPLATE_ID, BUDGET_PROMPT_TEMPLATES,
    BUDGET_RESUME_PREAMBLE_PROMPT_TEMPLATE, BUDGET_RESUME_PREAMBLE_PROMPT_TEMPLATE_ID,
    BudgetAdmission, BudgetDenied, BudgetExhaustionPolicy, BudgetGuard, BudgetLadderEvent,
    BudgetLease, BudgetPromptTemplate, BudgetRead, BudgetSettlement, BudgetSignalDeliveryChannel,
    BudgetSteeringSignal, BudgetThreshold, CallClass, CallEnvelope, CallPurpose, ContentPart,
    DEFAULT_BUDGET_RESERVE_UNITS, DeterministicFallback, FatalLlmError, FinishReason, ImageContent,
    LlmBackend, LlmCapability, LlmCatalogCost, LlmCatalogEntry, LlmError, LlmGenerateFuture,
    LlmInputUsage, LlmMessage, LlmMessageRole, LlmOutputUsage, LlmRequest, LlmResponse, LlmResult,
    LlmStream, LlmStreamEvent, LlmStreamResult, LlmToolSpec, LlmUsage, ModelId, ModelIdError,
    ModelLocality, ModelTierRef, ReasoningEffort, ResponseFormat, RetryableLlmError,
    TierPrecedence, UnsupportedCapability,
};
pub use crate::maintain::{MaintenanceBuilder, MaintenanceReport};
pub use crate::outbound::{
    COMMON_OUTBOUND_VERB_KINDS, OUTBOUND_CAPABILITY_MANIFEST_VERSION, OUTBOUND_VERB_FIELD_CONTRACT,
    OutboundCapabilityManifest, OutboundCapabilityPermission, OutboundDeliverySemantics,
    OutboundDeliverySemanticsKind, OutboundInterruptionClass, OutboundPermissionState,
    OutboundRetryClass, OutboundVerbContract, UnsupportedOutboundCapability,
    outbound_capability_manifest, outbound_capability_manifests, outbound_verb_contract,
    unsupported_outbound_connector,
};
pub use crate::pipeline::{
    DEFAULT_RECENCY_HALF_LIFE_DAYS, FacetMode, PendingVectorEmbedding, PipelineBuilder,
    RetrievalWithPendingVectors, RetrievalWithTelemetry, WorldScope,
};
pub use crate::provenance::{
    EDGE_PROVENANCE_BODY_KEYS, EDGE_REF_LEN, EdgeProvenanceClaimBody, EdgeRef,
    MODEL_SUBSTRATE_FIELD_MAX_BYTES, PREDICATE_EDGE_PROVENANCE, REASONING_EFFORT_MAX_BYTES,
    SupersessionStatus, decode_edge_provenance_body, derive_confirmation_status,
    validate_actor_class,
};
pub use crate::receipt::{
    PendingTrayAsk, PendingTrayQuery, ReceiptKind, ReceiptQuery, ReceiptRecord, ReceiptView,
};
pub use crate::recovery::{
    QuarantinedArtifact, RECOVERY_ARTIFACT_INVALID_SUFFIX_PREFIX, RECOVERY_ARTIFACT_MAGIC,
    RECOVERY_ARTIFACT_VERSION, RecoveryArtifact, RecoveryArtifactFailure, RecoveryArtifactLoad,
    decode_recovery_artifact, encode_recovery_artifact, load_recovery_artifact,
};
pub use crate::repo_mutation::{
    REPO_CONFLICT_CLAIM_VALUE_SCHEMA_VERSION, REPO_CONFLICT_OPEN_VALUE_KEYS,
    REPO_CONFLICT_RESOLUTION_VALUE_KEYS, REPO_MUTATION_ALLOWED_OPERATION_KINDS,
    REPO_MUTATION_FORBIDDEN_GIT_COMMANDS, REPO_MUTATION_OPLOG_SCHEMA_VERSION, RepoConflictClaim,
    RepoConflictResolutionClaim, RepoForkHash, RepoMutationOperation, RepoMutationOplogEntry,
    RepoMutationOutcome, RepoMutationRequest, RepoMutationStatus,
};
pub use crate::run_tree::{
    RunTree, RunTreeAdapter, RunTreeEvent, RunTreeEventKind, RunTreeFailure, RunTreeNode,
    RunTreeRepair, RunTreeStatus, RunTreeTimestamps, render_run_tree,
};
pub use crate::settings::{
    AccentLayer, CUSTOMIZATION_SETTINGS_CHANGED_EVENT_KIND, CUSTOMIZATION_SETTINGS_LAYER_COUNT,
    CUSTOMIZATION_SETTINGS_SCHEMA_VERSION, CustomizationLayer, CustomizationLayerValue,
    CustomizationSettings, CustomizationSettingsChangeEvent, CustomizationSettingsUpdate,
    DEFAULT_MODEL_STACK_CURRENT_ID, DEFAULT_MODEL_STACK_V1_ID, ModeLayer, ModelStack,
    ModelStackDeprecation, ModelStackDeprecationStage, ModelStackDeprecationStatus,
    ModelStackDisclosure, ModelStackId, ModelStackIdError, ModelStackModel, ModelStackPreference,
    ModelStackRegistry, ModelStackRegistryError, ModelStackResolution, TypeLayer, WorldLayer,
    default_model_stack_registry, try_default_model_stack_registry,
};
pub use crate::skill::{
    SKILL_DEPENDENCY_KEYS, SKILL_DESC_MAX_BYTES, SKILL_ID_MAX_BYTES, SKILL_MAX_DEPENDENCIES,
    SKILL_RECORD_BODY_KEYS, SKILL_VERSION_MAX_BYTES, SkillDependency, SkillRecord,
    decode_skill_record, encode_skill_record,
};
pub use crate::store::{
    PendingGateConsentGroup, PendingGateConsentRecord, RetrievalAction, RetrievalBlendSignal,
    RetrievalBlendTuningConfig, RetrievalBlendWeightDataWindow, RetrievalBlendWeightTableEntry,
    RetrievalBlendWeights, RetrievalOutcome, RetrievalOutcomeRecord, RetrievalRunId,
    RetrievalRunRecord, RetrievalScoreBreakdown, RetrievalScoreComponent, RetrievalSignal,
    RetrievalTrace, RetrievalTraceChannelRecord, RetrievalTraceForkHash, RetrievalTraceStage,
    RetrievalTraceStageRecord,
};
pub use crate::surface_event::{
    INBOUND_SURFACE_RECEIPT_KIND, InboundSurfaceEventInput, InboundSurfaceRejectionReason,
    InboundSurfaceRouteOutcome, InboundSurfaceRouteReceipt, SURFACE_EVENT_SCHEMA_VERSION,
    SurfaceCounterpartyStamp, SurfaceEvent,
};
pub use crate::tokenizer::{
    ContextPackTokenizer, DEFAULT_CONTEXT_PACK_TOKENIZER, DEFAULT_CONTEXT_PACK_TOKENIZER_ID,
    PackTokenizer, count_context_pack_tokens,
};
pub use crate::types::{
    Bm25RankProfile, COMPANION_TASK_JOB_KIND, COMPANION_TASK_PAYLOAD_KEYS,
    COMPANION_TASK_PAYLOAD_SCHEMA_VERSION, ClaimCandidate, ClaimCompanionTask,
    ClaimCompanionTaskOutcome, CompanionExportClassification, CompanionExpression,
    CompanionExpressionRegister, CompanionProvenance, CompanionQueue, CompanionRecord,
    CompanionRecordKey, CompanionRecordKind, CompanionRegister, CompanionScope,
    CompanionScopeResolution, CompanionScopeResolutionSource, CompanionSubject, CompanionTask,
    CompanionTaskKind, CompanionTaskStatus, CompleteCompanionTask, CompleteCompanionTaskOutcome,
    ContextEntity, ContextPack, ContextPackRetrievalBudget, DecodedEdgeValue,
    EIRI_CONTEXT_VERSION_V4, ENTITY_TYPE_ACCESS_GRANT, ENTITY_TYPE_AUTHORITY_LOG,
    ENTITY_TYPE_CHANNEL_IDENTITY, ENTITY_TYPE_CODE_ARTIFACT, ENTITY_TYPE_CODE_SYMBOL,
    ENTITY_TYPE_COMPANION_REGISTER, ENTITY_TYPE_COUNTERPARTY_CONTACT, ENTITY_TYPE_FEDERATION_GRANT,
    ENTITY_TYPE_PSYCH_PROFILE, EdgeActorClass, EdgeConfirmationStatus, EdgeInfo, EdgeKind,
    EdgeProvenanceFlags, EdgeValueLayout, EiriCompanionAssembly, EiriMemoryBoard,
    EiriMemoryBoardBudget, EiriMemoryBoardRow, EiriMemoryBoardSlot, EiriMemoryBoardSource,
    EiriSessionRagState, EmptyContext, EmptyReason, EndCompanionRelationship,
    EndCompanionRelationshipOutcome, EnqueueCompanionTask, EnqueueCompanionTaskOutcome, EntityId,
    FailCompanionTask, FailCompanionTaskOutcome, FieldProfile, HnswConfig, HydratedShortIdDeletion,
    HydratedShortIdDeletionReason, HydratedShortIdDeletionSource, MemoryOperationKind,
    MemoryTimeline, MemoryTimelineRecord, MemoryTimelineRecordState, NamedMemoryVerb,
    NotificationItem, PackFormat, PackItemTokenStats, PackSectionTokenStats, PackStats,
    PackTokenStats, ResumeBudget, ResumeBundle, RetryCompanionTask, RetryCompanionTaskOutcome,
    ScoredEntity, SessionContext, Signal, StructuralKindRegistration, TemporalAnchorMode,
    TemporalGranularity, TextAnalyzerConfig, TextIndexOptions, TimeRange, TokenAllocation,
    TypeByteBand, UnprocessedItem, Vad, VadAnnotation, VadAnnotationSource, VadComponent,
    VaultConfig, WriteActor, WriteEnvelope, WriteProvenance, companion_value_from_json,
    companion_value_to_json, decode_companion_record_body, decode_companion_task_payload,
    encode_companion_record_body, encode_companion_task_payload,
};
pub use crate::types::{
    PSYCH_PROFILE_BODY_KEYS, PSYCH_PROFILE_SCHEMA_VERSION, PsychProfile, PsychProfileConfidence,
    PsychProfileSnapshotStatus, PsychProfileStaleReason, PsychProfileState,
    decode_psych_profile_body, encode_psych_profile_body,
};
pub use crate::vault::{
    ActorBound, HydratedShortId, TextIndexStatus, Vault, VaultDoctorDbManifestReport,
    VaultDoctorHnswRecordState, VaultDoctorHnswReport, VaultDoctorReport,
};

pub(crate) fn unix_seconds_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

pub(crate) fn le_bytes_to_f32_vec(bytes: &[u8]) -> Result<Vec<f32>> {
    if !bytes.len().is_multiple_of(4) {
        return Err(Error::InvalidKey);
    }

    let (chunks, rem) = bytes.as_chunks::<4>();
    debug_assert!(rem.is_empty());
    Ok(chunks
        .iter()
        .map(|bytes| f32::from_le_bytes(*bytes))
        .collect())
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod tests_bug;

#[cfg(test)]
pub(crate) mod test_util {
    //! Shared test helpers. Centralized to avoid drift between per-module
    //! copies of `open_test_vault`. Each module keeps its own `test_config()`
    //! because configs diverge (map sizes, dimensions, embedding model).
    use crate::types::VaultConfig;
    use crate::vault::Vault;

    /// Opens a temporary vault with the supplied config. Returns the
    /// `TempDir` so callers keep the directory alive for the vault's lifetime.
    pub(crate) fn open_test_vault_with(cfg: VaultConfig) -> (tempfile::TempDir, Vault) {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::open(dir.path(), cfg).expect("open vault");
        clear_default_policy_manifest_for_legacy_tests(&vault);
        (dir, vault)
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
