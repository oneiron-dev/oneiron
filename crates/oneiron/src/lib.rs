use std::time::{SystemTime, UNIX_EPOCH};

pub mod access_grant;
pub mod actor_claims;
pub mod affect;
pub mod agent_def;
pub mod agent_dispatch;
pub mod analyzer;
pub mod anchored_annotation;
pub mod artifact_hosting;
pub mod attempt_queue;
pub mod authority;
pub mod batch;
pub mod blob_artifact;
pub(crate) mod bm25;
pub mod booking;
pub mod calendar;
pub mod campaign;
pub mod channel_identity;
pub mod channel_identity_lifecycle;
pub mod channel_identity_manifest;
pub mod channel_identity_provider;
pub mod claim;
pub mod cluster;
pub mod code_artifact;
pub mod code_revision;
pub mod code_run;
pub mod code_sandbox;
pub mod code_symbol;
pub mod codebase;
pub mod comm;
pub mod companion;
pub mod config;
pub mod connector_key;
pub mod consent;
pub mod consent_graduation;
pub mod context_board;
pub mod context_pack;
pub mod counterparty_contact;
pub mod critic;
pub mod deletion;
pub mod delivery_window;
pub mod disclosure;
pub(crate) mod distance;
pub mod dreamer_consolidation;
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
pub mod facade;
pub mod federation;
pub(crate) mod fusion;
pub(crate) mod gate;
pub mod genui;
pub mod graph_fs;
pub mod habit;
pub(crate) mod hnsw;
pub(crate) mod identity;
pub mod identity_redirect;
pub mod identity_reputation;
pub mod identity_topology;
pub mod inbox;
pub mod ingest;
pub mod interlocutor;
pub mod lens;
pub(crate) mod limits;
pub mod linkedin_connector;
pub mod llm;
pub mod maintain;
pub mod off_record;
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
pub mod receipt;
pub mod recovery;
pub mod registry;
pub mod repo_mutation;
pub mod rerank;
pub mod run_tree;
pub mod saved_query;
pub mod secret_custody;
pub mod secret_manifest;
pub mod serialize;
pub mod session_lifecycle;
pub(crate) mod session_overlay;
pub mod settings;
pub mod skill;
pub mod skill_attribution;
pub mod skill_convert;
pub mod skill_hub;
pub mod skill_reliability;
pub mod skill_scan;
pub mod speculative;
pub mod store;
pub mod surface_event;
pub(crate) mod sweep;
#[cfg(feature = "sync")]
pub mod sync;
pub mod task_verb;
pub mod temporal;
pub mod thread_lens;
pub mod tokenizer;
mod vault;
pub mod write_envelope;

pub use crate::access_grant::{
    ACCESS_GRANT_BODY_KEYS, ACCESS_GRANT_SCHEMA_VERSION, AccessGrant, AccessGrantCapability,
    AccessGrantScope, AccessGrantStatus, CalendarAccessGrantRow, decode_access_grant_body,
    encode_access_grant_body,
};
pub use crate::actor_claims::{
    ACTOR_CLAIM_LINEAGE_KEY, ACTOR_CLAIM_MAX_CITED_EVIDENCE, ACTOR_DISTILL_CALL_PURPOSE_NAME,
    ACTOR_EDIT_COST_SCOPE_KEY, ACTOR_EDIT_COST_SCOPE_MAX_BYTES, ACTOR_NOTE_MAX_BYTES,
    ACTOR_SKILL_FIT_SCOPE_KEY, ActorClaimEvidence, ActorClaimRow, ActorNote, ActorNoteKind,
    LAPSE_FAILURE_MODE, PREDICATE_ACTOR_FAILURE_MODE, PREDICATE_ACTOR_LESSON,
    PREDICATE_ACTOR_SCOPE_NOTE, PREDICATE_ACTOR_SKILL_FIT, SessionActorDistiller,
    SessionDistillBrief, SessionDistillTurn, actor_claim_lineage, actor_distill_call_purpose,
    is_actor_claim_predicate, pending_session_actor_distills, project_actor_claims_from_judgments,
    run_session_end_actor_distill, skill_fit_for, write_actor_claim,
};
pub use crate::affect::coping::{
    COPING_OUTCOME_PREDICATE, CopingOutcomeRecord, CopingOutcomeUpdate, CopingOutcomeValue,
    CopingStrategy, coping_delta_successful, coping_outcome_claim_candidate, coping_outcome_value,
    decode_coping_outcome_claim, decode_coping_outcome_value,
};
pub use crate::affect::{
    AFFECT_TRIGGER_PREDICATE, AffectTriggerValue, CLAIM_VAD_REAPPRAISAL_PREDICATE,
    ClaimVadConsolidation, ClaimVadReappraisal, ClaimVadTurnEvidence, Vad, VadAnnotation,
    VadAnnotationSource, VadComponent, VadDelta, affect_trigger_claim_candidate,
    affect_trigger_value, decode_affect_trigger_claim, decode_affect_trigger_value,
};
pub use crate::agent_def::{
    AGENT_DEF_BODY_KEYS, AGENT_DESC_MAX_BYTES, AGENT_ID_MAX_BYTES, AGENT_INSTRUCTIONS_MAX_BYTES,
    AGENT_MAX_LIST_ENTRIES, AGENT_MODEL_TIER_MAX_BYTES, AGENT_REF_KEY_MAX_BYTES,
    AGENT_VERSION_MAX_BYTES, AgentCeiling, AgentDefinition, AgentScope, MCP_REF_KEYS, McpRef,
    SYSTEM_AGENT_PRESET_VERSION, SystemAgentPreset, decode_agent_definition,
    encode_agent_definition,
};
pub use crate::agent_dispatch::{
    AGENT_DISPATCH_ATTEMPT_TYPE, AGENT_DISPATCH_INPUT_KEYS, AGENT_DISPATCH_INPUT_SCHEMA_VERSION,
    AGENT_DISPATCH_MILESTONE_AGENT_KEY, AgentDispatchInput, AgentDispatchOutcome,
    AgentDispatchStatus, AgentDispatchTarget, AgentDispatcher, DispatchAgent, agent_dispatch_actor,
    agent_dispatch_payload_agent_id, decode_agent_dispatch_input, encode_agent_dispatch_input,
};
pub use crate::analyzer::{
    ANALYZER_VERSION, AnalyzerAssetManifest, AnalyzerChannel, AnalyzerContext, AnalyzerManifest,
    AnalyzerMode, LangPolicy, LanguageHint, NormalizationPolicy, Token, TokenKind,
};
pub use crate::anchored_annotation::{
    A1Range, ANNOTATION_BRIEF_PREDICATE, ANNOTATION_COMMENT_PREDICATE,
    ANNOTATION_COMMENT_TEXT_MAX_BYTES, ANNOTATION_LOCATOR_RANGE_MAX_BYTES,
    ANNOTATION_LOCATOR_TEXT_MAX_BYTES, ANNOTATION_THREAD_PREDICATE, Anchor, AnnotationComment,
    AnnotationThread, DriftMarker, Locator, ReanchorOp, ReanchorOutcome, ReanchorSummary,
    TaskBrief, ThreadState, replay_locator,
};
pub use crate::artifact_hosting::{
    ARTIFACT_POINTER_CHANNELS, ARTIFACT_PUBLISH_VERB_FEATURE, ArtifactPointer,
    ArtifactPointerChannel, ArtifactPublishVerbOutcome, ArtifactPublishVerbRequest,
    ArtifactPublishVerbStatus, ArtifactServedFile, ArtifactSnapshotRef, ArtifactSnapshotSelector,
    artifact_hex, parse_codebase_fork_hash_hex,
};
pub use crate::attempt_queue::{
    AttemptEvent, AttemptId, AttemptInterventionEffect, AttemptInterventionKind, AttemptQueue,
    AttemptQueueCleanupMetricsSnapshot, AttemptQueueCleanupReport, AttemptQueueRetryReason,
    AttemptQueueRetryReasonCount, AttemptRecord, AttemptState, ClaimAttempt, ClaimOutcome,
    CleanupAttemptLeases, CompleteAttempt, CompleteOutcome, EnqueueAttempt, EnqueueOutcome,
    FailAttempt, FailOutcome, InterveneAttempt, InterveneOutcome, MAX_ATTEMPT_MANIFEST_ENTRIES,
    ManifestEntry, ManifestKind, RetryAttempt, RetryOutcome,
    attempt_queue_cleanup_metrics_snapshot,
};
pub use crate::authority::{
    AUTHORITY_FORK_ALARM_KIND, AUTHORITY_LOG_SCHEMA_VERSION, AUTHORITY_TRANSCRIPT_DOMAIN,
    AuthorityAttestation, AuthorityConfirmAction, AuthorityConfirmKind, AuthorityEntryHash,
    AuthorityFold, AuthorityFoldIssue, AuthorityFork, AuthorityForkAlarm, AuthorityForkStatus,
    AuthorityKey, AuthorityLogEntry, AuthorityOp, AuthorityPendingWiden, AuthoritySignature,
    AuthoritySignatureSuite, AuthorityTier, AuthorityVaultId, DEFAULT_PENDING_WIDEN_DELAY_SECS,
    DeviceAuthority, FEDERATION_PACT_DOMAIN, FEDERATION_SCOPE_COMMIT_DOMAIN,
    FederationGrantActivation, FederationLifecycleAction, FederationLifecycleKind,
    FederationLifecycleRejection, FederationPactGesture, FederationPactState, FederationPactStatus,
    FoldedDevice, MAX_DEFAULT_PENDING_WIDEN_DELAY_SECS, MAX_PACT_SCOPE_BYTES,
    MIN_DEFAULT_PENDING_WIDEN_DELAY_SECS, ROLE_ADMIN, ROLE_AGENT, ROLE_CLOUD, ROLE_OWNER,
    ROLE_RECOVERY, authority_entry_hash, authority_transcript, decode_authority_log_entry_body,
    encode_authority_log_entry_body, federation_grant_activation, federation_pact_transcript,
    federation_scope_digest, fold_authority_log, fold_authority_log_with_seen_times,
    genesis_vault_id, sign_federation_pact_gesture, validate_authority_log_entry_body_bytes,
    verify_authority_signature,
};
pub use crate::batch::{BatchBuilder, TxnBatchBuilder};
pub use crate::blob_artifact::{
    BLOB_ARTIFACT_BODY_KEYS, BLOB_ARTIFACT_CONTENT_HASH_LEN, BLOB_ARTIFACT_MEDIA_TYPE_MAX_BYTES,
    BLOB_ARTIFACT_NAME_MAX_BYTES, BLOB_ARTIFACT_RUN_REF_MAX_BYTES,
    BLOB_ARTIFACT_VERSION_RECORD_KEYS, BlobArtifactBody, BlobArtifactVersion,
    BlobVersionProvenance, decode_blob_artifact_body, encode_blob_artifact_body,
};
pub use crate::bm25::{
    Bm25DiagnosticCounter, Bm25DiagnosticKind, Bm25DiagnosticsSnapshot, Bm25Formula,
    bm25_diagnostics_snapshot,
};
pub use crate::booking::{
    ActiveHoldSource, BOOKING_EVENT_TYPE_META_PREFIX, BOOKING_EVENT_TYPE_PREDICATE,
    BOOKING_EVENT_TYPE_SCHEMA_VERSION, BookingCountBucket, BookingCounts, BookingError,
    BookingEventTypeClaimValue, BookingSolver, BusyBlockRow, CalendarDisclosureDefault,
    ConstraintObject, DEFAULT_INTRO_DURATION_MIN, DEFAULT_MIN_NOTICE_SECS, DisclosureRung,
    EventDetailsRow, EventRow, EventTypeConfig, EventTypeKey, HIGH_VALUE_MIN_NOTICE_SECS,
    HostAvailabilityConfig, MAX_BOOKING_WINDOW_SECS, NoActiveHolds, RankedSlot, RoutingMode,
    RungProjection, SlotMask, SlotOracle, SolveRequest, SolveResult, SurfaceClass, TitledEventRow,
    WeeklyWallWindow, decode_event_type_claim_value, default_disclosure_rung,
    encode_event_type_claim_value, event_type_index_key, is_booking_claim_predicate,
    project_at_rung, project_calendar_grant, slot_mask,
};
pub use crate::calendar::{
    BusyInterval, BusyUnion, CALENDAR_SAFEGUARD_CONFIG_KEY, CALENDAR_SAFEGUARD_REASON_NO_SCREENER,
    CalendarAdmissionRequest, CalendarBodyScreener, CalendarEventView, CalendarInboundBody,
    CalendarRangeDto, CalendarReadRequest, CalendarScreenVerdict, CalendarSearchRequest,
    CalendarSel, MAX_CALENDAR_SEARCH_LIMIT, Screened, SeriesDtStart, SeriesExceptionKey,
    exception_identity, expand_master_window, expand_window, freebusy, freebusy_scoped,
    mask_master_exceptions, read_event, read_event_scoped, screen_then_claim, search_events,
    search_events_scoped,
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
pub use crate::channel_identity_provider::{
    CHANNEL_IDENTITY_PROVIDER_ADAPTER_VERSION, ChannelIdentityProviderAdapter,
    ChannelIdentityProviderInbound, ChannelIdentityProviderProvision,
    DEFAULT_EMAIL_LOCAL_PART_PREFIX, DEFAULT_LINE_PUSH_MONTHLY_ALLOWANCE, DEV_EMAIL_PROVIDER_KEY,
    DevEmailIdentityAdapter, DevEmailIdentityAdapterConfig, EMAIL_CHANNEL, EmailProviderInbound,
    LINE_CHANNEL, LINE_OFFICIAL_ACCOUNT_PROVIDER_KEY, LineOfficialAccountAdapter,
    LineOfficialAccountAdapterConfig, LineOfficialAccountInbound, LineOfficialAccountPlanTier,
    MockChannelIdentityProviderAdapter, SLACK_CHANNEL, SLACK_SHARED_PRESENCE_PROVIDER_KEY,
    SlackOutboundMessage, SlackPersonaAttribution, SlackPersonaOutbound, SlackProviderInbound,
    SlackSharedPresenceAdapter, SlackSharedPresenceAdapterConfig,
};
pub use crate::claim::{
    CLAIM_BODY_KEYS, ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource,
    ClaimSubject, MAX_PREDICATE_BYTES, PREDICATE_ACTOR_EDIT_COST, PREDICATE_CONFLICT_OPEN,
    PREDICATE_CONFLICT_RESOLVED, PREDICATE_SKILL_EDIT_COST, RESERVED_PREDICATE_NAMESPACE,
    SessionClaimBundle, SessionClaimBundleClaim, predicate_root,
};
pub use crate::cluster::{
    CLUSTER_COHESION_THRESHOLD, CLUSTER_ID_DOMAIN, ClaimCohort, ClusterAssignments, ClusterClaim,
    ClusterOptions, ClusterPartitionKey, CohortId, cluster_claims,
};
pub use crate::code_artifact::{
    CODE_ARTIFACT_BODY_KEYS, CODE_ARTIFACT_REPO_REF_MAX_BYTES, CODE_ARTIFACT_SUMMARY_HASH_LEN,
    CODE_ARTIFACT_SUMMARY_PROMPT_MAX_BYTES, CodeArtifactBody, CodeArtifactClass,
    decode_code_artifact_body, encode_code_artifact_body,
};
pub use crate::code_revision::{
    CODE_REVISION_FORK_KEYS, CODE_REVISION_RECORD_KEYS, CodeRevision, CodeRevisionFork,
    CodeRevisionKind, decode_code_revision, decode_code_revision_fork, encode_code_revision,
    encode_code_revision_fork,
};
pub use crate::code_run::{
    GatedActorWrite, HostSelfDispatcher, SelfAskHumanCall, SelfCall, SelfDeniedResult,
    SelfDispatchOutcome, SelfDispatcher, SelfDurableWait, SelfDurableWaitReason, SelfEffect,
    SelfFailedResult, SelfFixtureEffectCall, SelfMemoryEdgeWriteResult, SelfMemoryPutClaimCall,
    SelfMemoryPutEdgeCall, SelfMemorySearchCall, SelfMemorySearchResult,
    SelfMemorySupersedeClaimCall, SelfMemoryWriteFixtureCall, SelfMemoryWriteResult,
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
    CodebaseSnapshot, HostedMediaHashMatchDecision, HostedMediaHashMatchInput,
    HostedMediaHashMatchProvider, NoopHostedMediaHashMatchProvider, RepoIngestConfig,
    RepoIngestResult, RepoRef, decode_codebase_snapshot, encode_codebase_snapshot,
};
pub use crate::comm::{
    COMM_CLAIM_PREDICATES, COMM_SCHEMA_VERSION, CommClaim, CommClaimValue, CommClearOptOutOutcome,
    CommError, CommResult, PREDICATE_COMM_LAST_TOUCH, PREDICATE_COMM_OPT_OUT,
    PREDICATE_COMM_REACHABLE_VIA, PREDICATE_COMM_THREAD_MEMBER, approve_pending_opt_out_clear,
    count_active_comm_claims, count_active_thread_member_claims,
    count_contact_record_claim_entries, count_opt_out_clear_receipts,
    count_pending_comm_consent_gates, count_total_comm_claim_rows, drop_contact_record,
    is_comm_claim_predicate, materialize_contact_record, record_comm_inbound_stop,
    record_comm_send_receipt, record_comm_thread_event, request_opt_out_clear,
    resolve_or_create_comm_party, run_comm_projector,
};
pub use crate::companion::{
    COMPANION_TASK_ATTEMPT_KIND, COMPANION_TASK_PAYLOAD_KEYS,
    COMPANION_TASK_PAYLOAD_SCHEMA_VERSION, ClaimCompanionTask, ClaimCompanionTaskOutcome,
    CompanionExportClassification, CompanionExpression, CompanionExpressionRegister,
    CompanionProvenance, CompanionQueue, CompanionRecord, CompanionRecordKey, CompanionRecordKind,
    CompanionRegister, CompanionScope, CompanionScopeResolution, CompanionScopeResolutionSource,
    CompanionSubject, CompanionTask, CompanionTaskKind, CompanionTaskStatus, CompleteCompanionTask,
    CompleteCompanionTaskOutcome, ENTITY_TYPE_COMPANION_REGISTER, EndCompanionRelationship,
    EndCompanionRelationshipOutcome, EnqueueCompanionTask, EnqueueCompanionTaskOutcome,
    FailCompanionTask, FailCompanionTaskOutcome, RetryCompanionTask, RetryCompanionTaskOutcome,
    companion_value_from_json, companion_value_to_json, decode_companion_record_body,
    decode_companion_task_payload, encode_companion_record_body, encode_companion_task_payload,
};
pub use crate::config::{
    Bm25RankProfile, DEFAULT_OFF_RECORD_OVERLAY_BUDGET_BYTES, HnswConfig, TextAnalyzerConfig,
    TextIndexOptions, VaultConfig,
};
pub use crate::connector_key::{
    CONNECTOR_KEY_BODY_KEYS, CONNECTOR_KEY_SCHEMA_VERSION, CalendarPeriod, CompiledCharter,
    CompiledConnectorPolicy, ConnectorCharterBlock, ConnectorCharterCompileIssue,
    ConnectorKeyDispatchTally, ConnectorKeyRecord, ConnectorKeyStatus,
    EFFECTOR_BUDGET_LAND_PROMPT_TEMPLATE, EFFECTOR_BUDGET_LAND_PROMPT_TEMPLATE_ID,
    EFFECTOR_BUDGET_PLAN_PROMPT_TEMPLATE, EFFECTOR_BUDGET_PLAN_PROMPT_TEMPLATE_ID, EffectorBudget,
    EffectorBudgetCharge, EffectorBudgetDimension, EffectorBudgetOnExhaust, EffectorBudgetRead,
    EffectorBudgetReservePolicy, EffectorBudgetRowRead, EffectorBudgetWindow,
    PendingConnectorCharter, compile_connector_charter, decode_connector_key_body,
    encode_connector_key_body,
};
// DEC-0006 unified consent-mode. `consent::ActorBound` is deliberately NOT
// re-exported here: `crate::vault::ActorBound` (the engine-internal write
// handle) already owns that name at the crate root, and `vault.rs` is outside
// this contract's claim. The pinned downstream import path for the consent
// subject type is therefore `oneiron::consent::ActorBound`; every other name
// in the contract is re-exported below.
pub use crate::consent::{
    ActionClass, ActionEnvelope, ActionGrant, AudienceBound, AuthenticatedOwner,
    BULK_BLAST_RADIUS_FLOOR, BoundClass, BoundEnvelope, BoundSubject, CATASTROPHE_FLOOR_V1,
    CATASTROPHE_FLOOR_VERSION, CONSENT_CONTENT_KIND, CONSENT_GRANT_BODY_KEYS,
    CONSENT_GRANT_SCHEMA_VERSION, CONSENT_REASON_APPROVE_ONCE, CONSENT_REASON_DENIED,
    CONSENT_REASON_REVOKED, CONSENT_REASON_STANDING_CREATED, CONSENT_REASON_STANDING_USED,
    CONSENT_REVOKE_COMMAND, CatastropheClass, ComposedEffect, ConsentDecision, ConsentDomain,
    ConsentGrant, ConsentGrantRow, ConsentGrantStatus, ConsentGuard, ConsentOwnerStamp,
    ConsentProposal, ConsentReceipt, ConsentRegistry, ConsentRegistryQuery, ConsentRegistryRow,
    ConsentRevokeAction, DisclosureClass, DisclosureEnvelope, DisclosureGrant, EffectDigest,
    EffectFacts, GrantBound, MAX_AUDIENCE_MEMBERS, MAX_CONSENT_REF_LEN, MAX_ENVELOPE_SELECTORS,
    ReversibilityClass, StandingConsentGrant, UndoFidelity, access_grant_projection_is_active,
    action_grant_from_standing_outbound_grant, bound_catastrophe_class, decode_consent_grant_row,
    disclosure_grant_from_access_grant, disclosure_grant_from_disclosure_scope,
    encode_consent_grant_row,
};
pub use crate::consent_graduation::{
    DEFAULT_GRADUATION_STREAK_FLOOR, DemotionReason, RampScope, RampState, ScopeOutcomeStats,
    is_ramp_demotion_receipt, is_ramp_outcome_receipt, op_kind_is_ramp_eligible,
};
pub use crate::context_pack::{
    ContextEntity, ContextPack, ContextPackBuilder, ContextPackRetrievalBudget, EmptyContext,
    EmptyReason, FieldProfile, PackFormat, PackItemTokenStats, PackSectionTokenStats, PackStats,
    PackTokenStats, SerializedContextPack, TokenAllocation,
};
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
    DecodedTombstoneValue, DeleteEntityOutcome, DeleteReason, HydratedShortIdDeletion,
    HydratedShortIdDeletionReason, HydratedShortIdDeletionSource, MemoryOperationKind,
    MemoryTimeline, MemoryTimelineRecord, MemoryTimelineRecordState, NamedMemoryVerb,
    TOMBSTONE_VALUE_LEGACY_LEN, TOMBSTONE_VALUE_V2_LEN, TombstoneReason, TombstoneValueV2,
    decode_tombstone_value,
};
pub use crate::delivery_window::{
    DELIVERY_WINDOW_CLAIM_PREDICATES, DELIVERY_WINDOW_SCHEMA_VERSION,
    DeliveryWindowApnsInterruptionLevel, DeliveryWindowAppliesTo, DeliveryWindowContextCondition,
    DeliveryWindowDecision, DeliveryWindowEvaluationContext, DeliveryWindowEvaluator,
    DeliveryWindowPolicyClaim, DeliveryWindowTimeWindow, DeliveryWindowVerbClass,
    PREDICATE_DELIVERY_WINDOW_CHANNEL, PREDICATE_DELIVERY_WINDOW_CONTEXT,
    PREDICATE_DELIVERY_WINDOW_QUIET, is_delivery_window_claim_predicate,
};
pub use crate::disclosure::{
    DISCLOSURE_CLAIM_PREDICATES, DISCLOSURE_SCOPE_BODY_KEYS, DISCLOSURE_SCOPE_SCHEMA_VERSION,
    DisclosureAssembly, DisclosureContext, DisclosureMode, DisclosureScope, DisclosureScopeStatus,
    DisclosureTier, decode_disclosure_scope_body, encode_disclosure_scope_body,
    is_disclosure_claim_predicate, presence_discretion_notice,
};
pub use crate::dreamer_consolidation::{
    CollapsedEvidence, ConflictIdentity, ConflictSet, ConsolidationBucketKey,
    ConsolidationBucketPlan, ConsolidationCursor, ConsolidationExecutor, ConsolidationPartitionKey,
    ConsolidationPartitionPlan, ConsolidationSink, ConsolidationWatermark,
    DREAMER_BUCKET_HASH_DOMAIN, DREAMER_EVIDENCE_HASH_DOMAIN, DREAMER_GAP_DECAY_MS,
    DREAMER_GAP_HASH_DOMAIN, DREAMER_GAP_SCAN_ATTEMPT_TYPE, GapQueueDelta, PriorHead,
    PromotionCandidate, ReflectionGap, ReflectionGapKind, SwarmChildReturn, SwarmEvidenceRef,
    TURN_BODY_FACET_REF_KEY, TURN_BODY_WORLD_REF_KEY, WorkingSetTurn, advance_watermark,
    collapse_sibling_evidence, corroboration_count, decode_partition_payload, detect_conflicts,
    enqueue_partition_attempts, entity_ref_from_value, evidence_trust_meet, gap_hash,
    plan_candidate_buckets, plan_partitions, read_cursor, read_watermark, scan_dirty_turns,
    scan_reflection_gaps, swarm_evidence_content_hash, turn_trust_class, upsert_gap_queue,
    validate_child_read_pin, write_cursor,
};
pub use crate::dreamer_promotion::{
    DreamerRunContext, PromotionOutcome, PromotionWriterSink, promote_consolidated_claims,
};
pub use crate::dreamer_runner::{
    AbortDreamerBudgetReservation, AdmitDreamerAttempt, AdmitDreamerConsolidationAttempt,
    CompleteDreamerAttempt, CompleteDreamerAttemptOutcome, DEFAULT_DREAMER_CHILD_RESERVE_UNITS,
    DEFAULT_DREAMER_TOURNAMENT_DEPTH_K, DEFAULT_DREAMER_TOURNAMENT_FANOUT_M,
    DREAMER_ATTEMPT_PAYLOAD_KEYS, DREAMER_ATTEMPT_PAYLOAD_SCHEMA_VERSION,
    DREAMER_CONSOLIDATION_MACRO_ATTEMPT_KIND, DREAMER_CONSOLIDATION_MESO_ATTEMPT_KIND,
    DREAMER_CONSOLIDATION_MICRO_ATTEMPT_KIND, DREAMER_HOME_NODE_DESIGNATION_KEYS,
    DREAMER_HOME_NODE_DESIGNATION_SCHEMA_VERSION, DREAMER_MILESTONE_PREDICATE,
    DREAMER_MILESTONE_VALUE_KEYS, DREAMER_MILESTONE_VALUE_SCHEMA_VERSION,
    DREAMER_RUNNER_ATTEMPT_KIND, DreamerAdmissionOutcome, DreamerAdmittedAttempt,
    DreamerAttemptPayload, DreamerAttemptProgressState, DreamerAttemptStatus, DreamerBudgetRecord,
    DreamerBudgetReservation, DreamerBudgetReserveOutcome, DreamerBudgetSettlement,
    DreamerBudgetSettlementOutcome, DreamerClaimAuthoringAdmission, DreamerClaimAuthoringBatchTier,
    DreamerClaimAuthoringBudgetTrap, DreamerClaimAuthoringGateDecision,
    DreamerClaimAuthoringSchedule, DreamerClaimAuthoringSinglePassReason,
    DreamerClaimAuthoringStrategy, DreamerClaimEvidenceState, DreamerConsolidationAdmissionOutcome,
    DreamerConsolidationScope, DreamerDurableMilestone, DreamerHomeNodeCandidate,
    DreamerHomeNodeClass, DreamerHomeNodeDesignation, DreamerMilestoneClaim, DreamerMilestoneKind,
    DreamerParkedAttemptRecord, DreamerReservedBudget, DreamerRunTreeRecord, DreamerRunnerStore,
    DreamerTournamentAdmission, DreamerTournamentAdmissionGrant, DreamerTournamentBudgetAxes,
    DreamerTournamentClaim, DreamerTurnRole, DreamerWakeBudgetConfig, EnqueueDreamerAttempt,
    EnqueueDreamerAttemptOutcome, EnqueueDreamerConsolidationAttempt, FailDreamerAttempt,
    FailDreamerAttemptOutcome, ParkDreamerAttempt, ReserveDreamerBudget, SettleDreamerBudget,
    decode_dreamer_attempt_payload, dreamer_extraction_role_admissible, dreamer_turn_role,
    encode_dreamer_attempt_payload,
};
#[cfg(feature = "sync")]
pub use crate::dreamer_runner::{
    DREAMER_ATTEMPT_PROGRESS_KEY_PREFIX, DREAMER_ATTEMPT_PROGRESS_TERMINAL_RETENTION_MS,
    DREAMER_ATTEMPT_PROGRESS_THROTTLE_MS, DREAMER_ATTEMPT_PROGRESS_VALUE_SCHEMA_VERSION,
    DreamerAttemptProgressProducer, DreamerAttemptProgressSnapshot, DreamerAttemptProgressSource,
    DreamerAttemptProgressUpdate, DreamerProgressed, dreamer_attempt_progress_key,
};
pub use crate::dreamer_tournament::{
    DREAMER_TOURNAMENT_BRANCH_EVIDENCE_SCHEMA_VERSION, DREAMER_TOURNAMENT_MAX_FANOUT_M,
    DREAMER_TOURNAMENT_MAX_ROUNDS_K, DREAMER_TOURNAMENT_MIN_FANOUT_M, DreamerTournamentAuthorFork,
    DreamerTournamentBlindJudgeContext, DreamerTournamentBordaBallot, DreamerTournamentBranch,
    DreamerTournamentBranchEvidence, DreamerTournamentBranchVerdict, DreamerTournamentCandidate,
    DreamerTournamentCandidateIdentity, DreamerTournamentEvidenceStore,
    DreamerTournamentJudgeClaim, DreamerTournamentRound, DreamerTournamentRun,
    DreamerTournamentRunResult, DreamerTournamentStopReason, DreamerTournamentSynthesisArtifact,
    DreamerTournamentSynthesisVerdict, DreamerTournamentWeaveArtifact, DreamerTournamentWinner,
    run_dreamer_claim_tournament,
};
#[cfg(feature = "sync")]
pub use crate::dreamer_wake::WakeProgressLane;
pub use crate::dreamer_wake::{
    BudgetLegibilityEnvelope, DREAMER_CANCELLED_PARK_REASON, DREAMER_EXECUTOR_ERROR_PARK_REASON,
    DREAMER_GRACEFUL_WRAP_WINDOW_MS, DREAMER_HARD_CUT_PARK_OWNER, DREAMER_HARD_CUT_PARK_REASON,
    DREAMER_WAKE_PASS_WALL_CLOCK_CEILING_MS, DREAMER_WRAP_UP_NOTICE_PERCENT,
    DreamerAttemptExecution, DreamerAttemptExecutor, DreamerWakeDriver, RunWakePass,
    WakeAttemptContext, WakeCancellation, WakeMilestoneAuthor, WakePassDeadline, WakePassReport,
    WakePassStop, WakeTrigger, current_legibility, legibility_envelope, request_wake,
};
pub use crate::edge::{
    DecodedEdgeValue, EdgeActorClass, EdgeConfirmationStatus, EdgeInfo, EdgeKind,
    EdgeProvenanceFlags, EdgeValueLayout,
};
pub use crate::edit_distance::attribution::{
    AmendmentAuditFixture, AmendmentCause, AmendmentClass, AmendmentEvidence, AmendmentJudgment,
    PreferenceProposal, amendment_evidence, amendment_judgments, classify_amendment, edit_cost_for,
    held_out_amendment_fixtures, judge_amendment, judge_amendment_with, judge_audit_reports,
    pending_preference_proposals, project_edit_cost_claims, record_amendment_evidence,
    run_judge_audit, run_judge_audit_with_judge,
};
pub use crate::edit_distance::escalation::{
    DEFAULT_ESCALATION_STANDING_N, ESCALATION_LAST_RULINGS_BOUND, ESCALATION_STANDING_N_KEY,
    EscalationReceipt, EscalationRuling, EscalationStats, EscalationTrigger, StandingPolicy,
    StandingPolicyStatus, accept_standing_policy, escalation_standing_n, escalation_stats,
    is_escalation_receipt, is_standing_policy_receipt, maybe_propose_standing_policy,
    record_escalation, set_escalation_standing_n, standing_policy_for,
};
pub use crate::edit_distance::graduation::{
    DEFAULT_POSTERIOR_GUARD, OfferAnswer, OfferAnswerOutcome, SnoozeState, ThresholdRow,
    TrustTableRow, WILDCARD_PATTERN, answer_graduation_offer, clear_graduation_policy,
    exact_pattern, graduation_policy_for, graduation_policy_rows, guard_evidence,
    is_graduation_answer_receipt, posterior_lower_bound, set_graduation_policy, snooze_state,
    trust_table, unpin_scope,
};
pub use crate::edit_distance::miner::{
    MINER_K_DEFAULT, MINER_K_SETTINGS_KEY, MINER_REJECTION_COOLDOWN_SECS, MinedOutcome,
    MinedSkillEditProposal, MinerRun, PREDICATE_PREFERENCE_PHRASING, SubstitutionClass,
    SubstitutionCluster, classify_substitution, mine_substitution_clusters, mined_skill_edit,
    miner_attempt_input, miner_k, miner_run_from_input, miner_watermark,
    pending_substitution_skill_edits, run_substitution_miner, set_miner_k,
};
pub use crate::eiri::{
    EIRI_CONTEXT_VERSION_V4, EiriCompanionAssembly, EiriMemoryBoard, EiriMemoryBoardBudget,
    EiriMemoryBoardRow, EiriMemoryBoardSlot, EiriMemoryBoardSource, EiriSessionRagState,
    NotificationItem, ResumeBudget, ResumeBundle, SessionContext, UnprocessedItem,
};
#[cfg(feature = "sync")]
pub use crate::embed::{
    DEFAULT_PENDING_EMBEDDING_LEASE_MS, DEFAULT_REMOTE_PENDING_EMBEDDING_LEASE_MS,
    PendingEmbeddingReconcileReport, PendingEmbeddingReconciler, RemoteRung,
};
pub use crate::embed::{
    EMBED_PRIORITY_BACKFILL, EMBED_PRIORITY_DEVICE, EMBED_PRIORITY_SERVER,
    EMBED_PRIORITY_SURFACED_HOT, EgressDecision, EgressPredicate, Embedder, EmbedderLocality,
    PendingEmbeddingInput, dequantize_int8_embedding,
};
pub use crate::engine_executor::{
    ENGINE_EXECUTOR_FALLBACK_NAME, ENGINE_EXECUTOR_HARD_STEP_LIMIT, ENGINE_EXECUTOR_PURPOSE_NAME,
    ENGINE_EXECUTOR_SOFT_STEP_LIMIT, EngineExecutorConfig, EngineExecutorError,
    EngineExecutorLimits, EngineExecutorOutcome, EngineExecutorResult, EngineExecutorStatus,
    EngineNativeExecutor, ExecutorLegibility, GUEST_BUDGET_RESPONSE_KEY, JsCodeModeHost,
    JsCodeModeOutput, JsCodeModeRuntime, JsCodeModeStep, JsCodeModeStepOutcome,
    SelfDispatchResponse, guest_response_with_budget,
};
pub use crate::entity_id::EntityId;
pub use crate::error::{Error, ErrorKind, Result};
#[cfg(feature = "sync")]
pub use crate::error::{
    SyncConfigField, SyncEngineContext, SyncProtocolPruneScope, SyncProtocolValidation,
    SyncSelectorValidation,
};
pub use crate::extraction_eval::{
    OF360_AR3_METRIC_TIER_INTERFACE_VERSION, OF360_GOLD_DATASET_ID, OF360_GOLD_DATASET_REVISION,
    OF360_METRIC_DEFINITION_SET_ID, OF360_METRIC_DEFINITION_SET_REVISION, OF360_SCHEMA_VERSION,
    Of360Ar3MetricTier, Of360CaseExtractionOutput, Of360ConversationTurn, Of360DatasetCompleteness,
    Of360DerivationEnvelope, Of360EvalError, Of360EvalReport, Of360ExtractedClaim,
    Of360ExtractionRun, Of360ExtractionScore, Of360GoldCase, Of360GoldDataset, Of360GoldMatch,
    Of360GoldMemoryPoint, Of360MemoryKind, Of360MetricDefinition, Of360MetricDefinitionSet,
    Of360MetricDirection, Of360ParsedMetrics, Of360RateMetric, Of360SeededSubsetConfig,
    Of360Speaker, evaluate_of360_extraction, generate_of360_seeded_gold_subset,
    of360_ar3_metric_tier, of360_builtin_ar3_metric_tier, of360_gold_subset,
    of360_gold_subset_json, of360_metric_definitions, of360_metric_definitions_json,
};
pub use crate::facade::{
    AdmitImportedClaimInput, BRIDGE_OUTBOUND_ATTEMPT_KIND, BlobArtifactInput, BlobVersionView,
    CALENDAR_INVITE_OUTBOUND_CHANNEL, CALENDAR_INVITE_OUTBOUND_VERB, CalendarFreebusyDto,
    CalendarFreebusyIntervalDto, CalendarInviteSurfaceInput, CalendarInviteSurfaceMethod,
    ClaimInput, ClaimListFilter, ClaimView, CommitReceipt, CompanionRecordInput,
    ConsolidationAttemptInput, DeleteReceipt, DreamerAttemptRef, DreamerAttemptView, Effort,
    EntityRefReceipt, EntityView, FACADE_CODE_BAD_REQUEST, FACADE_CODE_FORBIDDEN,
    FACADE_CODE_INTERNAL, FACADE_CODE_INVALID_STATE, FACADE_CODE_LEASE_REQUIRED,
    FACADE_CODE_NOT_FOUND, FacadeError, FacadeReceipt, FacadeResult, HabitCheckinInput, LexicalHit,
    MEMORY_PACK_VERSION, MULTI_CARDINALITY_PREDICATES, MemoryFacade, MemoryItem, MemoryPack,
    MemoryProvenance, NeighborHit, NeighborOpts, OutboundDraftInput, OutboundIntentReceipt,
    PendingWrite, RecallScope, RetrievalMeta, SafeDeleteReason, ScopeHonesty, StructuralEdgeSpec,
    StructuralPutInput, TextIndexField, WitnessAuthor, WitnessMessage, WitnessReceipt, WitnessTurn,
    parse_actor_key, resolve_entity_ref,
};
pub use crate::federation::{
    FEDERATION_GRANT_BODY_KEYS, FEDERATION_GRANT_SCHEMA_VERSION,
    FEDERATION_PACT_SCOPE_SCHEMA_VERSION, FederationDirectionScope, FederationGrant,
    FederationGrantPreset, FederationGrantRole, FederationGrantScope, FederationPactScope,
    FederationScopeBands, FederationScopeFacets, FederationScopeWorlds,
    decode_federation_grant_body, decode_federation_pact_scope, encode_federation_grant_body,
    encode_federation_pact_scope,
};
pub use crate::genui::{
    BundleApprovalScope, BundleApproveCard, BundleSendItem, ConsentActionDecision,
    ConsentActionEvaluation, ConsentActionKind, ConsentActionRequest, ConsentActorIdentity,
    ConsentAskCard, ConsentScopeEscalator, ConsentSurface, GrantMintIntent, GrantMintIntentScope,
    OF336_CARD_CATALOG_VERSION, OF336_MCP_UI_MIME, OF336_PROTOCOL_VERSION, Of336ActionDescriptor,
    Of336Component, Of336ComponentKind, Of336RenderedComponent, Of336SurfaceAdapter,
    ReceiptDeepLink, ReceiptDeepLinkKind, ReceiptViewComponent, ViewTimeResolution,
};
pub use crate::graph_fs::{
    GRAPH_FS_COREUTILS_DEFAULT_RESULT_CAP, GRAPH_FS_COREUTILS_MAX_RESULT_CAP,
    GRAPH_FS_DEFAULT_MAX_ENTRIES, GRAPH_FS_DEFAULT_PAGE_BYTE_CAP, GRAPH_FS_HOST_IMPORTS,
    GRAPH_FS_MAX_PAGE_BYTE_CAP, GRAPH_FS_MAX_PAGE_ENTRIES, GRAPH_FS_MIN_PAGE_BYTE_CAP,
    GRAPH_FS_MORE_ENTRY, GRAPH_FS_PROJECTION_VERSION, GraphFsCommandOutput,
    GraphFsCoreutilsDecision, GraphFsCoreutilsVerb, GraphFsEntry, GraphFsEntryKind, GraphFsFile,
    GraphFsMount, GraphFsOptions, GraphFsPage, GraphFsResolver,
};
pub use crate::identity_redirect::REDIRECT_CARRIER_CLASS;
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
pub use crate::identity_topology::{
    AssertDistinctOp, EntityLifecycleState, FacetOp, FacetSpec, IdentityOpEvidence,
    IdentityOpOutcome, IdentityOpWrite, IdentityTopologyAction, IdentityTopologyEvent,
    IdentityTopologyFold, IdentityTopologyOp, IdentityTopologyRejection, MergeOp,
    PREDICATE_ENTITY_DISTINCT_FROM, PROPOSAL_SCOPE_ACTOR_UNATTRIBUTED, ProposalOutcome,
    ProposalRuling, ProposalScope, ReassignmentEntry, ReassignmentMap, ReassignmentStats,
    ReassignmentTarget, SplitOp, StoredIdentityOpAction, StoredIdentityOpEvent, SurvivorshipPlan,
    decode_identity_op_amendment, distinct_pair_key, encode_identity_op_amendment,
    evaluate_transition, fold_identity_topology_log, merge_lifecycle_states,
};
pub use crate::inbox::{
    INBOX_GROUP_DOOR_PREFIX, INBOX_PENDING_SCAN_LIMIT, INBOX_REASON_CHECKER_PREFIX,
    INBOX_SUBCLUSTER_MIN_MEMBERS, InboxBulkVerb, InboxBundleResolution, InboxExceptionClass,
    InboxGroup, InboxGroupMember, InboxGroupReopen, InboxPointerRow, InboxQuery, InboxReviewDial,
    InboxSubCluster,
};
pub use crate::ingest::{
    INGEST_SOURCE_REGISTRY, IngestAdapterSkillRef, IngestError, IngestHarnessConfig, IngestResult,
    IngestSource, IngestSourceConfig, IngestSourceFormat, IngestSourceRegistration,
    IngestSourceRegistry, IngestTrustCeiling, JSONL_TRANSCRIPT_SOURCE_ID, JsonlTranscriptSource,
    KNOWN_INGEST_HARNESS_CONFIG, MEETING_TRANSCRIPT_SCHEMA_V1, MEETING_TRANSCRIPT_SOURCE_ID,
    MeetingTranscriptSource, NormalizedIngestBatch, NormalizedIngestClaim, NormalizedIngestNote,
    NormalizedIngestRecord,
};
pub use crate::interlocutor::{
    Interlocutor, InterlocutorClass, InterlocutorPartyInput, InterlocutorResolutionInput,
    InterlocutorSet, InterlocutorStamp, PresenceEvidence, validate_interlocutor_stamp_value,
};
pub use crate::lens::{
    AnswerSheetAtom, AsofScrubberAtom, ButtonControl, ClaimLineAtom, CollectionAtom, FiniteF64,
    GENERATED_LENS_ATOM_KINDS, GENERATED_UI_SEGMENT_CONTENT_TYPE, GENERATED_UI_WIRE_VERSION,
    GeneratedLens, GeneratedUiCard, GeneratedUiCardElement, GeneratedUiCardStart,
    GeneratedUiCardStateUpdate, GeneratedUiCatalog, GeneratedUiDataModel, GeneratedUiNode,
    GeneratedUiPrebuilt, GeneratedUiPrimitive, GeneratedUiRender, GeneratedUiSegment,
    GeneratedUiSummaryCardPrebuilt, GeneratedUiSurfaceCapabilities, GraphEdge, GraphNode,
    InspectorAtom, LENS_ATOM_KIT_VERSION, LedgerCell, LedgerRowAtom, LensActingPrincipalKind,
    LensApprovedAction, LensApprovedActionArg, LensAtom, LensAtomId, LensBackingRefId,
    LensBackingRefToken, LensBackingTarget, LensBackingTargetKind, LensExecutionBoundary,
    LensGateWriteChokepoint, LensHandleName, LensHandleRef, LensHandleRole, LensHostBackingRef,
    LensHostImport, LensHostMediatedWrite, LensMediaHandle, LensNode, LensPrincipalBinding,
    LensRenderFrame, LensRenderId, LensStatus, LensText, LensTextSpan, MediaAtom, MetaLineAtom,
    NeighborhoodGraphAtom, PackLineAtom, PostmarkAtom, QuickFilterAtom, ReceiptAtom, SealAtom,
    SealLevel, SectionAtom, SegmentedControl, SelectControl, SelfUiAction, SelfUiActionId,
    SelfUiControl, SelfUiControlId, SelfUiOption, SelfUiOptionValue, SelfUiValue, SliderControl,
    StatusDotAtom, TextBlockAtom, TextInputControl, ThreadEntryAtom, ThrobberAtom, ToggleControl,
    TwoClocksAtom, VadBadge, VoiceLineAtom,
};
pub use crate::linkedin_connector::{
    DEFAULT_LINKEDIN_INBOX_BACKFILL_WINDOW_SECS, LINKEDIN_CHANNEL, LINKEDIN_CONNECT_CONSENT_BODY,
    LINKEDIN_CONNECT_REQUEST_VERB, LINKEDIN_DEFAULT_CADENCE_JITTER_MAX_SECONDS,
    LINKEDIN_DEFAULT_CADENCE_JITTER_MIN_SECONDS, LINKEDIN_DEFAULT_DAILY_DM_CAP,
    LINKEDIN_DEFAULT_DAILY_PROFILE_READ_CAP, LINKEDIN_INBOX_SYNC_ATTEMPT_KIND,
    LINKEDIN_MCP_CONNECT_WITH_PERSON_TOOL, LINKEDIN_MCP_CONNECTOR_KEY,
    LINKEDIN_MCP_SEND_MESSAGE_TOOL, LINKEDIN_SEND_DM_VERB, LinkedInAccountRiskLimits,
    LinkedInConsentScreenCopy, LinkedInConversationMessage, LinkedInConversationMessageEvent,
    LinkedInEscalationConfig, LinkedInInboxSyncConfig, LinkedInInboxSyncProvenanceRow,
    LinkedInInboxSyncReport, LinkedInInboxSyncRunner, LinkedInLoginHandoff,
    LinkedInManagedTransport, LinkedInMcpConnectorAdapter, LinkedInMcpInboxSyncTransport,
    LinkedInMcpSendMessageRequest, LinkedInMcpSendTransport, LinkedInMcpServerHarness,
    LinkedInMcpVerifiedSendSink, LinkedInNetworkRoute, LinkedInPasswordCustody,
    LinkedInSandboxHostConfig, LinkedInSandboxHostHarness, LinkedInSandboxRuntime,
    LinkedInSeatDispatchState, LinkedInSeatPolicyAction, LinkedInSeatPolicyDecision,
    LinkedInSeatSandboxPolicy, LinkedInSelectorDriver, LinkedInVerifiedSendPlan,
    linkedin_connect_consent_screen_copy, linkedin_inbox_sync_provenance_rows,
    linkedin_inbox_sync_runner_from_attempt, run_linkedin_kill_switch,
};
pub use crate::llm::{
    BUDGET_LAND_PROMPT_TEMPLATE, BUDGET_LAND_PROMPT_TEMPLATE_ID,
    BUDGET_OWNER_DIGEST_PROMPT_TEMPLATE, BUDGET_OWNER_DIGEST_PROMPT_TEMPLATE_ID,
    BUDGET_PLAN_PROMPT_TEMPLATE, BUDGET_PLAN_PROMPT_TEMPLATE_ID, BUDGET_PROMPT_TEMPLATES,
    BUDGET_RESUME_PREAMBLE_PROMPT_TEMPLATE, BUDGET_RESUME_PREAMBLE_PROMPT_TEMPLATE_ID,
    BudgetAdmission, BudgetDenied, BudgetExhaustionPolicy, BudgetGuard, BudgetLadderEvent,
    BudgetLease, BudgetPromptTemplate, BudgetRead, BudgetSettlement, BudgetSignalDeliveryChannel,
    BudgetSteeringSignal, BudgetThreshold, CallClass, CallEnvelope, CallPurpose, ContentPart,
    DEFAULT_BUDGET_RESERVE_UNITS, DEFAULT_ON_DEVICE_SAFEGUARD_TIER,
    DEFAULT_SAFEGUARD_MODEL_BINDING, DREAMER_STEP_INLINE_RESPONSE_MAX_BYTES,
    DREAMER_STEP_PREDICATE, DREAMER_STEP_RETRY_BACKOFF_MS, DREAMER_STEP_VALUE_KEYS,
    DREAMER_STEP_VALUE_SCHEMA_VERSION, DREAMER_TRAP_PREDICATE, DREAMER_TRAP_VALUE_KEYS,
    DREAMER_TRAP_VALUE_SCHEMA_VERSION, DeterministicFallback, DreamerTrapKind, DreamerTrapState,
    DurableStepContext, DurableStepError, DurableStepResult, FatalLlmError, FinishReason,
    ImageContent, LlmBackend, LlmCapability, LlmCatalogCost, LlmCatalogEntry, LlmError,
    LlmGenerateFuture, LlmInputUsage, LlmMessage, LlmMessageRole, LlmOutputUsage, LlmRequest,
    LlmResponse, LlmResult, LlmStream, LlmStreamEvent, LlmStreamResult, LlmToolSpec, LlmUsage,
    ModelId, ModelIdError, ModelLocality, ModelTierRef, ReasoningEffort, ResponseFormat,
    RetryableLlmError, SafeguardModelBinding, SafeguardModelBindingError, StepOutcome,
    StepProgression, TierPrecedence, TrapRef, UnsupportedCapability, call_as_step,
    consume_trap_signal, open_trap, register_wait, send_trap_signal, trap_for_durable_wait,
    trap_park_owner,
};
pub use crate::maintain::{MaintenanceBuilder, MaintenanceReport};
pub use crate::off_record::{
    OffRecordBackendClass, OffRecordCloseOutcome, OffRecordMode, OffRecordPromoteReceipt,
    OffRecordSession, OffRecordSessionRecord, OffRecordSessionVault,
};
pub use crate::outbound::{
    COMMON_OUTBOUND_VERB_KINDS, CONNECTOR_SEND_TASK_SUBKIND, ConnectorSendTask,
    ConnectorSendTaskOutcome, ConnectorTaskExecutorError, OUTBOUND_CAPABILITY_MANIFEST_VERSION,
    OUTBOUND_INTENT_SCHEMA_VERSION, OUTBOUND_VERB_FIELD_CONTRACT, OutboundCapabilityManifest,
    OutboundCapabilityPermission, OutboundDeliverySemantics, OutboundDeliverySemanticsKind,
    OutboundDeliveryWindowDecision, OutboundDispatchActor, OutboundDispatchError,
    OutboundDispatchGate, OutboundDispatchOutcome, OutboundDispatchPipeline,
    OutboundDispatchPolicyRisk, OutboundDispatchRequest, OutboundDispatchResult,
    OutboundExecutionOutcome, OutboundExecutionOutcomeKind, OutboundExecutionRequest,
    OutboundExecutionSink, OutboundIntent, OutboundIntentDraft, OutboundIntentSource,
    OutboundIntentTrigger, OutboundInterruptionClass, OutboundPermissionState, OutboundRetryClass,
    OutboundVerbContract, UnsupportedOutboundCapability, connector_actor_id,
    outbound_capability_manifest, outbound_capability_manifests, outbound_verb_contract,
    unsupported_outbound_connector,
};
pub use crate::outbound_consent::{
    AuthorizedRecoveryError, AuthorizedRecoveryReport, DataClass, FrozenMcpPayload,
    OutboundBindingAuthority, OutboundBindingValidation, OutboundResultSender,
    OutboundTransportPolicy, OutboundTransportResult, QuarantinedOutboundResult, RawOutboundResult,
    ScopedMcpAuthorization, ScopedMcpBatchVerdict, ScopedMcpCall, ScopedMcpCallContext,
    ScopedMcpConsentDecision, ScopedMcpDispatchResult, ScopedMcpEscalationReason,
    ScopedMcpGrantRef, ScrubbedOutboundResult, StdioSandboxPolicy, evaluate_scoped_mcp_call,
    evaluate_scoped_mcp_calls, recover_authorized_outbound_intents, scrub_outbound_result,
};
pub use crate::outbound_grant::{
    OUTBOUND_GRANT_BODY_KEYS, OUTBOUND_GRANT_SCHEMA_VERSION, ScopedMcpGrantMintIntent,
    StandingOutboundGrant, StandingOutboundGrantScope, StandingOutboundGrantStatus,
    decode_standing_outbound_grant_body, encode_standing_outbound_grant_body,
};
pub use crate::outbound_intent_ledger::{
    BudgetChargeMarker, BudgetClass, FrozenOutboundCall, INTENT_LEDGER_SCHEMA_VERSION,
    INTENT_LEDGER_VALUE_KEYS, IntentDispatchResult, IntentEscalation, IntentEscalationReason,
    IntentLedgerError, IntentLedgerRecord, IntentLedgerResult, IntentRecoveryFailure,
    IntentRecoveryReport, IntentState, OUTBOUND_BINDING_VERSION, OutboundAuthorizationBinding,
    OutboundCallClass, OutboundCallRequest, OutboundFailureKind, OutboundSendFailure,
    OutboundSendOutcome, OutboundToolDescriptor, RecordedOutboundOutcome, classify_outbound_tool,
    derive_intent_id, intent_ledger_records,
};
pub use crate::persona_snapshot::{
    DEFAULT_PERSONA_SNAPSHOT_MAX_CLAIM_ROWS, DEFAULT_PERSONA_SNAPSHOT_MAX_THIRD_PARTY_ROWS,
    DEFAULT_PERSONA_SNAPSHOT_STALE_AFTER_SECS, MEMORY_PACK_LITE_SCHEMA_VERSION,
    PERSONA_SNAPSHOT_COMPILE_STAMP_SCHEMA_VERSION, PERSONA_SNAPSHOT_EXPORT_BODY_KEYS,
    PERSONA_SNAPSHOT_EXPORT_SCHEMA_VERSION, PERSONA_SNAPSHOT_NAME_PREDICATE,
    PERSONA_SNAPSHOT_ROLE_PREDICATE, PersonaSnapshotAgentTake, PersonaSnapshotArtifact,
    PersonaSnapshotCompile, PersonaSnapshotCompileOptions, PersonaSnapshotCompileStamp,
    PersonaSnapshotExportConsent, PersonaSnapshotExportRecord, PersonaSnapshotRow,
    PersonaSnapshotRowKind, PersonaSnapshotStrikeList, STRUCK_IDENTITY_LINE_PLACEHOLDER,
    decode_persona_snapshot_export_body, encode_persona_snapshot_export_body,
};
pub use crate::pipeline::{
    DEFAULT_RECENCY_HALF_LIFE_DAYS, FacetMode, PendingVectorEmbedding, PipelineBuilder,
    RetrievalWithPendingVectors, RetrievalWithTelemetry, ScoredEntity, Signal, WorldScope,
};
pub use crate::policy_model::{
    AgeGateSubclass, CrisisSubclass, LegalFloorSubclass, POLICY_MODEL_REWORD_RETRY_BUDGET,
    PolicyAgeTier, PolicyBargeInKill, PolicyClassifyDecision, PolicyClassifyPrompt,
    PolicyClassifyRequest, PolicyClassifySubject, PolicyClassifyVerdict, PolicyConfidence,
    PolicyContentBinding, PolicyEnforcementAction, PolicyEnforcementVoice, PolicyHedgeBucket,
    PolicyHelpRouting, PolicyModelConfig, PolicyModelEnforcement, PolicyRewordFeedback,
    PolicyRubricLayer, PolicyRubricRow, PolicyVerdictCategory, RelayFloorDegrade, RelayFloorPass,
    RelayTrustDomain,
};
pub use crate::prompt::{
    DEFAULT_PROMPT_PACKAGE_RELATIVE_PATH, EIRI_V3_PROMPT_RELATIVE_PATH,
    PROMPT_RECOMPILE_STAMP_SCHEMA_VERSION, PromptRecompileStamp, ResolvedPrompt,
    SessionPromptAssembly, SessionPromptParts, StampedLlmRequest, assemble_eiri_session_prompt,
    build_eiri_session_request, resolve_eiri_v3_prompt, resolve_prompt,
    workspace_prompt_package_root,
};
pub use crate::provenance::{
    EDGE_PROVENANCE_BODY_KEYS, EDGE_REF_LEN, EdgeProvenanceClaimBody, EdgeRef,
    MODEL_SUBSTRATE_FIELD_MAX_BYTES, PREDICATE_EDGE_PROVENANCE, REASONING_EFFORT_MAX_BYTES,
    SupersessionStatus, decode_edge_provenance_body, derive_confirmation_status,
    validate_actor_class,
};
#[cfg(feature = "test-support")]
pub use crate::provider_confidence::write_enrichment_claim;
pub use crate::provider_confidence::{
    PREDICATE_ACTOR_CONFIDENCE_PRIOR, count_active_prior_claims,
    count_active_prior_claims_with_evidence, count_superseded_prior_claims, effective_confidence,
    is_actor_confidence_prior_claim_predicate, stored_confidence, write_provider_prior,
};
pub use crate::psych_profile::{
    PSYCH_PROFILE_BODY_KEYS, PSYCH_PROFILE_SCHEMA_VERSION, PsychProfile, PsychProfileConfidence,
    PsychProfileSnapshotStatus, PsychProfileStaleReason, PsychProfileState,
    decode_psych_profile_body, encode_psych_profile_body,
};
pub use crate::receipt::{
    BriefReceiptProjection, ContextReceiptFields, CounterpartyReceiptProjection,
    FIELD_MANIFEST_ACTOR_CLAIMS, FIELD_MANIFEST_SKILLS, FIELD_TASK_REF, FIELD_TRANSPORT_DISPATCHED,
    GrantReceiptProjection, PendingTrayAsk, PendingTrayQuery, ReceiptKind, ReceiptProjectionIntent,
    ReceiptProjectionRun, ReceiptQuery, ReceiptRecord, ReceiptView, SessionLocalReceiptLog,
    SessionReceiptClose, StandingOutboundGrantLensRow, StandingOutboundGrantRevokeAction,
    StandingOutboundGrantsLens, StandingOutboundGrantsLensQuery, append_context_receipt_fields,
    append_pack_manifest_fields, attempt_pack_receipt, attempt_pack_receipt_id,
    eiri_memory_board_state_ref, outbound_intent_receipt, project_receipts_by_brief,
    project_receipts_by_counterparty, project_receipts_by_grant, proposal_outcome_amended_body,
    proposal_outcome_delta,
};
pub use crate::recovery::{
    QuarantinedArtifact, RECOVERY_ARTIFACT_INVALID_SUFFIX_PREFIX, RECOVERY_ARTIFACT_MAGIC,
    RECOVERY_ARTIFACT_VERSION, RecoveryArtifact, RecoveryArtifactFailure, RecoveryArtifactLoad,
    decode_recovery_artifact, encode_recovery_artifact, load_recovery_artifact,
};
pub use crate::registry::{
    ENTITY_TYPE_ACCESS_GRANT, ENTITY_TYPE_AUTHORITY_LOG, ENTITY_TYPE_CHANNEL_IDENTITY,
    ENTITY_TYPE_CODE_ARTIFACT, ENTITY_TYPE_CODE_SYMBOL, ENTITY_TYPE_COMM_RECORD,
    ENTITY_TYPE_COUNTERPARTY_CONTACT, ENTITY_TYPE_FEDERATION_GRANT,
    ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT, ENTITY_TYPE_OUTBOUND_GRANT,
    ENTITY_TYPE_PERSONA_SNAPSHOT_EXPORT, ENTITY_TYPE_PSYCH_PROFILE, StructuralKindRegistration,
    TypeByteBand,
};
pub use crate::repo_mutation::{
    REPO_CONFLICT_CLAIM_VALUE_SCHEMA_VERSION, REPO_CONFLICT_OPEN_VALUE_KEYS,
    REPO_CONFLICT_RESOLUTION_VALUE_KEYS, REPO_MUTATION_ALLOWED_OPERATION_KINDS,
    REPO_MUTATION_FORBIDDEN_GIT_COMMANDS, REPO_MUTATION_OPLOG_SCHEMA_VERSION,
    REPO_PROVENANCE_DERIVATION_ENVELOPE_KEYS, REPO_PROVENANCE_NOTES_REF, REPO_PROVENANCE_PREDICATE,
    REPO_PROVENANCE_TRAILER_KEY, REPO_PROVENANCE_VALUE_KEYS, RepoCommitProvenance,
    RepoConflictClaim, RepoConflictResolutionClaim, RepoForkHash, RepoMutationOperation,
    RepoMutationOplogEntry, RepoMutationOutcome, RepoMutationRequest, RepoMutationStatus,
    export_repo_provenance_git_note, parse_repo_provenance_trailer,
    repo_commit_for_provenance_claim, repo_commit_provenance, repo_commit_provenance_from_git_note,
    repo_provenance_git_note,
};
pub use crate::rerank::{RERANK_TOP_N_DEFAULT, RerankCandidate, RerankOptions, Reranker};
pub use crate::run_tree::{
    RunTree, RunTreeAdapter, RunTreeEvent, RunTreeEventKind, RunTreeFailure, RunTreeNode,
    RunTreeRepair, RunTreeStatus, RunTreeTimestamps, render_run_tree,
};
pub use crate::saved_query::{
    ClaimComparison, CreateSavedQueryRequest, EvalMode, EvalPolicy, EvaluationOutcome,
    EvaluationRequest, EvidenceDependencies, FilterAst, MatchDecision, MatchVerdict, MatcherSpec,
    MembershipCause, MembershipCommitOutcome, MembershipEvent, MembershipTransition,
    MembershipWritePlan, PackDrift, PackDriftResolution, PackMigrationMap, PackPredicateRewrite,
    QueryScope, RelevantEvidence, SavedQueryDefinition, SavedQueryDerivationEnvelope,
    SavedQueryEvaluator, SavedQueryJudgeBinding, SavedQueryLifecycle, SavedQueryRecord,
    UpdateSavedQueryRequest, VerdictMemoKey, VerdictMemoRow, WakeEvaluationReport,
};
pub use crate::session_lifecycle::{
    EndedSession, OpenSession, SessionClosePredicate, SessionEndReason, SessionEndWake,
    SessionLifecycleRecord, SessionMintOutcome,
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
    SKILL_CONTENT_HASH_HEX_LEN, SKILL_DEPENDENCY_KEYS, SKILL_DESC_MAX_BYTES, SKILL_ID_MAX_BYTES,
    SKILL_MAX_DEPENDENCIES, SKILL_RECORD_BODY_KEYS, SKILL_TREE_HASH_DOMAIN,
    SKILL_TREE_PATH_MAX_BYTES, SKILL_VERSION_MAX_BYTES, SkillContentHash, SkillDependency,
    SkillLifecycle, SkillRecord, canonical_skill_tree_hash, cross_check_declared_content_hash,
    decode_skill_record, encode_skill_record,
};
pub use crate::skill_attribution::{
    ATTRIBUTION_CALL_PURPOSE_NAME, AttemptOutcome, AttributionAuditReport, AttributionJudge,
    AttributionJudgment, AttributionVerdict, AuditFixture, OutcomeEvidence, RuleAttributionJudge,
    SKILL_ATTRIBUTION_SCHEMA_VERSION, SkillEditProposal, attribution_audit_reports,
    attribution_call_purpose, attribution_judgments, held_out_audit_fixtures,
    pending_edit_proposals, read_attribution_cursor, record_attribution_evidence,
    run_attribution_audit, run_attribution_audit_with_judge, run_attribution_projector,
    run_attribution_projector_with_judge,
};
pub use crate::skill_convert::{
    CONVERT_BIRTH_PATH, CONVERT_HINT_MAX_BYTES, CONVERT_MAX_NEIGHBORS, CONVERT_MAX_SOURCE_MESSAGES,
    CONVERT_RATIONALE_MAX_BYTES, ConvertOutcome, ConvertRequest, ConvertUtterance,
    PROVENANCE_BIRTH_KEY, PROVENANCE_DEDUP_RATIONALE_KEY, PROVENANCE_MERGE_OF_KEY,
    PROVENANCE_SOURCE_MESSAGES_KEY, RefineVerdict, RefinedSkill, SKILL_CONVERT_CALL_PURPOSE_NAME,
    STALE_NOTE_DELETED_REFS_KEY, STALE_NOTE_REASON_KEY, STALE_REASON_SOURCE_MESSAGE_DELETED,
    SkillNeighbor, SkillRefineBrief, SkillRefiner, SkillStaleNote, convert_messages_to_skill,
    rebuild_skill_source_index, skill_convert_call_purpose, skill_stale_note,
    skills_dependent_on_message, source_message_refs,
};
pub use crate::skill_hub::{
    GitSkillHubAdapter, HUB_PIN_KEYS, HUB_REF_KEYS, HttpIndexSkillHubAdapter,
    HubDependencyResolution, HubFile, HubIndexEntry, HubPackage, HubPin, HubRef,
    HubSyncDisposition, HubSyncPolicy, LocalDirSkillHubAdapter, PREDICATE_SKILL_HUB_PROVENANCE,
    PREDICATE_SKILL_HUB_UPDATE_PROPOSAL, PREDICATE_SKILL_SCAN_VERDICT, SKILL_HUB_BODY_KEYS,
    ScanCompleteness, ScanRiskLevel, ScanVerdict, SkillCapabilitySurface, SkillGovernance,
    SkillHubAdapter, SkillHubKind, SkillHubRecord, SkillHubTrustTier, SkillScanReceipt,
    TrackedHubRef, decode_skill_hub_record, encode_skill_hub_record,
};
pub use crate::skill_reliability::{
    DEFAULT_SKILL_RELIABILITY_FLOOR, PREDICATE_SKILL_QUARANTINE_PROPOSAL,
    PREDICATE_SKILL_RELIABILITY, ProvenanceTrustClass, SKILL_RELIABILITY_FLOOR_KEY,
    SKILL_RELIABILITY_FLOOR_MIN_OUTCOMES, SKILL_RELIABILITY_MAX_CITED_RECEIPTS,
    SKILL_RELIABILITY_SCHEMA_VERSION, SkillReliabilityPosterior, check_reliability_floor,
    project_skill_reliability, project_skill_reliability_for, rebuild_skill_confidence_cache,
    record_skill_contributing_win, set_skill_reliability_floor, skill_provenance_trust_class,
    skill_reliability_floor, skill_reliability_posterior, skill_reliability_prior,
    skill_selection_score,
};
pub use crate::skill_scan::{
    ActivationPosture, DEFAULT_ACTIVATION_RISK_THRESHOLD, SCAN_PROVIDER_STATIC_V1,
    SKILL_SCAN_ACTIVATION_RISK_THRESHOLD_KEY, run_static_skill_scan, scan_gate_for_activation,
    set_skill_scan_activation_risk_threshold, skill_scan_activation_risk_threshold,
};
pub use crate::speculative::{
    SPECULATIVE_FIRE_CAP_DEFAULT, SPECULATIVE_FIRE_LIMIT_DEFAULT, SpeculativeFinal,
    SpeculativeFireDecision, SpeculativePartial, SpeculativeSession, SpeculativeSessionConfig,
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
    InboundSurfaceRouteOutcome, InboundSurfaceRouteReceipt, SURFACE_EVENT_ATTEMPT_KIND,
    SURFACE_EVENT_SCHEMA_VERSION, SurfaceCounterpartyStamp, SurfaceEvent, SurfaceEventAck,
    SurfaceEventAction, SurfaceEventAdmission, SurfaceEventAttemptPayload, SurfaceEventAttemptRef,
    SurfaceEventDispatchDisposition, SurfaceEventDispatchRequest, SurfaceEventDispatchRoute,
    SurfaceEventDispatcher, SurfaceEventHandoffState, SurfaceEventHandoffStatus,
    SurfaceEventSource, SurfaceEventWorkerOutcome, SurfaceInteractionKind, SurfaceSourceApp,
    decode_surface_event_attempt_payload, encode_surface_event_attempt_payload,
    surface_event_run_id,
};
pub use crate::task_verb::{
    DEFAULT_TASK_CANCEL_MODE, TASKS_VERBS, TaskAckReceipt, TaskCancelMode, TaskCancelReceipt,
    TaskCancelTarget, TaskCreateRateLimit, TaskCreateReceipt, TaskCreateSpec, TasksVerb,
};
pub use crate::temporal::{TemporalAnchorMode, TemporalGranularity, TimeRange};
pub use crate::thread_lens::{
    THREAD_LENS_INBOX_DRAFTS_KIND, THREAD_LENS_OF327_SEND_COMMAND, ThreadLensEntry,
    ThreadLensInstrument, ThreadLensSendBox, ThreadLensSendProgress, ThreadLensStepState,
};
pub use crate::tokenizer::{
    ContextPackTokenizer, DEFAULT_CONTEXT_PACK_TOKENIZER, DEFAULT_CONTEXT_PACK_TOKENIZER_ID,
    PackTokenizer, count_context_pack_tokens,
};
pub use crate::vault::{
    ActorBound, HydratedShortId, TextIndexStatus, Vault, VaultDoctorDbManifestReport,
    VaultDoctorHnswRecordState, VaultDoctorHnswReport, VaultDoctorReport,
};
pub use crate::write_envelope::{ClaimCandidate, WriteActor, WriteEnvelope, WriteProvenance};

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
    /// - `0xA1..=0xA6`: system-agent preset actor ids (write-door-reserved)
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
    /// (`SystemAgentPreset::…::actor_entity_id()`,
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
    /// `test-model-v1` embedding model, 16 readers. Everything else is the
    /// `VaultConfig::device()` preset — HNSW and text-analyzer defaults
    /// included, so do NOT re-assign defaults here.
    pub(crate) fn embedding_test_config() -> VaultConfig {
        let mut config = VaultConfig::device();
        config.map_size = 16 * 1024 * 1024;
        config.dimensions = 4;
        config.embedding_model = Some("test-model-v1".to_owned());
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
