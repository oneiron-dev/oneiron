//! Engine-facing LLM invocation seam.
//!
//! This module defines the shared request, response, streaming, usage, error,
//! and catalog types consumed by engine callers and host-supplied adapters, the
//! backend trait, and the per-attempt budget guard that issues the leases a
//! backend call carries. It intentionally contains no provider implementation or
//! inference dependency. `oneiron` re-exports every item at `oneiron::llm`,
//! beside the vault-bound parts of the seam (durable steps, seats, manifests,
//! routing, defaults and the RSI ledger).

mod assembly;
pub use assembly::StreamAssembly;
mod backend;
mod backend_identity;
mod bus;
mod subscribers;
pub use bus::{LlmEventBus, StreamSubscription, TerminalSink};
pub use subscribers::{ProgressSnapshot, ProgressSubscriber, VoiceChunkPolicy, VoiceChunker};
mod budget;
mod burst_inputs;
mod cache;
mod call;
mod defaults;
mod inference;
mod inference_observation;
mod inference_publisher;
pub use defaults::{
    ExtractionEgressPredicate, PurposeDefault, PurposeDefaultTable, SelfCompactionDefault,
    SelfCompactionSource, ValidatedPurposeDefaults, VoiceBackendBinding, VoiceLane,
    VoicePrecedence, locality_within_extraction_bound,
};
// Public so `oneiron`'s resident-default door ranks routes the same way the table does.
pub use defaults::locality_rank;
pub mod scope;
#[cfg(test)]
mod streaming_tests;
pub use self::scope::{Scope, ScopeResource};
mod catalog;
mod error;
mod fallback;
pub mod limit;
pub use fallback::{DeterministicRunner, FallbackError, FallbackRegistry};
mod failure_policy;
pub use failure_policy::{DreamerFailureClass, DreamerFailureDecision, DreamerFailureRoute};
// Public so `oneiron`'s policy-manifest decoder and durable step executor (the only
// callers outside this module) parse and apply the same failure rules across the crate
// line. Pure functions over values.
pub use failure_policy::{
    DreamerFailurePrecedence, DreamerFailureRule, decide_failure, fallback_failure_class,
    parse_failure_rules,
};
pub mod image;
mod label_read;
pub mod media;
pub use label_read::{
    LabelReadModel, LabelReadRequest, LabelReadResponse, LabelReadout, LabelSet, joint_marginals,
};
mod model_id;
mod protocol;
mod reply_assertions;
mod safeguard;
mod scheduling;
mod segments;
mod session;

pub use budget::{
    BUDGET_LAND_PROMPT_TEMPLATE, BUDGET_LAND_PROMPT_TEMPLATE_ID,
    BUDGET_OWNER_DIGEST_PROMPT_TEMPLATE, BUDGET_OWNER_DIGEST_PROMPT_TEMPLATE_ID,
    BUDGET_PLAN_PROMPT_TEMPLATE, BUDGET_PLAN_PROMPT_TEMPLATE_ID, BUDGET_PROMPT_TEMPLATES,
    BUDGET_RESUME_PREAMBLE_PROMPT_TEMPLATE, BUDGET_RESUME_PREAMBLE_PROMPT_TEMPLATE_ID,
    BudgetAdmission, BudgetExhaustionPolicy, BudgetGuard, BudgetLadderEvent, BudgetLeaseState,
    BudgetPromptTemplate, BudgetRead, BudgetSettlement, BudgetSignalDeliveryChannel,
    BudgetSteeringSignal, BudgetThreshold, DEFAULT_BUDGET_RESERVE_UNITS, DispatchBinding,
    DispatchRefused, FAILED_RUNGS_KEY, answered_units, answered_units_wide,
};
// Public so `oneiron`'s policy-manifest decoder and frontier hash (the only callers outside
// this module) build and hash the policy rows a guard enforces. Rows are values; a guard
// built from them still issues every lease itself.
pub use budget::{BudgetPolicyRow, BudgetPolicySelector, BudgetPolicyTable};

pub use self::burst_inputs::{NormalizedBurstInputs, normalized_burst_inputs};

// FIX 6567: the cache evidence a backend reports on a physical call.
pub use self::cache::{
    CacheBackend, CacheCallUsage, CacheCounterSource, CacheDigest, CacheEpoch, CacheEvidenceError,
    CacheIdentity, CacheOutcome, CachePassReport, CachePassUsage, CachePhase,
};
// FIX 8314 (INFERENCE R1): model workers and the receipt of each physical call.
pub use self::inference::{
    INFERENCE_CALLS_KEY, InferenceCallReceipt, InferenceEndReason, QueueWait, WorkerBuildEvidence,
    WorkerDescriptor, WorkerFailure, WorkerFailureDetail, WorkerKind, WorkerMode, WorkerPhase,
    WorkerReadiness, WorkerStatus,
};
// FIX 9065: what each physical request measured, published on its lease while it runs.
pub use self::inference_observation::{InferenceCallObservation, InferenceObservationId};
pub use self::inference_publisher::InferencePublisher;
// FIX 7895: the answering llama.cpp process's launch alias, read in one place.
pub use self::backend_identity::{LlamaAlias, parse_llama_alias, returned_model_wire_id};

pub use self::backend::{
    BrokerIsolation, BudgetLease, LlmBackend, LlmGenerateFuture, LlmResult, LlmStream,
    LlmStreamResult, SingleRouteBackend, SingleSend,
};
pub use self::call::{
    CallClass, CallEnvelope, CallPurpose, DeterministicFallback, LlmRole, ModelLocality,
    ModelTierRef, PinnedConfigViolation, PinnedModelConfig, ResponseFormat, TierPrecedence,
};
pub use self::catalog::{
    LlmCapability, LlmCatalogCost, LlmCatalogEntry, MEDIA_METADATA_KEY, REASONING_BUDGET_PARAM,
    ReasoningEffort,
};
pub use self::error::{
    BudgetDenied, FatalLlmError, InterruptedMediaCall, LabelReadFailure, LlmError,
    RetryableLlmError, SpentKind, UnsupportedCapability,
};
// Public so `oneiron`'s auto-checker names a dynamic model the same way the safeguard
// binding does, across the crate line.
pub use self::model_id::dynamic_model_id;
pub use self::model_id::{ModelId, ModelIdError};
// Public so `oneiron`'s step, edit-distance and saved-query records hash the same canonical
// JSON bytes across the crate line.
pub use self::protocol::canonical_json_bytes;
pub use self::protocol::{
    ContentPart, FinishReason, ImageContent, IncompleteReason, LlmInputUsage, LlmMessage,
    LlmMessageRole, LlmOutputUsage, LlmRequest, LlmResponse, LlmStreamEvent, LlmToolSpec, LlmUsage,
};
// FIX 3416: the typed records a reply cited or created, which its host alone fills.
pub use self::reply_assertions::{ReplyAssertionRecord, ReplyAssertions};
pub use self::safeguard::{
    DEFAULT_ON_DEVICE_SAFEGUARD_TIER, DEFAULT_SAFEGUARD_MODEL_BINDING, SafeguardModelBinding,
    SafeguardModelBindingError,
};
// DESIGN-V2 R2: the typed segment manifest a host sets on a call, and the
// session contracts of exact conversation reuse on a model worker.
pub use self::segments::{
    ByteSpan, DisclosureLabel, ManifestDigest, MessageDigest, MessageStamp, Segment, SegmentClass,
    SegmentClock, SegmentKind, SegmentLocator, SegmentManifest, SourceRevision, TrustFence,
    message_digest, role_name,
};
pub use self::session::{
    BranchHandle, CanonicalCheckpointRef, ConditioningDigest, ConversationAnchor,
    SESSION_HANDLE_BYTES, SESSION_SCHEMA_MINOR, SESSIONS_CAPABILITY, ScopeDigest, SessionAppend,
    SessionAppended, SessionBinding, SessionCapability, SessionCheckpoint, SessionCheckpointed,
    SessionCreate, SessionCreated, SessionDrop, SessionFork, SessionForked, SessionGenerate,
    SessionHandle, SessionInvalidation, SessionKey, SessionOp, SessionOpStamp, SessionReleased,
    SessionResidency, SessionRestore, SessionRestored, SessionSuffixCommit, SessionSuffixStaged,
    SessionTarget, TokenDigest, VaultRef,
};
// DESIGN-V2 R3: the snapshot ops of the worker session wire.
pub use self::session::{
    RegionDescriptor, SNAPSHOT_ENCODING, SNAPSHOT_HASH, SNAPSHOT_SCHEMA, SNAPSHOT_SCHEMA_MINOR,
    SessionExport, SessionExported, SessionImport, SessionImported, SnapshotCapability,
    SnapshotDigest, SnapshotMiss,
};
// DESIGN-V2 R4: the scheduling wire of a model worker (codec v1.3).
pub use self::scheduling::{
    AdmissionGrant, CallSchedule, ResourceClass, SCHEDULING_CAPABILITY, SCHEDULING_POLICY,
    SCHEDULING_SCHEMA_MINOR, ScheduleAck, ScheduleAction, ScheduleBoundary, ScheduleUpdate,
    SchedulingCapability, SchedulingReceipt, WorkCancel, WorkClass, WorkContext, WorkId,
    WorkPhysical, WorkPriority,
};
