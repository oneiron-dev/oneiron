//! Engine-facing LLM invocation seam.
//!
//! This module defines the shared request, response, streaming, usage, error,
//! and catalog types consumed by engine callers and host-supplied adapters. It
//! intentionally contains no provider implementation or inference dependency.
//!
//! The vault-free part of the seam (protocol, backend, catalog, errors, stream bus,
//! budget guard and leases) is defined in `oneiron-model` and re-exported here; the
//! vault-bound parts (durable steps, seats, manifests, routing, defaults, the RSI
//! ledger, role defaults) live in this module.

mod autocheck;
mod budget;
mod defaults;
mod inference_admission;
mod role_defaults;
pub use inference_admission::{
    AuthorizedInference, BoundInference, HostInferenceBinding, HostInferenceContext,
    InferencePolicySnapshot,
};
pub use oneiron_model::llm::{
    ExtractionEgressPredicate, PurposeDefault, PurposeDefaultTable, ValidatedPurposeDefaults,
    VoiceBackendBinding, VoiceLane, VoicePrecedence, locality_within_extraction_bound,
};
pub(crate) mod entity_refs;
pub use oneiron_model::llm::{
    DeterministicRunner, DreamerFailureClass, DreamerFailureDecision, DreamerFailureRoute,
    FallbackError, FallbackRegistry, LlmEventBus, ProgressSnapshot, ProgressSubscriber, Scope,
    ScopeResource, StreamAssembly, StreamSubscription, TerminalSink, VoiceChunkPolicy,
    VoiceChunker, image, scope,
};
pub(crate) use oneiron_model::llm::{
    DreamerFailurePrecedence, DreamerFailureRule, decide_failure, fallback_failure_class,
    parse_failure_rules,
};
pub mod manifest;
pub mod registry;
pub mod routing;
pub mod score_scraper;
pub mod seat;
mod step;
pub mod tagger;

pub use step::{
    DREAMER_STEP_INLINE_RESPONSE_MAX_BYTES, DREAMER_STEP_PREDICATE, DREAMER_STEP_RETRY_BACKOFF_MS,
    DREAMER_STEP_VALUE_KEYS, DREAMER_STEP_VALUE_SCHEMA_VERSION, DREAMER_TRAP_PREDICATE,
    DREAMER_TRAP_VALUE_KEYS, DREAMER_TRAP_VALUE_SCHEMA_VERSION, DreamerTrapKind, DreamerTrapState,
    DurableStepContext, DurableStepError, DurableStepResult, PeerResultWaitBinding, StepOutcome,
    StepProgression, TrapRef, call_as_step, call_as_step_with_fallbacks, consume_trap_signal,
    open_trap, reconcile_peer_result_signals, register_peer_result_wait, register_wait,
    send_peer_result_signal, send_trap_signal, trap_for_durable_wait, trap_park_owner,
    validate_json_schema,
};
pub(crate) use step::{
    StepEffectBinding, consume_step_wait_in_txn, deindex_dreamer_step_claim,
    index_dreamer_step_claim_for_put, open_step_wait_in_txn, register_detached_step_in_txn,
    signal_step_wait_in_txn, verified_step_consolidation_eligible_in_txn,
    verified_step_effector_eligible_in_txn,
};

pub use oneiron_model::llm::{
    BUDGET_LAND_PROMPT_TEMPLATE, BUDGET_LAND_PROMPT_TEMPLATE_ID,
    BUDGET_OWNER_DIGEST_PROMPT_TEMPLATE, BUDGET_OWNER_DIGEST_PROMPT_TEMPLATE_ID,
    BUDGET_PLAN_PROMPT_TEMPLATE, BUDGET_PLAN_PROMPT_TEMPLATE_ID, BUDGET_PROMPT_TEMPLATES,
    BUDGET_RESUME_PREAMBLE_PROMPT_TEMPLATE, BUDGET_RESUME_PREAMBLE_PROMPT_TEMPLATE_ID,
    BudgetAdmission, BudgetExhaustionPolicy, BudgetGuard, BudgetLadderEvent, BudgetPromptTemplate,
    BudgetRead, BudgetSettlement, BudgetSignalDeliveryChannel, BudgetSteeringSignal,
    BudgetThreshold, DEFAULT_BUDGET_RESERVE_UNITS,
};
pub(crate) use oneiron_model::llm::{BudgetPolicyRow, BudgetPolicySelector, BudgetPolicyTable};

pub use oneiron_model::llm::{NormalizedBurstInputs, normalized_burst_inputs};

pub(crate) use self::autocheck::truncate_on_char_boundary;
pub use self::autocheck::{
    AUTO_CHECK_VALUE_PREVIEW_BYTES, AUTO_CHECKER_DEADLINE_MS, AutoCheckCandidate,
    AutoCheckCandidateOwned, AutoCheckOutcome, AutoCheckSignals, AutoChecker, BoundedAutoChecker,
    auto_check_llm_request,
};
pub use self::role_defaults::RoleModelDefaults;
pub(crate) use self::step::{ExecutedModelWitness, terminal_step_identity};
pub(crate) use oneiron_model::llm::canonical_json_bytes;
pub use oneiron_model::llm::{
    BudgetDenied, BudgetLease, CallClass, CallEnvelope, CallPurpose, ContentPart,
    DEFAULT_ON_DEVICE_SAFEGUARD_TIER, DEFAULT_SAFEGUARD_MODEL_BINDING, DeterministicFallback,
    FatalLlmError, FinishReason, ImageContent, LlmBackend, LlmCapability, LlmCatalogCost,
    LlmCatalogEntry, LlmError, LlmGenerateFuture, LlmInputUsage, LlmMessage, LlmMessageRole,
    LlmOutputUsage, LlmRequest, LlmResponse, LlmResult, LlmRole, LlmStream, LlmStreamEvent,
    LlmStreamResult, LlmToolSpec, LlmUsage, ModelId, ModelIdError, ModelLocality, ModelTierRef,
    PinnedConfigViolation, PinnedModelConfig, ReasoningEffort, ResponseFormat, RetryableLlmError,
    SafeguardModelBinding, SafeguardModelBindingError, TierPrecedence, UnsupportedCapability,
};

#[cfg(test)]
mod tests;

// The flat llm.rs module used to provide these names to the sibling test
// module through `use super::*`: every llm-internal item the tests name
// bare, plus the module's own private import header. After the directory
// split the seam re-imports both so `tests.rs` resolves exactly as it did
// before.
#[cfg(test)]
use self::autocheck::AUTO_CHECK_PURPOSE_DEFAULT_TIER;
#[cfg(test)]
use crate::claim::ClaimSource;
#[cfg(test)]
use crate::write_envelope::SourceLineage;
#[cfg(test)]
use serde_json::Value as JsonValue;
#[cfg(test)]
use std::collections::BTreeMap;

/// Typed question and outcome contracts.
pub mod decision;
pub use budget::{
    RsiBudgetConfig, RsiBudgetError, RsiBudgetRead, RsiBudgetShare, RsiExplorationRead,
    RsiOverdraftReceipt, RsiSettlement, RsiSpendPurpose,
};
pub(crate) use step::resume_peer_result_steps;
