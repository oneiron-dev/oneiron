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
mod bus;
mod subscribers;
pub use bus::{LlmEventBus, StreamSubscription, TerminalSink};
pub use subscribers::{ProgressSnapshot, ProgressSubscriber, VoiceChunkPolicy, VoiceChunker};
mod budget;
mod burst_inputs;
mod call;
mod defaults;
pub use defaults::{
    ExtractionEgressPredicate, PurposeDefault, PurposeDefaultTable, ValidatedPurposeDefaults,
    VoiceBackendBinding, VoiceLane, VoicePrecedence, locality_within_extraction_bound,
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
mod model_id;
mod protocol;
mod safeguard;

pub use budget::{
    BUDGET_LAND_PROMPT_TEMPLATE, BUDGET_LAND_PROMPT_TEMPLATE_ID,
    BUDGET_OWNER_DIGEST_PROMPT_TEMPLATE, BUDGET_OWNER_DIGEST_PROMPT_TEMPLATE_ID,
    BUDGET_PLAN_PROMPT_TEMPLATE, BUDGET_PLAN_PROMPT_TEMPLATE_ID, BUDGET_PROMPT_TEMPLATES,
    BUDGET_RESUME_PREAMBLE_PROMPT_TEMPLATE, BUDGET_RESUME_PREAMBLE_PROMPT_TEMPLATE_ID,
    BudgetAdmission, BudgetExhaustionPolicy, BudgetGuard, BudgetLadderEvent, BudgetPromptTemplate,
    BudgetRead, BudgetSettlement, BudgetSignalDeliveryChannel, BudgetSteeringSignal,
    BudgetThreshold, DEFAULT_BUDGET_RESERVE_UNITS,
};
// Public so `oneiron`'s policy-manifest decoder and frontier hash (the only callers outside
// this module) build and hash the policy rows a guard enforces. Rows are values; a guard
// built from them still issues every lease itself.
pub use budget::{BudgetPolicyRow, BudgetPolicySelector, BudgetPolicyTable};

pub use self::burst_inputs::{NormalizedBurstInputs, normalized_burst_inputs};

pub use self::backend::{
    BudgetLease, LlmBackend, LlmGenerateFuture, LlmResult, LlmStream, LlmStreamResult,
};
pub use self::call::{
    CallClass, CallEnvelope, CallPurpose, DeterministicFallback, LlmRole, ModelLocality,
    ModelTierRef, PinnedConfigViolation, PinnedModelConfig, ResponseFormat, TierPrecedence,
};
pub use self::catalog::{LlmCapability, LlmCatalogCost, LlmCatalogEntry, ReasoningEffort};
pub use self::error::{
    BudgetDenied, FatalLlmError, LlmError, RetryableLlmError, UnsupportedCapability,
};
// Public so `oneiron`'s auto-checker names a dynamic model the same way the safeguard
// binding does, across the crate line.
pub use self::model_id::dynamic_model_id;
pub use self::model_id::{ModelId, ModelIdError};
// Public so `oneiron`'s step, edit-distance and saved-query records hash the same canonical
// JSON bytes across the crate line.
pub use self::protocol::canonical_json_bytes;
pub use self::protocol::{
    ContentPart, FinishReason, ImageContent, LlmInputUsage, LlmMessage, LlmMessageRole,
    LlmOutputUsage, LlmRequest, LlmResponse, LlmStreamEvent, LlmToolSpec, LlmUsage,
};
pub use self::safeguard::{
    DEFAULT_ON_DEVICE_SAFEGUARD_TIER, DEFAULT_SAFEGUARD_MODEL_BINDING, SafeguardModelBinding,
    SafeguardModelBindingError,
};
