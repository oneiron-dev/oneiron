//! Engine-facing LLM invocation seam.
//!
//! This module defines the shared request, response, streaming, usage, error,
//! and catalog types consumed by engine callers and host-supplied adapters. It
//! intentionally contains no provider implementation or inference dependency.

mod autocheck;
mod backend;
mod budget;
mod call;
mod catalog;
mod error;
mod model_id;
mod protocol;
mod safeguard;
mod step;

pub use step::{
    DREAMER_STEP_INLINE_RESPONSE_MAX_BYTES, DREAMER_STEP_PREDICATE, DREAMER_STEP_RETRY_BACKOFF_MS,
    DREAMER_STEP_VALUE_KEYS, DREAMER_STEP_VALUE_SCHEMA_VERSION, DREAMER_TRAP_PREDICATE,
    DREAMER_TRAP_VALUE_KEYS, DREAMER_TRAP_VALUE_SCHEMA_VERSION, DreamerTrapKind, DreamerTrapState,
    DurableStepContext, DurableStepError, DurableStepResult, PeerResultWaitBinding, StepOutcome,
    StepProgression, TrapRef, call_as_step, consume_trap_signal, open_trap,
    reconcile_peer_result_signals, register_peer_result_wait, register_wait,
    send_peer_result_signal, send_trap_signal, trap_for_durable_wait, trap_park_owner,
};
pub(crate) use step::{deindex_dreamer_step_claim, index_dreamer_step_claim_for_put};

pub use budget::{
    BUDGET_LAND_PROMPT_TEMPLATE, BUDGET_LAND_PROMPT_TEMPLATE_ID,
    BUDGET_OWNER_DIGEST_PROMPT_TEMPLATE, BUDGET_OWNER_DIGEST_PROMPT_TEMPLATE_ID,
    BUDGET_PLAN_PROMPT_TEMPLATE, BUDGET_PLAN_PROMPT_TEMPLATE_ID, BUDGET_PROMPT_TEMPLATES,
    BUDGET_RESUME_PREAMBLE_PROMPT_TEMPLATE, BUDGET_RESUME_PREAMBLE_PROMPT_TEMPLATE_ID,
    BudgetAdmission, BudgetExhaustionPolicy, BudgetGuard, BudgetLadderEvent, BudgetPromptTemplate,
    BudgetRead, BudgetSettlement, BudgetSignalDeliveryChannel, BudgetSteeringSignal,
    BudgetThreshold, DEFAULT_BUDGET_RESERVE_UNITS,
};
pub(crate) use budget::{BudgetPolicyRow, BudgetPolicySelector, BudgetPolicyTable};

pub(crate) use self::autocheck::truncate_on_char_boundary;
pub use self::autocheck::{
    AUTO_CHECK_VALUE_PREVIEW_BYTES, AUTO_CHECKER_DEADLINE_MS, AutoCheckCandidate,
    AutoCheckCandidateOwned, AutoCheckOutcome, AutoChecker, BoundedAutoChecker,
    auto_check_llm_request,
};
pub use self::backend::{
    BudgetLease, LlmBackend, LlmGenerateFuture, LlmResult, LlmStream, LlmStreamResult,
};
pub use self::call::{
    CallClass, CallEnvelope, CallPurpose, DeterministicFallback, LlmRole, ModelLocality,
    ModelTierRef, PinnedConfigViolation, PinnedModelConfig, ResponseFormat, RoleModelDefaults,
    TierPrecedence,
};
pub use self::catalog::{LlmCapability, LlmCatalogCost, LlmCatalogEntry, ReasoningEffort};
pub use self::error::{
    BudgetDenied, FatalLlmError, LlmError, RetryableLlmError, UnsupportedCapability,
};
pub use self::model_id::{ModelId, ModelIdError};
pub(crate) use self::protocol::canonical_json_bytes;
pub use self::protocol::{
    ContentPart, FinishReason, ImageContent, LlmInputUsage, LlmMessage, LlmMessageRole,
    LlmOutputUsage, LlmRequest, LlmResponse, LlmStreamEvent, LlmToolSpec, LlmUsage,
};
pub use self::safeguard::{
    DEFAULT_ON_DEVICE_SAFEGUARD_TIER, DEFAULT_SAFEGUARD_MODEL_BINDING, SafeguardModelBinding,
    SafeguardModelBindingError,
};

#[cfg(test)]
mod tests;

// The flat llm.rs module used to provide these names to the sibling test
// module through `use super::*`: every llm-internal item the tests name
// bare, plus the module's own private import header. After the directory
// split the seam re-imports both so `tests.rs` resolves exactly as it did
// before.
#[cfg(test)]
use self::autocheck::{
    AUTO_CHECK_HOLD_REASON_MAX_BYTES, AUTO_CHECK_MAX_HOLD_REASONS, AUTO_CHECK_PURPOSE_DEFAULT_TIER,
    auto_check_verdict_schema,
};
#[cfg(test)]
use crate::claim::ClaimSource;
#[cfg(test)]
use crate::write_envelope::SourceLineage;
#[cfg(test)]
use futures_core::Stream;
#[cfg(test)]
use serde_json::{Map as JsonMap, Value as JsonValue};
#[cfg(test)]
use std::collections::BTreeMap;
#[cfg(test)]
use std::pin::Pin;
#[cfg(test)]
use std::sync::Arc;
#[cfg(test)]
use std::sync::atomic::Ordering;
#[cfg(test)]
use std::sync::mpsc;
#[cfg(test)]
use std::time::Duration;
