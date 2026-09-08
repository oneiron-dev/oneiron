//! Engine-native JS code-mode executor.
//!
//! This module intentionally sits above [`crate::LlmBackend`],
//! [`crate::code_sandbox`], and [`crate::code_run`]. The LLM backend generates
//! plain JavaScript, the CODE-1 sandbox runtime executes that JavaScript inside
//! the pinned component boundary, and every `self.*` import is routed through a
//! host dispatcher that records the typed bridge call in the durable replay log.

mod driver;
mod host;
mod record;
mod repl;
mod store;
mod types;
mod wire;

pub use self::driver::EngineNativeExecutor;
#[cfg(test)]
pub(crate) use self::record::step_state_hash;
pub use self::types::{
    ENGINE_EXECUTOR_FALLBACK_NAME, ENGINE_EXECUTOR_HARD_STEP_LIMIT, ENGINE_EXECUTOR_PURPOSE_NAME,
    ENGINE_EXECUTOR_SOFT_STEP_LIMIT, EngineExecutorConfig, EngineExecutorError,
    EngineExecutorLimits, EngineExecutorOutcome, EngineExecutorResult, EngineExecutorStatus,
    ExecutorLegibility, GUEST_BUDGET_RESPONSE_KEY, JsCodeModeHost, JsCodeModeOutput,
    JsCodeModeRuntime, JsCodeModeStep, JsCodeModeStepOutcome, SelfDispatchResponse,
    guest_response_with_budget,
};
#[cfg(test)]
pub(crate) use self::wire::{
    ExecutorWireRepairs, HealedExecutorReply, heal_executor_reply,
    partition_top_level_console_blocks,
};

#[cfg(test)]
mod tests;

// The flat engine_executor.rs module used to provide these names to the sibling
// test module through `use super::*`: every engine-internal item the tests name
// bare. After the directory split the seam re-imports them so `tests.rs`
// resolves exactly as it did before.
#[cfg(test)]
use self::{host::*, record::*, store::*, wire::*};
// The flat module's own crate/std import header, restored for the same reason:
// `tests.rs` names these bare through `use super::*`.
#[cfg(test)]
use crate::code_run::{
    CODE_RUN_CONSOLE_CLOSE, CODE_RUN_CONSOLE_OPEN, CODE_RUN_EXEC_CLOSE, CODE_RUN_EXEC_OPEN,
    CodeRunBridgeCall, CodeRunDeterminism, CodeRunHistoryTurn, CodeRunRawOutput,
    CodeRunReplayRecord, ExecutorStorage, GatedActorWrite, SelfCall, SelfDispatchOutcome,
    SelfDurableWait,
};
#[cfg(test)]
use crate::code_sandbox::{
    PLAIN_JS_HOST_VERB_DTS, SandboxBoundaryContract, SandboxComponentBoundary, SandboxGuestLanguage,
};
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::off_record::ExecutorUtterance;
#[cfg(test)]
use crate::{
    CallClass, CallPurpose, Error, LlmBackend, LlmMessage, LlmMessageRole, LlmRequest,
    ModelLocality, ModelTierRef, Result, Vault,
};
