//! Engine-native JS code-mode executor.
//!
//! This module intentionally sits above [`crate::LlmBackend`],
//! [`crate::code_sandbox`], and [`crate::code_run`]. The LLM backend generates
//! plain JavaScript, the CODE-1 sandbox runtime executes that JavaScript inside
//! the pinned component boundary, and every `self.*` import is routed through a
//! host dispatcher that records the typed bridge call in the durable replay log.

mod attempt_cancels;
mod board_frames;
mod cancel;
mod capture;
pub mod checkpoint_read;
mod code_check;
mod compaction;
mod compaction_host;
pub mod continuation;
mod driver;
pub mod history;
mod host;
mod program_entry;
mod record;
mod repl;
mod shadow_step;
mod skill_call;
mod stack_floor;
mod store;
mod turn_hooks;
mod type_feedback;
mod types;
mod wire;

pub(crate) use self::attempt_cancels::{AttemptCancels, stop_attempt_step};
pub use self::cancel::{CANCEL_POLL_SLICE, StepCancellation};
pub use self::code_check::TypeFeedback;
pub use self::compaction::{CompactionReport, CompactionSpawn, RunCompaction, WindowFullReason};
pub use self::driver::EngineNativeExecutor;
// DOOR-141 PR3b: a turn program's pinned entry, for its runtime alone.
pub(crate) use self::program_entry::{PinnedProgramEntry, PinnedProgramRun};
#[cfg(test)]
use self::record::step_state_hash;
pub use self::record::{EnteredRun, entered_run};
pub use self::shadow_step::run_shadow_step;
pub(crate) use self::shadow_step::shadow_readable_outputs;
pub use self::skill_call::{execute_live_skill_call, execute_live_skill_call_listing};
pub(crate) use self::store::{
    RESULT_READ_ROOT, RESULT_REPLY_INLINE_BYTES, clean_for_context, holds_reply_content,
    is_result_output_path, result_handle_json, store_result_output_path,
};
pub use self::types::{
    ENGINE_EXECUTOR_COMPACTION_PURPOSE_NAME, ENGINE_EXECUTOR_FALLBACK_NAME,
    ENGINE_EXECUTOR_PURPOSE_NAME, ENGINE_EXECUTOR_SOFT_STEP_LIMIT, EngineExecutorConfig,
    EngineExecutorError, EngineExecutorLimits, EngineExecutorOutcome, EngineExecutorResult,
    EngineExecutorStatus, ExecutorLegibility, GUEST_BUDGET_RESPONSE_KEY, JsCodeModeHost,
    JsCodeModeOutput, JsCodeModeRuntime, JsCodeModeStep, JsCodeModeStepOutcome, JsCodeModeStream,
    JsResultCall, JsResultRef, JsResultTarget, ParkedWait, SelfDispatchResponse, StoreReceiptInput,
    StoreReceiptTree, guest_response_with_budget,
};

#[cfg(test)]
mod tests;

// The flat engine_executor.rs module used to provide these names to the sibling
// test module through `use super::*`: every engine-internal item the tests name
// bare. After the directory split the seam re-imports them so `tests.rs`
// resolves exactly as it did before.
#[cfg(test)]
use self::{record::*, store::*};
// The flat module's own crate/std import header, restored for the same reason:
// `tests.rs` names these bare through `use super::*`.
#[cfg(test)]
use crate::code_run::{
    CODE_RUN_CONSOLE_CLOSE, CODE_RUN_CONSOLE_OPEN, CODE_RUN_EXEC_CLOSE, CODE_RUN_EXEC_OPEN,
    CodeRunBridgeCall, CodeRunDeterminism, CodeRunHistoryTurn, CodeRunRawOutput, ExecutorStorage,
    GatedActorWrite, SelfCall, SelfDispatchOutcome, SelfDurableWait,
};
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::{
    Error, LlmBackend, LlmMessage, LlmMessageRole, LlmRequest, ModelLocality, ModelTierRef, Result,
    Vault,
};
