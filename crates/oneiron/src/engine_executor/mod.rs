//! Engine-native JS code-mode executor.
//!
//! This module intentionally sits above [`crate::LlmBackend`],
//! [`crate::code_sandbox`], and [`crate::code_run`]. The LLM backend generates
//! plain JavaScript, the CODE-1 sandbox runtime executes that JavaScript inside
//! the pinned component boundary, and every `self.*` import is routed through a
//! host dispatcher that records the typed bridge call in the durable replay log.

mod attempt_cancels;
mod board_frames;
use oneiron_base::step_cancellation as cancel;
mod caller_run_output;
mod capture;
pub mod checkpoint_read;
mod code_check;
mod compaction;
mod compaction_host;
pub mod continuation;
mod driver;
pub mod history;
mod host;
mod no_model;
mod program_entry;
mod record;
mod repl;
pub mod reply_evidence;
pub(crate) mod resume_divergence;
mod run_position;
mod run_signals;
mod self_brief;
mod session_refusal;
pub(crate) mod setting_keys;
mod shadow_step;
mod skill_call;
mod source_entry;
mod stack_floor;
mod step_evidence;
mod store;
mod turn_hooks;
mod type_feedback;
mod types;
mod wire;

pub(crate) use self::attempt_cancels::{AttemptCancels, stop_attempt_step};
pub use self::caller_run_output::{CallerRunOutput, read_caller_run_output};
pub use self::cancel::{CANCEL_POLL_SLICE, StepCancellation};
pub use self::code_check::TypeFeedback;
// FIX 10389: a program a door other than a run's own step runs, checked as a
// step's is.
pub(crate) use self::code_check::{CheckedDoor, LatestFeedback, RowsCheck};
pub use self::compaction::{CompactionReport, CompactionSpawn, RunCompaction, WindowFullReason};
pub(crate) use self::compaction_host::{ParkedKindFolds, console_fold_stub, parked_kind_folds};
pub use self::driver::EngineNativeExecutor;
pub(crate) use self::host::ACT_GATES_COUNT_CALLABLE_ROWS;
pub use self::no_model::NoModelBackend;
// DOOR-141 PR3b: a turn program's pinned entry, for its runtime alone.
pub(crate) use self::program_entry::{PinnedProgramEntry, PinnedProgramRun};
#[cfg(test)]
use self::record::step_state_hash;
pub use self::record::{EnteredRun, caller_run_input, entered_run};
pub(crate) use self::record::{caller_run_input_in_txn, code_run_terminal_in_txn, parked_wait_now};
#[cfg(oneiron_test_support)]
pub(crate) use self::record::{executor_config_hash_for_test, step_state_hash_for_test};
// FIX 4606: a canonical run's generation and parked wait, read outside its
// entries.
pub use self::run_position::{CodeRunPosition, code_run_parked_wait, code_run_position};
// FIX 17594: the host's self-brief port a native run's requests carry.
pub use self::self_brief::{
    BriefBoundary, BriefCandidateToken, BriefPrefix, BriefRecheck, FoldBoundary, SelfBriefPort,
};
// FIX OFF-RECORD-RUN-POLICY-REFUSAL-500: a session's refusal of a run's act.
pub use self::session_refusal::is_session_act_refusal;
pub use self::shadow_step::{ArmTypeFeedback, run_shadow_step};
pub(crate) use self::shadow_step::{run_shadow_callable_branch, shadow_readable_outputs};
pub use self::skill_call::{
    AdmittedSkillAnswer, AdmittedSkillText, execute_live_skill_call,
    execute_live_skill_call_listing, judge_admitted_skill_text, spill_admitted_skill_view,
};
// FIX 4414: the owner's per-run step evidence.
pub(crate) use self::step_evidence::step_evidence_page;
pub use self::store::{RESULT_READ_ROOT, RESULT_REPLY_INLINE_BYTES};
pub(crate) use self::store::{
    bridge_result_output_path, clean_for_context, holds_reply_content, is_result_output_path,
    mask_known_text, observation_output_path, parse_result_read_path, record_only_output_path,
    result_handle_json, result_read_path_for, resumed_output_wait, script_output_path,
    store_agent_verb_write_answer, store_ordinal_base, store_result_output_path,
    terminal_output_seq, write_receipt_result_output_path,
};
pub use self::types::{
    CallableProgram, CallerRunInput, ENGINE_EXECUTOR_COMPACTION_PURPOSE_NAME,
    ENGINE_EXECUTOR_FALLBACK_NAME, ENGINE_EXECUTOR_PURPOSE_NAME, ENGINE_EXECUTOR_SOFT_STEP_LIMIT,
    EngineExecutorConfig, EngineExecutorError, EngineExecutorLimits, EngineExecutorOutcome,
    EngineExecutorResult, EngineExecutorStatus, ExecutorLegibility, GUEST_BUDGET_RESPONSE_KEY,
    JsCodeModeHost, JsCodeModeOutput, JsCodeModeRuntime, JsCodeModeStep, JsCodeModeStepOutcome,
    JsCodeModeStream, JsResultCall, JsResultRef, JsResultTarget, ParkedWait, SelfDispatchResponse,
    StoreReceiptInput, StoreReceiptTree, guest_response_with_budget,
};
// L8-23: what a resumed pending step's walk met, on its outcome and its hold.
pub use self::host::resume_preflight::{
    ChangedStep, ResumePreflightReport, ResumeVerdict, UnreachedStep,
};

pub(crate) use self::host::executor_declarations_block;
#[cfg(oneiron_test_support)]
pub(crate) use self::host::executor_system_prompt;
#[cfg(oneiron_test_support)]
pub(crate) use self::host::spill_before_record;
#[cfg(oneiron_test_support)]
pub(crate) use self::wire::{HealedExecutorReply, heal_executor_text_tracking_repairs};

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
