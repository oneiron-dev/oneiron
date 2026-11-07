//! Canonical code-run persistence rows and the executor's storage routing.

mod compaction;
mod continuation;
mod folds;
mod lift;
mod model_seat;
mod program_resume;
mod read_worlds;
mod reader_folds;
mod reader_jobs;
mod records;
mod replay_bodies;
mod replay_capsule;
mod response_erase;
mod response_owners;
mod routing;
mod secret_lift;
pub(crate) use secret_lift::{
    drop_code_run_result_marks_in_txn, erase_retained_result_marks_in_txn,
};
mod session_checkpoint;
pub(crate) use session_checkpoint::SessionCheckpointBody;
mod session_write;
// FIX 5426: the caller's view a room write's receipt keeps.
pub(crate) use self::session_write::{KeptCallerView, kept_caller_view};
mod spawn_erase;
mod speech_identity;
mod type_diagnostics;
mod wait_delivery;
mod wait_holders;

pub(crate) use self::compaction::{CodeRunCompactionCoverage, ExecutorOutputSpan};
pub(crate) use self::continuation::{
    StoredRunContinuation, continuation_seed_body_in_txn, publish_continuation_output_in_txn,
    put_run_continuation_row_in_txn, run_continuation_in_txn, seed_continuation_run,
};
pub use self::read_worlds::ReadWorldUnknown;
pub(crate) use self::read_worlds::{
    ReadWorldSeal, ReadWorldSnapshot, captured_step_read_scopes_in_txn, read_world_snapshot_in_txn,
};
pub(crate) use self::reader_folds::{
    OccurrenceRef, ReaderFoldReceipt, ReaderSubstrateRef, ReceiptFinding, ReceiptPartial,
    ReceiptSource, ReceiptTree,
};
pub(crate) use self::reader_jobs::{
    NewReaderJob, ReportOutcome, SpawnAdmission, SpendBook, WaitSetOutcome,
};
pub use self::reader_jobs::{ReaderJobs, SummaryMember, SummaryRead};
pub use self::records::{CodeRunModelHealCount, CodeRunSecretLiftProposal};
pub(crate) use self::records::{
    StagedSinks, code_run_body_file_of_row, code_run_body_held_in_txn, code_run_body_row_key,
    code_run_inline_body_of_row, lift_code_run_file_hold_in_txn,
    retire_unlanded_inline_body_keys_in_txn,
};
pub(crate) use self::replay_bodies::{
    CODE_RUN_OUTPUT_PREVIEW_ERASED, RESPONSE_ERASED, replay_carriage, replay_owners,
    response_erased_error,
};
pub(crate) use self::replay_capsule::retire_replay_bodies_in_rows;
pub use self::replay_capsule::step_replay_capsules;
pub(crate) use self::replay_capsule::undecodable_step_capsule_in_txn;
pub(crate) use self::replay_capsule::{
    ForkProvenance, ForkRows, actor_gone_in_txn, bind_capsule_answer, capsule_context_body,
    capsule_request, capsule_route_prompt, capsule_start_body,
    contribution_pair_erase_candidates_in_txn, erase_capsule_actor_in_txn,
    erase_contribution_forks_in_txn, finalize_capsule, fork_execution_outputs, fork_response,
    fork_rows, fork_rows_in_txn, put_fork, put_staged_capsule, put_unavailable,
    refresh_staged_request, route_prompt_at, step_replay_capsules_in_txn, store_fork_execution,
    store_fork_response,
};
pub(crate) use self::replay_capsule::{
    accept_owner_pair_in_txn, bind_owner_pair_ask_in_txn, close_owner_pair_in_txn,
    judge_owner_pair_in_txn, owner_pair_in_txn, put_owner_pair,
};
pub(crate) use self::replay_capsule::{
    drop_step_start_in_rows, kept_step_start_in_txn, kept_step_starts_in_txn,
    release_step_start_in_txn, republish_step_start_in_rows, republish_step_start_in_txn,
    settle_start_bodies_in_rows, step_capsule_row, step_start_body_row, step_start_owners_in_txn,
};
pub(crate) use self::response_erase::{
    actor_gone, retire_actor_responses_in_txn, retire_sourced_code_outputs_in_txn,
    soft_delete_actor_responses_in_txn,
};
pub(crate) use self::response_owners::stamp_response_owner_in_txn;
pub(crate) use self::routing::{
    ExecutorStorage, FeedbackRoute, SessionInstanceBind, require_facet_placement_in, unplaceable,
};
pub use self::secret_lift::{
    CodeRunRoomSecretLiftRequest, CodeRunSecretLiftDismiss, CodeRunSecretLiftDismissal,
    CodeRunSecretLiftProposalView, CodeRunSecretLiftRequest, CodeRunSecretLiftStatus,
};
pub(crate) use self::spawn_erase::erase_spawn_targets_in_txn;
#[cfg(test)]
pub(super) use self::speech_identity::canonical_speech_conversation_id;
pub(in crate::code_run) use self::speech_identity::derived_executor_id;
#[cfg(test)]
pub(crate) use self::speech_identity::executor_speech_message_id;
#[cfg(test)]
pub(super) use self::speech_identity::executor_speech_turn_id;
pub(crate) use self::speech_identity::{
    ResultSpeech, RunAssertionCollector, executor_compaction_session_id,
    executor_speech_message_id_in_run, executor_speech_turn_id_for_run,
};
pub(crate) use self::type_diagnostics::{
    StepKey, StoredStepFeedback, erase_type_diagnostics_actor_in_txn, runs_program_steps,
    session_type_diagnostics_row,
};
pub use self::wait_delivery::{
    WaitDeliveries, WaitDelivery, WaitKey, bind_wait_trap, park_and_bind_wait_trap,
};
pub(crate) use self::wait_delivery::{
    canonical_wait_ids, deliver_changed_wait_in_txn, has_parked_run_in_txn, observe_wait_change,
};
pub(crate) use self::wait_delivery::{
    deliver_wait_in_txn, deliver_wait_listing_in_txn, settled_wait_reply_in_txn,
};
// DOOR-141 PR3b: a turn program's resume checkpoint and its wait.
pub(crate) use self::program_resume::{
    ProgramCheckpointTail, ProgramResumeCall, ProgramResumeCommit, ProgramResumeHead,
    ProgramResumeWait, ProgramRowAnswer, load_program_checkpoint_tail, program_resume_call,
    program_resume_calls_in_txn, program_resume_head_in_txn,
};
pub(crate) use self::wait_delivery::wait_delivered_in_txn;
pub(crate) use self::wait_holders::{
    WaitReply, erase_settled_reply_of_erased_run_in_txn, wait_delivery_owners, wait_reply_in_txn,
};

// The lift sweep's typed acceptance for this module's authored side
// tables (FIX 2680), named by their declarations.
pub(crate) use self::continuation::code_run_continuation_accepts_masked;
pub(crate) use self::reader_folds::code_run_summary_memo_accepts_masked;
pub(crate) use self::reader_jobs::code_run_reader_job_accepts_masked;
pub(crate) use self::reader_jobs::code_run_reader_wait_accepts_masked;
pub(crate) use self::records::code_run_replay_record_accepts_masked;
pub(crate) use self::replay_capsule::code_run_replay_capsule_accepts_masked;
pub(crate) use self::type_diagnostics::code_run_type_diagnostics_accepts_masked;
