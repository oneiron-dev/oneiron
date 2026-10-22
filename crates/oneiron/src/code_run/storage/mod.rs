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
mod session_write;
mod speech_identity;
mod type_diagnostics;
mod wait_delivery;
mod wait_holders;

pub(crate) use self::compaction::{CodeRunCompactionCoverage, ExecutorOutputSpan};
pub(crate) use self::continuation::{
    StoredRunContinuation, put_run_continuation_row_in_txn, run_continuation_in_txn,
    seed_continuation_run,
};
pub(crate) use self::read_worlds::{
    ReadWorldSeal, ReadWorldSnapshot, ReadWorldUnknown, read_world_snapshot_in_txn,
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
    CodeRunResultBodyReader, StagedSinks, code_run_body_file_of_row, code_run_body_held_in_txn,
    code_run_body_row_key, code_run_inline_body_of_row, code_run_row_inline,
    lift_code_run_file_hold_in_txn,
};
pub(crate) use self::replay_bodies::{
    CODE_RUN_OUTPUT_PREVIEW_ERASED, RESPONSE_ERASED, replay_carriage, replay_owners,
    response_erased_error,
};
pub use self::replay_capsule::step_replay_capsules;
pub(crate) use self::replay_capsule::{
    ForkRows, capsule_request, capsule_start_body, erase_capsule_actor_in_txn, finalize_capsule,
    fork_response, fork_rows, fork_rows_in_txn, put_fork, put_staged_capsule, put_unavailable,
    step_replay_capsules_in_txn, store_fork_response,
};
pub(crate) use self::response_erase::{actor_gone, retire_actor_responses_in_txn};
pub(crate) use self::response_owners::stamp_response_owner_in_txn;
pub(crate) use self::routing::{ExecutorStorage, require_facet_placement_in, unplaceable};
#[cfg(test)]
pub(super) use self::speech_identity::canonical_speech_conversation_id;
pub(in crate::code_run) use self::speech_identity::derived_executor_id;
#[cfg(test)]
pub(crate) use self::speech_identity::executor_speech_message_id;
#[cfg(test)]
pub(super) use self::speech_identity::executor_speech_turn_id;
pub(crate) use self::speech_identity::{
    ResultSpeech, executor_compaction_session_id, executor_speech_message_id_in_run,
    executor_speech_turn_id_for_run,
};
pub(crate) use self::type_diagnostics::{
    StepKey, StoredStepFeedback, erase_type_diagnostics_actor_in_txn, runs_program_steps,
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
    WaitReply, erase_settled_reply_of_erased_run_in_txn, settled_reply_held_in_txn,
    settled_wait_key, wait_delivery_owners, wait_reply_in_txn, wait_reply_stub,
    wait_settled_owners,
};
