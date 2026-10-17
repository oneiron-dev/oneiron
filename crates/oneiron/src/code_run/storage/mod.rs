//! Canonical code-run persistence rows and the executor's storage routing.

mod compaction;
mod folds;
mod reader_folds;
mod reader_jobs;
mod records;
mod routing;
mod speech_identity;
mod wait_delivery;

pub(crate) use self::compaction::{CodeRunCompactionCoverage, ExecutorOutputSpan};
pub(crate) use self::reader_folds::{
    OccurrenceRef, ReaderFoldReceipt, ReaderSubstrateRef, ReceiptFinding, ReceiptPartial,
    ReceiptSource, ReceiptTree,
};
pub(crate) use self::reader_jobs::{
    NewReaderJob, ReportOutcome, SpawnAdmission, SpendBook, WaitSetOutcome,
};
pub use self::reader_jobs::{ReaderJobs, SummaryMember, SummaryRead};
pub use self::records::{CodeRunModelHealCount, CodeRunSecretLiftProposal};
pub(crate) use self::records::{FinishedOutput, code_run_body_file_of_row};
pub(crate) use self::routing::{ExecutorStorage, require_facet_placement_in, unplaceable};
#[cfg(test)]
pub(super) use self::speech_identity::canonical_speech_conversation_id;
pub(in crate::code_run) use self::speech_identity::derived_executor_id;
#[cfg(test)]
pub(crate) use self::speech_identity::executor_speech_message_id;
#[cfg(test)]
pub(super) use self::speech_identity::executor_speech_turn_id;
pub(crate) use self::speech_identity::{
    executor_compaction_session_id, executor_speech_message_id_in_run,
    executor_speech_turn_id_for_run,
};
pub(crate) use self::wait_delivery::deliver_wait_in_txn;
pub use self::wait_delivery::{
    WaitDeliveries, WaitDelivery, WaitKey, bind_wait_trap, park_and_bind_wait_trap,
};
pub(crate) use self::wait_delivery::{
    canonical_wait_ids, deliver_changed_wait_in_txn, has_parked_run_in_txn, observe_wait_change,
};
