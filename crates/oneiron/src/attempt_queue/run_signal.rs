//! Durable branch signal and ask vocabulary with persisted-row validation.

use crate::attempt_queue::AttemptId;
pub(crate) use crate::store::attempt_record_codec::signal_validators::{
    field, validate_questions, validate_signal_rows,
};
pub(crate) use crate::store::attempt_run_signal::SignalIntent;
pub use crate::store::attempt_run_signal::{
    RunAsk, RunAskAnswer, RunAskAnswerKind, RunAskQuestion, RunBranchSignal, RunSignalKind,
    RunSignalState,
};

/// Caller-authenticated control intent; the adapter must resolve the actor and
/// cancel standing before calling this storage door.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunSignalInput {
    pub branch: AttemptId,
    pub run_id: String,
    pub key: String,
    pub actor: String,
    pub kind: RunSignalKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunAskState {
    Pending(RunAsk),
    Ready(RunAsk),
}
