//! One trace per settled marker attempt. A trace names the turn, the tagger and
//! what happened; it never carries the turn's text or the tagger's answer.

use std::panic::AssertUnwindSafe;
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::EntityId;
use crate::attempt_queue::AttemptId;
use crate::error::Result;
use crate::memory::extraction::{EncoderAttempt, EncoderExecution, EncoderOutput};

/// An attempt id as the 32 lowercase hex digits a trace carries.
pub(super) fn attempt_hex(id: &AttemptId) -> String {
    id.as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// What one attempt on one marker did.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TaggingTrace {
    /// The marker attempt, as 32 lowercase hex digits.
    pub attempt: String,
    /// The marked turn; `None` only for a payload this build cannot read.
    pub turn: Option<EntityId>,
    /// The checkpoint the marker was committed for.
    pub checkpoint: String,
    /// The stack pinned beside it, when the marker was committed with one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stack: Option<String>,
    /// The serving model's id, when the tagger was called.
    pub model: Option<String>,
    /// The input digest, when the turn had text to read.
    pub input_hash: Option<String>,
    /// 1 for a marker's first attempt, n for its (n-1)th retry. The retry
    /// chain is walked to a bounded depth, so from the 1,025th try on this
    /// reads 1,025.
    pub try_number: u32,
    /// Wall time of the tagger call in microseconds, when one was made.
    pub call_micros: Option<u64>,
    /// What ran the call, when a worker was dispatched for it: its runtime,
    /// compute and pick, and how long it waited and ran.
    pub execution: Option<EncoderExecution>,
    pub outcome: TaggingOutcome,
}

impl TaggingTrace {
    /// Makes one tagger call, recording its wall time and the facts of the
    /// worker that ran it on this trace. A panic is caught and returned as
    /// `Err`, with no facts recorded; a worker panic comes back as `Err`
    /// with its facts kept.
    pub(super) fn record_call(
        &mut self,
        call: impl FnOnce() -> EncoderAttempt,
    ) -> std::thread::Result<Result<EncoderOutput>> {
        let started = Instant::now();
        let called = std::panic::catch_unwind(AssertUnwindSafe(call));
        self.call_micros = Some(u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX));
        match called {
            Err(panic) => Err(panic),
            Ok(attempt) => {
                self.execution = attempt.execution;
                if attempt.panicked {
                    Err(Box::new("the worker panicked") as Box<dyn std::any::Any + Send>)
                } else {
                    Ok(attempt.result)
                }
            }
        }
    }
}

#[doc(hidden)]
pub use oneiron_records::tagging::trace::{
    HandBackReason, SkipReason, TaggingFailure, TaggingOutcome,
};
