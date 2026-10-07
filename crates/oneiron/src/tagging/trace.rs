//! One trace per settled marker attempt. A trace names the turn, the tagger and
//! what happened; it never carries the turn's text or the tagger's answer.

use serde::Serialize;

use super::output::OutputRefusal;
use crate::EntityId;
use crate::attempt_queue::AttemptId;

/// An attempt id as the 32 lowercase hex digits a trace carries.
pub(super) fn attempt_hex(id: &AttemptId) -> String {
    id.as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// What one attempt on one marker did.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TaggingTrace {
    /// The marker attempt, as 32 lowercase hex digits.
    pub attempt: String,
    /// The marked turn; `None` only for a payload this build cannot read.
    pub turn: Option<EntityId>,
    /// The checkpoint the marker was committed for.
    pub checkpoint: String,
    /// The serving model's id, when the tagger was called.
    pub model: Option<String>,
    /// The input digest, when the turn had text to read.
    pub input_hash: Option<String>,
    /// 1 for a marker's first attempt, n for its (n-1)th retry.
    pub try_number: u32,
    /// Wall time of the tagger call in microseconds, when one was made.
    pub call_micros: Option<u64>,
    pub outcome: TaggingOutcome,
}

/// How an attempt settled.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum TaggingOutcome {
    /// The answer passed every check and the marker completed. In shadow
    /// nothing else is written.
    Shadowed {
        spans: usize,
        links: usize,
        mood: bool,
        /// Spans whose label the label table maps to an entity kind.
        mapped_spans: usize,
    },
    /// An importer completed the marker with tags it already held.
    Imported {
        spans: usize,
        links: usize,
        mood: bool,
    },
    /// Nothing was owed; the marker completed with no tagger call.
    Skipped { reason: SkipReason },
    /// The turn changed while the tagger read it; the marker is retried at
    /// once on the new text.
    Superseded { retry_at: u64 },
    /// The call failed or its answer was refused; retried at `retry_at`
    /// (store-clock seconds).
    Failed {
        failure: TaggingFailure,
        retry_at: u64,
    },
    /// A marker committed for another checkpoint, moved onto the active one.
    Rekeyed,
    /// A payload this build cannot read; the marker is failed for good.
    Unreadable,
}

/// Why a marker owed nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SkipReason {
    /// The turn is absent, deleted or archived.
    TurnGone,
    /// The turn holds no visible text.
    NoText,
}

/// Why an attempt failed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "class", rename_all = "snake_case")]
pub enum TaggingFailure {
    /// The tagger call returned an error. `code` is the host's failure class
    /// (the tagger client puts no vault text in it) or the engine error kind.
    Call { code: String },
    /// The answer broke a contract rule.
    Refused { refusal: OutputRefusal },
    /// The tagger panicked.
    Panicked,
}
