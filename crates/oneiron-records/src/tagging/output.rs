//! Moved from `crates/oneiron/src/tagging/output.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// Why an answer was refused. Each code names the rule it broke and carries
/// none of the answer or the turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputRefusal {
    /// A mood value outside valence −1..1, arousal and dominance 0..1.
    MoodOutOfRange,
    /// A span names a message the input does not have.
    UnknownMessage,
    /// A span is empty, runs past its message, or splits a character.
    BadOffsets,
    /// A label is empty or longer than 64 bytes.
    BadLabel,
    /// A confidence is not a finite value in 0..1.
    BadConfidence,
    /// A link names a missing span or points forward, or a span carries a
    /// second link of any kind.
    BadLink,
    /// A context link names a turn or a message the input did not send as
    /// context.
    UnknownContext,
    /// Spans are out of (message, start, end) order, or two share
    /// coordinates.
    SpanOrder,
    /// The answer names another stack than the one the marker is owed to.
    OtherStack,
}
