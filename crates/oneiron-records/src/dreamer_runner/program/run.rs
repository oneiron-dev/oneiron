//! Moved from `crates/oneiron/src/dreamer_runner/program/run.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// The issuing binding, committed before the effect runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StepIssue {
    /// A model step: its logical occurrence in the run and its request.
    Model {
        occurrence: u64,
        request_hash: [u8; 32],
    },
    /// A verb write: its place in its step and the call it makes.
    Write {
        step_start: u64,
        ordinal: u64,
        receipt: EntityId,
        call_digest: [u8; 32],
    },
    /// An outbound send: its frozen intent.
    Outbound { intent: [u8; 32], call_seq: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StepState {
    /// Bound and not ended.
    Issued,
    /// Ended, with its exact result's digest and, for a send, the body the
    /// transport returned as the side-row wall admitted it. The digest is
    /// over the bytes returned; the body is absent when the wall refused it
    /// or the program's actor is erased.
    Settled {
        result_digest: [u8; 32],
        result: Option<Vec<u8>>,
    },
    /// Its end is unknown: never taken for settled, never sent again.
    Uncertain { why: String },
}
