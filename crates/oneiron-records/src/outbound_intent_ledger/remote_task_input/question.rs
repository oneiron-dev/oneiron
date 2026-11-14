//! Moved from `crates/oneiron/src/outbound_intent_ledger/remote_task_input/question.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use serde_json::json;
use std::collections::BTreeMap;
use std::fmt;
use zeroize::Zeroizing;

/// Where a parked question stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteTaskInputPhase {
    /// Waiting for the owner's values, or a Decline or Cancel.
    AwaitingOwner,
    /// The owner submitted the values; the poller sends them.
    Ready,
    /// The owner declined; the poller sends `decline`.
    Declined,
    /// The owner cancelled; the poller sends `cancel`.
    Cancelled,
    /// The poller claimed the answer and may have sent it.
    Sending,
    /// The connector accepted the answer.
    Sent,
    /// Whether the connector took the answer is unknown; it is never sent
    /// again.
    Uncertain,
    /// The poller came to send the owner's accept and found the send's
    /// authority no longer admits it: the grant that admitted the send is
    /// gone, no longer live or names another principal, the connector key
    /// is no longer active, or its setting for the tool or for elicitation
    /// is now never allow. Nothing went to the connector and nothing is
    /// withdrawn: the row stays, so the owner reads this phase on the
    /// question, the Ask keeps the owner's Answer, and the task waits on its
    /// question until its provider drops it or asks another. Never sent.
    Refused,
}

impl RemoteTaskInputPhase {
    /// The owner answered and the answer is not claimed yet.
    pub const fn owner_answered(self) -> bool {
        matches!(self, Self::Ready | Self::Declined | Self::Cancelled)
    }
}

/// A parked question, as its row keeps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParkedInput {
    /// The form round, from 0.
    pub generation: u32,
    pub phase: RemoteTaskInputPhase,
    /// [`RemoteTaskFormQuestion::digest`] of the question parked.
    pub question_digest: [u8; 32],
    /// The owner Ask's arrival number on the decision-ask queue.
    pub ask: u64,
}
