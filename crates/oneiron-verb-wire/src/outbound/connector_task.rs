//! Moved from `crates/oneiron/src/outbound/connector_task.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// What the owner's answer to an uncertain send's ask came to (FIX 4747).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum UncertainSendAnswerOutcome {
    /// The TASK's executor sends it once more, under the same engine send id.
    ResendReleased,
    /// The TASK settles with the owner's word, unsent again.
    Declined,
    /// An earlier answer settled the ask, or the send settled without one:
    /// this answer changed nothing.
    AlreadySettled,
}
