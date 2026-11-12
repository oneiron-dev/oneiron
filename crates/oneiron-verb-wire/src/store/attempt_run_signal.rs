//! Moved from `crates/oneiron/src/store/attempt_run_signal.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::store::attempt_cancel::CancelStanding;
pub use oneiron_store::attempt_run_signal::*;
use serde::Deserialize;
use serde::Serialize;

/// No answer variant grants effect confirmation: that remains at the
/// authenticated effect/consent door, not at this message transport.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub enum RunSignalKind {
    Steer {
        instruction: String,
    },
    Interject {
        content: String,
    },
    Cancel {
        standing: CancelStanding,
        reason: Option<String>,
    },
    AskAnswer {
        handle: String,
        who: String,
        answer: String,
        kind: RunAskAnswerKind,
    },
}

/// A per-branch idempotency receipt, kept after consumption for retry replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RunBranchSignal {
    pub key: String,
    pub actor: String,
    pub kind: RunSignalKind,
    pub state: RunSignalState,
}
