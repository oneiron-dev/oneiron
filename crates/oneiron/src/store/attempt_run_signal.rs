//! Core half of `store::attempt_run_signal`: its store-layer items live in `oneiron_store::attempt_run_signal` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::attempt_run_signal::*;

use crate::store::attempt_cancel::CancelStanding;
use serde::{Deserialize, Serialize};

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
