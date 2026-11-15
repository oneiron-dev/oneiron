//! Moved from `crates/oneiron/src/autoreason_campaign/research/continuation.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_store::attempt_id::AttemptId;
use oneiron_verb_wire::autoreason_campaign::research::ForkKind;
use serde::Deserialize;
use serde::Serialize;

/// The one hold a pass retries: the reservation found no room.
pub const BUDGET_HELD: &str = "budget";

/// Which campaign work a continuation carries out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ResearchWork {
    /// Measure the unmeasured incumbent root on the search split.
    Bootstrap,
    /// Carry out selection round `n`'s fork.
    Round(u64),
}

impl ResearchWork {
    fn key(self) -> u64 {
        match self {
            Self::Bootstrap => 0,
            Self::Round(round) => round.saturating_add(1),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ResearchSplit {
    Search,
    HeldOut,
}

/// One unit of work a continuation runs, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResearchTask {
    /// Score `node`'s candidate on a split with the scorer, outside the
    /// experiment's write scope.
    Measure {
        node: AttemptId,
        split: ResearchSplit,
    },
    /// Run the experimenter under `parent` for one child candidate.
    Experiment { parent: AttemptId, kind: ForkKind },
    /// Decide promotion of `candidate` against the incumbent once.
    Basis { candidate: AttemptId },
    /// Spend the sealed confirmation shot and run the referee on it.
    Confirm { candidate: AttemptId },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ResearchContinuationState {
    Open,
    Held { reason: String },
    Done { note: String },
    Failed { reason: String },
}

impl ResearchContinuationState {
    /// Open, or held for budget: the states a pass takes up.
    fn live(&self) -> bool {
        match self {
            Self::Open => true,
            Self::Held { reason } => reason == BUDGET_HELD,
            Self::Done { .. } | Self::Failed { .. } => false,
        }
    }
}
