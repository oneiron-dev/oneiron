//! Each swept saved query's health (FIX 11250): one row per query the
//! host's evaluator wakes, written at every wake, reactive or paged, which
//! its owner reads beside the query (a memory watch's on its watch). It is
//! a record only: no wake is refused, held or cut for what it says.

use serde::{Deserialize, Serialize};

use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

/// Progress report for a bounded wake batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WakeEvaluationReport {
    /// Entities evaluated in this batch.
    pub evaluated: u32,
    /// Evaluations answered by a memo.
    pub memo_hits: u32,
    /// Stage-2 judgements actually executed.
    pub judges_run: u32,
    /// Last entity visited when a bound stopped the batch early. `None` means
    /// the candidate set was exhausted.
    pub resume_after: Option<EntityId>,
}

/// Which of the host's passes woke a query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SavedQueryPass {
    /// The re-check of the people a run of the change log moved.
    Reactive,
    /// The paged pass over every candidate.
    Paged,
}

/// What one wake of a query came to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SavedQueryWakeOutcome {
    /// It ran to its end: the candidates it evaluated, the memo hits and
    /// judges among them, and whether one of the query's own bounds stopped
    /// it before its candidates ran out.
    Evaluated {
        evaluated: u32,
        memo_hits: u32,
        judges_run: u32,
        stopped_at_bound: bool,
    },
    /// It failed: the error's kind, as the host's record names it.
    Failed { kind: String },
}

impl SavedQueryWakeOutcome {
    /// The outcome of a wake that returned `report`.
    #[must_use]
    pub fn evaluated(report: &WakeEvaluationReport) -> Self {
        Self::Evaluated {
            evaluated: report.evaluated,
            memo_hits: report.memo_hits,
            judges_run: report.judges_run,
            stopped_at_bound: report.resume_after.is_some(),
        }
    }
}

/// One wake as the host ran it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SavedQueryWake {
    pub pass: SavedQueryPass,
    /// The vault-clock second of the oldest change the wake answers, when
    /// it answers one (a reactive re-check); `None` for a paged wake.
    pub triggered_at: Option<u64>,
    pub outcome: SavedQueryWakeOutcome,
}

/// A query's health as its last wake left it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedQueryHealth {
    /// When its last wake ended, on the vault clock.
    pub last_evaluated_at: u64,
    /// Which pass that was.
    pub pass: SavedQueryPass,
    /// What it came to.
    pub outcome: SavedQueryWakeOutcome,
    /// Failed wakes in a row, its last included; 0 once one runs to its end.
    pub consecutive_failures: u32,
    /// The oldest change its last wake answered, when it answered one.
    pub triggered_at: Option<u64>,
    /// How far its last wake ended behind that change, in seconds.
    pub lag_secs: Option<u64>,
}
