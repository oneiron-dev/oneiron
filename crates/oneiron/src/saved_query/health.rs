//! Each swept saved query's health (FIX 11250): one row per query the
//! host's evaluator wakes, written at every wake, reactive or paged, which
//! its owner reads beside the query (a memory watch's on its watch). It is
//! a record only: no wake is refused, held or cut for what it says.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};

use super::evidence::WakeEvaluationReport;

pub(super) const HEALTH: SideTable<EntityId, SavedQueryHealth, Named> =
    SideTable::new(&side_table::SAVED_QUERY_HEALTH);

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

/// Records `wake` of `query_ref`, ended at `now`, and returns the health it
/// leaves: the failure count carries on from the row before it.
pub fn record_saved_query_wake(
    vault: &Vault,
    query_ref: EntityId,
    wake: SavedQueryWake,
    now: u64,
) -> Result<SavedQueryHealth> {
    vault.with_write_txn(|txn| {
        let failures = match &wake.outcome {
            SavedQueryWakeOutcome::Evaluated { .. } => 0,
            SavedQueryWakeOutcome::Failed { .. } => HEALTH
                .get(&vault.store, txn, &query_ref)?
                .map_or(0, |held| held.consecutive_failures)
                .saturating_add(1),
        };
        let health = SavedQueryHealth {
            last_evaluated_at: now,
            pass: wake.pass,
            outcome: wake.outcome,
            consecutive_failures: failures,
            triggered_at: wake.triggered_at,
            lag_secs: wake.triggered_at.map(|at| now.saturating_sub(at)),
        };
        HEALTH.put(&vault.store, txn, &query_ref, &health)?;
        Ok(health)
    })
}

/// `query_ref`'s health, when a wake has recorded one.
pub fn saved_query_health(vault: &Vault, query_ref: EntityId) -> Result<Option<SavedQueryHealth>> {
    let txn = vault.store.env.read_txn()?;
    health_in_txn(vault, &txn, query_ref)
}

/// [`saved_query_health`], in the caller's transaction.
pub(super) fn health_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    query_ref: EntityId,
) -> Result<Option<SavedQueryHealth>> {
    HEALTH.get(&vault.store, txn, &query_ref)
}
