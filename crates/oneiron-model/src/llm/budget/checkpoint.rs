//! Settled state of one budget meter across a workflow hook wait.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use super::guard::BudgetGuard;
use super::ledger::{BudgetRowTally, LeaseState};
use super::policy::{BudgetPolicyRow, BudgetPolicyTable};
use super::state::BudgetState;
use super::types::{BudgetExhaustionPolicy, BudgetThreshold};
use crate::llm::BudgetDenied;
use oneiron_contracts::entity_id::EntityId;

/// The settled meter, not an admission or a lease. Its resolved policy is
/// the original meter's table, with each tally attached to that same row.
/// Guard identity and outstanding leases never cross a checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetCheckpoint {
    attempt_id: String,
    limit_units: u64,
    reserve_units: u64,
    on_budget_exhausted: BudgetExhaustionPolicy,
    actor: Option<EntityId>,
    used_units: u64,
    shared_used_units: u64,
    next_lease_seq: u64,
    fired_thresholds: BTreeSet<BudgetThreshold>,
    rows: Vec<CheckpointRow>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CheckpointRow {
    policy: BudgetPolicyRow,
    used_units: u64,
    floor_used_units: u64,
    fired_thresholds: BTreeSet<BudgetThreshold>,
}

impl BudgetGuard {
    /// Captures the exact settled meter after its calls have all closed.
    /// No admission, settlement, threshold emission or scope booking occurs.
    /// The caller must also finish booking the meter's spend on its scope
    /// before durably parking it, and fence use of the original guard.
    ///
    /// # Errors
    ///
    /// [`BudgetDenied::LeaseInvalid`] while any lease is still open, even
    /// an unmetered lease that holds no reservation.
    pub fn checkpoint(&self) -> Result<BudgetCheckpoint, BudgetDenied> {
        let state = self.lock_state();
        if state
            .leases
            .values()
            .any(|lease| lease.state == LeaseState::Open)
        {
            return Err(BudgetDenied::LeaseInvalid);
        }
        let rows = state
            .policy
            .rows()
            .iter()
            .zip(&state.row_tallies)
            .map(|(policy, tally)| CheckpointRow {
                policy: policy.clone(),
                used_units: tally.used_units,
                floor_used_units: tally.floor_used_units,
                fired_thresholds: tally.fired_thresholds.clone(),
            })
            .collect();
        Ok(BudgetCheckpoint {
            attempt_id: state.attempt_id.clone(),
            limit_units: state.limit_units,
            reserve_units: state.reserve_units,
            on_budget_exhausted: state.on_budget_exhausted,
            actor: state.actor,
            used_units: state.used_units,
            shared_used_units: state.shared_used_units,
            next_lease_seq: state.next_lease_seq,
            fired_thresholds: state.fired_thresholds.clone(),
            rows,
        })
    }

    /// Rebuilds that same meter with a fresh guard identity and no live
    /// leases. Settled spend, floor/shared allocations and fired ladders
    /// are copied exactly, never replayed as admissions or booked again.
    /// Its original resolved table stays paired with its original tallies;
    /// a later live scope look may revise the line as before.
    /// This is meter state only, never proof of caller authority or funding.
    /// Each row is addressed by its position, so a checkpoint of any length
    /// restores whole (FIX 8781).
    ///
    /// # Errors
    ///
    /// None today: every well-formed checkpoint restores. The `Result` keeps
    /// the restore callers' refusal path for a check a later checkpoint
    /// field needs.
    pub fn from_checkpoint(checkpoint: BudgetCheckpoint) -> Result<Self, BudgetDenied> {
        let policy = BudgetPolicyTable::from_rows(
            checkpoint
                .rows
                .iter()
                .map(|row| row.policy.clone())
                .collect(),
        );
        let mut state = BudgetState::new(
            checkpoint.attempt_id,
            checkpoint.limit_units,
            checkpoint.reserve_units,
            checkpoint.on_budget_exhausted,
            checkpoint.actor,
            policy,
        );
        state.used_units = checkpoint.used_units;
        state.shared_used_units = checkpoint.shared_used_units;
        state.next_lease_seq = checkpoint.next_lease_seq;
        state.fired_thresholds = checkpoint.fired_thresholds;
        state.row_tallies = checkpoint
            .rows
            .into_iter()
            .map(|row| BudgetRowTally {
                used_units: row.used_units,
                floor_used_units: row.floor_used_units,
                fired_thresholds: row.fired_thresholds,
                ..BudgetRowTally::default()
            })
            .collect();
        Ok(Self {
            state: Arc::new(Mutex::new(state)),
        })
    }
}
