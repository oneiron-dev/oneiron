//! Core half of `store::query_health`: its store-layer items live in `oneiron_store::query_health` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::query_health::*;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};
use serde::{Deserialize, Serialize};

pub(crate) const HEALTH: SideTable<EntityId, SavedQueryHealth, Named> =
    SideTable::new(&side_table::SAVED_QUERY_HEALTH);

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
pub(crate) fn health_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    query_ref: EntityId,
) -> Result<Option<SavedQueryHealth>> {
    HEALTH.get(&vault.store, txn, &query_ref)
}
