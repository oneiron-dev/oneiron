//! Doors for `tests/executor_agent_runtime_tier.rs` (FIX LIBTEST-AGENT-RUNTIME-TIER):
//! the run-bound compaction coverage rows a summary mint commits; and for
//! `tests/archive_export_keeps_out_held_copies_carriers_floors.rs`
//! (REVIEW-9874 P1 3): a lineage's epoch floor, as a removed epoch summary
//! leaves it.
//! Compiled only under `--cfg oneiron_test_support`; never API.

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::vault::Vault;

/// One run-bound coverage row, projected to public shapes: the summary that
/// covers the run's steps `first` through `last`. The stored row's fields stay
/// crate-private, so the door carries the query's run with each row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoverageRow {
    run_id: EntityId,
    summary_id: EntityId,
    first: u64,
    last: u64,
}

impl CoverageRow {
    /// The SUMMARY entity this row's mint committed.
    #[must_use]
    pub const fn summary_id(&self) -> EntityId {
        self.summary_id
    }

    /// Whether this row covers `step` of `run_id`: the row's own run and its
    /// first-through-last span, as the stored row's `covers` reads it.
    #[must_use]
    pub fn covers(&self, run_id: EntityId, step: u64) -> bool {
        self.run_id == run_id && (self.first..=self.last).contains(&step)
    }
}

/// The run's coverage rows, verified as the mint left them.
///
/// # Errors
///
/// The store's.
pub fn coverage_rows(vault: &Vault, run_id: EntityId) -> Result<Vec<CoverageRow>> {
    Ok(vault
        .code_run_compaction_coverage(run_id)?
        .into_iter()
        .map(|row| CoverageRow {
            run_id,
            summary_id: row.summary_id(),
            first: row.first(),
            last: row.last(),
        })
        .collect())
}

/// Raises the epoch floor of the lineage of `session` (a conversation's
/// within it when `conversation` names one) to `(epoch, turn_end)`, as a hard
/// purge of that lineage's epoch summary leaves it (OF-013). The floor only
/// rises.
///
/// # Errors
///
/// The store's.
pub fn raise_epoch_floor(
    vault: &Vault,
    session: EntityId,
    conversation: Option<EntityId>,
    epoch: u64,
    turn_end: u64,
) -> Result<()> {
    let scope = crate::compaction::EpochScope {
        session,
        conversation,
    };
    vault.with_write_txn(|txn| {
        crate::compaction::raise_epoch_scope_floor_in_txn(
            &vault.store,
            txn,
            &scope,
            epoch,
            turn_end,
        )
    })
}
