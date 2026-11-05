//! Core half of `store::commitment_due_record`: its store-layer items live in `oneiron_store::commitment_due_record` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::commitment_due_record::*;

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::temporal::TimeRange;
use crate::vault::Vault;
use heed::{RoTxn, RwTxn};

/// One concrete occurrence of a series: the instant it is owed, the valid-time
/// window it covers, and which slot of that window it is.
///
/// `ordinal` matters only for [`Schedule::Quota`], where every slot of a window
/// shares one due instant (the window's inclusive end) and is distinguished
/// solely by its position. Once/Interval occurrences are always ordinal 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitmentOccurrence {
    /// When this occurrence is owed.
    pub due_at: u64,
    /// The occurrence's valid-time window; must contain `due_at`.
    pub window: TimeRange,
    /// Slot index inside `window`.
    pub ordinal: u32,
}

/// One durable due row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitmentDueEntry {
    /// The instant this row becomes visible.
    pub at: u64,
    /// Which lifecycle moment it marks.
    pub phase: CommitmentDuePhase,
    /// The series the row belongs to.
    pub series_ref: EntityId,
    /// The materialized instance, absent exactly on a `Project` row.
    pub instance_ref: Option<EntityId>,
    /// The occurrence this row describes. On a `Project` row it is the
    /// occurrence about to be minted.
    pub occurrence: CommitmentOccurrence,
}

impl CommitmentDueEntry {
    /// A `Project` row names no instance; every other phase must name one.
    pub(crate) fn validate(&self) -> Result<()> {
        if self.instance_ref.is_some() == (self.phase == CommitmentDuePhase::Project) {
            return Err(Error::InvariantViolation(
                "commitment due row phase and instance ref disagree",
            ));
        }
        if self.occurrence.window.end < self.occurrence.window.start {
            return Err(Error::InvariantViolation(
                "commitment due row window is inverted",
            ));
        }
        Ok(())
    }
}

impl Vault {
    /// The current due-index summary.
    ///
    /// # Errors
    ///
    /// [`Error::CorruptedIndex`] when a row does not parse. A commitment engine
    /// that answered "nothing is due" on a corrupt index would silently drop
    /// obligations, so the read fails loudly instead.
    pub fn commitment_due_index_snapshot(&self) -> Result<CommitmentDueIndexSnapshot> {
        let rtxn = self.store.env.read_txn()?;
        self.store.commitment_due_snapshot_in_txn(&rtxn)
    }

    /// Every due row of every phase whose instant has arrived, ascending.
    pub fn commitment_entries_through(&self, now: u64) -> Result<Vec<CommitmentDueEntry>> {
        let rtxn = self.store.env.read_txn()?;
        self.store.commitment_due_entries_through_in_txn(
            &rtxn,
            now,
            &[
                CommitmentDuePhase::Project,
                CommitmentDuePhase::Lead,
                CommitmentDuePhase::Due,
                CommitmentDuePhase::LifecycleDue,
            ],
        )
    }

    /// The earliest actionable wake row — `Lead` or `Due` only.
    ///
    /// `Project` is engine-internal and `LifecycleDue` is a lapse marker;
    /// neither is something a surface should be woken for.
    pub fn next_actionable_wake_phase(&self) -> Result<Option<CommitmentDueEntry>> {
        let rtxn = self.store.env.read_txn()?;
        self.next_actionable_wake_phase_in_txn(&rtxn)
    }

    /// Transaction-composable [`Vault::next_actionable_wake_phase`].
    pub(crate) fn next_actionable_wake_phase_in_txn(
        &self,
        rtxn: &RoTxn<'_>,
    ) -> Result<Option<CommitmentDueEntry>> {
        self.store.commitment_due_first_in_phases_in_txn(
            rtxn,
            &CommitmentDuePhase::ACKNOWLEDGEABLE_PHASES,
        )
    }

    /// Instances whose `LifecycleDue` row is strictly before `now`.
    ///
    /// Status-unfiltered: this is the lapse-classification and crash-repair
    /// feed, and the rows that most need attention are exactly the ones whose
    /// status write already landed.
    pub fn overdue_commitment_instances(&self, now: u64) -> Result<Vec<EntityId>> {
        let rtxn = self.store.env.read_txn()?;
        self.store
            .commitment_due_overdue_instances_in_txn(&rtxn, now)
    }

    /// Consumes an actionable due row after a surface has shown it.
    ///
    /// # Errors
    ///
    /// [`Error::InvariantViolation`] for `Project` or `LifecycleDue`: those are
    /// owner-managed. A `Project` row is consumed only by the projector minting
    /// its occurrence, and a `LifecycleDue` row only by the close hook — letting
    /// a surface "acknowledge" either would erase an obligation by looking at it.
    pub fn acknowledge_commitment_due(&self, entry: &CommitmentDueEntry) -> Result<bool> {
        self.with_write_txn_grouped(|wtxn| self.acknowledge_commitment_due_in_txn(wtxn, entry))
    }

    /// Transaction-composable [`Vault::acknowledge_commitment_due`], with the
    /// same phase refusal.
    pub(crate) fn acknowledge_commitment_due_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        entry: &CommitmentDueEntry,
    ) -> Result<bool> {
        if !entry.phase.is_acknowledgeable() {
            return Err(Error::InvariantViolation(OWNER_MANAGED_PHASE));
        }
        entry.validate()?;
        self.store.commitment_due_delete_in_txn(wtxn, entry)
    }

    /// TEST-SUPPORT ONLY: see
    /// [`crate::store::Store::corrupt_commitment_due_row_for_test_in_txn`].
    /// Hidden from the docs and named so it cannot be reached by accident; it
    /// exists so the DRIVER's deadline source can be proven to answer `Err`
    /// rather than `Ok(None)` on a corrupt index.
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn corrupt_commitment_due_row_for_test(&self, at: u64) -> Result<()> {
        self.with_write_txn_grouped(|wtxn| {
            self.store
                .corrupt_commitment_due_row_for_test_in_txn(wtxn, at)
        })
    }
}
