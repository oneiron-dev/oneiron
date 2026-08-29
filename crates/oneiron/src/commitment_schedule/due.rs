//! Due-index consumer types and the vault's read/consume/acknowledge surface.
//!
//! The bytes live in [`crate::store`]; the MEANING lives here, next to the
//! evaluator that produces it. Four phases, each with a different owner:
//!
//! * [`CommitmentDuePhase::Project`] — "materialize the next occurrence". Owned
//!   by the engine's projector, acknowledged by nobody else.
//! * [`CommitmentDuePhase::Lead`] and [`CommitmentDuePhase::Due`] — the two
//!   phases a surface may act on and acknowledge.
//! * [`CommitmentDuePhase::LifecycleDue`] — the lapse-detection marker. It
//!   NEVER enters the timer feed: an unmet obligation is not a reason to wake
//!   the machine, it is a fact to notice on the next pass.

use heed::{RoTxn, RwTxn};

use super::CommitmentOccurrence;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::vault::Vault;

/// Refusal message for an attempt to acknowledge an owner-managed phase.
pub(crate) const OWNER_MANAGED_PHASE: &str = "commitment due phase is owner-managed";

/// Which lifecycle moment a due row marks.
///
/// The discriminants are the on-disk phase byte and are ABI: reordering them
/// would silently re-interpret every stored row.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum CommitmentDuePhase {
    /// Materialize the next occurrence of a series.
    Project = 0,
    /// The occurrence becomes visible (`due_at - lead`).
    Lead = 1,
    /// The occurrence is owed now.
    Due = 2,
    /// The occurrence's window has closed and it may have lapsed.
    LifecycleDue = 3,
}

impl CommitmentDuePhase {
    /// Number of phases; the width of a snapshot's minima array.
    pub const COUNT: usize = 4;

    /// The phases an INSTANCE carries. A series carries only `Project`.
    pub const INSTANCE_PHASES: [Self; 3] = [Self::Lead, Self::Due, Self::LifecycleDue];

    /// The phases a surface may acknowledge.
    pub const ACKNOWLEDGEABLE_PHASES: [Self; 2] = [Self::Lead, Self::Due];

    /// The stored phase byte.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Index into a snapshot's `phase_minima` array.
    #[must_use]
    pub const fn as_index(self) -> usize {
        self as usize
    }

    /// Parses a stored phase byte. An unknown byte is never a phase.
    #[must_use]
    pub const fn from_u8(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Project),
            1 => Some(Self::Lead),
            2 => Some(Self::Due),
            3 => Some(Self::LifecycleDue),
            _ => None,
        }
    }

    /// Whether a surface may acknowledge this phase.
    #[must_use]
    pub const fn is_acknowledgeable(self) -> bool {
        matches!(self, Self::Lead | Self::Due)
    }
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

/// A point-in-time view of the due index: the global minimum plus the minimum
/// per phase.
///
/// Two numbers instead of one because the driver and the surfaces want
/// different things. The timer must arm only on phases it is allowed to wake
/// for, while `next_due_at` answers "is there ANY timed obligation" — including
/// a `LifecycleDue` row the timer must not chase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitmentDueIndexSnapshot {
    next_due_at: Option<u64>,
    phase_minima: [Option<u64>; CommitmentDuePhase::COUNT],
}

impl CommitmentDueIndexSnapshot {
    pub(crate) const fn new(
        next_due_at: Option<u64>,
        phase_minima: [Option<u64>; CommitmentDuePhase::COUNT],
    ) -> Self {
        Self {
            next_due_at,
            phase_minima,
        }
    }

    /// The earliest row of ANY phase.
    #[must_use]
    pub const fn next_due_at(&self) -> Option<u64> {
        self.next_due_at
    }

    /// The earliest row in one phase.
    #[must_use]
    pub const fn phase_minimum(&self, phase: CommitmentDuePhase) -> Option<u64> {
        self.phase_minima[phase.as_index()]
    }

    /// The per-phase minima, indexed by [`CommitmentDuePhase::as_index`].
    #[must_use]
    pub const fn phase_minima(&self) -> &[Option<u64>; CommitmentDuePhase::COUNT] {
        &self.phase_minima
    }

    /// The earliest row among exactly the named phases.
    ///
    /// This is the timer's door: naming the phases at the call site is what
    /// keeps `LifecycleDue` out of the wake feed structurally, rather than by a
    /// filter someone can forget.
    #[must_use]
    pub fn next_timer_at(&self, phases: &[CommitmentDuePhase]) -> Option<u64> {
        phases
            .iter()
            .filter_map(|phase| self.phase_minimum(*phase))
            .min()
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
        self.with_write_txn(|wtxn| self.acknowledge_commitment_due_in_txn(wtxn, entry))
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
        self.with_write_txn(|wtxn| {
            self.store
                .corrupt_commitment_due_row_for_test_in_txn(wtxn, at)
        })
    }
}
