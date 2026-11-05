//! Due-index consumer types and the vault's read/consume/acknowledge surface.
//!
//! Stored occurrence and due-index values, with the vault's read/consume surface.
//! Four phases, each with a different owner:
//!
//! * [`CommitmentDuePhase::Project`] — "materialize the next occurrence". Owned
//!   by the engine's projector, acknowledged by nobody else.
//! * [`CommitmentDuePhase::Lead`] and [`CommitmentDuePhase::Due`] — the two
//!   phases a surface may act on and acknowledge.
//! * [`CommitmentDuePhase::LifecycleDue`] — the lapse-detection marker. It
//!   NEVER enters the timer feed: an unmet obligation is not a reason to wake
//!   the machine, it is a fact to notice on the next pass.

use heed::{RoTxn, RwTxn};

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::temporal::TimeRange;

/// Refusal message for an attempt to acknowledge an owner-managed phase.
pub const OWNER_MANAGED_PHASE: &str = "commitment due phase is owner-managed";

/// Which lifecycle moment a due row marks.
///
/// The discriminants are the on-disk phase byte and are ABI: reordering them
/// would silently re-interpret every stored row.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
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

/// A point-in-time view of the due index: the global minimum plus the minimum
/// per phase.
///
/// Two numbers instead of one because the driver and the surfaces want
/// different things. The timer must arm only on phases it is allowed to wake
/// for, while `next_due_at` answers "is there ANY timed obligation" — including
/// a `LifecycleDue` row the timer must not chase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitmentDueIndexSnapshot {
    pub next_due_at: Option<u64>,
    pub phase_minima: [Option<u64>; CommitmentDuePhase::COUNT],
}

impl CommitmentDueIndexSnapshot {
    pub const fn new(
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
