//! Moved from `crates/oneiron/src/session_lifecycle.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::session_lifecycle::speakers::SessionParticipant;
use serde::Deserialize;
use serde::Serialize;

/// Why a session ended. `Explicit` is the app's own end hint; `IdleFloor`
/// is the driver's inactivity backstop; `LifetimeCeiling` is the hard
/// wall-clock cap that closes a session regardless of activity hints
/// (H-S4: forged typing hints reset `last_activity` forever, so the floor
/// alone is defeatable — the ceiling is not).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionEndReason {
    Explicit,
    IdleFloor,
    LifetimeCeiling,
}

/// The three timestamps retained for one driver-authored session hint.
///
/// `claimed_ms` is producer provenance and is never rewritten, even when the
/// driver rejects it for derivation. `arrival_ms` is the channel stamp, and
/// `effective_ms` is the driver's monotone, bounded decisional time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionHintTimestamp {
    pub claimed_ms: Option<u64>,
    pub arrival_ms: u64,
    pub effective_ms: u64,
}

/// A loss-aware rollup of adjacent activity hints. The endpoints retain the
/// complete timestamp provenance; `count` records how many hints the period
/// represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionActivityPeriod {
    pub first: SessionHintTimestamp,
    pub last: SessionHintTimestamp,
    pub count: u64,
}
pub mod speakers;
