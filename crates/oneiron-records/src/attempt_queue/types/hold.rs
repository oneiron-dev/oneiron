//! Moved from `crates/oneiron/src/attempt_queue/types/hold.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub(crate) use crate::store::attempt_record::AttemptPause;

impl AttemptPause {
    /// Whether an engine hold, not a person, paused the row.
    pub const fn is_engine_hold(self) -> bool {
        !matches!(self, Self::Person)
    }
}
