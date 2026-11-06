//! The pause a paused attempt row is held under (FIX 9579), kept on the row
//! itself rather than read back from its event history, which prunes.

pub(crate) use crate::store::attempt_record::AttemptPause;

impl AttemptPause {
    /// Whether an engine hold, not a person, paused the row.
    pub(crate) const fn is_engine_hold(self) -> bool {
        !matches!(self, Self::Person)
    }
}
