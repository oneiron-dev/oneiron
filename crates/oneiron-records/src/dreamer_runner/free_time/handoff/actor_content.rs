//! Moved from `crates/oneiron/src/dreamer_runner/free_time/handoff/actor_content.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use heed::RoTxn;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;

/// Which of the five free-time sections a row stands in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FreeTimeSlot {
    Policy,
    Clock,
    Cycle,
    Item,
    Receipt,
}

/// One carried row as adoption finds it.
pub enum FreeTimeAdoptRow<Live, F> {
    /// Its subject's content opened here: the row as its old home kept it,
    /// less any attribution whose actor's content did not.
    Live(Live),
    /// Its subject's content did not open here, or its subject is erased
    /// here: non-executable history that lands nothing and conflicts with
    /// nothing.
    Scrubbed(F),
}
