//! Moved from `crates/oneiron/src/failure_signals/held.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_verb_wire::failure_signals::held::read::HeldFailureSignalBatchView;
use serde::Deserialize;
use serde::Serialize;

/// Where a kept batch stood after its last send. A record: what a pass does
/// with a carried batch is read from durable facts, and this counts only
/// where the Gate's decisions on it are gone, to say the Gate held it once.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HeldStage {
    /// Written before its send.
    Staged,
    /// The Gate held it for the owner.
    Held,
    /// Admitted on the owner's press and failed definitely: it retries
    /// under its own ref on that recorded press (CALLS `FIX 6679 held batch
    /// retry proof`).
    Admitted,
}
