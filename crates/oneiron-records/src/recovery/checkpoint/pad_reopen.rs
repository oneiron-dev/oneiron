//! Moved from `crates/oneiron/src/recovery/checkpoint/pad_reopen.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::ErrorKind;
use serde::Serialize;

/// One stage of a world's reopen that did not complete.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PadReopenFault {
    /// The world, by hex id; `None` for the epoch's reconciliation.
    pub world: Option<String>,
    pub stage: PadReopenStage,
    /// The error's kind; `None` when the stage committed but what it wrote
    /// did not read back.
    pub error_kind: Option<ErrorKind>,
}

/// The stages a world's reopen goes through, in order, then the epoch's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PadReopenStage {
    Install,
    ReadBack,
    Rest,
    Verify,
    Reconcile,
}
