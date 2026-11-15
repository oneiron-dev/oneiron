//! Moved from `crates/oneiron/src/recovery/checkpoint/pad_reopen.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::recovery::checkpoint::pad_custody::PadRestoreNote;
use oneiron_base::error::ErrorKind;
use serde::Serialize;

/// What a reopen of a restore epoch's Locked worlds did. Public ids and
/// counts alone: never a pad, a key or a secret.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PadReopenReport {
    /// The restore epoch it reopened, by sequence.
    pub epoch: u64,
    /// The checkpoint that epoch landed, which the backup is.
    pub checkpoint_id: String,
    /// Each world whose owed pads the head gave, installed into current
    /// custody, read back and rested, by hex id.
    pub opened_worlds: Vec<String>,
    /// Pads published into current custody, or found there with the same
    /// bytes, in committed installs.
    pub installed: usize,
    /// Bare references rested again in committed writes.
    pub rested: usize,
    /// References the epoch still owes.
    pub owed_refs: usize,
    /// What the epoch still says of its pads: a world the head did not open
    /// stays Locked, Pending and Withheld stay, and an erase that stands is
    /// ErasedUnavailable.
    pub remaining: Vec<PadRestoreNote>,
    /// Each stage that faulted, by world; what committed before it stands.
    pub faults: Vec<PadReopenFault>,
    /// What the head it used says: rollback is not proven when no custody
    /// anchor is configured.
    pub custody_note: Option<String>,
}

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
