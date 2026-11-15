//! Moved from `crates/oneiron/src/store/resident_budget_rows.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// The owner's setting for one resident's share of the allocation.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
pub struct ResidentShare {
    /// The share, in the allocation's unit. `None` is the default share:
    /// what the residents with no share of their own split equally, once the
    /// shares the owner set are taken from the allocation.
    pub units: Option<u64>,
    /// The owner pinned it: past it, new paid work for the resident is
    /// refused. An unpinned share is soft, and spend past it writes an
    /// overdraft receipt.
    pub pinned: bool,
}
