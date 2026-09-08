//! Atomic multi-database write-batch builder doors.

mod claims;
mod commit;
mod edges;
mod ops;
mod preflight;
mod puts;

use crate::Vault;
use crate::error::Error;

use super::vad_postcommit;

pub(crate) use self::ops::BatchOp;
// Sync-only: the sole cross-module caller is `txn_builder::put_replicated`
// (`#[cfg(feature = "sync")]`); without sync nothing routes through the
// seam name and the re-export would be an unused import.
#[cfg(feature = "sync")]
pub(super) use self::ops::replicated_put_op;

/// Builder for atomic multi-database write batches.
#[must_use = "BatchBuilder performs no writes until `.commit()` is called"]
pub struct BatchBuilder<'a> {
    vault: &'a Vault,
    ops: Vec<BatchOp>,
    validation_error: Option<Error>,
}
