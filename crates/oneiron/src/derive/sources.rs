//! The commit's recheck of every source its items cite (untangle 6.7a, from
//! 6.4a's primitive A): each version the caller's read served must still
//! read for the caller, at the same revision, in the commit's own write. A
//! source that moved or is withheld since aborts the whole batch, as a
//! malformed batch does.

use super::batch::{DerivationBatch, DerivationStamp};
use crate::Vault;
use crate::error::{Error, GateError, Result};
use crate::snapshot_read::SourceVersionCheck;

/// The refusal of a batch citing a source whose revision moved since the
/// caller read it.
pub const SOURCE_MOVED: &str = "gate.deny.derive.source_moved";

/// The refusal of a batch citing a source the caller no longer reads.
pub const SOURCE_WITHHELD: &str = "gate.deny.derive.source_withheld";

/// Rechecks every source version of `batch` in `txn` under the committing
/// actor's own read.
///
/// # Errors
///
/// The gate's refusal ([`SOURCE_MOVED`], [`SOURCE_WITHHELD`]) for the first
/// source that no longer stands, which aborts the commit, and storage
/// errors.
pub(super) fn recheck_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    stamp: &DerivationStamp,
    batch: &DerivationBatch,
) -> Result<()> {
    if batch.sources.is_empty() {
        return Ok(());
    }
    let read = super::actor_read(vault, stamp.actor)?;
    for version in &batch.sources {
        let refusal = match version.recheck_in_txn(&read, txn)? {
            SourceVersionCheck::Current => continue,
            SourceVersionCheck::Moved => SOURCE_MOVED,
            SourceVersionCheck::Withheld => SOURCE_WITHHELD,
        };
        return Err(Error::Gate(GateError::GateWriteRejected {
            outcome: "deny",
            reason_codes: vec![refusal],
        }));
    }
    Ok(())
}
