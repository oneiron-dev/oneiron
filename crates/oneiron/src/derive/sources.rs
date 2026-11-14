//! The commit's recheck of every source its items cite (untangle 6.7a, from
//! 6.4a's primitive A): each version the caller's read served must still
//! read for the caller, at the same revision, in the commit's own write. A
//! source that moved or is withheld since aborts the whole batch, as a
//! malformed batch does. So does a source that is a foreign copy: a pact's
//! WORLD copy or a copied inquiry answer is never a source for a write
//! (federation.md #model, Guest federation row; L7-02).

use super::batch::{DerivationBatch, DerivationStamp};
use crate::Vault;
use crate::error::{Error, GateError, Result};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::snapshot_read::SourceVersionCheck;

/// The refusal of a batch citing a source whose revision moved since the
/// caller read it.
pub const SOURCE_MOVED: &str = "gate.deny.derive.source_moved";

/// The refusal of a batch citing a source the caller no longer reads.
pub const SOURCE_WITHHELD: &str = "gate.deny.derive.source_withheld";

/// The refusal of a batch citing a foreign copy: a claim in a received
/// foreign WORLD, which a pact's WORLD copy or a copied inquiry answer lands
/// in.
pub const SOURCE_FOREIGN_COPY: &str = "gate.deny.derive.source_foreign_copy";

/// Rechecks every source version of `batch` in `txn` under the committing
/// actor's own read.
///
/// # Errors
///
/// The gate's refusal ([`SOURCE_MOVED`], [`SOURCE_WITHHELD`],
/// [`SOURCE_FOREIGN_COPY`]) for the first source that no longer stands or is
/// a foreign copy, which aborts the commit, and storage errors.
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
            SourceVersionCheck::Current
                if version.entity_type == ENTITY_TYPE_CLAIM
                    && vault.claim_is_foreign_copy_in_txn(txn, &version.entity)? =>
            {
                SOURCE_FOREIGN_COPY
            }
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
