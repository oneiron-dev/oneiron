//! The keys a translated copy edit's landed bytes hold, marked in the writer
//! that lands them (FIX 10732).
//!
//! A copy edit translated onto its source lands new source bytes whose BLAKE3
//! is no longer the marked blob's, so the masked copy made from the old
//! marks no longer applies. The landed bytes are therefore planned and marked
//! as the receive door marks a pushed blob, in the same two steps: the file
//! mask's detectors, field rules and the values custody knows place each key
//! (the old blob's keys left in place are known values), and each key goes to
//! custody, the bytes' spans to their mask row under the new BLAKE3. A key
//! the peer wrote that custody does not know yet is minted, and the owner
//! hears of it as of any key found. Nothing here releases a byte or widens a
//! copy; it only adds spans to what a reader masks.
//!
//! The `repo.secret_mark` facts that name the new bytes as a marked repo blob
//! are written by the receive door's own fact writer, which this writer does
//! not reach (origin/secret_marks.rs); until they are, later copies of the
//! source stay the sealed-file placeholder, as before.

use heed::RwTxn;

use crate::Vault;
use crate::batch::secret_scan::{
    RetainedRepoCustody, mark_retained_repo_blob_in_txn, plan_retained_repo_blob,
};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::secret_custody::{CustodyWrite, KnownValues};

/// The reason landed bytes no rule places a key in are planned under: the
/// plan's whole-blob residue, which this writer marks nothing for.
const LANDING_REASON: &str = "sync.copy_edit_landing";

/// Plans and marks the keys in `landed`, the bytes a translated copy edit
/// lands on the marked source `source`, in `wtxn`, the writer that lands
/// them.
///
/// # Errors
/// A custody, mark or store failure: the landing aborts with it.
pub(super) fn remark_landed_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    source: EntityId,
    landed: &[u8],
) -> Result<()> {
    let known = KnownValues::load_in_writer(&vault.store, wtxn)?;
    let plan = plan_retained_repo_blob("", landed, known.as_ref(), LANDING_REASON, source)?;
    let at = crate::ports::recorded_at_in_txn(&vault.store, wtxn)?;
    let mut custody = RetainedRepoCustody::load_in_writer(&vault.store, wtxn)?;
    mark_retained_repo_blob_in_txn(
        &CustodyWrite::of(vault),
        wtxn,
        &mut custody,
        plan,
        source,
        at,
    )?;
    Ok(())
}
