//! A home part's new revision withdraws what wore the old one (FIX 4817).
//!
//! A self-written epoch or fold depends on each home row its call wore
//! whole, as on any source, and its receipt keeps the revision each was read
//! at. Erasing such a row withdraws the summary through the dependent walk,
//! as before. An edit keeps the row and publishes another revision: the
//! publishing write calls [`withdraw_changed_home_dependents_in_txn`], which
//! finds the row's dependents through the same dependency index and, in that
//! write, withdraws each self-written one whose worn revision of the row no
//! longer stands. The withdrawal is the one the source chain walk applies:
//! an epoch keeps its keyframe and its lineage, a fold its span, and nothing
//! is queued for the Dreamer to write again, since an agent's own words are
//! never rewritten (its next flight compacts afresh). A summary that read
//! the row only as its window's evidence, and every other dependent, is left
//! as it is.

use super::integrity;
use crate::EntityId;
use crate::error::Result;
use heed::RwTxn;

/// Withdraws, in the write that just published a new revision of `source`,
/// every self-written summary and fold that wore `source` whole at another
/// revision. A row with no dependents costs one prefix probe.
pub(crate) fn withdraw_changed_home_dependents_in_txn(
    write: &crate::secret_custody::CustodyWrite<'_>,
    txn: &mut RwTxn<'_>,
    source: &EntityId,
) -> Result<()> {
    let store = write.store;
    if !integrity::source_has_dependents_in_txn(store, txn, source)? {
        return Ok(());
    }
    let mut changed = Vec::new();
    for dependent in integrity::dependents_in_txn(store, txn, source)? {
        let Some(execution) = crate::compaction::self_written_execution_in(store, txn, &dependent)?
        else {
            continue;
        };
        if execution.wore_changed_source_in(store, txn, source)? {
            changed.push(dependent);
        }
    }
    if changed.is_empty() {
        return Ok(());
    }
    let worlds = integrity::carried_now(store, txn, source)?;
    integrity::withdraw_source_chain_in_txn(write, txn, changed, &worlds)
}
