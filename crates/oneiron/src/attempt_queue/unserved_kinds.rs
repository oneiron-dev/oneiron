//! The kinds the engine once queued and no executor serves (FIX 12327). An
//! open drops any of their rows still in the ledger, with every index entry
//! naming them, so no work waits forever for a runner that does not exist.

use crate::error::Result;
use crate::store::Store;

use super::AttemptQueue;

/// `derived.regenerate`: a withdrawn dependent's regeneration, queued until
/// FIX 12327. Each family re-derives a withdrawn dependent under a new id of
/// its own, and the withdrawn row stays withdrawn.
const UNSERVED_KINDS: &[&str] = &["derived.regenerate"];

/// Drops every row of an [`UNSERVED_KINDS`] kind, in one write when one is
/// there; an open whose ledger holds none writes nothing.
///
/// # Errors
///
/// Storage errors, and a row that does not decode.
pub(crate) fn drop_unserved_kinds(store: &Store) -> Result<()> {
    let queued = {
        let txn = store.env.read_txn()?;
        let mut queued = false;
        for kind in UNSERVED_KINDS {
            queued |= !super::index::kind_ids_in_txn(store, &txn, kind)?.is_empty();
        }
        queued
    };
    if !queued {
        return Ok(());
    }
    let queue = AttemptQueue::from_store(store);
    let mut wtxn = store.env.write_txn()?;
    let mut dropped = 0;
    for kind in UNSERVED_KINDS {
        dropped += queue.drop_kind_in_txn(&mut wtxn, kind)?;
    }
    wtxn.commit()?;
    tracing::info!(dropped, "rows of a kind no executor serves left the queue");
    Ok(())
}
