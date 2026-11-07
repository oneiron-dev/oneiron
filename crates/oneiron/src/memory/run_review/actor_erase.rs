//! FIX 4727: an erased author leaves the run settlements that name it.
use super::{RunInverse, SETTLEMENTS};
use crate::{EntityId, Result, Vault};

/// The actor scrub `RUN_REVIEW_SETTLEMENT` declares (FIX 4727): a landed
/// change whose undo names `actor` as its author keeps no such name, in the
/// erase's writer. The settlement stands; that change is then one-way, as
/// the erase is, and a revert reports it so.
///
/// # Errors
/// A store failure.
pub(crate) fn erase_run_review_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    let author = actor.to_hex();
    let mut changed = Vec::new();
    for (run, mut stored) in SETTLEMENTS.scan(&vault.store, &*wtxn)? {
        let mut named = false;
        for change in &mut stored.changes {
            if matches!(
                &change.inverse,
                Some(RunInverse::Authored { author: by, .. }) if *by == author
            ) {
                change.inverse = Some(RunInverse::AuthorErased);
                named = true;
            }
        }
        if named {
            changed.push((run, stored));
        }
    }
    for (run, stored) in changed {
        SETTLEMENTS.put(&vault.store, wtxn, &run, &stored)?;
    }
    Ok(())
}
