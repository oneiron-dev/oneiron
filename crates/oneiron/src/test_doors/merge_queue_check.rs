//! Doors to the merge queue's check slots for tests/queue_check_reuse_source.rs (L4-30). Not API.

use crate::error::{Error, Result};
use crate::git_wire::lock_repository;
use crate::merge_queue::{BatchState, MergeBatch, MergeQueue};
use crate::side_table::{self, Named, SideTable};
use crate::store::code_snapshot::RepoRef;
use crate::store::contract_oracle::invalid;
use crate::{EntityId, Vault};

/// Clears the FAST verdict slot of the stored batch's path `mask`, and moves
/// a `Ready` batch back to `Staged`, the state before every path passed: the
/// finish that stored its receipt but did not bind the slot, the only state
/// where a refresh-free check reuses a passing receipt instead of running.
/// The slow verdict is untouched. The write mirrors the queue's own batch
/// store: the same table, key and encoding in one write transaction under
/// the repository lock. The batch index keeps its rows: the door changes
/// neither the proposals nor the run order they file the batch under.
///
/// # Errors
///
/// No CODE_ARTIFACT, queue or batch for `repo` and `batch`, no staged path
/// for `mask`, or a store or lock failure.
pub fn unbind_slot_verdict(vault: &Vault, repo: EntityId, batch: &str, mask: u64) -> Result<()> {
    let artifact = vault
        .get_code_artifact(&repo)?
        .ok_or(Error::EntityNotFound)?;
    let queue = MergeQueue::open(vault, RepoRef::parse(&artifact.repo_ref)?)?;
    let _guard = lock_repository(queue.repository().common_dir())?;
    let mut current = queue.batch(batch)?;
    let path = current
        .paths
        .iter_mut()
        .find(|path| path.mask == mask)
        .ok_or_else(|| invalid("speculative path not staged"))?;
    path.verdict = None;
    if current.state == BatchState::Ready {
        current.state = BatchState::Staged;
    }
    let table: SideTable<String, MergeBatch, Named> =
        SideTable::new(&side_table::MERGE_QUEUE_BATCH);
    let repo_hex = queue.repository().identity().as_hex();
    let key = format!("{repo_hex}:{batch}");
    let mut txn = vault.store.env.write_txn()?;
    table.put(&vault.store, &mut txn, &key, &current)?;
    txn.commit()?;
    vault.wake_merge_queue();
    Ok(())
}
