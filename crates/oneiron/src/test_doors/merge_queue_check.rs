//! Doors to the merge queue's check slots and check work rows for
//! tests/queue_check_reuse_source.rs (L4-30). Not API.

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

/// Rewrites every stored check work row's receipts in the shape they had
/// before the reuse source had a key of its own: the reuse entry becomes
/// `reused_from`, holding the receipt's own inputs digest when it reused a
/// receipt and nil when it did not. Each entry keeps its place in the
/// receipt. Returns how many receipts were reuses.
///
/// # Errors
///
/// A row that is not a map with a receipts array of maps, a receipt with no
/// inputs digest or reuse entry, or a store failure.
pub fn store_reuse_as_before_its_own_key(vault: &Vault) -> Result<usize> {
    let table: SideTable<String, rmpv::Value, Named> =
        SideTable::new(&side_table::MERGE_QUEUE_CHECK_WORK);
    let mut txn = vault.store.env.write_txn()?;
    let rows = table.scan(&vault.store, &txn)?;
    let mut reuses = 0;
    for (key, mut row) in rows {
        let Some(rmpv::Value::Array(receipts)) = map_entry_mut(&mut row, "receipts") else {
            return Err(invalid("a check work row holds its receipts"));
        };
        for receipt in receipts.iter_mut() {
            let rmpv::Value::Map(entries) = receipt else {
                return Err(invalid("a stored receipt is a map"));
            };
            let digest = entries
                .iter()
                .find(|entry| entry.0.as_str() == Some("inputs_digest"))
                .map(|entry| entry.1.clone())
                .ok_or_else(|| invalid("a stored receipt holds its inputs digest"))?;
            let reuse = entries
                .iter_mut()
                .find(|entry| matches!(entry.0.as_str(), Some("reused_from" | "reuse_source")))
                .ok_or_else(|| invalid("a stored receipt holds its reuse entry"))?;
            let reused = !reuse.1.is_nil();
            *reuse = (
                rmpv::Value::from("reused_from"),
                if reused { digest } else { rmpv::Value::Nil },
            );
            reuses += usize::from(reused);
        }
        table.put(&vault.store, &mut txn, &key, &row)?;
    }
    txn.commit()?;
    Ok(reuses)
}

fn map_entry_mut<'v>(value: &'v mut rmpv::Value, key: &str) -> Option<&'v mut rmpv::Value> {
    let rmpv::Value::Map(entries) = value else {
        return None;
    };
    entries
        .iter_mut()
        .find(|entry| entry.0.as_str() == Some(key))
        .map(|entry| &mut entry.1)
}
