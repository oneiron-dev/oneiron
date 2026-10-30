//! Keyed reads of one queue's batches (FIX 7067): a run's enqueue, stage
//! and observe read the batches that name a proposal, a work or a
//! declaration through one index row each, never every batch the queue
//! ever kept. The rows are written in the writer that saves the batch; a
//! reader reads each named batch whole and judges what it holds.
use super::storage::BATCHES;
use super::{MergeBatch, MergeQueue};
use crate::error::{Error, Result};
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;

/// One row per batch and what it names. Key: hex(repo identity) ":" kind
/// ":" id ":" hex64(batch id).
const BATCH_INDEX: SideTable<String, (), Named> =
    SideTable::new(&side_table::MERGE_QUEUE_BATCH_INDEX);

/// What an index row files a batch under.
#[derive(Debug, Clone, Copy)]
pub(super) enum BatchIndexKind {
    /// A proposal the batch holds, by its id.
    Proposal,
    /// A run entry's work, by hex id.
    Work,
    /// A run entry's own declaration, by hex id.
    Declaration,
}

impl BatchIndexKind {
    const fn tag(self) -> &'static str {
        match self {
            Self::Proposal => "proposal",
            Self::Work => "work",
            Self::Declaration => "declaration",
        }
    }
}

/// Writes `batch`'s index rows in `txn`; a row already there is put again
/// unchanged.
///
/// # Errors
/// A store failure.
pub(super) fn put_batch_index(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    repo_hex: &str,
    batch: &MergeBatch,
) -> Result<()> {
    let mut named: Vec<(BatchIndexKind, String)> = batch
        .proposals
        .iter()
        .map(|proposal| (BatchIndexKind::Proposal, proposal.id.clone()))
        .collect();
    if let Some(order) = &batch.run_order {
        named.push((BatchIndexKind::Work, order.work.to_hex()));
        if let Some(declaration) = order.declaration {
            named.push((BatchIndexKind::Declaration, declaration.to_hex()));
        }
    }
    for (kind, id) in named {
        let key = format!("{}{}", index_prefix(repo_hex, kind, &id), batch.id);
        BATCH_INDEX.put(store, txn, &key, &())?;
    }
    Ok(())
}

fn index_prefix(repo_hex: &str, kind: BatchIndexKind, id: &str) -> String {
    format!("{repo_hex}:{}:{id}:", kind.tag())
}

impl MergeQueue<'_> {
    /// The batches of this queue filed under `kind` and `id`, read in
    /// `txn`, in batch key order. A row of a longer id that shares the
    /// prefix is passed over.
    ///
    /// # Errors
    /// A store failure, or a row that names no batch.
    pub(super) fn indexed_batches_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        kind: BatchIndexKind,
        id: &str,
    ) -> Result<Vec<MergeBatch>> {
        let prefix = index_prefix(&self.repo.identity().as_hex(), kind, id);
        let mut batches = Vec::new();
        for key in BATCH_INDEX.scan_keys(&self.vault.store, txn, prefix.as_bytes())? {
            let Some(batch_id) = key.strip_prefix(&prefix).filter(|rest| !rest.contains(':'))
            else {
                continue;
            };
            let batch = BATCHES
                .get(&self.vault.store, txn, &self.batch_key(batch_id))?
                .ok_or(Error::CorruptedIndex(
                    "a merge batch index row names no batch",
                ))?;
            batches.push(batch);
        }
        Ok(batches)
    }
}
