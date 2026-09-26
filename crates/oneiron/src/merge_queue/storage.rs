//! Repo-scoped queue/batch rows; every transition is under the repo single writer.
use super::types::QueueRecord;
use super::{BatchState, MergeBatch, MergeQueue, MergeQueuePointers};
use crate::{
    contract_oracle::{ContractOracle, WorkspaceGraph, invalid},
    error::{Error, Result},
    git_wire::lock_repository,
    side_table::{self, Named, SideTable},
};

/// One repo's queue state: a singleton row per repo, keyed by the repo's hex identity.
const QUEUE_STATE: SideTable<String, QueueRecord, Named> =
    SideTable::new(&side_table::MERGE_QUEUE_STATE);

/// One merge batch, keyed by `{repo_hex}:{batch_id}` exactly as `batch_key` spelled it —
/// a plain `String` key rather than a split key type, since nothing ever scans this table.
const BATCHES: SideTable<String, MergeBatch, Named> =
    SideTable::new(&side_table::MERGE_QUEUE_BATCH);

impl MergeQueue<'_> {
    pub fn initialize(
        &self,
        baseline_id: &str,
        graph: WorkspaceGraph,
    ) -> Result<MergeQueuePointers> {
        let _guard = lock_repository(self.repo.common_dir())?;
        if let Some(state) = self.read_queue()? {
            return Ok(state.pointers);
        }
        ContractOracle::new(self.vault)
            .baseline(baseline_id)?
            .ok_or_else(|| invalid("merge baseline not found"))?;
        self.require_clean(self.repo.repo_root())?;
        let head = self.head()?;
        let pointers = MergeQueuePointers {
            head: head.clone(),
            green: head,
            pending_slow: Vec::new(),
        };
        let state = QueueRecord {
            schema_version: 1,
            sequence: 0,
            baseline_id: baseline_id.to_owned(),
            graph,
            pointers: pointers.clone(),
            intent: None,
        };
        self.save(&state, &[])?;
        Ok(pointers)
    }

    pub fn pointers(&self) -> Result<MergeQueuePointers> {
        let _guard = lock_repository(self.repo.common_dir())?;
        let queue = self.queue()?;
        self.require_current(&queue)?;
        Ok(queue.pointers)
    }

    pub fn batch(&self, id: &str) -> Result<MergeBatch> {
        validate_id(id)?;
        let batch = self
            .read(BATCHES, self.batch_key(id))?
            .ok_or_else(|| invalid("merge batch not found"))?;
        if batch.schema_version != 1
            || batch.id != id
            || batch.proposals.is_empty()
            || batch.proposals.len() > 6
        {
            return Err(Error::CorruptedIndex("merge batch identity or schema"));
        }
        if !matches!(
            batch.state,
            BatchState::Queued | BatchState::Quarantined | BatchState::Cancelled
        ) && (batch.paths.len() != (1 << batch.proposals.len()) - 1
            || batch.pre_snapshot.is_none())
        {
            return Err(Error::CorruptedIndex("merge batch paths incomplete"));
        }
        for (index, path) in batch.paths.iter().enumerate() {
            if path.mask != index as u64 + 1 || path.worktree != self.worktree_path(id, path.mask) {
                return Err(Error::CorruptedIndex("merge worktree path identity"));
            }
        }
        Ok(batch)
    }

    pub(super) fn require_current(&self, queue: &QueueRecord) -> Result<()> {
        if queue.intent.is_some() {
            return Err(Error::ConcurrentWrite("merge effect needs recovery"));
        }
        if self.head()? != queue.pointers.head {
            return Err(Error::ConcurrentWrite("merge queue HEAD diverged"));
        }
        Ok(())
    }
    pub(super) fn queue(&self) -> Result<QueueRecord> {
        self.read_queue()?
            .ok_or_else(|| invalid("merge queue is not initialized"))
    }
    fn read_queue(&self) -> Result<Option<QueueRecord>> {
        let record = self.read(QUEUE_STATE, self.queue_key())?;
        if let Some(record) = &record
            && (record.schema_version != 1 || record.sequence > 100_000)
        {
            return Err(Error::CorruptedIndex("merge queue schema or bound"));
        }
        Ok(record)
    }
    pub(super) fn save(&self, state: &QueueRecord, batches: &[&MergeBatch]) -> Result<()> {
        check_row_size(&QUEUE_STATE.encode_value(state)?)?;
        let mut txn = self.vault.store.env.write_txn()?;
        QUEUE_STATE.put(&self.vault.store, &mut txn, &self.queue_key(), state)?;
        for batch in batches {
            check_row_size(&BATCHES.encode_value(batch)?)?;
            BATCHES.put(
                &self.vault.store,
                &mut txn,
                &self.batch_key(&batch.id),
                batch,
            )?;
        }
        txn.commit()?;
        Ok(())
    }
    fn read<T>(&self, table: SideTable<String, T, Named>, key: String) -> Result<Option<T>>
    where
        T: serde::Serialize + serde::de::DeserializeOwned,
    {
        let txn = self.vault.store.env.read_txn()?;
        table.get(&self.vault.store, &txn, &key)
    }
    fn queue_key(&self) -> String {
        self.repo.identity().as_hex()
    }
    fn batch_key(&self, id: &str) -> String {
        format!("{}:{id}", self.repo.identity().as_hex())
    }
}
fn check_row_size(bytes: &[u8]) -> Result<()> {
    if bytes.len() > 128 * 1024 * 1024 {
        return Err(invalid("merge queue row exceeds limit"));
    }
    Ok(())
}
fn validate_id(id: &str) -> Result<()> {
    if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(invalid("merge batch id must be a digest"));
    }
    Ok(())
}
