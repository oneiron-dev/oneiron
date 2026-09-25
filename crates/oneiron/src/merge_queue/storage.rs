//! Repo-scoped queue/batch rows; every transition is under the repo single writer.
use super::types::QueueRecord;
use super::{BatchState, MergeBatch, MergeQueue, MergeQueuePointers};
use crate::{
    contract_oracle::{ContractOracle, WorkspaceGraph, invalid},
    error::{Error, Result},
    git_wire::lock_repository,
};
use serde::{Serialize, de::DeserializeOwned};

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
        let batch: MergeBatch = self
            .read(&self.batch_key(id))?
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
        let record: Option<QueueRecord> = self.read(&self.queue_key())?;
        if let Some(record) = &record
            && (record.schema_version != 1 || record.sequence > 100_000)
        {
            return Err(Error::CorruptedIndex("merge queue schema or bound"));
        }
        Ok(record)
    }
    pub(super) fn save(&self, state: &QueueRecord, batches: &[&MergeBatch]) -> Result<()> {
        let mut txn = self.vault.store.env.write_txn()?;
        self.vault
            .store
            .vault_meta
            .put(&mut txn, &self.queue_key(), &encode(state)?)?;
        for batch in batches {
            self.vault.store.vault_meta.put(
                &mut txn,
                &self.batch_key(&batch.id),
                &encode(batch)?,
            )?;
        }
        txn.commit()?;
        Ok(())
    }
    fn read<T: DeserializeOwned>(&self, key: &[u8]) -> Result<Option<T>> {
        let txn = self.vault.store.env.read_txn()?;
        self.vault
            .store
            .vault_meta
            .get(&txn, key)?
            .map(|raw| {
                rmp_serde::from_slice(&raw).map_err(|_| Error::CorruptedIndex("merge queue row"))
            })
            .transpose()
    }
    fn queue_key(&self) -> Vec<u8> {
        format!("merge_queue:state:v1:{}", self.repo.identity().as_hex()).into_bytes()
    }
    fn batch_key(&self, id: &str) -> Vec<u8> {
        format!(
            "merge_queue:batch:v1:{}:{id}",
            self.repo.identity().as_hex()
        )
        .into_bytes()
    }
}
fn encode(value: &impl Serialize) -> Result<Vec<u8>> {
    let bytes =
        rmp_serde::to_vec_named(value).map_err(|_| invalid("merge queue encoding failed"))?;
    if bytes.len() > 128 * 1024 * 1024 {
        return Err(invalid("merge queue row exceeds limit"));
    }
    Ok(bytes)
}
fn validate_id(id: &str) -> Result<()> {
    if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(invalid("merge batch id must be a digest"));
    }
    Ok(())
}
