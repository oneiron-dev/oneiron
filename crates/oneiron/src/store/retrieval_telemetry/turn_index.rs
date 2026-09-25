//! Ordered by-turn projection of independent retrieval runs.

use super::run_store::{decode_retrieval_run, retrieval_run_key};
use super::{RetrievalRunId, RetrievalRunRecord};
use crate::store::{ManifestDbs, Store};
use crate::{Error, Result, Vault};
use heed::{RoTxn, RwTxn};
const PREFIX: &[u8] = b"retr_turn:v1:";

fn prefix(turn: &[u8; 16]) -> Vec<u8> {
    [PREFIX, turn.as_slice()].concat()
}
fn key(record: &RetrievalRunRecord) -> Option<Vec<u8>> {
    let turn = record.turn?;
    Some(
        [
            prefix(&turn.turn_id).as_slice(),
            &record.started_at.to_be_bytes(),
            &record.run_id.as_bytes(),
        ]
        .concat(),
    )
}
pub(super) fn put(
    target: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    record: &RetrievalRunRecord,
) -> Result<()> {
    if let Some(key) = key(record) {
        target.vault_meta().put(txn, &key, b"")?;
    }
    Ok(())
}
pub(super) fn delete(
    target: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    record: &RetrievalRunRecord,
) -> Result<()> {
    if let Some(key) = key(record) {
        target.vault_meta().delete(txn, &key)?;
    }
    Ok(())
}
fn read(
    target: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    turn: &[u8; 16],
) -> Result<Vec<RetrievalRunId>> {
    let mut runs = Vec::new();
    let prefix = prefix(turn);
    for row in target.vault_meta().prefix_iter(txn, &prefix)? {
        let (index_key, _) = row?;
        let suffix = &index_key[prefix.len()..];
        if suffix.len() != 24 {
            return Err(Error::CorruptedIndex("retrieval turn index"));
        }
        let bytes = suffix[8..]
            .try_into()
            .map_err(|_| Error::CorruptedIndex("retrieval turn index"))?;
        let id = RetrievalRunId { bytes };
        let raw = target
            .vault_meta()
            .get(txn, &retrieval_run_key(id))?
            .ok_or(Error::CorruptedIndex("retrieval turn index"))?;
        let record = decode_retrieval_run(&raw)?;
        if key(&record).as_deref() != Some(index_key.as_ref()) {
            return Err(Error::CorruptedIndex("retrieval turn index"));
        }
        runs.push(id);
    }
    Ok(runs)
}
impl Store {
    pub fn retrieval_runs_by_turn(&self, turn: &[u8; 16]) -> Result<Vec<RetrievalRunId>> {
        read(self, &self.env.read_txn()?, turn)
    }
}
impl Vault {
    pub fn retrieval_runs_by_turn(&self, turn: &[u8; 16]) -> Result<Vec<RetrievalRunId>> {
        self.store.retrieval_runs_by_turn(turn)
    }
    /// Measured one-shot baseline from persisted latency, with no policy or
    /// bandit activation. Nearest-rank percentiles include zero-result runs.
    pub fn retrieval_latency_baseline(&self, limit: usize) -> Result<Option<(u64, u64)>> {
        let mut times: Vec<u64> = self
            .retrieval_runs(limit)?
            .into_iter()
            .filter(|run| run.state.iteration == 0)
            .map(|run| run.elapsed_us)
            .collect();
        if times.is_empty() {
            return Ok(None);
        }
        times.sort_unstable();
        let rank = |p: usize| times[(times.len() * p).div_ceil(100).saturating_sub(1)];
        Ok(Some((rank(50), rank(95))))
    }
}

/// Cleanup must work even if the primary row was corrupted before publication.
pub(super) fn delete_for_run(
    target: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    run_id: RetrievalRunId,
) -> Result<()> {
    let mut keys = Vec::new();
    for row in target.vault_meta().prefix_iter(txn, PREFIX)? {
        let (key, _) = row?;
        if key.len() == PREFIX.len() + 16 + 8 + 16 && key.ends_with(&run_id.as_bytes()) {
            keys.push(key.to_vec());
        }
    }
    for key in keys {
        target.vault_meta().delete(txn, &key)?;
    }
    Ok(())
}
