//! Ordered by-turn projection of independent retrieval runs.

use super::run_store::RETRIEVAL_RUN;
use super::{RetrievalRunId, RetrievalRunRecord};
use crate::side_table::{self, SideTable};
use crate::store::{ManifestDbs, Store};
use crate::{Error, Result, Vault};
use heed::{RoTxn, RwTxn};

type TurnIndexKey = ([u8; 16], u64, RetrievalRunId);

const TURN_INDEX: SideTable<TurnIndexKey, (), side_table::Raw> =
    SideTable::new(&side_table::RETRIEVAL_TURN_INDEX);

fn key(record: &RetrievalRunRecord) -> Option<TurnIndexKey> {
    let turn = record.turn?;
    Some((turn.turn_id, record.started_at, record.run_id))
}
pub(super) fn put(
    target: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    record: &RetrievalRunRecord,
) -> Result<()> {
    if let Some(key) = key(record) {
        TURN_INDEX.put(target, txn, &key, &())?;
    }
    Ok(())
}
pub(super) fn stage(record: &RetrievalRunRecord) -> Result<Option<crate::side_table::StagedRow>> {
    key(record).map(|key| TURN_INDEX.stage(&key, &())).transpose()
}
pub(super) fn delete(
    target: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    record: &RetrievalRunRecord,
) -> Result<()> {
    if let Some(key) = key(record) {
        TURN_INDEX.delete(target, txn, &key)?;
    }
    Ok(())
}
pub(super) fn read(
    target: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    turn: &[u8; 16],
) -> Result<Vec<RetrievalRunId>> {
    let mut runs = Vec::new();
    for row in TURN_INDEX.scan_from(target, txn, turn)? {
        let ((turn_id, started_at, run_id), ()) = row;
        let record = RETRIEVAL_RUN
            .get(target, txn, &run_id)?
            .ok_or(Error::CorruptedIndex("retrieval turn index"))?;
        if record.turn.map(|turn| turn.turn_id) != Some(turn_id)
            || record.started_at != started_at
            || record.run_id != run_id
        {
            return Err(Error::CorruptedIndex("retrieval turn index"));
        }
        runs.push(run_id);
    }
    Ok(runs)
}
impl Store {
    /// The runs a turn made, read once the detached writes queued so far are
    /// decided (FIX 12023).
    pub fn retrieval_runs_by_turn(&self, turn: &[u8; 16]) -> Result<Vec<RetrievalRunId>> {
        self.wait_for_deferred_commits();
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
    delete_for_run_with_memory(target, txn, run_id, None)
}

pub(super) fn delete_for_run_with_memory(
    target: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    run_id: RetrievalRunId,
    mut memory: Option<&mut crate::host_memory::MemoryLease>,
) -> Result<()> {
    let mut keys = Vec::new();
    let rows = TURN_INDEX
        .iter_from(target, &*txn, &[])?
        .collect::<Result<Vec<_>>>()?;
    if let Some(memory) = memory.as_deref_mut() {
        memory.materialized(
            0,
            (rows.capacity() as u64)
                .saturating_mul(std::mem::size_of::<(TurnIndexKey, ())>() as u64),
        );
    }
    for (key, ()) in rows {
        if key.2 == run_id {
            keys.push(key);
        }
    }
    if let Some(memory) = memory.as_deref_mut() {
        memory.materialized(
            0,
            (keys.capacity() as u64)
                .saturating_mul(std::mem::size_of::<TurnIndexKey>() as u64),
        );
    }
    for key in keys {
        if let Some(memory) = memory.as_deref_mut() {
            TURN_INDEX.delete_with_key_capacity(target, txn, &key, |bytes| {
                memory.materialized(0, bytes);
            })?;
        } else {
            TURN_INDEX.delete(target, txn, &key)?;
        }
    }
    Ok(())
}
