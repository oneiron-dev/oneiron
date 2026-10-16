//! MACRO admission shares the queue's leases: one attempt per partition.
//! The ready scan skips held partitions so one busy bucket cannot block others.

use std::collections::{BTreeSet, HashSet};

use crate::attempt_queue::{AttemptId, AttemptRecord, AttemptState};
use crate::dreamer_consolidation::{ConsolidationPartitionKey, decode_partition_payload};
use crate::error::Result;

use super::super::{DreamerConsolidationScope, DreamerRunnerStore, decode_dreamer_attempt_payload};
use super::AdmitDreamerAttempt;

fn bucket(record: &AttemptRecord) -> Option<ConsolidationPartitionKey> {
    let payload = decode_dreamer_attempt_payload(&record.payload).ok()?;
    decode_partition_payload(&payload.input)
        .ok()
        .map(|(key, _, _)| key)
}

fn bucket_available(
    held: &BTreeSet<Option<ConsolidationPartitionKey>>,
    row: &AttemptRecord,
) -> bool {
    !held.contains(&None)
        && match bucket(row) {
            Some(key) => !held.contains(&Some(key)),
            None => held.is_empty(),
        }
}

impl DreamerRunnerStore<'_> {
    /// Ready-indexed MACRO attempts whose bucket is not already leased.
    /// Deadline readers use the same bucket rule as admission, so a parked
    /// bucket cannot keep waking a pass that has nothing it may admit.
    pub fn macro_schedulable_attempts(&self) -> Result<HashSet<AttemptId>> {
        let txn = self.vault.store.env.read_txn()?;
        let kind = DreamerConsolidationScope::Macro.attempt_kind();
        let records = self.attempts.list_in_txn(&txn)?;
        let held = records
            .iter()
            .filter(|row| row.kind == kind && row.state.is_running())
            .map(bucket)
            .collect();
        Ok(records
            .iter()
            .filter(|row| {
                row.kind == kind
                    && matches!(row.state, AttemptState::Queued | AttemptState::Scheduled)
                    && bucket_available(&held, row)
            })
            .map(|row| row.id)
            .collect())
    }

    /// The queued disjoint MACRO partitions a host may prepare executors for.
    /// Jobs without a partition use one exclusive whole-vault slot.
    pub fn macro_bucket_count(&self) -> Result<usize> {
        let txn = self.vault.store.env.read_txn()?;
        let buckets: BTreeSet<_> = self
            .attempts
            .list_in_txn(&txn)?
            .into_iter()
            .filter(|row| {
                row.kind == DreamerConsolidationScope::Macro.attempt_kind()
                    && matches!(row.state, AttemptState::Queued | AttemptState::Scheduled)
            })
            .map(|row| bucket(&row))
            .collect();
        Ok(buckets.len().max(1))
    }

    pub(super) fn ready_macro_candidate_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        input: &AdmitDreamerAttempt,
    ) -> Result<Option<AttemptId>> {
        let kind = DreamerConsolidationScope::Macro.attempt_kind();
        let held: BTreeSet<_> = self
            .attempts
            .list_in_txn(txn)?
            .into_iter()
            .filter(|row| row.kind == kind && row.state.is_running())
            .map(|row| bucket(&row))
            .collect();
        self.attempts
            .ready_kind_matching_in_txn(txn, kind, input.now, |row| {
                Ok(row.accepts_worker(&input.lease_owner) && bucket_available(&held, row))
            })
    }
}
