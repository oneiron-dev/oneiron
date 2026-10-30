//! MACRO admission shares the queue's leases: one attempt per partition.
//! A child's buckets are its parts' partitions (FIX 7524): it is admitted
//! all or none, only when no running MACRO work holds any of them. The ready
//! scan skips held buckets, so one busy bucket cannot block disjoint work.

use std::collections::{BTreeSet, HashSet};

use crate::attempt_queue::{AttemptId, AttemptRecord, AttemptState};
use crate::dreamer_consolidation::{ConsolidationPartitionKey, decode_partition_payload};
use crate::error::Result;

use super::super::{DreamerConsolidationScope, DreamerRunnerStore, decode_dreamer_attempt_payload};
use super::AdmitDreamerAttempt;

/// A row's sorted, deduplicated set of part partition buckets; `None` for a
/// job without a partition, which takes one exclusive whole-vault slot.
fn bucket(record: &AttemptRecord) -> Option<Vec<ConsolidationPartitionKey>> {
    let payload = decode_dreamer_attempt_payload(&record.payload).ok()?;
    decode_partition_payload(&payload.input)
        .ok()
        .map(|branch| branch.bucket_set())
}

/// What running MACRO work holds: every bucket of every running row, and
/// whether any running row holds the whole-vault slot.
#[derive(Default)]
struct Held {
    any: bool,
    whole_vault: bool,
    buckets: BTreeSet<ConsolidationPartitionKey>,
}

impl Held {
    /// What the running rows of `kind` among `records` hold.
    fn running(records: &[AttemptRecord], kind: &str) -> Self {
        let mut held = Self::default();
        for row in records
            .iter()
            .filter(|row| row.kind == kind && row.state.is_running())
        {
            held.any = true;
            match bucket(row) {
                Some(set) => held.buckets.extend(set),
                None => held.whole_vault = true,
            }
        }
        held
    }

    /// Whether `row` may be admitted now, all or none: no whole-vault slot is
    /// held and none of its buckets is; a row without a partition needs
    /// nothing running. A held set is a wait, never a refusal.
    fn admits(&self, row: &AttemptRecord) -> bool {
        !self.whole_vault
            && match bucket(row) {
                Some(set) => set.iter().all(|key| !self.buckets.contains(key)),
                None => !self.any,
            }
    }
}

impl DreamerRunnerStore<'_> {
    /// Ready-indexed MACRO attempts whose bucket is not already leased.
    /// Deadline readers use the same bucket rule as admission, so a parked
    /// bucket cannot keep waking a pass that has nothing it may admit.
    pub fn macro_schedulable_attempts(&self) -> Result<HashSet<AttemptId>> {
        let txn = self.vault.store.env.read_txn()?;
        let kind = DreamerConsolidationScope::Macro.attempt_kind();
        let records = self.attempts.kind_working_rows_in_txn(&txn, kind)?;
        let held = Held::running(&records, kind);
        Ok(records
            .iter()
            .filter(|row| {
                row.kind == kind
                    && matches!(row.state, AttemptState::Queued | AttemptState::Scheduled)
                    && held.admits(row)
            })
            .map(|row| row.id)
            .collect())
    }

    /// The queued distinct MACRO bucket sets a host may prepare executors
    /// for: each child's sorted set of part partitions counts once. Jobs
    /// without a partition use one exclusive whole-vault slot.
    pub fn macro_bucket_count(&self) -> Result<usize> {
        let txn = self.vault.store.env.read_txn()?;
        let buckets: BTreeSet<_> = self
            .attempts
            .kind_working_rows_in_txn(&txn, DreamerConsolidationScope::Macro.attempt_kind())?
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
        let records = self.attempts.kind_working_rows_in_txn(txn, kind)?;
        let held = Held::running(&records, kind);
        self.attempts
            .ready_kind_matching_in_txn(txn, kind, input.now, |row| {
                Ok(row.accepts_worker(&input.lease_owner) && held.admits(row))
            })
    }
}
