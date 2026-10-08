//! The doors an owner-retained kind's tries leave the ledger by: a settled
//! attempt with every try it retried, and the older tries of a lineage that
//! is still retrying.

use std::collections::HashSet;

use crate::attempt_queue::encoding::{
    DedupeIndexKeys, decode_record, encode_record, legacy_dedupe_index_key, ready_at, ready_key,
};
use crate::attempt_queue::telemetry::invalid_transition;
use crate::attempt_queue::types::{AttemptId, AttemptRecord};
use crate::error::{ArtifactError, Error, Result};

use super::AttemptQueue;
use super::reads::{ERR_RETRY_CHAIN_CYCLE, ERR_RETRY_CHAIN_MISMATCH, retries_the_same_attempt};

impl AttemptQueue<'_> {
    /// Deletes a settled attempt and every try it retried, with each index
    /// entry that still names one of them, in the caller's transaction, and
    /// returns how many rows went.
    ///
    /// Only a kind whose owner keeps its own bounded history leaves this way
    /// ([`crate::attempt_queue::owner_retained_kind`]), and only a chain that
    /// is settled from end to end and that no run or task names. A live try
    /// anywhere in the chain is refused, so the caller must abort. An index
    /// entry is deleted only while it names the pruned row, so a later
    /// attempt at the same work keeps its own. A try the chain names that is
    /// already gone ends the walk: an earlier prune took it.
    pub(crate) fn prune_settled_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: AttemptId,
    ) -> Result<usize> {
        let mut seen = HashSet::new();
        let mut child: Option<AttemptRecord> = None;
        let mut next = Some(id);
        let mut pruned = 0;
        while let Some(id) = next {
            if !seen.insert(id) {
                return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
                    ERR_RETRY_CHAIN_CYCLE,
                )));
            }
            let raw = self
                .store
                .attempt_records
                .get(wtxn, id.as_bytes())?
                .map(std::borrow::Cow::into_owned);
            let Some(raw) = raw else {
                if child.is_none() {
                    return Err(invalid_transition("prune", "missing"));
                }
                break;
            };
            let record = decode_record(&raw, id)?;
            if !crate::attempt_queue::owner_retained_kind(&record.kind)
                || !record.state.is_terminal()
                || record.run_id.is_some()
                || record.task_ref.is_some()
            {
                return Err(invalid_transition("prune", record.state.as_str()));
            }
            if child
                .as_ref()
                .is_some_and(|child| !retries_the_same_attempt(child, &record))
            {
                return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
                    ERR_RETRY_CHAIN_MISMATCH,
                )));
            }
            self.delete_entries_naming(wtxn, &record)?;
            self.store.attempt_records.delete(wtxn, id.as_bytes())?;
            crate::vault_cleanup::forget_archived_attempt_in_txn(self.store, wtxn, &record)?;
            pruned += 1;
            next = record.retry_of;
            child = Some(record);
        }
        Ok(pruned)
    }

    /// Compacts the lineage of the try `id` of an owner-retained kind in the
    /// caller's transaction, and returns how many rows went.
    ///
    /// It keeps the newest `keep` tries `id` retried that were finalized at
    /// or after `kept_since`. Every older try is deleted, with each index
    /// entry that still names it. Their count is folded into the oldest row
    /// kept, whose `retry_of` is cleared
    /// ([`AttemptRecord::folded_retries`]), so the lineage depth, and every
    /// backoff that reads it, stays what it was. A try that fails again and
    /// again leaves the ledger a bounded lineage, so the settlement that
    /// prunes it deletes a bounded one. A deleted try must be settled and
    /// named by no run or task, as for [`Self::prune_settled_in_txn`];
    /// anything else is refused, so the caller must abort.
    pub(crate) fn compact_retry_chain_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: AttemptId,
        keep: usize,
        kept_since: u64,
    ) -> Result<usize> {
        let mut seen = HashSet::from([id]);
        let mut kept = self.retry_chain_record_in_txn(wtxn, id)?;
        if !crate::attempt_queue::owner_retained_kind(&kept.kind) {
            return Err(invalid_transition("compact", kept.state.as_str()));
        }
        let mut kept_tries = 0;
        let mut child = loop {
            let Some(parent_id) = kept.retry_of else {
                return Ok(0);
            };
            if !seen.insert(parent_id) {
                return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
                    ERR_RETRY_CHAIN_CYCLE,
                )));
            }
            let parent = self.retry_chain_record_in_txn(wtxn, parent_id)?;
            if !retries_the_same_attempt(&kept, &parent) {
                return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
                    ERR_RETRY_CHAIN_MISMATCH,
                )));
            }
            if kept_tries == keep || parent.updated_at < kept_since {
                break parent;
            }
            kept_tries += 1;
            kept = parent;
        };
        let mut deleted = 0_u32;
        let folded_before = loop {
            if !child.state.is_terminal() || child.run_id.is_some() || child.task_ref.is_some() {
                return Err(invalid_transition("compact", child.state.as_str()));
            }
            self.delete_entries_naming(wtxn, &child)?;
            self.store
                .attempt_records
                .delete(wtxn, child.id.as_bytes())?;
            crate::vault_cleanup::forget_archived_attempt_in_txn(self.store, wtxn, &child)?;
            deleted = deleted.saturating_add(1);
            let Some(parent_id) = child.retry_of else {
                break child.folded_retries;
            };
            if !seen.insert(parent_id) {
                return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
                    ERR_RETRY_CHAIN_CYCLE,
                )));
            }
            let parent = self.retry_chain_record_in_txn(wtxn, parent_id)?;
            if !retries_the_same_attempt(&child, &parent) {
                return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
                    ERR_RETRY_CHAIN_MISMATCH,
                )));
            }
            child = parent;
        };
        kept.retry_of = None;
        kept.folded_retries = deleted.saturating_add(folded_before);
        self.store
            .attempt_records
            .put(wtxn, kept.id.as_bytes(), &encode_record(&kept)?)?;
        Ok(usize::try_from(deleted).unwrap_or(usize::MAX))
    }

    /// Deletes the ready and dedupe entries that name `record`. A settled row
    /// holds none; one left by an older build goes with its row, and an entry
    /// that names a later try is left alone.
    fn delete_entries_naming(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        record: &AttemptRecord,
    ) -> Result<()> {
        let ready = ready_key(ready_at(record), record.id);
        let names_ready = self
            .store
            .attempt_ready
            .get(wtxn, &ready)?
            .is_some_and(|value| *value == *record.id.as_bytes());
        if names_ready {
            self.store.attempt_ready.delete(wtxn, &ready)?;
        }
        let Some(dedupe_key) = record.dedupe_key.as_deref() else {
            return Ok(());
        };
        let keys =
            DedupeIndexKeys::new(&record.kind, record.dedupe_actor_ref.as_deref(), dedupe_key);
        let mut entries = vec![keys.primary.to_vec()];
        entries.extend(keys.fallback_v1.map(|key| key.to_vec()));
        entries.push(legacy_dedupe_index_key(&record.kind, dedupe_key));
        for key in entries {
            let names_row = self
                .store
                .attempt_dedupe
                .get(wtxn, &key)?
                .is_some_and(|value| *value == *record.id.as_bytes());
            if names_row {
                self.store.attempt_dedupe.delete(wtxn, &key)?;
            }
        }
        Ok(())
    }
}
