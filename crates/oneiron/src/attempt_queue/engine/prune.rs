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
    /// or after `kept_since`, each judged on its own stamp, so a clock that
    /// ran back between two tries drops neither the wrong one nor every one
    /// after it. Every other try is deleted, with each index entry that still
    /// names it. A kept row is linked to the next one kept and counts the
    /// tries deleted between them ([`AttemptRecord::folded_retries`]), so
    /// the lineage depth, and every backoff that reads it, stays what it
    /// was. A try that fails again and again leaves the ledger a bounded
    /// lineage, so the settlement that prunes it deletes a bounded one. A
    /// deleted try must be settled and named by no run or task, as for
    /// [`Self::prune_settled_in_txn`]; anything else is refused, so the
    /// caller must abort.
    pub(crate) fn compact_retry_chain_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: AttemptId,
        keep: usize,
        kept_since: u64,
    ) -> Result<usize> {
        let live = self.retry_chain_record_in_txn(wtxn, id)?;
        if !crate::attempt_queue::owner_retained_kind(&live.kind) {
            return Err(invalid_transition("compact", live.state.as_str()));
        }
        // The lineage, newest first, with whether each row stays.
        let mut seen = HashSet::from([id]);
        let mut lineage = vec![(live, true)];
        let mut kept_tries = 0;
        while let Some((child, _)) = lineage.last() {
            let Some(parent_id) = child.retry_of else {
                break;
            };
            if !seen.insert(parent_id) {
                return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
                    ERR_RETRY_CHAIN_CYCLE,
                )));
            }
            let parent = self.retry_chain_record_in_txn(wtxn, parent_id)?;
            if !retries_the_same_attempt(child, &parent) {
                return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
                    ERR_RETRY_CHAIN_MISMATCH,
                )));
            }
            let stays = kept_tries < keep && parent.updated_at >= kept_since;
            kept_tries += usize::from(stays);
            lineage.push((parent, stays));
        }
        let mut deleted = 0;
        // The newest kept row whose link is not yet rebuilt, and the tries
        // deleted behind it so far.
        let mut newer: Option<AttemptRecord> = None;
        let mut gap = 0_u32;
        for (row, stays) in lineage {
            if !stays {
                if !row.state.is_terminal() || row.run_id.is_some() || row.task_ref.is_some() {
                    return Err(invalid_transition("compact", row.state.as_str()));
                }
                self.delete_entries_naming(wtxn, &row)?;
                self.store.attempt_records.delete(wtxn, row.id.as_bytes())?;
                crate::vault_cleanup::forget_archived_attempt_in_txn(self.store, wtxn, &row)?;
                deleted += 1;
                gap = gap.saturating_add(1).saturating_add(row.folded_retries);
                continue;
            }
            if let Some(kept) = newer.take().filter(|_| gap > 0) {
                self.relink_in_txn(wtxn, kept, Some(row.id), gap)?;
            }
            newer = Some(row);
            gap = 0;
        }
        if let Some(oldest) = newer.filter(|_| gap > 0) {
            self.relink_in_txn(wtxn, oldest, None, gap)?;
        }
        Ok(deleted)
    }

    /// Rewrites a kept row of a compacted lineage to retry `parent`, counting
    /// the `folded` tries deleted between the two.
    fn relink_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        mut row: AttemptRecord,
        parent: Option<AttemptId>,
        folded: u32,
    ) -> Result<()> {
        row.retry_of = parent;
        row.folded_retries = row.folded_retries.saturating_add(folded);
        self.store
            .attempt_records
            .put(wtxn, row.id.as_bytes(), &encode_record(&row)?)?;
        Ok(())
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
