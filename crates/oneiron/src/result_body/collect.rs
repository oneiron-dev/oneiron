//! The result body collector: released bodies first, then orphan files.

use std::time::SystemTime;

use super::files::{BodyEntry, body_entries, remove_unnamed, sync_dir, unlink_body};
use super::{
    RAW_OUTPUT_ROWS, RAW_OUTPUT_SECRETS, RAW_OUTPUT_TAINTS, raw_output_handle, unowned_mark_key,
};
use crate::provenance::body::{
    digest_is_held_in_txn, released_bodies_in_txn, take_released_in_txn,
};
use crate::store::BodyDir;
use crate::{Result, Vault};

/// Body directory names the orphan sweep checks under one read transaction.
const SWEEP_BATCH: usize = 256;

/// What one collector pass did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResultBodyCollectReport {
    /// Released bodies whose raw-output row, unowned marks and file went.
    pub collected: usize,
    /// Released digests a descriptor holds again, or another pass took
    /// first: off the queue, left as they are.
    pub held: usize,
    /// Released bodies a reader still pinned: left for a later pass.
    pub pinned: usize,
    /// Orphan body files (and line indexes whose body is gone) removed.
    pub orphans: usize,
}

impl Vault {
    /// Collects the result bodies nothing holds any longer (OF-597): up to
    /// `limit` released digests, then up to `limit` orphan files. Each
    /// released digest is rechecked in the write transaction that drops its
    /// raw-output row and its unowned occurrence's taint sidecar and secret
    /// mark, and its file and line index are unlinked only once that
    /// commits. An owned occurrence's marks stay with its manifest. An orphan is a body file no
    /// raw-output row or descriptor names, older than an hour, so a body
    /// whose row has yet to commit stays. A pinned body is left for a later
    /// pass. Idempotent; a file already gone is fine.
    ///
    /// # Errors
    ///
    /// Storage and filesystem errors as they occur.
    pub fn collect_result_bodies(&self, limit: usize) -> Result<ResultBodyCollectReport> {
        let mut report = self.collect_released_result_bodies(limit)?;
        if limit > 0 {
            report.orphans = self.sweep_orphan_result_bodies(&self.store.body_dir()?, limit)?;
        }
        Ok(report)
    }

    /// The released half of [`Self::collect_result_bodies`], with no
    /// directory sweep: what an erase runs once its transaction commits.
    ///
    /// # Errors
    ///
    /// Storage and filesystem errors as they occur.
    pub(crate) fn collect_released_result_bodies(
        &self,
        limit: usize,
    ) -> Result<ResultBodyCollectReport> {
        let mut report = ResultBodyCollectReport::default();
        let released = {
            let rtxn = self.store.env.read_txn()?;
            released_bodies_in_txn(&self.store, &rtxn, limit)?
        };
        if released.is_empty() {
            return Ok(report);
        }
        let pins = &self.result_body_pins;
        let taken = self.with_write_txn_grouped(|txn| {
            let mut taken = Vec::with_capacity(released.len());
            for digest in &released {
                // A reader holding it keeps it queued for a later pass.
                if pins.holds(digest) {
                    report.pinned += 1;
                    continue;
                }
                if !take_released_in_txn(&self.store, txn, digest)? {
                    report.held += 1;
                    continue;
                }
                let marks = unowned_mark_key(digest)?;
                RAW_OUTPUT_ROWS.delete(&self.store, txn, &raw_output_handle(digest))?;
                RAW_OUTPUT_TAINTS.delete(&self.store, txn, &marks)?;
                RAW_OUTPUT_SECRETS.delete(&self.store, txn, &marks)?;
                taken.push(*digest);
            }
            Ok(taken)
        })?;
        if taken.is_empty() {
            return Ok(report);
        }
        // The rows are gone for good, so each file may go now. One a reader
        // pinned since stays until the orphan sweep finds it unpinned.
        let dir = self.store.body_dir()?;
        for digest in &taken {
            match pins.unless_pinned(digest, || unlink_body(&dir, digest)) {
                Some(unlinked) => {
                    unlinked?;
                    report.collected += 1;
                }
                None => report.pinned += 1,
            }
        }
        if report.collected > 0 {
            sync_dir(&dir)?;
        }
        Ok(report)
    }

    /// Removes up to `limit` body files in `dir` that no raw-output row or
    /// descriptor names, each with its line index, and line indexes whose
    /// body is gone: what a writer left before its row committed, or the
    /// collector left to a reader. Returns how many went.
    fn sweep_orphan_result_bodies(&self, dir: &BodyDir, limit: usize) -> Result<usize> {
        let now = SystemTime::now();
        let mut entries = body_entries(dir)?;
        let mut removed = 0;
        while removed < limit {
            let batch = entries
                .by_ref()
                .take(SWEEP_BATCH)
                .collect::<Result<Vec<_>>>()?;
            if batch.is_empty() {
                break;
            }
            for entry in self.unnamed_result_bodies(batch)? {
                if removed == limit {
                    break;
                }
                if remove_unnamed(dir, &entry, now, &self.result_body_pins)? {
                    removed += 1;
                }
            }
        }
        if removed > 0 {
            sync_dir(dir)?;
        }
        Ok(removed)
    }

    /// The entries of `batch` whose digest no raw-output row or descriptor
    /// names, read in one transaction.
    fn unnamed_result_bodies(&self, batch: Vec<BodyEntry>) -> Result<Vec<BodyEntry>> {
        let rtxn = self.store.env.read_txn()?;
        let mut unnamed = Vec::new();
        for entry in batch {
            if !RAW_OUTPUT_ROWS.contains(&self.store, &rtxn, &raw_output_handle(&entry.digest))?
                && !digest_is_held_in_txn(&self.store, &rtxn, &entry.digest)?
            {
                unnamed.push(entry);
            }
        }
        Ok(unnamed)
    }
}
