//! The result body collector: released bodies first, then orphan files.

use std::time::SystemTime;

use super::files::{BodyEntry, body_entries, remove_unnamed, sync_dir, unlink_body};
use super::{
    RAW_OUTPUT_ROWS, RAW_OUTPUT_SECRETS, RAW_OUTPUT_TAINTS, raw_output_handle, unowned_mark_key,
};
use crate::provenance::body::{
    digest_is_held_in_txn, released_bodies_in_txn, take_released_in_txn,
};
use crate::store::{BODY_FILE_SHRED_SCOPE, BodyDir, body_key_row_in_txn, retire_body_key_in_txn};
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
    /// Key rows of sealed body files deleted with their final holder's
    /// release (FIX 5348).
    pub keys_retired: usize,
    /// Whether a key's retirement reaches every kept copy, older
    /// checkpoints and backups included. `false`: it reaches the live vault
    /// only, so no retirement here is reported complete (CALLS
    /// "BODY_FILE_SHRED_SCOPE").
    pub retirement_reaches_kept_copies: bool,
}

impl Vault {
    /// Collects the result bodies nothing holds any longer (OF-597): up to
    /// `limit` released digests, then up to `limit` orphan files. Each
    /// released digest is rechecked in the write transaction that drops its
    /// raw-output row and its unowned occurrence's taint sidecar and secret
    /// mark and its sealed file's key row (FIX 5348), and its file and line
    /// index are unlinked only once that commits. An owned occurrence's marks stay with its manifest. An orphan is a body file no
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
        let mut report = ResultBodyCollectReport {
            retirement_reaches_kept_copies: BODY_FILE_SHRED_SCOPE.reaches_kept_copies(),
            ..ResultBodyCollectReport::default()
        };
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
                // A reader holding it keeps it queued for a later pass, and
                // no pin is admitted while its rows and key row go: a reader
                // pinned since reads the snapshot that still holds them.
                let Some(retired) =
                    pins.unless_pinned(digest, || self.retire_released_in_txn(txn, digest))
                else {
                    report.pinned += 1;
                    continue;
                };
                match retired? {
                    Some(instance) => taken.push((*digest, instance)),
                    None => report.held += 1,
                }
            }
            Ok(taken)
        })?;
        report.keys_retired = taken
            .iter()
            .filter(|(_, instance)| instance.is_some())
            .count();
        if taken.is_empty() {
            return Ok(report);
        }
        // The rows are gone for good, so each file may go now. One a reader
        // pinned since stays until the orphan sweep finds it unpinned.
        let dir = self.store.body_dir()?;
        for (digest, instance) in &taken {
            match pins.unless_pinned(digest, || unlink_body(&dir, digest, instance.as_ref())) {
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

    /// Takes the released `digest` off the queue in `txn` and drops its
    /// raw-output row, its unowned occurrence's taint sidecar and secret
    /// mark, and its sealed file's key row (FIX 5348, the live vault only),
    /// when no descriptor holds it again: `Some` with that file's instance,
    /// if it had one. `None` leaves it as it is.
    fn retire_released_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        digest: &[u8; 32],
    ) -> Result<Option<Option<[u8; 16]>>> {
        if !take_released_in_txn(&self.store, txn, digest)? {
            return Ok(None);
        }
        let marks = unowned_mark_key(digest)?;
        RAW_OUTPUT_ROWS.delete(&self.store, txn, &raw_output_handle(digest))?;
        RAW_OUTPUT_TAINTS.delete(&self.store, txn, &marks)?;
        RAW_OUTPUT_SECRETS.delete(&self.store, txn, &marks)?;
        Ok(Some(retire_body_key_in_txn(&self.store, txn, digest)?))
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
    /// names, read in one transaction, and the files of a digest its key
    /// row does not name: a sealed file of another instance, or a plain one
    /// beside a sealed pair (FIX 5348).
    fn unnamed_result_bodies(&self, batch: Vec<BodyEntry>) -> Result<Vec<BodyEntry>> {
        let rtxn = self.store.env.read_txn()?;
        let mut unnamed = Vec::new();
        for entry in batch {
            let named =
                RAW_OUTPUT_ROWS.contains(&self.store, &rtxn, &raw_output_handle(&entry.digest))?
                    || digest_is_held_in_txn(&self.store, &rtxn, &entry.digest)?;
            let keyed =
                body_key_row_in_txn(&self.store, &rtxn, &entry.digest)?.map(|row| row.instance);
            if !named || keyed != entry.instance {
                unnamed.push(entry);
            }
        }
        Ok(unnamed)
    }
}
