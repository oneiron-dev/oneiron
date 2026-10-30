//! The result body collector: released bodies first, then orphan files.

use std::time::SystemTime;

use super::files::{BodyEntry, body_entries, remove_unnamed, sync_dir, unlink_body};
use super::{
    RAW_OUTPUT_ROWS, RAW_OUTPUT_SECRETS, RAW_OUTPUT_TAINTS, raw_output_handle, unowned_mark_key,
};
use crate::code_run::code_run_body_held_in_txn;
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
    /// Released digests a descriptor holds again, a raw output holds on its
    /// own (FIX 5399b), or another pass took first, and released bodies a
    /// publisher named again before their file went: off the queue, left
    /// as they are.
    pub held: usize,
    /// Released bodies, and orphan files (FIX 11137), a reader still
    /// pinned: left for a later pass.
    pub pinned: usize,
    /// Orphan body files (and line indexes whose body is gone) removed.
    pub orphans: usize,
    /// Instance rows of body files deleted with their final holder's
    /// release (FIX 5348). Their keys stay in custody: a collection is never
    /// an erase (KS-2A).
    pub keys_retired: usize,
    /// Whether an erase's key retirement reaches every kept copy, older
    /// checkpoints and backups included: `true`, as every body instance's
    /// key rests in typed custody, outside every image (CALLS
    /// "BODY_FILE_SHRED_SCOPE", KS-2A).
    pub retirement_reaches_kept_copies: bool,
}

impl Vault {
    /// Collects the result bodies nothing holds any longer (OF-597): up to
    /// `limit` released digests, then up to `limit` orphan files. Each
    /// released digest is rechecked in the write transaction that drops its
    /// raw-output row and its unowned occurrence's taint sidecar and secret
    /// mark and its sealed file's key row (FIX 5348), and its file and line
    /// index are unlinked only once that commits, in a fresh writer that
    /// finds no row, descriptor or key row naming it again (FIX 5399b). An
    /// owned occurrence's marks stay with its manifest. An orphan is a body
    /// file no raw-output row or descriptor names, older than an hour, so a
    /// body whose row has yet to commit stays; it too goes only once a fresh
    /// writer finds it unnamed. A pinned body is left for a later pass.
    /// Idempotent; a file already gone is fine.
    ///
    /// # Errors
    ///
    /// Storage and filesystem errors as they occur.
    pub fn collect_result_bodies(&self, limit: usize) -> Result<ResultBodyCollectReport> {
        let mut report = self.collect_released_result_bodies(limit)?;
        if limit > 0 {
            let (orphans, pinned) =
                self.sweep_orphan_result_bodies(&self.store.body_dir()?, limit)?;
            report.orphans = orphans;
            report.pinned += pinned;
        }
        // Unnamed debris and expired history go by the one retention policy
        // (FIX 6022, 6228), warning-only.
        self.sweep_body_retention_after_commit();
        self.finish_body_custody_retirements_after_commit();
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
        // The rows are gone for good, so each file may go now, in a fresh
        // writer that reads them again: no row naming the digest commits
        // between that check and the unlink, and a publisher whose file is
        // out before its row holds its pin (FIX 5399b). One a publisher
        // named again, or a reader pinned since, stays until the orphan
        // sweep finds it unnamed and unpinned.
        let dir = self.store.body_dir()?;
        self.with_write_txn_grouped(|txn| {
            for (digest, instance) in &taken {
                if self.released_named_in_txn(txn, digest)? {
                    report.held += 1;
                    continue;
                }
                match pins.unless_pinned(digest, || unlink_body(&dir, digest, instance.as_ref())) {
                    Some(unlinked) => {
                        unlinked?;
                        report.collected += 1;
                    }
                    None => report.pinned += 1,
                }
            }
            Ok(())
        })?;
        if report.collected > 0 {
            sync_dir(&dir)?;
        }
        // An erase's retirement of an instance whose file just went.
        self.finish_body_custody_retirements_after_commit();
        Ok(report)
    }

    /// Carries out every body instance retirement nothing names any longer
    /// (KS-2A). Post-commit and warning-only: the intent is durable, so a
    /// failure here is retried by the next pass and never fails the act
    /// that committed.
    pub(crate) fn finish_body_custody_retirements_after_commit(&self) {
        if let Err(error) = self.store.finish_body_custody_retirements() {
            tracing::warn!(
                error = %error,
                "body key retirement deferred to the next collector pass"
            );
        }
    }

    /// Takes the released `digest` off the queue in `txn` and drops its
    /// raw-output row, its unowned occurrence's taint sidecar and secret
    /// mark, and its sealed file's key row (FIX 5348, the live vault only),
    /// when no descriptor holds it again and no raw output holds it on its
    /// own (FIX 5399b): `Some` with that file's instance, if it had one.
    /// `None` leaves it as it is.
    fn retire_released_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        digest: &[u8; 32],
    ) -> Result<Option<Option<[u8; 16]>>> {
        if !take_released_in_txn(&self.store, txn, digest)?
            || code_run_body_held_in_txn(&self.store, txn, digest)?
        {
            return Ok(None);
        }
        let marks = unowned_mark_key(digest)?;
        RAW_OUTPUT_ROWS.delete(&self.store, txn, &raw_output_handle(digest))?;
        RAW_OUTPUT_TAINTS.delete(&self.store, txn, &marks)?;
        RAW_OUTPUT_SECRETS.delete(&self.store, txn, &marks)?;
        Ok(Some(retire_body_key_in_txn(&self.store, txn, digest)?))
    }

    /// Whether anything in `txn` names the body `digest` its retirement
    /// took: a raw-output row, a descriptor, or a key row bound since (FIX
    /// 5399b).
    fn released_named_in_txn(&self, txn: &heed::RoTxn<'_>, digest: &[u8; 32]) -> Result<bool> {
        Ok(
            RAW_OUTPUT_ROWS.contains(&self.store, txn, &raw_output_handle(digest))?
                || digest_is_held_in_txn(&self.store, txn, digest)?
                || body_key_row_in_txn(&self.store, txn, digest)?.is_some(),
        )
    }

    /// Removes up to `limit` body files in `dir` that no raw-output row or
    /// descriptor names, each with its line index, and line indexes whose
    /// body is gone: what a writer left before its row committed, or the
    /// collector left to a reader. Returns how many went, and how many a
    /// reader's pin kept (FIX 11137).
    fn sweep_orphan_result_bodies(&self, dir: &BodyDir, limit: usize) -> Result<(usize, usize)> {
        let now = SystemTime::now();
        let sealed = self.store.dir_seal(crate::store::KeyScope::Vault).is_some();
        let mut entries = body_entries(dir)?;
        let mut removed = 0;
        let mut pinned = 0;
        while removed < limit {
            let batch = entries
                .by_ref()
                .take(SWEEP_BATCH)
                .collect::<Result<Vec<_>>>()?;
            if batch.is_empty() {
                break;
            }
            let unnamed = self.unnamed_result_bodies(batch, sealed)?;
            if unnamed.is_empty() {
                continue;
            }
            // Each goes in a fresh writer that finds it unnamed again, so no
            // row naming it commits between that check and the unlink (FIX
            // 5399b).
            let (went, kept) = self.with_write_txn_grouped(|txn| {
                let (mut went, mut kept) = (0, 0);
                for entry in &unnamed {
                    if removed + went == limit {
                        break;
                    }
                    if !self.entry_unnamed_in_txn(txn, entry, sealed)? {
                        continue;
                    }
                    if remove_unnamed(dir, entry, now, &self.result_body_pins)? {
                        went += 1;
                    } else if self.result_body_pins.unless_pinned(&entry.digest, || ()).is_none() {
                        kept += 1;
                    }
                }
                Ok((went, kept))
            })?;
            removed += went;
            pinned += kept;
        }
        if removed > 0 {
            sync_dir(dir)?;
        }
        Ok((removed, pinned))
    }

    /// The entries of `batch` nothing names, read in one transaction (see
    /// [`Self::entry_unnamed_in_txn`]); `sealed`: the vault's directory is
    /// sealed.
    fn unnamed_result_bodies(&self, batch: Vec<BodyEntry>, sealed: bool) -> Result<Vec<BodyEntry>> {
        let rtxn = self.store.env.read_txn()?;
        let mut unnamed = Vec::new();
        for entry in batch {
            if self.entry_unnamed_in_txn(&rtxn, &entry, sealed)? {
                unnamed.push(entry);
            }
        }
        Ok(unnamed)
    }

    /// Whether `entry` is unnamed in `txn`: no raw-output row or descriptor
    /// names its digest, or its digest's key row does not name it, as a
    /// sealed file of another instance or a plain one beside a sealed pair
    /// is not (FIX 5348).
    fn entry_unnamed_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        entry: &BodyEntry,
        sealed: bool,
    ) -> Result<bool> {
        let named =
            RAW_OUTPUT_ROWS.contains(&self.store, txn, &raw_output_handle(&entry.digest))?
                || digest_is_held_in_txn(&self.store, txn, &entry.digest)?;
        // A plain file is named by its digest alone; a sealed one by the
        // instance its row names.
        let keyed = if sealed {
            body_key_row_in_txn(&self.store, txn, &entry.digest)?.map(|row| row.instance)
        } else {
            None
        };
        Ok(!named || keyed != entry.instance)
    }
}
