//! The result body collector: released bodies first, then orphan files.

use std::collections::BTreeSet;
use std::time::SystemTime;

use super::BODY_GRACE;
use super::ResultBodyPin;
use super::files::{BodyEntry, body_entries, entry_retirable, sync_dir, unlink_retiring};
use super::{RAW_OUTPUT_ROWS, raw_output_handle, unowned_mark_key};
use crate::code_run::code_run_body_held_in_txn;
use crate::provenance::body::{
    digest_is_held_in_txn, released_bodies_in_txn, take_released_in_txn,
};
use crate::store::result_body_pins::RetiringFile;
use crate::store::{BODY_FILE_SHRED_SCOPE, BodyDir, body_key_row_in_txn, retire_body_key_in_txn};
use crate::{Result, Vault};

/// Body directory names the orphan sweep checks under one read transaction.
const SWEEP_BATCH: usize = 256;

/// What one drain of the collector's notes came to (FIX 22101).
#[derive(Default)]
struct Retired {
    /// Files that went.
    removed: usize,
    /// Notes an older read snapshot or a reader's pin keeps for a later
    /// pass, and ones a pin taken since forgot.
    kept: usize,
    /// Files a write names again: their notes are forgotten.
    named: usize,
}

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
    /// pinned, or a read snapshot older than their release may still read
    /// (FIX 22101): left for a later pass.
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
    /// writer finds it unnamed. A pinned body is left for a later pass. No
    /// file goes while a read transaction older than the write that stopped
    /// naming it is live, so every snapshot reads the files it names,
    /// whatever door opened it (FIX 22101). Idempotent; a file already gone
    /// is fine.
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
        let pins = &self.result_body_pins;
        if !released.is_empty() {
            report.keys_retired = self.with_write_txn_grouped(|txn| {
                // The write that stops naming them: a read snapshot older
                // than it still names their files (FIX 22101).
                let since = txn.id();
                let mut keys = 0;
                for digest in &released {
                    // A reader holding it keeps it queued for a later pass,
                    // and no pin is admitted while its rows and key row go:
                    // a reader pinned since reads the snapshot that still
                    // holds them.
                    let Some(retired) =
                        pins.unless_pinned(digest, || self.retire_released_in_txn(txn, digest))
                    else {
                        report.pinned += 1;
                        continue;
                    };
                    match retired? {
                        Some(instance) => {
                            keys += usize::from(instance.is_some());
                            pins.retire(*digest, RetiringFile::Released(instance), since);
                        }
                        None => report.held += 1,
                    }
                }
                Ok(keys)
            })?;
        }
        // The rows are gone for good, so each file goes once no older
        // snapshot is left, in a fresh writer that reads them again: no row
        // naming the digest commits between that check and the unlink, and
        // a publisher whose file is out before its row holds its pin (FIX
        // 5399b). One a publisher named again stays; one a reader pinned
        // since is left to the orphan sweep.
        if limit > 0 {
            let retired = self.remove_due_retiring(
                &self.store.body_dir()?,
                |_, file| matches!(file, RetiringFile::Released(_)),
                limit,
            )?;
            report.collected += retired.removed;
            report.pinned += retired.kept;
            report.held += retired.named;
        }
        // An erase's retirement of an instance whose file just went.
        self.finish_body_custody_retirements_after_commit();
        Ok(report)
    }

    /// Unlinks up to `limit` of the files the collector noted as unnamed
    /// that `wanted` takes, once no live read transaction is older than the
    /// committed write that noted it, as the reader table reads under the
    /// unlinking writer (FIX 22101): every snapshot left sees it unnamed,
    /// and a write that named it since held a pin, whose drop forgot the
    /// note. Each goes in a fresh writer that finds it unnamed again, under
    /// the pin lock, so no pin is taken between that check and the unlink.
    /// A file a write names again is forgotten.
    fn remove_due_retiring(
        &self,
        dir: &BodyDir,
        wanted: impl Fn(&[u8; 32], &RetiringFile) -> bool,
        limit: usize,
    ) -> Result<Retired> {
        let mut retired = Retired::default();
        let oldest = self.store.env.oldest_reader_txn_id()?;
        let (due, waiting) = self.result_body_pins.due_retiring(oldest, limit, wanted);
        retired.kept = waiting;
        if due.is_empty() {
            return Ok(retired);
        }
        let sealed = self.store.dir_seal(crate::store::KeyScope::Vault).is_some();
        let pins = &self.result_body_pins;
        self.with_write_txn_grouped(|txn| {
            // The sample above may predate a note another collector made
            // since: each note goes only when the reader table, read again
            // under this writer, holds no snapshot older than the write that
            // made it, and that write has committed; one this writer's own
            // commit group made waits (FIX 22101). No reader opened from here
            // on sees an older snapshot.
            let writer = txn.id();
            let oldest = self.store.env.oldest_reader_txn_id()?;
            for (digest, file, since) in &due {
                if *since >= writer || oldest.is_some_and(|oldest| oldest < *since) {
                    retired.kept += 1;
                    continue;
                }
                let named = match *file {
                    RetiringFile::Released(_) => self.released_named_in_txn(txn, digest)?,
                    RetiringFile::Entry { instance, index } => {
                        let entry = BodyEntry {
                            digest: *digest,
                            instance,
                            index,
                        };
                        !self.entry_unnamed_in_txn(txn, &entry, sealed)?
                    }
                };
                if named {
                    pins.forget_retiring(digest, *file);
                    retired.named += 1;
                    continue;
                }
                match pins.remove_retiring(digest, *file, *since, || {
                    unlink_retiring(dir, digest, *file)
                }) {
                    Some(unlinked) => retired.removed += usize::from(unlinked?),
                    None => retired.kept += 1,
                }
            }
            Ok(())
        })?;
        if retired.removed > 0 {
            sync_dir(dir)?;
        }
        Ok(retired)
    }

    /// Gives back a save's `pins` and unlinks each body it brought into
    /// `bodies/` as a new instance that nothing names once its transaction
    /// has ended: a refused save, or a copy that skipped its MESSAGE, leaves
    /// no base copy of off-record bytes for the orphan sweep (FIX 3633). Each
    /// is noted in a fresh writer that finds it unnamed and goes once no
    /// older read snapshot is left (FIX 22101); one a reader pins, or one an
    /// older snapshot keeps, stays for a later pass. Warning-only: it never
    /// fails the save it follows.
    pub(crate) fn discard_unnamed_promoted_bodies(&self, pins: Vec<ResultBodyPin>) {
        let sealed = self.store.dir_seal(crate::store::KeyScope::Vault).is_some();
        let imported: Vec<BodyEntry> = pins
            .iter()
            .filter_map(|pin| {
                let digest = pin.digest()?;
                let instance = self.result_body_pins.promoted(&digest)?;
                Some(BodyEntry {
                    digest,
                    instance: sealed.then_some(instance),
                    index: false,
                })
            })
            .collect();
        drop(pins);
        if imported.is_empty() {
            return;
        }
        let pins = &self.result_body_pins;
        let discarded = self.store.body_dir().and_then(|dir| {
            let mut noted = Vec::new();
            self.with_write_txn_grouped(|txn| {
                // An older snapshot may name the same file: it goes once
                // none is left (FIX 22101).
                let since = txn.id();
                for entry in &imported {
                    if self.entry_unnamed_in_txn(txn, entry, sealed)? && !pins.holds(&entry.digest)
                    {
                        pins.retire(entry.digest, entry.retiring(), since);
                        noted.push((entry.digest, entry.retiring()));
                    }
                }
                Ok(())
            })?;
            self.remove_due_retiring(
                &dir,
                |digest, file| noted.contains(&(*digest, *file)),
                noted.len(),
            )
            .map(drop)
        });
        if let Err(error) = discarded {
            tracing::warn!(
                error = %error,
                "an unnamed promoted result body is left to the orphan sweep"
            );
        }
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
        crate::code_run::drop_code_run_result_marks_in_txn(&self.store, txn, &marks)?;
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
    /// collector left to a reader. Each is noted in a fresh writer that
    /// finds it unnamed, and goes once no read snapshot older than that
    /// writer is left (FIX 22101). Returns how many went, and how many a
    /// reader's pin kept (FIX 11137) or an older snapshot keeps for now.
    fn sweep_orphan_result_bodies(&self, dir: &BodyDir, limit: usize) -> Result<(usize, usize)> {
        let now = SystemTime::now();
        let sealed = self.store.dir_seal(crate::store::KeyScope::Vault).is_some();
        let pins = &self.result_body_pins;
        let mut entries = body_entries(dir)?;
        let mut noted = 0;
        let mut pinned = 0;
        while noted < limit {
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
            // Each is noted in a fresh writer that finds it unnamed again,
            // so no row naming it commits between that check and the note
            // (FIX 5399b).
            let (went, kept) = self.with_write_txn_grouped(|txn| {
                let since = txn.id();
                let (mut went, mut kept) = (0, 0);
                for entry in &unnamed {
                    if noted + went == limit {
                        break;
                    }
                    if !self.entry_unnamed_in_txn(txn, entry, sealed)?
                        || !entry_retirable(dir, entry, now, Some(BODY_GRACE))?
                    {
                        continue;
                    }
                    if pins.holds(&entry.digest) {
                        kept += 1;
                        continue;
                    }
                    pins.retire(entry.digest, entry.retiring(), since);
                    went += 1;
                }
                Ok((went, kept))
            })?;
            noted += went;
            pinned += kept;
        }
        let retired = self.remove_due_retiring(dir, |_, _| true, limit)?;
        Ok((retired.removed, pinned + retired.kept))
    }

    /// Removes the staged `digests` an aborted import left unnamed (FIX
    /// 588): the import's post-error cleanup, run once its pins are
    /// released. Each entry is noted only once a fresh writer finds it
    /// unnamed again, as the orphan sweep's are, so a newly named or shared
    /// body is never deleted, and goes once no older read snapshot is left
    /// (FIX 22101); there is no age floor, as a just-staged body is still
    /// debris once its writer aborted. Returns how many went, how many a
    /// reader's pin or an older snapshot kept, and how many were not their
    /// entry's to remove. The hourly sweep stays the backstop for what this
    /// leaves.
    pub(crate) fn cleanup_import_staged_bodies(
        &self,
        staged: &[[u8; 32]],
    ) -> Result<(usize, usize, usize)> {
        if staged.is_empty() {
            return Ok((0, 0, 0));
        }
        let dir = self.store.body_dir()?;
        let sealed = self.store.dir_seal(crate::store::KeyScope::Vault).is_some();
        let wanted: BTreeSet<&[u8; 32]> = staged.iter().collect();
        let entries = body_entries(&dir)?
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .filter(|entry| wanted.contains(&entry.digest))
            .collect::<Vec<_>>();
        if entries.is_empty() {
            return Ok((0, 0, 0));
        }
        let pins = &self.result_body_pins;
        let now = SystemTime::now();
        let (mut pinned, mut skipped) = (0, 0);
        let mut noted = Vec::new();
        self.with_write_txn_grouped(|txn| {
            // Another instance of a staged digest may be one an older
            // snapshot names: each goes once none is left (FIX 22101).
            let since = txn.id();
            for entry in &entries {
                if !self.entry_unnamed_in_txn(txn, entry, sealed)? {
                    continue;
                }
                if !entry_retirable(&dir, entry, now, None)? {
                    skipped += 1;
                    continue;
                }
                if pins.holds(&entry.digest) {
                    pinned += 1;
                    continue;
                }
                pins.retire(entry.digest, entry.retiring(), since);
                noted.push((entry.digest, entry.retiring()));
            }
            Ok(())
        })?;
        let retired = self.remove_due_retiring(
            &dir,
            |digest, file| noted.contains(&(*digest, *file)),
            noted.len(),
        )?;
        Ok((
            retired.removed,
            pinned + retired.kept,
            skipped + retired.named,
        ))
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
