//! Job finalize, retry rewrite, and dropped-obligation audit.

use std::collections::BTreeSet;

#[cfg(all(feature = "sync", test))]
use super::run::{INJECT_UW_ROW_BEFORE_FINALIZE, RACE_BENIGN_MARKER};
use super::run::{RETRY_BACKOFF_BASE_SECS, RETRY_BACKOFF_CAP_SECS};
use crate::Vault;
use crate::deletion::{
    HARD_ERASE_SWEEP_PREFIX, HardEraseRetryState, HardEraseSweepJob,
    WITHDRAWN_GENERATION_SWEEP_PREFIX, WithdrawnGenerationSweepJob,
    append_redaction_sweep_completion_in_txn, decode_hard_erase_sweep_job,
    decode_hard_erase_sweep_seq, decode_redaction_audit_receipt, encode_hard_erase_sweep_job_value,
    encode_withdrawn_generation_job_value, finish_redaction_erase_in_txn,
    is_corrupt_claim_repair_event, raise_withdrawn_generation_fence_in_txn,
    receipt_attested_by_this_device_in_txn, redaction_sweep_completion_in_txn,
    validate_redaction_receipt_body,
};
use crate::entity_id::EntityId;
#[cfg(all(feature = "sync", test))]
use crate::error::SyncEngineContext;
use crate::error::{Error, Result, SecretError};
use crate::ports::{EntityStoreRead, WindowDeletionRows};
use crate::registry::ENTITY_TYPE_REDACTION_AUDIT;
#[cfg(all(feature = "sync", test))]
use crate::sync::window_rows::WINDOW_UPDATE;

/// Finalizes one job: append a signed linked completion row (OF-470,
/// ARCH-0038 step 10) for every matching pending receipt, then its erase's
/// overall final row when every custody retirement the receipt binds has
/// finished too (FIX 5844), and delete the `h:` row — in ONE transaction,
/// row deletion last (a crash before the commit keeps the obligation; the
/// re-run is idempotent). The job goes even while custody is pending: the
/// final row's later retries read the receipts, never the job. A receipt is
/// never rewritten; one whose completion row exists is no longer pending.
///
/// Receipt↔job correlation is scope-set equality: origin and replay both
/// write the receipt and its job in the same transaction with the same
/// scope. When several pending receipts share a scope (delete → re-put →
/// delete again), one completed sweep satisfies all of them — the
/// obligation ("the ids' historical carriers are scrubbed") is global per
/// run, and the sibling job then finalizes nothing extra. Only a receipt
/// this device attested gets its completion row here; a replicated one is
/// its own device's to complete, and the job's scrub still finishes (FIX
/// 2596).
///
/// Returns [`FinalizeOutcome::FenceDeferred`] when DEFERRED by the final
/// carrier fence: `compact_all_windows` only reaches here as `AllCompacted`
/// when ZERO windows were live, so a swept window then carries ZERO `u:w:`
/// rows. Any `u:w:` row observed inside the finalize txn is therefore an
/// unambiguous post-compaction arrival — a SECOND TOCTOU between
/// compaction-commit and finalize. The fence scans `u:w:` as the FIRST step
/// of the SAME write txn that appends completions and deletes the h: row
/// (LMDB single-writer makes recheck+delete atomic; a separate pre-finalize
/// pass would reintroduce the race) and, on any hit, defers with NO mutation.
/// The caller defers the job (no retry backoff consumed); the raced carrier
/// self-heals on the next run.
pub(super) fn finalize_job(
    vault: &Vault,
    job_key: &[u8],
    job: &HardEraseSweepJob,
    now: u64,
) -> Result<FinalizeOutcome> {
    // Test-only carrier-race injection: land a valid `u:w:` row in the gap
    // between compaction-commit and the finalize txn so the in-txn fence
    // below observes it. Its own committed txn (the finalize txn has not
    // opened yet) — same idiom as the compaction-phase race injection.
    #[cfg(all(feature = "sync", test))]
    inject_uw_row_before_finalize(vault)?;

    // A completion row is signed in the txn: load the device key first (P6c).
    // A job with no pending receipt signs nothing, so an install that cannot
    // load it still finalizes that; the in-txn signer refuses if it must
    // sign, and the job waits for the next pass (FIX 2597).
    let signing = vault.prepare_install_signing();
    let job_ids: BTreeSet<&str> = job.scope.entity_ids.iter().map(String::as_str).collect();
    let finalized = vault.with_write_txn_grouped(|wtxn| {
        // FINAL CARRIER FENCE (in-txn, FIRST step, NO mutation before it):
        // any `u:w:` row present at AllCompacted-finalize is a post-
        // compaction arrival → abort with no mutation, signalling defer.
        //
        // Raw keys, undecoded: any row at all is an arrival.
        if vault
            .store
            .port_window_update_keys(wtxn, None, |_| ())?
            .next()
            .transpose()?
            .is_some()
        {
            tracing::warn!(
                seq = ?decode_hard_erase_sweep_seq(job_key),
                "sweep: u:w: carrier arrived after compaction, before finalize — \
                 obligation kept, job deferred (fail closed, no retry consumed)"
            );
            return Ok(None);
        }

        if crate::note::any_citation_erase_pending(&vault.store, wtxn)? {
            return Ok(None);
        }
        // A retained copy of a scoped row, kept again since the sweep
        // scrubbed it, holds the job for the next pass (FIX 7998).
        #[cfg(feature = "sync")]
        {
            let scoped = job
                .scope
                .entity_ids
                .iter()
                .filter_map(|hex| EntityId::from_hex(hex).ok());
            if crate::sync::federation_burst::retained_copies_in(
                &vault.store,
                wtxn,
                &scoped.collect::<Vec<_>>(),
            )? {
                return Ok(None);
            }
        }
        let mut finalized = 0u64;
        let mut completed = Vec::new();
        for id in vault
            .store
            .port_entity_ids_by_type(&*wtxn, ENTITY_TYPE_REDACTION_AUDIT, None)?
        {
            let id = id?;
            let Some(raw) = vault.store.port_entity_raw(&*wtxn, &id)? else {
                continue;
            };
            let header_len = crate::batch::ENTITY_METADATA_HEADER_LEN;
            if raw.len() < header_len {
                return Err(Error::CorruptedIndex("entity metadata"));
            }
            // A valid corrupt-CLAIM repair event is no erase receipt and owes
            // no sweep (FIX 7800); any other body still meets the check below.
            if is_corrupt_claim_repair_event(&raw[header_len..]) {
                continue;
            }
            // Finding 2 (fail closed): a REDACTION_AUDIT entity
            // whose body cannot be decoded is on-disk accountability
            // corruption, NOT a foreign shape — we cannot prove it is
            // unrelated to this job's scope, so we abort the WHOLE finalize
            // txn (the h: row is kept; any co-scoped valid receipt staged so
            // far rolls back too — all-or-nothing). The exact literal
            // `decode_redaction_audit_receipt` already emits is reused, and
            // the AllCompacted loop catches it to route THIS job to retry.
            //
            // Structural validation FIRST, on the STORED raw bytes: Serde's
            // `decode_redaction_audit_receipt` silently drops unknown fields,
            // so a re-encode-then-validate (below, line ~859) only ever sees
            // the dropped-field body and lets a divergent stored receipt
            // finalize. The raw validator rejects unknown/duplicate keys, so
            // running it on the on-disk body closes that gap. Its native
            // `InvalidRedactionReceiptBody` is MAPPED to the exact
            // `CorruptedIndex("redaction audit receipt body")` literal the
            // AllCompacted loop's per-job retry arm catches — without the map
            // it would hit `Err(err) => return Err(err)` and hard-abort the
            // WHOLE sweep run instead of keeping this one h: row for retry.
            validate_redaction_receipt_body(&raw[header_len..])
                .map_err(|_| Error::CorruptedIndex("redaction audit receipt body"))?;
            let receipt = decode_redaction_audit_receipt(&raw[header_len..])?;
            // An initial receipt alone owes a sweep: its appended sweep and
            // final rows owe none.
            if receipt.sweep_queued_at.is_none() || !receipt.is_initial() {
                continue;
            }
            let receipt_ids: BTreeSet<&str> = receipt
                .scope
                .entity_ids
                .iter()
                .map(String::as_str)
                .collect();
            // A receipt another device attested is its device's to complete
            // (FIX 2596).
            if receipt_ids != job_ids
                || !receipt_attested_by_this_device_in_txn(vault, &*wtxn, &id, &receipt)?
            {
                continue;
            }
            // Completed already: its linked completion row exists. A
            // different occupant there aborts this job to retry.
            if redaction_sweep_completion_in_txn(&vault.store, &*wtxn, &id, &receipt)?.is_some() {
                continue;
            }

            completed.push((id, receipt));
        }
        // Append, never update: each pending receipt gets its signed linked
        // completion row. Its final row, and a legal hold's "erase
        // completed" with it, follow here once the receipt's custody
        // retirements have finished as well; a custody fault keeps it owed.
        for (id, receipt) in &completed {
            if append_redaction_sweep_completion_in_txn(vault, wtxn, id, receipt, now)? {
                finalized += 1;
            }
            finish_redaction_erase_in_txn(vault, wtxn, id, receipt, now)?;
        }
        // An erased epoch summary's words have left every window now, and
        // what it was withdrawn for retires with them.
        for hex in &job.scope.entity_ids {
            if let Ok(id) = EntityId::from_hex(hex) {
                crate::ports::retire_withdrawn_in_txn(&vault.store, wtxn, &id)?;
            }
        }
        // Obligation row deletion LAST, same txn (crash-safe ordering).
        vault.store.sync_queue.delete(wtxn, job_key)?;
        Ok(Some(finalized))
    });
    let finalized = match finalized {
        Ok(Some(finalized)) => finalized,
        Ok(None) => return Ok(FinalizeOutcome::FenceDeferred),
        // The in-txn signer refused a pending receipt's completion row: the
        // txn rolled back, so the obligation and its receipts are as they
        // were. The preparer's fault is the cause when it had one.
        Err(Error::Secret(SecretError::KeystoreUnavailable(refused))) => {
            let cause = signing
                .err()
                .unwrap_or(Error::Secret(SecretError::KeystoreUnavailable(refused)));
            return Ok(FinalizeOutcome::SignerUnavailable(cause));
        }
        Err(error) => return Err(error),
    };
    if finalized == 0 {
        // Job without a pending receipt: §8c-style carrier-only obligation
        // (or a sibling job's sweep already finalized the shared receipt).
        tracing::debug!(
            seq = ?decode_hard_erase_sweep_seq(job_key),
            "sweep: job completed with no pending receipt to finalize"
        );
    }
    Ok(FinalizeOutcome::Finalized(finalized))
}

/// What one [`finalize_job`] came to.
pub(super) enum FinalizeOutcome {
    /// Finalized, with this many completion rows appended.
    Finalized(u64),
    /// The final carrier fence deferred it, with no mutation.
    FenceDeferred,
    /// A pending receipt of this device's needed its completion row signed,
    /// and this install's signer was not loaded (FIX 2597): nothing was
    /// written, and the next pass tries again. Carries the cause.
    SignerUnavailable(Error),
}

/// Finalizes one withdrawn-generation job (OF-013): raise the artifact's
/// fence to the generation, retire its withdrawn-worlds record once no other
/// `hw:` row of it waits, and delete the `hw:` row LAST, in ONE transaction
/// behind the same in-txn carrier fence as [`finalize_job`]. No receipt
/// changes: a withdrawal writes none. `false` when the fence deferred it
/// (no mutation, no retry consumed).
pub(super) fn finalize_withdrawn_job(
    vault: &Vault,
    job_key: &[u8],
    id: &EntityId,
    job: &WithdrawnGenerationSweepJob,
) -> Result<bool> {
    vault.with_write_txn_grouped(|wtxn| {
        if vault
            .store
            .port_window_update_keys(wtxn, None, |_| ())?
            .next()
            .transpose()?
            .is_some()
        {
            tracing::warn!(
                entity = %id.to_hex(),
                "sweep: u:w: carrier arrived after compaction, before finalize — \
                 hw: obligation kept, job deferred (fail closed, no retry consumed)"
            );
            return Ok(false);
        }
        // Ingest keeps refusing the withdrawn body once this row is gone, and
        // the fence keeps the row's replacement (FIX 931).
        raise_withdrawn_generation_fence_in_txn(&vault.store, wtxn, id, job.scope.cutoff())?;
        // The words have left every window, and what the artifact was
        // withdrawn for retires with them, unless another generation of it
        // still waits.
        let prefix = [WITHDRAWN_GENERATION_SWEEP_PREFIX, id.as_bytes()].concat();
        let mut waiting = false;
        for row in vault.store.sync_queue.prefix_iter(&*wtxn, &prefix)? {
            let (key, _) = row?;
            waiting |= *key != *job_key;
        }
        if !waiting {
            crate::ports::retire_withdrawn_in_txn(&vault.store, wtxn, id)?;
        }
        // Obligation row deletion LAST, same txn (crash-safe ordering).
        vault.store.sync_queue.delete(wtxn, job_key)?;
        Ok(true)
    })
}

/// Test-only seam — see [`INJECT_UW_ROW_BEFORE_FINALIZE`]. When armed with a
/// window label, appends a fresh, VALID higher-seq `u:w:{window}:*` update
/// row (built from the window's own lineage so a clean re-run imports it
/// without missing deps) in its OWN committed txn, then disarms. Mirrors the
/// compaction-phase race injection.
#[cfg(all(feature = "sync", test))]
fn inject_uw_row_before_finalize(vault: &Vault) -> Result<()> {
    use crate::sync::loro_support::{doc_from_snapshot, export_updates_from};
    use crate::sync::schema::create_window_doc;
    use crate::sync::types::WindowKey;

    let Some(label) = INJECT_UW_ROW_BEFORE_FINALIZE.with(|cell| cell.borrow_mut().take()) else {
        return Ok(());
    };
    let key = WindowKey::new(&label);
    let snapshot = vault.sync_state_get(&format!("d:w:{key}"))?;
    let racer = match snapshot {
        Some(bytes) => doc_from_snapshot(&bytes)?,
        None => create_window_doc("racer", &key),
    };
    let base_vv = racer.oplog_vv();
    racer
        .get_map("entities")
        .insert(EntityId::now().to_hex().as_str(), RACE_BENIGN_MARKER)
        .map_err(|e| Error::sync_engine(SyncEngineContext::LoroMapInsert, e))?;
    racer.commit();
    let delta = export_updates_from(&racer, &base_vv)?;
    let mut wtxn = vault.store.env.write_txn()?;
    WINDOW_UPDATE.put(
        &vault.store,
        &mut wtxn,
        &crate::sync::window_rows::WindowUpdateKey {
            window: key.to_string(),
            seq: 0xffff_ffff,
        },
        &delta,
    )?;
    wtxn.commit()?;
    Ok(())
}

/// Rewrites a job's `retry_state` IN PLACE after a failed attempt (the row
/// is never deleted on failure): attempt_count+1, exponential backoff
/// capped at 24 h, the failing `ErrorKind` name in `last_error_code`.
/// `queued_at` / `deadline_at` are untouched — backoff never extends the
/// 30-day SLA clock.
pub(super) fn rewrite_job_for_retry(
    vault: &Vault,
    job_key: &[u8],
    job: &HardEraseSweepJob,
    now: u64,
    error_code: &str,
) -> Result<()> {
    let mut updated = job.clone();
    retry_later(&mut updated.retry_state, now, error_code);
    let value = encode_hard_erase_sweep_job_value(&updated)?;
    vault.with_write_txn_grouped(|wtxn| {
        vault.store.sync_queue.put(wtxn, job_key, &value)?;
        Ok(())
    })
}

/// [`rewrite_job_for_retry`] for a `hw:` withdrawn-generation job.
pub(super) fn rewrite_withdrawn_job_for_retry(
    vault: &Vault,
    job_key: &[u8],
    job: &WithdrawnGenerationSweepJob,
    now: u64,
    error_code: &str,
) -> Result<()> {
    let mut updated = job.clone();
    retry_later(&mut updated.retry_state, now, error_code);
    let value = encode_withdrawn_generation_job_value(&updated)?;
    vault.with_write_txn_grouped(|wtxn| {
        vault.store.sync_queue.put(wtxn, job_key, &value)?;
        Ok(())
    })
}

/// One more failed attempt: exponential backoff capped at 24 h, the failing
/// `ErrorKind` name kept, the SLA clock untouched.
fn retry_later(state: &mut HardEraseRetryState, now: u64, error_code: &str) {
    state.attempt_count = state.attempt_count.saturating_add(1);
    let exp = state.attempt_count.min(20);
    let backoff = RETRY_BACKOFF_BASE_SECS
        .saturating_mul(1u64 << exp)
        .min(RETRY_BACKOFF_CAP_SECS);
    state.next_attempt_at = now.saturating_add(backoff);
    state.last_error_code = Some(error_code.to_owned());
}

/// ONE-1091 audit: an initial receipt whose sweep was queued but never
/// completed must be covered by a pending `h:` row — a dropped obligation is
/// DETECTABLE, loud, and counted. Runs after job processing so receipts
/// completed this run (their linked completion row) are no longer pending.
/// A sweep complete while custody is pending is complete here. A receipt an
/// owed window compaction names waits on that row (FIX 11082), and a receipt
/// another device attested is that device's obligation (FIX 2596): neither
/// is dropped here.
pub(super) fn audit_dropped_obligations(vault: &Vault) -> Result<(u64, u64)> {
    let rtxn = vault.store.env.read_txn()?;
    #[cfg(feature = "sync")]
    let owed_receipts = super::owed::receipts_owed_compaction_in_txn(vault, &rtxn)?;

    let mut job_scopes: Vec<BTreeSet<String>> = Vec::new();
    for row in vault
        .store
        .sync_queue
        .prefix_iter(&rtxn, HARD_ERASE_SWEEP_PREFIX)?
    {
        let (key, value) = row?;
        if decode_hard_erase_sweep_seq(&key).is_none() {
            continue;
        }
        if let Ok(job) = decode_hard_erase_sweep_job(&value) {
            job_scopes.push(job.scope.entity_ids.iter().cloned().collect());
        }
        // Undecodable rows were already reported by the inventory pass; a
        // receipt they covered will flag below (loud twice — fail closed).
    }

    let mut missing = 0u64;
    let mut undecodable = 0u64;
    for id in vault
        .store
        .port_entity_ids_by_type(&rtxn, ENTITY_TYPE_REDACTION_AUDIT, None)?
    {
        let id = id?;
        let Some(raw) = vault.store.port_entity_raw(&rtxn, &id)? else {
            continue;
        };
        let header_len = crate::batch::ENTITY_METADATA_HEADER_LEN;
        if raw.len() < header_len {
            return Err(Error::CorruptedIndex("entity metadata"));
        }
        // A valid corrupt-CLAIM repair event is no erase receipt: neither
        // undecodable nor an obligation (FIX 7800).
        if is_corrupt_claim_repair_event(&raw[header_len..]) {
            continue;
        }
        // Undecodable count is SCOPED to the audit's own iteration over
        // LOCAL REDACTION_AUDIT obligations (the same predicate scope the covering
        // check already runs) — never a blanket scan over every REDACTION_AUDIT
        // body. An unreadable receipt is itself an un-discharged
        // accountability signal: counted SEPARATELY from `missing`
        // ("present-but-corrupt" ≠ "dropped"), never a quiet skip.
        let receipt = match decode_redaction_audit_receipt(&raw[header_len..]) {
            Ok(receipt) => receipt,
            Err(_) => {
                undecodable += 1;
                tracing::error!(
                    "sweep audit: REDACTION_AUDIT receipt body is undecodable — an \
                     unreadable accountability record (GDPR Art. 5(2) signal), never \
                     a silent skip"
                );
                continue;
            }
        };
        if receipt.sweep_queued_at.is_none() || !receipt.is_initial() {
            continue;
        }
        // A valid linked completion row discharges it. A different occupant
        // there (logged) completes nothing, so a covering h: row is owed.
        match redaction_sweep_completion_in_txn(&vault.store, &rtxn, &id, &receipt) {
            Ok(Some(_)) => continue,
            Ok(None) | Err(Error::CorruptedIndex("redaction audit receipt body")) => {}
            Err(err) => return Err(err),
        }
        let needed: BTreeSet<String> = receipt.scope.entity_ids.iter().cloned().collect();
        let covered = job_scopes.iter().any(|scope| needed.is_subset(scope));
        #[cfg(feature = "sync")]
        let covered = covered || owed_receipts.contains(&id);
        // Another device's receipt is that device's to audit (FIX 2596); a
        // cached identity that does not read counts it here, loud.
        if !covered
            && receipt_attested_by_this_device_in_txn(vault, &rtxn, &id, &receipt).unwrap_or(true)
        {
            missing += 1;
            tracing::error!(
                "sweep audit: receipt has sweep_queued_at but NO pending h: row and NO \
                 sweep_complete_at — erasure obligation was DROPPED (GDPR SLA breach signal)"
            );
        }
    }
    Ok((missing, undecodable))
}
