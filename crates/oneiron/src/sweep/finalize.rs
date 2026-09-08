//! Job finalize, retry rewrite, and dropped-obligation audit.

use std::collections::BTreeSet;

#[cfg(all(feature = "sync", test))]
use super::run::{INJECT_UW_ROW_BEFORE_FINALIZE, RACE_BENIGN_MARKER};
use super::run::{RETRY_BACKOFF_BASE_SECS, RETRY_BACKOFF_CAP_SECS};
use crate::Vault;
use crate::deletion::{
    HARD_ERASE_SWEEP_PREFIX, HardEraseSweepJob, decode_hard_erase_sweep_job,
    decode_hard_erase_sweep_seq, decode_redaction_audit_receipt, encode_hard_erase_sweep_job_value,
    validate_redaction_receipt_body,
};
#[cfg(all(feature = "sync", test))]
use crate::entity_id::EntityId;
#[cfg(all(feature = "sync", test))]
use crate::error::SyncEngineContext;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_REDACTION_AUDIT;

/// Finalizes one job: set `sweep_complete_at` on every matching pending
/// receipt and delete the `h:` row — in ONE transaction, row deletion last
/// (a crash before the commit keeps the obligation; the re-run is
/// idempotent).
///
/// Receipt↔job correlation is scope-set equality: origin and replay both
/// write the receipt and its job in the same transaction with the same
/// scope. When several pending receipts share a scope (delete → re-put →
/// delete again), one completed sweep satisfies all of them — the
/// obligation ("the ids' historical carriers are scrubbed") is global per
/// run, and the sibling job then finalizes nothing extra.
///
/// Returns `Ok(Some(n))` when finalized (n receipts updated), or `Ok(None)`
/// when DEFERRED by the final carrier fence: `compact_all_windows` only
/// reaches here as `AllCompacted` when ZERO windows were live, so a swept
/// window then carries ZERO `u:w:` rows. Any `u:w:` row observed inside the
/// finalize txn is therefore an unambiguous post-compaction arrival — a
/// SECOND TOCTOU between compaction-commit and finalize. The fence scans
/// `u:w:` as the FIRST step of the SAME write txn that rewrites receipts and
/// deletes the h: row (LMDB single-writer makes recheck+delete atomic; a
/// separate pre-finalize pass would reintroduce the race) and, on any hit,
/// returns `Ok(None)` with NO mutation. The caller defers the job (no retry
/// backoff consumed); the raced carrier self-heals on the next run.
pub(super) fn finalize_job(
    vault: &Vault,
    job_key: &[u8],
    job: &HardEraseSweepJob,
    now: u64,
) -> Result<Option<u64>> {
    // Test-only carrier-race injection: land a valid `u:w:` row in the gap
    // between compaction-commit and the finalize txn so the in-txn fence
    // below observes it. Its own committed txn (the finalize txn has not
    // opened yet) — same idiom as the compaction-phase race injection.
    #[cfg(all(feature = "sync", test))]
    inject_uw_row_before_finalize(vault)?;

    let job_ids: BTreeSet<&str> = job.scope.entity_ids.iter().map(String::as_str).collect();
    let finalized = vault.with_write_txn(|wtxn| {
        // FINAL CARRIER FENCE (in-txn, FIRST step, NO mutation before it):
        // any `u:w:` row present at AllCompacted-finalize is a post-
        // compaction arrival → abort with no mutation, signalling defer.
        if vault
            .store
            .sync_state
            .prefix_iter(&*wtxn, "u:w:")?
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

        let mut finalized = 0u64;
        let mut rewrites: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        for entry in vault
            .store
            .type_index
            .prefix_iter(&*wtxn, &[ENTITY_TYPE_REDACTION_AUDIT])?
        {
            let (type_key, _) = entry?;
            if type_key.len() != 17 {
                return Err(Error::CorruptedIndex("type index key"));
            }
            let id_bytes: [u8; 16] = type_key[1..17]
                .try_into()
                .map_err(|_| Error::CorruptedIndex("type index key"))?;
            let Some(raw) = vault.store.entities.get(&*wtxn, &id_bytes)? else {
                continue;
            };
            let header_len = crate::batch::ENTITY_METADATA_HEADER_LEN;
            if raw.len() < header_len {
                return Err(Error::CorruptedIndex("entity metadata"));
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
            let mut receipt = decode_redaction_audit_receipt(&raw[header_len..])?;
            if receipt.sweep_queued_at.is_none() || receipt.sweep_complete_at.is_some() {
                continue;
            }
            let receipt_ids: BTreeSet<&str> = receipt
                .scope
                .entity_ids
                .iter()
                .map(String::as_str)
                .collect();
            if receipt_ids != job_ids {
                continue;
            }

            // The single sanctioned mutation: monotone None→Some, envelope
            // preserved byte-exactly, body re-validated before the put.
            receipt.sweep_complete_at = Some(now);
            let body = rmp_serde::to_vec_named(&receipt)
                .map_err(|_| Error::InvariantViolation("redaction audit receipt encode"))?;
            validate_redaction_receipt_body(&body)?;
            let mut rewritten = Vec::with_capacity(header_len + body.len());
            rewritten.extend_from_slice(&raw[..header_len]);
            rewritten.extend_from_slice(&body);
            rewrites.push((id_bytes.to_vec(), rewritten));
        }
        for (id_bytes, rewritten) in &rewrites {
            vault.store.entities.put(wtxn, id_bytes, rewritten)?;
            finalized += 1;
        }
        // Obligation row deletion LAST, same txn (crash-safe ordering).
        vault.store.sync_queue.delete(wtxn, job_key)?;
        Ok(Some(finalized))
    })?;
    if finalized == Some(0) {
        // Job without a pending receipt: §8c-style carrier-only obligation
        // (or a sibling job's sweep already finalized the shared receipt).
        tracing::debug!(
            seq = ?decode_hard_erase_sweep_seq(job_key),
            "sweep: job completed with no pending receipt to finalize"
        );
    }
    Ok(finalized)
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
    vault
        .store
        .sync_state
        .put(&mut wtxn, &format!("u:w:{key}:ffffffff"), &delta)?;
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
    updated.retry_state.attempt_count = updated.retry_state.attempt_count.saturating_add(1);
    let exp = updated.retry_state.attempt_count.min(20);
    let backoff = RETRY_BACKOFF_BASE_SECS
        .saturating_mul(1u64 << exp)
        .min(RETRY_BACKOFF_CAP_SECS);
    updated.retry_state.next_attempt_at = now.saturating_add(backoff);
    updated.retry_state.last_error_code = Some(error_code.to_owned());
    let value = encode_hard_erase_sweep_job_value(&updated)?;
    vault.with_write_txn(|wtxn| {
        vault.store.sync_queue.put(wtxn, job_key, &value)?;
        Ok(())
    })
}

/// ONE-1091 audit: a receipt whose sweep was queued but never completed
/// must be covered by a pending `h:` row — a dropped obligation is
/// DETECTABLE, loud, and counted. Runs after job processing so receipts
/// finalized this run are no longer pending.
pub(super) fn audit_dropped_obligations(vault: &Vault) -> Result<(u64, u64)> {
    let rtxn = vault.store.env.read_txn()?;

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
    for entry in vault
        .store
        .type_index
        .prefix_iter(&rtxn, &[ENTITY_TYPE_REDACTION_AUDIT])?
    {
        let (type_key, _) = entry?;
        if type_key.len() != 17 {
            return Err(Error::CorruptedIndex("type index key"));
        }
        let Some(raw) = vault.store.entities.get(&rtxn, &type_key[1..17])? else {
            continue;
        };
        let header_len = crate::batch::ENTITY_METADATA_HEADER_LEN;
        if raw.len() < header_len {
            return Err(Error::CorruptedIndex("entity metadata"));
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
        if receipt.sweep_queued_at.is_none() || receipt.sweep_complete_at.is_some() {
            continue;
        }
        let needed: BTreeSet<String> = receipt.scope.entity_ids.iter().cloned().collect();
        let covered = job_scopes.iter().any(|scope| needed.is_subset(scope));
        if !covered {
            missing += 1;
            tracing::error!(
                request_id = %receipt.request_id,
                "sweep audit: receipt has sweep_queued_at but NO pending h: row and NO \
                 sweep_complete_at — erasure obligation was DROPPED (GDPR SLA breach signal)"
            );
        }
    }
    Ok((missing, undecodable))
}
