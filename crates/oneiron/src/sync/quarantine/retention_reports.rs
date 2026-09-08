//! Seq allocation, retention enforcement, quarantined_records plus sync_doctor.

use super::keys_classifier::{
    LAST_QUARANTINE_SEQ_KEY, MAX_QUARANTINE_ROWS, QUARANTINE_BATCH_DROPS_KEY,
    QUARANTINE_EVICTIONS_KEY, QUARANTINE_MAX_AGE_SECS, QUARANTINE_PREFIX, QuarantineRecord,
    RECENT_REASON_CODES, decode_quarantine_seq, decode_record, decode_u64_le_counter,
};
use super::remat_markers::pending_remat_windows;
use crate::Vault;
use crate::error::{Error, Result};
use serde::Serialize;

pub(super) fn allocate_next_quarantine_seq(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
) -> Result<u64> {
    let metadata = vault
        .store
        .sync_queue
        .get(&*wtxn, LAST_QUARANTINE_SEQ_KEY)?
        .and_then(|raw| decode_u64_le_counter(&raw));
    let max_existing = max_quarantine_seq(vault, wtxn)?;
    let current = match metadata {
        Some(seq) if seq >= max_existing => seq,
        _ => max_existing,
    };
    let next = current
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow("sync quarantine sequence"))?;
    vault
        .store
        .sync_queue
        .put(wtxn, LAST_QUARANTINE_SEQ_KEY, &next.to_le_bytes())?;
    Ok(next)
}

fn max_quarantine_seq(vault: &Vault, wtxn: &heed::RwTxn<'_>) -> Result<u64> {
    let mut max_seq = 0_u64;
    let iter = vault
        .store
        .sync_queue
        .prefix_iter(wtxn, QUARANTINE_PREFIX)?;
    for entry in iter {
        let (key, _) = entry?;
        if let Some(seq) = decode_quarantine_seq(&key) {
            max_seq = max_seq.max(seq);
        }
    }
    Ok(max_seq)
}

/// Enforces quarantine retention: rows past `max_age_secs` (relative to
/// `now`) are evicted, then the oldest rows beyond `max_rows` are evicted.
/// Rows whose value no longer decodes are evicted as well (they carry no
/// usable evidence). Every eviction increments `m:quarantine_evictions`.
pub(super) fn enforce_retention_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    max_rows: usize,
    max_age_secs: u64,
    now: u64,
) -> Result<u64> {
    let mut survivors: Vec<Vec<u8>> = Vec::new();
    let mut evict: Vec<Vec<u8>> = Vec::new();
    {
        let iter = vault
            .store
            .sync_queue
            .prefix_iter(&*wtxn, QUARANTINE_PREFIX)?;
        for entry in iter {
            let (key, value) = entry?;
            if decode_quarantine_seq(&key).is_none() {
                evict.push(key.to_vec());
                continue;
            }
            match decode_record(&value) {
                Ok(rec) if rec.quarantined_at.saturating_add(max_age_secs) < now => {
                    evict.push(key.to_vec());
                }
                Ok(_) => survivors.push(key.to_vec()),
                Err(_) => evict.push(key.to_vec()),
            }
        }
    }
    // `x:{seq:8BE}` keys iterate in insertion order — survivors[0] is oldest.
    if survivors.len() > max_rows {
        let excess = survivors.len() - max_rows;
        evict.extend(survivors.drain(..excess));
    }

    let evicted = evict.len() as u64;
    if evicted == 0 {
        return Ok(0);
    }
    for key in &evict {
        vault.store.sync_queue.delete(wtxn, key)?;
    }
    // Self-heals a malformed counter row instead of failing the replay path:
    // the counter is diagnostics, and a quarantine-write failure here would
    // abort an otherwise-healthy materialization batch.
    let prior = vault
        .store
        .sync_queue
        .get(&*wtxn, QUARANTINE_EVICTIONS_KEY)?
        .and_then(|raw| decode_u64_le_counter(&raw))
        .unwrap_or(0);
    let total = prior.saturating_add(evicted);
    vault
        .store
        .sync_queue
        .put(wtxn, QUARANTINE_EVICTIONS_KEY, &total.to_le_bytes())?;
    tracing::warn!(evicted, total, "sync: quarantine retention evicted rows");
    Ok(evicted)
}

/// On-demand retention pass for the ONE-1087 sweep executor: evicts `x:`
/// rows past the pinned cap/age (4096 rows / ≤30 d) without requiring a new
/// quarantine write to trigger it. Hash-only rows are GDPR-inert, so this
/// is hygiene, not erasure safety. Returns the number of rows evicted.
pub(crate) fn expire_stale_rows(vault: &Vault, now: u64) -> Result<u64> {
    let mut wtxn = vault.store.env.write_txn()?;
    let evicted = enforce_retention_in_txn(
        vault,
        &mut wtxn,
        MAX_QUARANTINE_ROWS,
        QUARANTINE_MAX_AGE_SECS,
        now,
    )?;
    wtxn.commit()?;
    Ok(evicted)
}

// ─── Read surface ────────────────────────────────────────────────────────────

/// Returns all persisted quarantine records ordered by sequence number.
/// Read-only: rows that fail to decode are skipped (retention prunes them
/// on the next write), never silently repaired.
pub fn quarantined_records(vault: &Vault) -> Result<Vec<(u64, QuarantineRecord)>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut records = Vec::new();
    let iter = vault
        .store
        .sync_queue
        .prefix_iter(&rtxn, QUARANTINE_PREFIX)?;
    for entry in iter {
        let (key, value) = entry?;
        let Some(seq) = decode_quarantine_seq(&key) else {
            continue;
        };
        match decode_record(&value) {
            Ok(rec) => records.push((seq, rec)),
            Err(_) => {
                tracing::warn!(seq, "sync: skipping undecodable quarantine row");
            }
        }
    }
    Ok(records)
}

/// Doctor/maintain surface for the sync quarantine + rematerialization
/// markers (ONE-1124 AC5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct SyncQuarantineReport {
    /// Number of currently persisted quarantine rows.
    pub quarantine_count: usize,
    /// Most-recent reason codes, newest first (up to 8).
    pub recent_reason_codes: Vec<String>,
    /// Cumulative retention evictions (`m:quarantine_evictions`).
    pub eviction_count: u64,
    /// Cumulative rows a `TerminalRejectionBatch` accounted by COUNT rather
    /// than by `x:` row, because the pass exceeded
    /// [`MAX_QUARANTINE_ROWS_PER_PASS`] (`m:quarantine_batch_drops`). Nonzero
    /// means a peer sent a frame with more rejectable rows than one pass mints
    /// evidence for — the rejections happened and are accounted here.
    pub batch_drop_count: u64,
    /// Windows with at least one pending `rm:w:{window}:{entity_hex}`
    /// marker — needs-rematerialization. Non-empty is an ERROR signal: a
    /// CRDT-tombstone purge failed, so hard-deleted content may still be
    /// live in the local active store (GDPR SLA breach signal) until
    /// [`drain_remat_markers`] succeeds. Unparsable `rm:` rows surface here
    /// too (fail closed — never dropped).
    pub rm_pending_windows: Vec<String>,
}

/// Builds the sync doctor report: quarantine count, most-recent reason
/// codes, eviction count, and pending `rm:` windows.
pub fn sync_doctor(vault: &Vault) -> Result<SyncQuarantineReport> {
    let records = quarantined_records(vault)?;
    let quarantine_count = records.len();
    let recent_reason_codes = records
        .iter()
        .rev()
        .take(RECENT_REASON_CODES)
        .map(|(_, rec)| rec.reason_code.clone())
        .collect();

    let rtxn = vault.store.env.read_txn()?;
    let eviction_count = vault
        .store
        .sync_queue
        .get(&rtxn, QUARANTINE_EVICTIONS_KEY)?
        .and_then(|raw| decode_u64_le_counter(&raw))
        .unwrap_or(0);
    let batch_drop_count = vault
        .store
        .sync_queue
        .get(&rtxn, QUARANTINE_BATCH_DROPS_KEY)?
        .and_then(|raw| decode_u64_le_counter(&raw))
        .unwrap_or(0);
    drop(rtxn);

    let rm_pending_windows = pending_remat_windows(vault)?;
    let report = SyncQuarantineReport {
        quarantine_count,
        recent_reason_codes,
        eviction_count,
        batch_drop_count,
        rm_pending_windows,
    };
    if !report.rm_pending_windows.is_empty() {
        tracing::error!(
            windows = ?report.rm_pending_windows,
            "sync doctor: rm: markers pending — hard-deleted content may still be live locally (GDPR SLA breach signal)"
        );
    }
    Ok(report)
}
