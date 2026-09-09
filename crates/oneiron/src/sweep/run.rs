//! Sweep driver, run state, and race-injection hooks.

use std::collections::BTreeSet;

use super::compact::compact_all_windows;
use super::finalize::{audit_dropped_obligations, finalize_job, rewrite_job_for_retry};
use crate::Vault;
use crate::deletion::{
    HARD_ERASE_SWEEP_PREFIX, HardEraseSweepJob, decode_hard_erase_sweep_job,
    decode_hard_erase_sweep_seq,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

/// Retry backoff cap: a failed job is retried no later than 24 h out, so
/// the ≤30 d `deadline_at` SLA cannot be silently outwaited by backoff.
pub(super) const RETRY_BACKOFF_CAP_SECS: u64 = 86_400;

/// Base retry backoff (doubles per attempt up to the cap).
pub(super) const RETRY_BACKOFF_BASE_SECS: u64 = 60;

/// Counters for one `run_hard_erase_sweep` pass (mirrored into
/// [`crate::maintain::MaintenanceReport`] by the maintain builder).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HardEraseSweepRun {
    pub jobs_processed: u64,
    pub jobs_deferred: u64,
    pub jobs_failed: u64,
    pub windows_compacted: u64,
    pub windows_deferred_live: u64,
    /// Windows deferred because a `u:w:` row appeared/vanished or the
    /// `d:w:` snapshot changed between the read phase and the compaction
    /// write txn (anti-clobber re-read guard) — the run defers, no carrier
    /// is overwritten, the obligation stays. SIBLING of
    /// `windows_deferred_live`; never folded into it.
    pub windows_deferred_raced: u64,
    pub receipts_finalized: u64,
    pub deadline_breaches: u64,
    pub quarantine_rows_expired: u64,
    pub obligations_missing: u64,
    /// REDACTION_AUDIT receipts whose stored body could not be decoded
    /// during the audit pass — an unreadable accountability record is an
    /// un-discharged signal, NOT a dropped obligation. SIBLING of
    /// `obligations_missing`; never folded into it (that would conflate
    /// "dropped" with "present-but-corrupt").
    pub obligations_undecodable: u64,
}

// Test-only crash injection: when armed, the run fails AFTER window
// compaction committed and BEFORE any job finalization transaction — the
// crash window the h:-row-deletion-LAST ordering must survive. One-shot.
#[cfg(test)]
thread_local! {
    pub(super) static INJECT_CRASH_BEFORE_FINALIZE: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}

/// Test-only race injection (sync builds only): fires once, AFTER
/// `compact_window`'s read phase and BEFORE its compaction write txn, to
/// land a concurrent write that the in-txn re-read guards must catch
/// (Findings 1 + 4). Pre-seeding a `u:w:` row before the run cannot
/// reproduce the race — the read phase would capture it.
#[cfg(all(feature = "sync", test))]
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub(super) enum RaceInjection {
    #[default]
    None,
    /// Append a fresh, VALID higher-seq `u:w:` update row (Finding 1).
    AppendUpdateRow,
    /// Replace the `d:w:` snapshot with a DIFFERENT valid snapshot
    /// (Finding 4).
    ReplaceSnapshot,
}

#[cfg(all(feature = "sync", test))]
thread_local! {
    pub(super) static INJECT_RACE_BEFORE_COMPACT_WRITE: std::cell::Cell<RaceInjection> =
        const { std::cell::Cell::new(RaceInjection::None) };
}

/// Benign, sentinel-free payload the race injection plants — distinctive so
/// a test can prove the externally-written snapshot was NOT clobbered.
#[cfg(all(feature = "sync", test))]
pub(super) const RACE_BENIGN_MARKER: &[u8] = b"SWEEP-RACE-BENIGN-MARKER-5b2e0a";

// Test-only carrier-race injection for the SECOND TOCTOU (sibling of
// INJECT_CRASH_BEFORE_FINALIZE): when armed with a window label, fires ONCE
// at the very start of `finalize_job` — AFTER `compact_all_windows` returned
// AllCompacted (zero u:w: rows anywhere) and BEFORE the finalize write txn
// opens — to append a fresh, VALID `u:w:{window}:*` update row in its own
// committed txn. This reproduces a post-compaction carrier arrival in the gap
// that the in-txn u:w: fence must catch and DEFER (NOT delete the h: row).
// Sync-only: building a valid update needs the Loro helpers.
#[cfg(all(feature = "sync", test))]
thread_local! {
    pub(super) static INJECT_UW_ROW_BEFORE_FINALIZE: std::cell::RefCell<Option<String>> =
        const { std::cell::RefCell::new(None) };
}

/// Executes one manual sweep pass (phase 1; scheduling is M6).
pub(crate) fn run_hard_erase_sweep(vault: &Vault) -> Result<HardEraseSweepRun> {
    let now = crate::unix_seconds_now();
    let mut run = HardEraseSweepRun::default();

    // ── 1. Inventory the h: obligation rows ─────────────────────────────
    let mut jobs: Vec<(Vec<u8>, HardEraseSweepJob)> = Vec::new();
    {
        let rtxn = vault.store.env.read_txn()?;
        for row in vault
            .store
            .sync_queue
            .prefix_iter(&rtxn, HARD_ERASE_SWEEP_PREFIX)?
        {
            let (key, value) = row?;
            if decode_hard_erase_sweep_seq(&key).is_none() {
                // Not the pinned `h:` + seq u64 BE shape — fail closed: the
                // row is kept (it may still be an obligation) and reported.
                tracing::error!(
                    key_len = key.len(),
                    "sweep: malformed h: row key — obligation kept, cannot execute"
                );
                run.jobs_deferred += 1;
                continue;
            }
            match decode_hard_erase_sweep_job(&value) {
                Ok(job) => jobs.push((key.to_vec(), job)),
                Err(_) => {
                    // An undecodable obligation can be neither executed nor
                    // safely discarded — keep the row, report loudly. The
                    // audit pass below will also flag any receipt this row
                    // was covering.
                    tracing::error!(
                        seq = ?decode_hard_erase_sweep_seq(&key),
                        "sweep: undecodable h: job row — obligation kept, cannot execute"
                    );
                    run.jobs_deferred += 1;
                }
            }
        }
    }

    // Deadline surveillance covers EVERY decodable row, due or not — a
    // breach of the queued_at + 30 d SLA (GDPR Art. 12(3)) is loud each run.
    for (key, job) in &jobs {
        if job.retry_state.deadline_at < now {
            run.deadline_breaches += 1;
            tracing::error!(
                seq = ?decode_hard_erase_sweep_seq(key),
                deadline_at = job.retry_state.deadline_at,
                attempt_count = job.retry_state.attempt_count,
                "sweep: h: job past its 30-day deadline (GDPR Art. 12(3) SLA breach)"
            );
        }
    }

    // Per-job independence: not-yet-due rows (retry backoff) are skipped
    // without blocking due jobs and without being rewritten.
    let (due, not_due): (Vec<_>, Vec<_>) = jobs
        .into_iter()
        .partition(|(_, job)| job.retry_state.next_attempt_at <= now);
    run.jobs_deferred += not_due.len() as u64;

    // Finding 3 (kept-and-loud): a decodable job whose `scope.entity_ids`
    // carries a non-parseable hex cannot be compacted-and-finalized —
    // id→window attribution would be wrong. Such a job is KEPT
    // BYTE-IDENTICAL (never added to `due`, never deleted, retry_state
    // untouched) and reported, mirroring the undecodable-h:-row branch.
    // `scope.revision_ids` is purely AUDIT CONTEXT on the phase-1 sweep
    // path (only `entity_ids` drives the erased-id authority and the
    // receipt↔job scope correlation; revision_ids are carried, never
    // consumed for erasure attribution), so only `entity_ids` is validated.
    let (due, malformed_scope): (Vec<_>, Vec<_>) = due.into_iter().partition(|(_, job)| {
        job.scope
            .entity_ids
            .iter()
            .all(|hex| EntityId::from_hex(hex).is_ok())
    });
    for (key, _) in &malformed_scope {
        tracing::error!(
            seq = ?decode_hard_erase_sweep_seq(key),
            "sweep: due h: job carries a malformed scope.entity_ids hex — \
             obligation kept BYTE-IDENTICAL, cannot execute (fail closed)"
        );
    }
    run.jobs_deferred += malformed_scope.len() as u64;

    // ── 2. Erased-id authority: dt: markers ∪ due-job scopes ────────────
    // The permanent `dt:` set covers §8c.2/§8c.3 ids with no local h: row.
    let mut erased: BTreeSet<EntityId> = BTreeSet::new();
    {
        let rtxn = vault.store.env.read_txn()?;
        for row in vault
            .store
            .sync_state
            .prefix_iter(&rtxn, crate::deletion::LOCAL_HARD_DELETE_PREFIX)?
        {
            let (key, _) = row?;
            if let Some(hex) = key.strip_prefix(crate::deletion::LOCAL_HARD_DELETE_PREFIX)
                && let Ok(id) = EntityId::from_hex(hex)
            {
                erased.insert(id);
            }
        }
    }
    for (_, job) in &due {
        for hex in &job.scope.entity_ids {
            if let Ok(id) = EntityId::from_hex(hex) {
                erased.insert(id);
            }
        }
    }

    // ── 3. Compact the historical carriers ──────────────────────────────
    let window_state = compact_all_windows(vault, &erased, &mut run, now)?;

    #[cfg(test)]
    {
        let armed = INJECT_CRASH_BEFORE_FINALIZE.with(std::cell::Cell::take);
        if armed {
            return Err(Error::InvariantViolation(
                "test: injected sweep crash before finalization",
            ));
        }
    }

    // ── 4. Finalize or retry the due jobs ───────────────────────────────
    match window_state {
        WindowSweepState::AllCompacted => {
            for (key, job) in &due {
                match finalize_job(vault, key, job, now) {
                    Ok(Some(finalized)) => {
                        run.receipts_finalized += finalized;
                        run.jobs_processed += 1;
                    }
                    // Final carrier fence (ONE-1087/1091, second TOCTOU): a
                    // `u:w:` row arrived AFTER compaction committed and BEFORE
                    // this finalize txn. The fence aborted the txn with NO
                    // mutation (h: row kept, receipt still nil). This is a
                    // transient race, NOT a failure: defer like the
                    // Deferred-window arm below — increment jobs_deferred and
                    // DO NOT consume retry backoff. Routing through
                    // rewrite_job_for_retry would misclassify it as failed
                    // and burn an attempt. The carrier self-heals next run.
                    Ok(None) => {
                        run.jobs_deferred += 1;
                    }
                    // Finding 2 (fail closed, per-job): an undecodable
                    // REDACTION_AUDIT receipt body aborted THIS job's
                    // finalize txn (the typed CorruptedIndex rolled it
                    // back, so the h: row is kept and any co-scoped valid
                    // receipt stays nil — all-or-nothing). Route this one
                    // job to retry, loud, and continue so sibling jobs
                    // still finalize. ONE corrupt receipt defers ONE job.
                    Err(Error::CorruptedIndex("redaction audit receipt body")) => {
                        tracing::error!(
                            seq = ?decode_hard_erase_sweep_seq(key),
                            "sweep: undecodable REDACTION_AUDIT receipt body during \
                             finalize — obligation kept, job routed to retry (fail closed)"
                        );
                        rewrite_job_for_retry(vault, key, job, now, "CorruptedIndex")?;
                        run.jobs_failed += 1;
                    }
                    Err(err) => return Err(err),
                }
            }
        }
        WindowSweepState::Deferred => {
            // Nothing failed — the engine REFUSED (live window open, or a
            // non-sync build facing CRDT carriers). No attempt was made, so
            // retry_state is not consumed; the obligation simply stays.
            run.jobs_deferred += due.len() as u64;
        }
        WindowSweepState::Failed(error_code) => {
            for (key, job) in &due {
                rewrite_job_for_retry(vault, key, job, now, &error_code)?;
                run.jobs_failed += 1;
            }
        }
    }

    // ── 5. x: quarantine retention (hygiene — rows are hash-only) ───────
    #[cfg(feature = "sync")]
    {
        run.quarantine_rows_expired = crate::sync::quarantine::expire_stale_rows(vault, now)?;
    }

    // ── 6. Audit: detect dropped obligations (ONE-1091) ─────────────────
    let (missing, undecodable) = audit_dropped_obligations(vault)?;
    run.obligations_missing = missing;
    run.obligations_undecodable = undecodable;

    Ok(run)
}

/// Outcome of the window-compaction phase, driving the fail-closed global
/// completion gate.
pub(super) enum WindowSweepState {
    /// Every persisted window compacted (or there were none).
    AllCompacted,
    /// At least one window was refused without an attempt (live window, or
    /// non-sync build with CRDT carriers present).
    Deferred,
    /// At least one window compaction FAILED; carries the first error's
    /// `ErrorKind` name for the jobs' `last_error_code`.
    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    Failed(String),
}
