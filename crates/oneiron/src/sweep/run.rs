//! Sweep driver, run state, and race-injection hooks.

use std::collections::{BTreeMap, BTreeSet};

use super::compact::compact_all_windows;
use super::finalize::{
    audit_dropped_obligations, finalize_job, finalize_withdrawn_job, rewrite_job_for_retry,
    rewrite_withdrawn_job_for_retry,
};
use crate::Vault;
use crate::deletion::{
    HARD_ERASE_SWEEP_PREFIX, HardEraseSweepJob, WITHDRAWN_GENERATION_SWEEP_PREFIX,
    WithdrawnGenerationSweepJob, decode_hard_erase_sweep_job, decode_hard_erase_sweep_seq,
    decode_withdrawn_generation_row, withdrawn_generation_cutoffs_in_txn,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, HexId, Raw, SideTable};

/// The local hard-delete marker this run scans for the erased-id authority.
/// `deletion::tombstone` owns the row family (see its `HARD_DELETE_MARKER`
/// doc comment: other modules keep using `local_hard_delete_key` plus their
/// own raw access) and is not reachable from here, so this binds the SAME
/// declaration independently (two typed tables, one declaration). Key:
/// hex32.
const HARD_DELETE_MARKER: SideTable<HexId, Vec<u8>, Raw> =
    SideTable::new(&side_table::DELETION_HARD_DELETE_MARKER);

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

// Test-only: runs once between a window's read phase and its compaction
// write, so a test can act on the window from another thread at that moment.
#[cfg(all(feature = "sync", test))]
thread_local! {
    pub(super) static BEFORE_COMPACT_WRITE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
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

/// The withdrawn generations one pass rewrites (OF-013), beside the
/// erased-id authority. Unlike an erased id, a withdrawn artifact keeps its
/// row and every newer generation: only its carriers of the withdrawn
/// generation or older change, to the content-free keyframe.
#[derive(Debug, Default)]
pub(super) struct WithdrawnSweep {
    /// Each artifact's newest withdrawn generation, from every `hw:` row and
    /// every fence. A fenced artifact's carriers are rewritten on every pass,
    /// as a `dt:` id's are scrubbed: a late re-put goes with the next one.
    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    pub(super) cutoffs: BTreeMap<EntityId, u64>,
    /// Artifacts with a due `hw:` row: their document outbox goes with this
    /// pass, and every compacted window's queued sends with it.
    pub(super) due: BTreeSet<EntityId>,
    /// Artifacts a carrier or document of which this pass could not clear:
    /// their `hw:` rows wait, and no other obligation waits with them.
    pub(super) held: BTreeSet<EntityId>,
}

/// Executes one sweep pass the owner asked for (phase 1): every window's
/// history is compacted past the erased ids, an obligation due or not.
pub(crate) fn run_hard_erase_sweep(vault: &Vault) -> Result<HardEraseSweepRun> {
    hard_erase_sweep(vault, true)
}

/// Executes one sweep pass no one asked for: the housekeeping pass's, daily
/// and hourly while an obligation waits. It compacts only for a due
/// obligation.
pub(crate) fn run_scheduled_hard_erase_sweep(vault: &Vault) -> Result<HardEraseSweepRun> {
    hard_erase_sweep(vault, false)
}

fn hard_erase_sweep(vault: &Vault, owner_asked: bool) -> Result<HardEraseSweepRun> {
    let now = vault.store.clock.now_recorded_at();
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

    // ── 1b. Inventory the hw: withdrawn-generation rows (OF-013) ────────
    // Decoded strictly, key and scope agreeing; a row that fails is kept and
    // reported like an undecodable h: row, never executed.
    let mut withdrawn_jobs: Vec<(Vec<u8>, EntityId, WithdrawnGenerationSweepJob)> = Vec::new();
    {
        let rtxn = vault.store.env.read_txn()?;
        for row in vault
            .store
            .sync_queue
            .prefix_iter(&rtxn, WITHDRAWN_GENERATION_SWEEP_PREFIX)?
        {
            let (key, value) = row?;
            match decode_withdrawn_generation_row(&key, &value) {
                Ok((id, job)) => withdrawn_jobs.push((key.to_vec(), id, job)),
                Err(_) => {
                    tracing::error!(
                        key_len = key.len(),
                        "sweep: undecodable hw: row — obligation kept, cannot execute"
                    );
                    run.jobs_deferred += 1;
                }
            }
        }
    }
    for (_, id, job) in &withdrawn_jobs {
        if job.retry_state.deadline_at < now {
            run.deadline_breaches += 1;
            tracing::error!(
                entity = %id.to_hex(),
                generation = job.scope.generation,
                deadline_at = job.retry_state.deadline_at,
                attempt_count = job.retry_state.attempt_count,
                "sweep: hw: job past its 30-day deadline"
            );
        }
    }
    let (withdrawn_due, withdrawn_not_due): (Vec<_>, Vec<_>) = withdrawn_jobs
        .into_iter()
        .partition(|(_, _, job)| job.retry_state.next_attempt_at <= now);
    run.jobs_deferred += withdrawn_not_due.len() as u64;

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
        for (HexId(id), _) in HARD_DELETE_MARKER
            .iter_from(&vault.store, &rtxn, &[])?
            .flatten()
        {
            erased.insert(id);
        }
    }
    for (_, job) in &due {
        for hex in &job.scope.entity_ids {
            if let Ok(id) = EntityId::from_hex(hex) {
                erased.insert(id);
            }
        }
    }

    // Withdrawn-generation authority: every hw: row and fence, due or not.
    let mut withdrawn = WithdrawnSweep {
        cutoffs: {
            let rtxn = vault.store.env.read_txn()?;
            withdrawn_generation_cutoffs_in_txn(&vault.store, &rtxn)?
        },
        due: withdrawn_due.iter().map(|(_, id, _)| *id).collect(),
        held: BTreeSet::new(),
    };

    // ── 3. Compact the historical carriers ──────────────────────────────
    // A shallow snapshot drops history, which is an erase, so a run no one
    // asked for spends it only for a due obligation (ARCH-0038 carrier-1,
    // ARCH-0073); the owner's run compacts every window. A late re-put of an
    // erased id never materializes; its bytes go with the next compaction.
    let window_state = if !owner_asked && due.is_empty() && withdrawn_due.is_empty() {
        WindowSweepState::NoObligation
    } else {
        compact_all_windows(vault, &erased, &mut withdrawn, &mut run, now)?
    };

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
            // A withdrawn generation finalizes on the same global gate, unless
            // a carrier of its artifact could not be cleared this pass.
            for (key, id, job) in &withdrawn_due {
                if !withdrawn.held.contains(id) && finalize_withdrawn_job(vault, key, id, job)? {
                    run.jobs_processed += 1;
                } else {
                    run.jobs_deferred += 1;
                }
            }
        }
        WindowSweepState::Deferred => {
            // Nothing failed — the engine REFUSED (live window open, or a
            // non-sync build facing CRDT carriers). No attempt was made, so
            // retry_state is not consumed; the obligation simply stays.
            run.jobs_deferred += due.len() as u64;
            run.jobs_deferred += withdrawn_due.len() as u64;
        }
        WindowSweepState::Failed(error_code) => {
            for (key, job) in &due {
                rewrite_job_for_retry(vault, key, job, now, &error_code)?;
                run.jobs_failed += 1;
            }
            for (key, _, job) in &withdrawn_due {
                rewrite_withdrawn_job_for_retry(vault, key, job, now, &error_code)?;
                run.jobs_failed += 1;
            }
        }
        WindowSweepState::NoObligation => {}
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
    /// A run no one asked for found no obligation due, so no window was
    /// touched.
    NoObligation,
}
