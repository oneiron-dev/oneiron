//! ARCH-0038 historical-carrier sweep executor — ONE-1087 / ONE-1091
//! phase 1 (manual trigger via [`crate::MaintenanceBuilder`]).
//!
//! The hard-delete path erases the ACTIVE carriers in the delete
//! transaction itself and queues a durable `h:{seq:8BE}` obligation row for
//! the HISTORICAL carriers — the persisted Loro op-history that still
//! embeds the erased payload bytes (`d:w:{key}` full snapshots above all,
//! plus the `u:w:{key}:{seq:08x}` incremental rows). This module is the
//! consumer of those rows.
//!
//! # Mechanism (OWNER-DECISION, ONE-1087 design)
//!
//! Each persisted window doc is rebuilt through a **Loro shallow snapshot
//! at its own latest frontiers** (`ExportMode::shallow_snapshot`): the live
//! state survives byte-exactly, the op history before the frontier — the
//! dominant residual byte carrier — is dropped, and, critically, the doc
//! IDENTITY and version vector are preserved. The rejected alternative (a
//! fresh doc rebuilt from live state) shares zero history with every peer
//! replica, so the first post-sweep delta exchange would re-import the
//! ENTIRE pre-sweep history — erased payload included — and silently undo
//! the sweep. With the shallow snapshot, peer echoes of pre-sweep ops are
//! VV-dominated no-ops and the dropped history can never be re-imported.
//!
//! Wire/SLA implication (pinned): a swept window can no longer SERVE
//! deltas to peers behind the shallow start (the ops are gone), so the
//! sweep re-asserts the `fr:w:{key}` full-resync marker (ONE-1135) in the
//! same transaction that replaces the snapshot — peers heal through a full
//! window resync, never through a partial delta.
//!
//! # Scope (pinned)
//!
//! * Sweep targets: `d:w:` snapshots + the `u:w:` rows each rebuilt
//!   snapshot subsumes, plus §8c.2 live-map residue (see below). Receipts,
//!   `dt:` markers and tombstones are PERMANENT — never swept. Orphan
//!   `d:{seq}` markers are inert fail-closed blockers — GC is not phase 1.
//!   General `u:w:` pruning on snapshot persist is ONE-1151 (separate).
//! * ALL persisted windows are compacted, not just tombstone-bearing ones:
//!   discovery would have to load every window doc anyway, and compacting
//!   everything is strictly safer (it also clears crafted cross-window
//!   history residue) at the same read cost.
//! * §8c.2 cross-node live-map residue: a concurrent re-put can win LWW
//!   over the tombstone commit's entities-key delete, leaving the erased
//!   payload LIVE in the map (gated from LMDB by the `dt:` marker, but
//!   still a carrier). Before each shallow export the executor removes
//!   every entities/edges map key referencing an erased id. The erased-id
//!   authority is the union of the permanent `dt:` marker set and the
//!   pending jobs' scopes — which also covers §8c.3 (receiver nodes that
//!   never materialized the entity: `dt:` exists, NO `h:` row and NO
//!   receipt; their obligation is carrier-scrub only, and the compaction
//!   pass handles it without a job).
//!
//! # Crash safety / completion gate (pinned)
//!
//! Per-window compaction commits in its own transaction (snapshot replace +
//! subsumed-row prune + `fr:w:` marker are atomic per window). Receipt
//! finalization + `h:` row deletion happen LAST, in one transaction per
//! job — a crash anywhere before that leaves the obligation row in place,
//! and the re-run is idempotent (shallow-of-shallow is a no-op rebuild).
//! The completion gate is fail-closed and GLOBAL: a job is finalized only
//! in a run where EVERY persisted window compacted successfully and none
//! was deferred — id→window attribution cannot be trusted when any window
//! is unreadable (a corrupt window might carry anything).
//!
//! * OPEN (registry-live) windows are DEFERRED, never compacted in place: a
//!   live doc holds the full history in memory, and its next
//!   `persist_state` full-snapshot export would rewrite the history over
//!   the shallow `d:w:` row — resurrecting the carrier.
//! * RACED windows are DEFERRED (anti-clobber): if a `u:w:` row is
//!   added/removed (full set-equality check) or the `d:w:` snapshot is
//!   replaced between the read phase and the compaction write txn, the
//!   write txn is ABORTED uncommitted — never overwriting a newer carrier —
//!   and the run defers. A quiesced re-run compacts cleanly.
//! * Builds WITHOUT the `sync` feature fail closed: if any CRDT carrier
//!   rows exist (`d:w:`/`u:w:`/`q:`), every job is deferred loudly (the
//!   executor cannot parse Loro docs without the feature). A vault that
//!   never ran sync has no historical CRDT carriers, so its jobs finalize.
//! * Undecodable `h:` rows are KEPT and reported loudly — an erasure
//!   obligation is never deleted unexecuted, never "quarantined away".
//! * A job whose `scope.entity_ids` carries an unparsable hex is KEPT
//!   BYTE-IDENTICAL and reported (never compacted-and-finalized) — wrong
//!   id→window attribution must never delete an obligation row.
//! * An undecodable REDACTION_AUDIT receipt body encountered during a job's
//!   finalize txn ABORTS that txn (typed `CorruptedIndex` — the `h:` row is
//!   kept, all-or-nothing) and routes ONE job to retry; the audit pass
//!   counts unreadable receipts in `obligations_undecodable` (a SIBLING of
//!   `obligations_missing`, never folded in).
//!
//! # Receipt finalization (pinned)
//!
//! `sweep_complete_at` None→Some on the OWN node's receipt is the single
//! sanctioned mutation of the otherwise-immutable REDACTION_AUDIT record.
//! It is LOCAL-LMDB-ONLY: the CRDT mirror keeps the pre-finalization bytes
//! (replicated receipt copies are informational; GDPR Art. 5(2)
//! accountability lives on the node that erased). The replay doors get the
//! matching narrow exception — see
//! [`crate::deletion::redaction_receipt_is_stale_finalization_echo`].
//! The rewritten body is re-validated against the pinned field set before
//! the put, and the 25 B entity envelope is preserved byte-exactly.
//!
//! # Audit path (ONE-1091)
//!
//! After processing, every receipt with `sweep_queued_at` set and
//! `sweep_complete_at` still nil must be covered by a pending `h:` row
//! whose scope contains the receipt's scope — a dropped obligation (e.g. a
//! manually deleted row) is surfaced as `sweep_obligations_missing` plus a
//! `tracing::error`, never silent. `SyncQueue::clear_all` re-bootstrap
//! already preserves `h:` rows byte-identically (ONE-1091 residual).

use std::collections::BTreeSet;

use crate::Vault;
use crate::deletion::{
    HARD_ERASE_SWEEP_PREFIX, HardEraseSweepJob, decode_hard_erase_sweep_job,
    decode_hard_erase_sweep_seq, decode_redaction_audit_receipt, encode_hard_erase_sweep_job_value,
    validate_redaction_receipt_body,
};
use crate::error::{Error, Result};
use crate::types::{ENTITY_TYPE_REDACTION_AUDIT, EntityId};

/// Retry backoff cap: a failed job is retried no later than 24 h out, so
/// the ≤30 d `deadline_at` SLA cannot be silently outwaited by backoff.
const RETRY_BACKOFF_CAP_SECS: u64 = 86_400;
/// Base retry backoff (doubles per attempt up to the cap).
const RETRY_BACKOFF_BASE_SECS: u64 = 60;

/// Counters for one `run_hard_erase_sweep` pass (mirrored into
/// [`crate::MaintenanceReport`] by the maintain builder).
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
    pub(crate) static INJECT_CRASH_BEFORE_FINALIZE: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}

/// Test-only race injection (sync builds only): fires once, AFTER
/// `compact_window`'s read phase and BEFORE its compaction write txn, to
/// land a concurrent write that the in-txn re-read guards must catch
/// (Findings 1 + 4). Pre-seeding a `u:w:` row before the run cannot
/// reproduce the race — the read phase would capture it.
#[cfg(all(feature = "sync", test))]
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum RaceInjection {
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
    pub(crate) static INJECT_RACE_BEFORE_COMPACT_WRITE: std::cell::Cell<RaceInjection> =
        const { std::cell::Cell::new(RaceInjection::None) };
}

/// Benign, sentinel-free payload the race injection plants — distinctive so
/// a test can prove the externally-written snapshot was NOT clobbered.
#[cfg(all(feature = "sync", test))]
pub(crate) const RACE_BENIGN_MARKER: &[u8] = b"SWEEP-RACE-BENIGN-MARKER-5b2e0a";

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
    pub(crate) static INJECT_UW_ROW_BEFORE_FINALIZE: std::cell::RefCell<Option<String>> =
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
            if decode_hard_erase_sweep_seq(key).is_none() {
                // Not the pinned `h:` + seq u64 BE shape — fail closed: the
                // row is kept (it may still be an obligation) and reported.
                tracing::error!(
                    key_len = key.len(),
                    "sweep: malformed h: row key — obligation kept, cannot execute"
                );
                run.jobs_deferred += 1;
                continue;
            }
            match decode_hard_erase_sweep_job(value) {
                Ok(job) => jobs.push((key.to_vec(), job)),
                Err(_) => {
                    // An undecodable obligation can be neither executed nor
                    // safely discarded — keep the row, report loudly. The
                    // audit pass below will also flag any receipt this row
                    // was covering.
                    tracing::error!(
                        seq = ?decode_hard_erase_sweep_seq(key),
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
enum WindowSweepState {
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

/// Per-window outcome of [`compact_window`].
#[cfg(feature = "sync")]
enum CompactOutcome {
    /// Persisted state existed and was rebuilt through a shallow snapshot.
    Compacted,
    /// No persisted state for this window — nothing to do.
    Empty,
    /// The window changed between the read phase and the compaction write
    /// txn (a `u:w:` row was added/removed, or the `d:w:` snapshot was
    /// replaced) — the shallow snapshot built from the stale read no longer
    /// reflects durable state. The write txn is ABORTED (nothing committed,
    /// no carrier overwritten) and the window deferred; a clean re-run
    /// re-reads the quiesced window and compacts.
    RacedDefer,
}

/// Distinct window labels currently carrying persisted CRDT state —
/// `d:w:{key}` snapshots and `u:w:{key}:{seq:08x}` update rows.
fn persisted_window_labels(vault: &Vault) -> Result<(BTreeSet<String>, bool)> {
    let mut labels = BTreeSet::new();
    let mut malformed = false;
    let rtxn = vault.store.env.read_txn()?;
    for row in vault.store.sync_state.prefix_iter(&rtxn, "d:w:")? {
        let (key, _) = row?;
        labels.insert(key["d:w:".len()..].to_owned());
    }
    for row in vault.store.sync_state.prefix_iter(&rtxn, "u:w:")? {
        let (key, _) = row?;
        let rest = &key["u:w:".len()..];
        match rest.rsplit_once(':') {
            Some((label, _seq)) => {
                labels.insert(label.to_owned());
            }
            None => {
                // A u:w: row that does not address a window cannot be
                // proven payload-free — fail closed, block completion.
                tracing::error!(key = %key, "sweep: malformed u:w: row key");
                malformed = true;
            }
        }
    }
    Ok((labels, malformed))
}

#[cfg(feature = "sync")]
fn compact_all_windows(
    vault: &Vault,
    erased: &BTreeSet<EntityId>,
    run: &mut HardEraseSweepRun,
    _now: u64,
) -> Result<WindowSweepState> {
    use crate::sync::types::{WindowKey, parse_window_key_str};

    let (labels, malformed) = persisted_window_labels(vault)?;
    let mut state = if malformed {
        WindowSweepState::Failed(format!("{:?}", crate::error::ErrorKind::InvalidKey))
    } else {
        WindowSweepState::AllCompacted
    };

    for label in &labels {
        if parse_window_key_str(label).is_none() {
            // Engine-written labels always validate; a foreign/corrupt row
            // cannot be loaded or proven payload-free — fail closed.
            tracing::error!(window = %label, "sweep: invalid persisted window label");
            if matches!(state, WindowSweepState::AllCompacted) {
                state =
                    WindowSweepState::Failed(format!("{:?}", crate::error::ErrorKind::InvalidKey));
            }
            continue;
        }
        let key = WindowKey::new(label);

        // OPEN or retained-handle windows are deferred (pinned): the live doc
        // keeps the full history in memory and its next full-snapshot persist
        // would resurrect the carrier over the shallow row, even after forced
        // deregistration removed the manager registry entry.
        if vault_window_is_live(vault, &key) {
            tracing::warn!(window = %label, "sweep: window live or retained — deferred");
            run.windows_deferred_live += 1;
            if matches!(state, WindowSweepState::AllCompacted) {
                state = WindowSweepState::Deferred;
            }
            continue;
        }

        match compact_window(vault, &key, erased) {
            Ok(CompactOutcome::Compacted) => run.windows_compacted += 1,
            Ok(CompactOutcome::Empty) => {}
            Ok(CompactOutcome::RacedDefer) => {
                tracing::warn!(
                    window = %label,
                    "sweep: window raced between read and compaction write — deferred"
                );
                run.windows_deferred_raced += 1;
                // Outcome precedence (pinned): Failed > Deferred(raced) >
                // Deferred(live) > AllCompacted. A raced window downgrades
                // ONLY from AllCompacted — it must never overwrite a Failed
                // (which routes to retry and consumes retry_state) nor an
                // existing Deferred.
                if matches!(state, WindowSweepState::AllCompacted) {
                    state = WindowSweepState::Deferred;
                }
            }
            Err(err) => {
                tracing::error!(
                    window = %label,
                    error = %err,
                    "sweep: window compaction FAILED — obligation kept for retry"
                );
                if !matches!(state, WindowSweepState::Failed(_)) {
                    state = WindowSweepState::Failed(format!("{:?}", err.kind()));
                }
            }
        }
    }
    Ok(state)
}

/// Non-sync builds cannot parse Loro window docs: if ANY CRDT carrier rows
/// exist, every job defers loudly (fail closed). A vault that never ran
/// sync has no historical CRDT carriers — its obligations can finalize
/// (the active carriers were erased in the delete transaction itself).
#[cfg(not(feature = "sync"))]
fn compact_all_windows(
    vault: &Vault,
    _erased: &BTreeSet<EntityId>,
    _run: &mut HardEraseSweepRun,
    _now: u64,
) -> Result<WindowSweepState> {
    let (labels, malformed) = persisted_window_labels(vault)?;
    let queue_rows_exist = {
        let rtxn = vault.store.env.read_txn()?;
        let mut iter = vault.store.sync_queue.prefix_iter(&rtxn, b"q:")?;
        iter.next().transpose()?.is_some()
    };
    if !labels.is_empty() || malformed || queue_rows_exist {
        tracing::error!(
            windows = labels.len(),
            "sweep: CRDT carrier rows present but the engine was built without \
             the `sync` feature — historical-carrier compaction deferred (fail closed)"
        );
        return Ok(WindowSweepState::Deferred);
    }
    Ok(WindowSweepState::AllCompacted)
}

#[cfg(feature = "sync")]
fn vault_window_is_live(vault: &Vault, key: &crate::sync::types::WindowKey) -> bool {
    vault.live_window_for_sweep(key)
}

/// Compacts one CLOSED window: load `d:w:` + pending `u:w:` rows, scrub
/// live-map residue for erased ids, export a shallow snapshot at the
/// latest frontiers, and atomically replace the persistence triple, prune
/// the subsumed `u:w:` rows, and re-assert `fr:w:`. Returns whether any
/// persisted state existed.
#[cfg(feature = "sync")]
fn compact_window(
    vault: &Vault,
    key: &crate::sync::types::WindowKey,
    erased: &BTreeSet<EntityId>,
) -> Result<CompactOutcome> {
    use crate::sync::loro_support::{doc_from_snapshot, doc_version_vector, import_doc};
    use crate::sync::schema::create_window_doc;
    use loro::ExportMode;

    // Read phase (one read txn, dropped before any Loro work).
    let (snapshot_bytes, update_rows) = {
        let rtxn = vault.store.env.read_txn()?;
        let snapshot = vault
            .store
            .sync_state
            .get(&rtxn, &format!("d:w:{key}"))?
            .map(<[u8]>::to_vec);
        let mut rows: Vec<(String, Vec<u8>)> = Vec::new();
        let prefix = format!("u:w:{key}:");
        for entry in vault.store.sync_state.prefix_iter(&rtxn, &prefix)? {
            let (k, v) = entry?;
            rows.push((k.to_owned(), v.to_vec()));
        }
        (snapshot, rows)
    };
    if snapshot_bytes.is_none() && update_rows.is_empty() {
        return Ok(CompactOutcome::Empty);
    }

    // Rebuild the doc UNOBSERVED — the sweep never touches LMDB through
    // Observer side effects; it only rewrites the persisted CRDT carriers.
    let doc = match &snapshot_bytes {
        Some(bytes) => doc_from_snapshot(bytes)?,
        None => create_window_doc("local", key),
    };
    for (_, bytes) in &update_rows {
        import_doc(&doc, bytes)?;
    }

    // §8c.2 live-map residue scrub: a concurrent re-put that won LWW over
    // the tombstone commit's key-delete leaves erased payload LIVE in the
    // map. Remove every entities/edges key referencing an erased id —
    // across hex-casing aliases (fail closed). Tombstones map untouched
    // (permanent); receipt entities are receipt-ids, never erased ids.
    scrub_erased_ids_from_doc(&doc, erased)?;

    // Shallow snapshot at the latest frontiers: live state byte-exact, op
    // history (the payload carrier) dropped, doc identity + VV preserved.
    doc.commit();
    let frontiers = doc.oplog_frontiers();
    let shallow = doc
        .export(ExportMode::shallow_snapshot(&frontiers))
        .map_err(|e| Error::SyncProtocolError(format!("sweep shallow snapshot export: {e}")))?;
    let vv = doc_version_vector(&doc);

    let merged_keys: BTreeSet<String> = update_rows.iter().map(|(k, _)| k.clone()).collect();
    let prefix = format!("u:w:{key}:");
    for k in &merged_keys {
        if !k.starts_with(&prefix) {
            // Surgical scope (fail closed): never touch another family.
            return Err(Error::SyncProtocolError(format!(
                "sweep u:w: prune scoped to {prefix}* refused foreign key {k}"
            )));
        }
    }

    // Test-only race injection point: lands a concurrent write AFTER the
    // read phase, BEFORE the compaction write txn, so the in-txn re-read
    // guards below have something to catch (one-shot).
    #[cfg(test)]
    inject_race_before_compact_write(vault, key, &snapshot_bytes)?;

    let dw_key = format!("d:w:{key}");
    // ABORT-ONLY raced-defer signal: the write closure returns `Err` (so
    // `with_write_txn` rolls the txn back, committing NOTHING) and sets this
    // flag, which the caller maps to `RacedDefer`. There is deliberately NO
    // `Ok` arm that commits nothing — the `d:w:`/`sv:` puts live AFTER the
    // re-read+compare, so an early return can never clobber a newer carrier.
    let raced = std::cell::Cell::new(false);
    let result = vault.with_write_txn(|wtxn| {
        // Finding 4 (anti-clobber): re-read `d:w:` and compare byte-for-byte
        // against the snapshot captured in the read phase — `Option<Vec<u8>>`
        // equality, so absent-vs-present (None↔Some) AND any byte difference
        // both count as a race. A concurrent persist replaced the snapshot;
        // overwriting it with our stale-based shallow would clobber newer
        // state, so defer.
        let current_snapshot = vault
            .store
            .sync_state
            .get(&*wtxn, &dw_key)?
            .map(<[u8]>::to_vec);
        if current_snapshot != snapshot_bytes {
            raced.set(true);
            return Err(Error::SyncProtocolError(
                "sweep raced: d:w: snapshot changed between read and write".to_owned(),
            ));
        }

        // Finding 1 (carrier completeness): re-read the `u:w:` row set and
        // require FULL SET-EQUALITY with what the read phase merged. A key
        // ADDED or REMOVED means a concurrent persist/prune raced in, so the
        // shallow snapshot no longer covers the window's durable ops — defer
        // rather than drop a carrier or finalize a window we cannot prove
        // payload-free. (Carrier completeness stays local here, not reliant
        // on any sibling d:w: co-write.)
        let mut current_keys: BTreeSet<String> = BTreeSet::new();
        for entry in vault.store.sync_state.prefix_iter(&*wtxn, &prefix)? {
            let (k, _) = entry?;
            current_keys.insert(k.to_owned());
        }
        if current_keys != merged_keys {
            raced.set(true);
            return Err(Error::SyncProtocolError(
                "sweep raced: u:w: row set changed between read and write".to_owned(),
            ));
        }

        // Race-free: the shallow snapshot reflects the durable window.
        // Replace the persistence triple, prune the now-subsumed `u:w:`
        // rows, and re-assert `fr:w:`. Every merged key is deleted and the
        // set matched exactly, so zero `u:w:` rows remain on top of the
        // snapshot — the freshness flag is honestly fresh.
        vault.store.sync_state.put(wtxn, &dw_key, &shallow)?;
        vault
            .store
            .sync_state
            .put(wtxn, &format!("sv:w:{key}"), &vv)?;
        for k in &merged_keys {
            vault.store.sync_state.delete(wtxn, k)?;
        }
        vault
            .store
            .sync_state
            .put(wtxn, &format!("svf:w:{key}"), &[1u8])?;

        // Wire/SLA pin: the swept window cannot serve pre-shallow deltas —
        // peers behind the shallow start must take a full window resync.
        vault
            .store
            .sync_state
            .put(wtxn, &format!("fr:w:{key}"), &[1u8])?;
        Ok(())
    });
    match result {
        Ok(()) => Ok(CompactOutcome::Compacted),
        // The race guards aborted the txn — nothing committed, no carrier
        // clobbered. Surface a deferral, not a failure (no retry_state
        // consumed); the obligation stays for the quiesced re-run.
        Err(_) if raced.get() => Ok(CompactOutcome::RacedDefer),
        Err(err) => Err(err),
    }
}

/// Test-only race injection — see [`INJECT_RACE_BEFORE_COMPACT_WRITE`].
/// Performs a concurrent write in its OWN committed txn so the subsequent
/// compaction write txn's re-read guards observe it.
#[cfg(all(feature = "sync", test))]
fn inject_race_before_compact_write(
    vault: &Vault,
    key: &crate::sync::types::WindowKey,
    snapshot_bytes: &Option<Vec<u8>>,
) -> Result<()> {
    use crate::sync::loro_support::{doc_from_snapshot, export_snapshot, export_updates_from};
    use crate::sync::schema::create_window_doc;

    match INJECT_RACE_BEFORE_COMPACT_WRITE.with(std::cell::Cell::take) {
        RaceInjection::None => {}
        RaceInjection::AppendUpdateRow => {
            // Build a VALID concurrent update from the SAME window lineage
            // (deps = the window's frontiers) so a clean re-run imports it
            // without missing dependencies. Benign, sentinel-free payload.
            let racer = match snapshot_bytes {
                Some(bytes) => doc_from_snapshot(bytes)?,
                None => create_window_doc("racer", key),
            };
            let base_vv = racer.oplog_vv();
            racer
                .get_map("entities")
                .insert(EntityId::now().to_hex().as_str(), RACE_BENIGN_MARKER)
                .map_err(|e| Error::SyncProtocolError(format!("race inject insert: {e}")))?;
            racer.commit();
            let delta = export_updates_from(&racer, &base_vv)?;
            let mut wtxn = vault.store.env.write_txn()?;
            vault
                .store
                .sync_state
                .put(&mut wtxn, &format!("u:w:{key}:ffffffff"), &delta)?;
            wtxn.commit()?;
        }
        RaceInjection::ReplaceSnapshot => {
            // Overwrite d:w: with a DIFFERENT valid snapshot carrying only
            // the benign marker — the re-read guard must refuse to clobber.
            let benign = create_window_doc("racer", key);
            benign
                .get_map("entities")
                .insert(EntityId::now().to_hex().as_str(), RACE_BENIGN_MARKER)
                .map_err(|e| Error::SyncProtocolError(format!("race inject insert: {e}")))?;
            benign.commit();
            let snap = export_snapshot(&benign)?;
            let mut wtxn = vault.store.env.write_txn()?;
            vault
                .store
                .sync_state
                .put(&mut wtxn, &format!("d:w:{key}"), &snap)?;
            wtxn.commit()?;
        }
    }
    Ok(())
}

/// Removes every entities/edges map key referencing an erased id (any
/// hex-casing alias), committing once if anything changed. The tombstones
/// map is PERMANENT and untouched.
#[cfg(feature = "sync")]
fn scrub_erased_ids_from_doc(doc: &loro::LoroDoc, erased: &BTreeSet<EntityId>) -> Result<()> {
    use crate::sync::loro_support::map_delete;

    if erased.is_empty() {
        return Ok(());
    }

    let entities = doc.get_map("entities");
    let mut doomed_entities: Vec<String> = Vec::new();
    entities.for_each(|key, _| {
        // ANY value shape under an erased id's key is residue (fail
        // closed) — including non-binary values a crafted update planted.
        if EntityId::from_hex(key).is_ok_and(|id| erased.contains(&id)) {
            doomed_entities.push(key.to_owned());
        }
    });

    let edges = doc.get_map("edges");
    let mut doomed_edges: Vec<String> = Vec::new();
    edges.for_each(|key, _| {
        if let Some((src, _, tgt)) = crate::sync::bridge::parse_edge_key(key)
            && (erased.contains(&src) || erased.contains(&tgt))
        {
            doomed_edges.push(key.to_owned());
        }
    });

    if doomed_entities.is_empty() && doomed_edges.is_empty() {
        return Ok(());
    }
    for key in &doomed_entities {
        map_delete(&entities, key)?;
    }
    for key in &doomed_edges {
        map_delete(&edges, key)?;
    }
    doc.commit();
    Ok(())
}

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
fn finalize_job(
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
            // Finding 2 (fail closed): a type-120 REDACTION_AUDIT entity
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
        .map_err(|e| Error::SyncProtocolError(format!("uw-row inject insert: {e}")))?;
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
fn rewrite_job_for_retry(
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
fn audit_dropped_obligations(vault: &Vault) -> Result<(u64, u64)> {
    let rtxn = vault.store.env.read_txn()?;

    let mut job_scopes: Vec<BTreeSet<String>> = Vec::new();
    for row in vault
        .store
        .sync_queue
        .prefix_iter(&rtxn, HARD_ERASE_SWEEP_PREFIX)?
    {
        let (key, value) = row?;
        if decode_hard_erase_sweep_seq(key).is_none() {
            continue;
        }
        if let Ok(job) = decode_hard_erase_sweep_job(value) {
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
        // LOCAL type-120 obligations (the same predicate scope the covering
        // check already runs) — never a blanket scan over every type-120
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deletion::{
        DeleteReason, HardEraseSweepExtras, RedactionScope, encode_hard_erase_sweep_job,
        encode_hard_erase_sweep_key,
    };
    use crate::types::{HnswConfig, TimeRange, VaultConfig};
    #[cfg(feature = "sync")]
    use core::assert_matches;

    fn test_config() -> VaultConfig {
        let mut config = VaultConfig::device();
        config.map_size = 16 * 1024 * 1024;
        config.dimensions = 4;
        config.embedding_model = Some("test-model-v1".to_owned());
        config.max_readers = 16;
        config.hnsw = HnswConfig::default();
        config
    }

    fn open_vault() -> (tempfile::TempDir, Vault) {
        crate::test_util::open_test_vault_with(test_config())
    }

    fn put_entity(vault: &Vault, id: &EntityId, learned_at: u64, body: &[u8]) {
        vault
            .batch()
            .put(
                id,
                1,
                TimeRange {
                    start: learned_at,
                    end: learned_at,
                },
                learned_at,
                body,
            )
            .commit()
            .expect("put entity");
    }

    fn h_rows(vault: &Vault) -> Vec<(Vec<u8>, Vec<u8>)> {
        let rtxn = vault.store.env.read_txn().unwrap();
        let mut rows = Vec::new();
        for row in vault
            .store
            .sync_queue
            .prefix_iter(&rtxn, HARD_ERASE_SWEEP_PREFIX)
            .unwrap()
        {
            let (key, value) = row.unwrap();
            rows.push((key.to_vec(), value.to_vec()));
        }
        rows
    }

    fn receipt_sweep_complete_at(vault: &Vault, receipt_id: &EntityId) -> Option<u64> {
        let raw = vault.get_raw(receipt_id).unwrap().expect("receipt raw");
        let receipt =
            decode_redaction_audit_receipt(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..])
                .expect("receipt decode");
        receipt.sweep_complete_at
    }

    fn write_h_row(vault: &Vault, seq: u64, value: &[u8]) -> Vec<u8> {
        let key = encode_hard_erase_sweep_key(seq);
        let mut wtxn = vault.store.env.write_txn().unwrap();
        vault.store.sync_queue.put(&mut wtxn, &key, value).unwrap();
        wtxn.commit().unwrap();
        key.to_vec()
    }

    /// Writes a type-120 REDACTION_AUDIT entity (entities row + type-index
    /// row) whose body is deliberately UNDECODABLE — the on-disk
    /// accountability-corruption shape Finding 2 / the audit must surface.
    fn write_corrupt_redaction_receipt(vault: &Vault) -> EntityId {
        let id = EntityId::now();
        let mut blob = Vec::new();
        blob.push(ENTITY_TYPE_REDACTION_AUDIT);
        for _ in 0..3 {
            blob.extend_from_slice(&1_771_027_200u64.to_be_bytes());
        }
        // 0xc1 is the msgpack "never used" byte — guarantees a decode error.
        blob.extend_from_slice(&[0xc1, 0x00, 0x01]);
        let mut type_key = Vec::with_capacity(17);
        type_key.push(ENTITY_TYPE_REDACTION_AUDIT);
        type_key.extend_from_slice(id.as_bytes());
        let mut wtxn = vault.store.env.write_txn().unwrap();
        vault
            .store
            .entities
            .put(&mut wtxn, id.as_bytes(), &blob)
            .unwrap();
        vault
            .store
            .type_index
            .put(&mut wtxn, &type_key, &[])
            .unwrap();
        wtxn.commit().unwrap();
        id
    }

    #[cfg(feature = "sync")]
    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    /// Byte-scans every persisted `sync_state` value and every `sync_queue`
    /// key+value for `needle` — the delete-safety carrier scan.
    #[cfg(feature = "sync")]
    fn sync_rows_contain(vault: &Vault, needle: &[u8]) -> bool {
        let rtxn = vault.store.env.read_txn().unwrap();
        for entry in vault.store.sync_state.iter(&rtxn).unwrap() {
            let (_, value) = entry.unwrap();
            if contains(value, needle) {
                return true;
            }
        }
        for entry in vault.store.sync_queue.iter(&rtxn).unwrap() {
            let (key, value) = entry.unwrap();
            if contains(key, needle) || contains(value, needle) {
                return true;
            }
        }
        false
    }

    /// Per-job independence (ONE-1087 retry semantics): a job whose
    /// `next_attempt_at` is in the future is skipped — byte-identical row,
    /// no retry_state consumption — while a due job in the same run
    /// completes (h: row deleted LAST, receipt finalized to the pinned
    /// `sweep_complete_at = Some(_)` shape).
    #[test]
    fn sweep_skips_not_due_job_while_processing_due_job() {
        let (_dir, vault) = open_vault();
        let id = EntityId::now();
        put_entity(&vault, &id, 1_771_027_200, b"due-job-body");
        let outcome = vault
            .delete_entity_with_reason(&id, DeleteReason::GdprDelete)
            .unwrap();
        let receipt_id = outcome.receipt_id.expect("receipt id");
        let due_key = outcome.sweep_key.expect("sweep key");

        // A NOT-due crafted job: queued_at (= next_attempt_at) in the future.
        let future = crate::unix_seconds_now() + 86_400;
        let not_due_value = encode_hard_erase_sweep_job(
            RedactionScope::entity(&EntityId::now()),
            HardEraseSweepExtras::default(),
            future,
        )
        .unwrap();
        let not_due_key = write_h_row(&vault, 1_000, &not_due_value);

        let run = run_hard_erase_sweep(&vault).unwrap();
        assert_eq!(run.jobs_processed, 1, "the due job must complete");
        assert!(run.jobs_deferred >= 1, "the not-due job must defer");
        assert_eq!(run.receipts_finalized, 1);
        assert!(
            receipt_sweep_complete_at(&vault, &receipt_id).is_some(),
            "receipt sweep_complete_at must be populated"
        );

        let rows = h_rows(&vault);
        assert!(
            !rows.iter().any(|(k, _)| *k == due_key),
            "completed job's h: row must be deleted"
        );
        let kept: Vec<_> = rows.iter().filter(|(k, _)| *k == not_due_key).collect();
        assert_eq!(kept.len(), 1, "not-due job row must survive");
        assert_eq!(
            kept[0].1, not_due_value,
            "not-due job row must be BYTE-IDENTICAL (no retry_state consumption)"
        );
    }

    /// A job past `deadline_at` (queued_at + 30 d, deletion.rs pin) is a
    /// loud SLA breach: counted every run, never silent — and still
    /// executed when due (a breach must not park the obligation).
    #[test]
    fn sweep_deadline_breach_is_loud_and_counted() {
        let (_dir, vault) = open_vault();
        let queued_at = crate::unix_seconds_now() - crate::deletion::HARD_ERASE_SWEEP_SLA_SECS - 10;
        let value = encode_hard_erase_sweep_job(
            RedactionScope::entity(&EntityId::now()),
            HardEraseSweepExtras::default(),
            queued_at,
        )
        .unwrap();
        let key = write_h_row(&vault, 7, &value);

        let run = run_hard_erase_sweep(&vault).unwrap();
        assert_eq!(run.deadline_breaches, 1, "SLA breach must be counted");
        assert_eq!(run.jobs_processed, 1, "a breached due job still executes");
        assert!(
            !h_rows(&vault).iter().any(|(k, _)| *k == key),
            "the executed job's row is deleted"
        );
    }

    /// ONE-1091 audit: a receipt with `sweep_queued_at` set, no
    /// `sweep_complete_at`, and NO covering pending `h:` row is a DROPPED
    /// erasure obligation — detected and counted. With the row present the
    /// audit is quiet (the run that consumes it also finalizes the receipt,
    /// so post-run state is clean either way).
    #[test]
    fn sweep_audit_detects_dropped_obligation() {
        // Dropped: the h: row vanishes before any sweep ran.
        let (_dir, vault) = open_vault();
        let id = EntityId::now();
        put_entity(&vault, &id, 1_771_027_200, b"dropped-obligation-body");
        let outcome = vault
            .delete_entity_with_reason(&id, DeleteReason::GdprDelete)
            .unwrap();
        let receipt_id = outcome.receipt_id.expect("receipt id");
        let sweep_key = outcome.sweep_key.expect("sweep key");
        {
            let mut wtxn = vault.store.env.write_txn().unwrap();
            vault
                .store
                .sync_queue
                .delete(&mut wtxn, &sweep_key)
                .unwrap();
            wtxn.commit().unwrap();
        }
        let run = run_hard_erase_sweep(&vault).unwrap();
        assert_eq!(
            run.obligations_missing, 1,
            "a queued-but-unswept receipt without an h: row must be flagged"
        );
        assert_eq!(run.jobs_processed, 0);
        assert!(
            receipt_sweep_complete_at(&vault, &receipt_id).is_none(),
            "the audit must never fabricate completion"
        );

        // Intact: the obligation row is present and consumed — audit quiet.
        let (_dir2, vault2) = open_vault();
        let id2 = EntityId::now();
        put_entity(&vault2, &id2, 1_771_027_200, b"intact-obligation-body");
        vault2
            .delete_entity_with_reason(&id2, DeleteReason::GdprDelete)
            .unwrap();
        let run2 = run_hard_erase_sweep(&vault2).unwrap();
        assert_eq!(run2.obligations_missing, 0);
        assert_eq!(run2.jobs_processed, 1);
    }

    /// Crash-safety ordering (h: row deletion LAST): a crash between window
    /// compaction and job finalization must leave the obligation row AND
    /// the unfinalized receipt in place; the re-run is idempotent and
    /// completes.
    #[cfg(feature = "sync")]
    #[test]
    fn sweep_crash_between_compaction_and_finalization_keeps_obligation() {
        let (_dir, vault) = open_vault();
        let id = EntityId::now();
        put_entity(&vault, &id, 1_771_027_200, b"crash-window-body");
        let outcome = vault
            .delete_entity_with_reason(&id, DeleteReason::GdprDelete)
            .unwrap();
        let receipt_id = outcome.receipt_id.expect("receipt id");
        let sweep_key = outcome.sweep_key.expect("sweep key");

        INJECT_CRASH_BEFORE_FINALIZE.with(|cell| cell.set(true));
        let err = run_hard_erase_sweep(&vault).expect_err("injected crash");
        assert_matches!(err, Error::InvariantViolation(_));

        // Obligation survives the crash window; the compaction already
        // committed (the d:w: row is now a shallow doc).
        assert!(
            h_rows(&vault).iter().any(|(k, _)| *k == sweep_key),
            "h: row must survive a crash before finalization"
        );
        assert!(receipt_sweep_complete_at(&vault, &receipt_id).is_none());
        let window = crate::deletion::window_label_from_timestamp(1_771_027_200);
        let snapshot = vault
            .sync_state_get(&format!("d:w:{window}"))
            .unwrap()
            .expect("window snapshot");
        let doc = loro::LoroDoc::from_snapshot(&snapshot).unwrap();
        assert!(doc.is_shallow(), "compaction committed before the crash");

        // Re-run: idempotent, completes the obligation.
        let run = run_hard_erase_sweep(&vault).unwrap();
        assert_eq!(run.jobs_processed, 1);
        assert_eq!(run.receipts_finalized, 1);
        assert!(!h_rows(&vault).iter().any(|(k, _)| *k == sweep_key));
        assert!(receipt_sweep_complete_at(&vault, &receipt_id).is_some());
    }

    /// Per-job failure semantics: an unreadable window FAILS the run's
    /// completion gate (fail closed — id→window attribution cannot be
    /// trusted), the job row is REWRITTEN in place (attempt_count,
    /// last_error_code, capped backoff; queued_at/deadline_at untouched),
    /// never deleted, and healthy windows still compact. After healing,
    /// a due re-run completes.
    #[cfg(feature = "sync")]
    #[test]
    fn sweep_failure_updates_retry_state_in_place_and_keeps_obligation() {
        let (_dir, vault) = open_vault();
        let id = EntityId::now();
        put_entity(&vault, &id, 1_771_027_200, b"retry-window-body");
        let outcome = vault
            .delete_entity_with_reason(&id, DeleteReason::GdprDelete)
            .unwrap();
        let receipt_id = outcome.receipt_id.expect("receipt id");
        let sweep_key = outcome.sweep_key.expect("sweep key");
        let original_job = decode_hard_erase_sweep_job(
            &h_rows(&vault)
                .iter()
                .find(|(k, _)| *k == sweep_key)
                .expect("job row")
                .1,
        )
        .unwrap();

        // A corrupt FOREIGN window snapshot: unreadable ⇒ run-level failure.
        vault
            .sync_state_put("d:w:2027-01", b"not-a-loro-snapshot")
            .unwrap();

        let before = crate::unix_seconds_now();
        let run = run_hard_erase_sweep(&vault).unwrap();
        assert_eq!(run.jobs_failed, 1, "the due job must be marked failed");
        assert_eq!(run.jobs_processed, 0);
        assert!(
            run.windows_compacted >= 1,
            "healthy windows still compact in a failing run"
        );
        assert!(receipt_sweep_complete_at(&vault, &receipt_id).is_none());

        let rows = h_rows(&vault);
        let (_, value) = rows
            .iter()
            .find(|(k, _)| *k == sweep_key)
            .expect("failed job row must be REWRITTEN, never deleted");
        let job = decode_hard_erase_sweep_job(value).unwrap();
        assert_eq!(job.retry_state.attempt_count, 1);
        assert_eq!(
            job.retry_state.last_error_code.as_deref(),
            Some("CrdtDecodeError"),
            "last_error_code carries the failing ErrorKind name"
        );
        assert!(job.retry_state.next_attempt_at > before, "backoff applied");
        assert!(
            job.retry_state.next_attempt_at <= before + RETRY_BACKOFF_CAP_SECS + 60,
            "backoff capped at 24h"
        );
        assert_eq!(
            job.retry_state.queued_at, original_job.retry_state.queued_at,
            "queued_at untouched"
        );
        assert_eq!(
            job.retry_state.deadline_at, original_job.retry_state.deadline_at,
            "backoff never extends the 30-day SLA clock"
        );

        // Heal the window, make the job due again, re-run: completes.
        assert!(vault.sync_state_delete("d:w:2027-01").unwrap());
        let mut due_again = job;
        due_again.retry_state.next_attempt_at = crate::unix_seconds_now();
        let value = encode_hard_erase_sweep_job_value(&due_again).unwrap();
        {
            let mut wtxn = vault.store.env.write_txn().unwrap();
            vault
                .store
                .sync_queue
                .put(&mut wtxn, &sweep_key, &value)
                .unwrap();
            wtxn.commit().unwrap();
        }
        let run = run_hard_erase_sweep(&vault).unwrap();
        assert_eq!(run.jobs_processed, 1);
        assert!(receipt_sweep_complete_at(&vault, &receipt_id).is_some());
        assert!(!h_rows(&vault).iter().any(|(k, _)| *k == sweep_key));
    }

    /// OPEN windows defer (pinned): a live registry doc holds the full
    /// history in memory and would clobber the shallow row on its next
    /// persist. The obligation stays queued without retry consumption;
    /// after unload the sweep completes.
    #[cfg(feature = "sync")]
    #[test]
    fn sweep_defers_open_windows_and_completes_after_unload() {
        use crate::sync::bridge::Materializer;
        use crate::sync::manager::WindowManager;
        use crate::sync::types::WindowKey;
        use std::sync::Arc;

        let dir = tempfile::tempdir().unwrap();
        let vault = Arc::new(Vault::open(dir.path(), test_config()).unwrap());
        let id = EntityId::now();
        put_entity(&vault, &id, 1_771_027_200, b"live-window-body");

        let materializer = Arc::new(Materializer::new());
        let manager = Arc::new(WindowManager::new(
            Arc::clone(&vault),
            materializer,
            "sweep-test",
        ));
        let window_key = WindowKey::from_timestamp(1_771_027_200);
        let window = manager.open_window(&window_key).unwrap();

        let outcome = vault
            .delete_entity_with_reason(&id, DeleteReason::GdprDelete)
            .unwrap();
        let receipt_id = outcome.receipt_id.expect("receipt id");
        let sweep_key = outcome.sweep_key.expect("sweep key");
        let job_value_before = h_rows(&vault)
            .iter()
            .find(|(k, _)| *k == sweep_key)
            .expect("job row")
            .1
            .clone();

        let run = run_hard_erase_sweep(&vault).unwrap();
        assert!(run.windows_deferred_live >= 1, "open window must defer");
        assert_eq!(run.jobs_processed, 0);
        assert!(run.jobs_deferred >= 1);
        assert_eq!(run.jobs_failed, 0, "a deferral is not a failed attempt");
        let job_value_after = h_rows(&vault)
            .iter()
            .find(|(k, _)| *k == sweep_key)
            .expect("obligation kept")
            .1
            .clone();
        assert_eq!(
            job_value_before, job_value_after,
            "deferral must not consume retry_state"
        );
        assert!(receipt_sweep_complete_at(&vault, &receipt_id).is_none());

        drop(window);
        assert!(manager.unload_window(&window_key).unwrap());
        let run = run_hard_erase_sweep(&vault).unwrap();
        assert_eq!(run.jobs_processed, 1);
        assert!(receipt_sweep_complete_at(&vault, &receipt_id).is_some());
    }

    /// ONE-1162: a retained `Arc<LoadedWindow>` can persist a full-history
    /// snapshot after `discard_window` removes the registry entry. The sweep
    /// must still defer while that handle exists, so no finalized shallow row
    /// can be clobbered by a late `persist_state`.
    #[cfg(feature = "sync")]
    #[test]
    fn retained_handle_cannot_resurrect_after_finalize() {
        use crate::sync::bridge::Materializer;
        use crate::sync::manager::WindowManager;
        use crate::sync::types::WindowKey;
        use std::sync::Arc;

        let dir = tempfile::tempdir().unwrap();
        let vault = Arc::new(Vault::open(dir.path(), test_config()).unwrap());
        let id = EntityId::now();
        let learned_at = 1_771_027_200;
        put_entity(&vault, &id, learned_at, b"retained-window-body");

        let materializer = Arc::new(Materializer::new());
        let manager = Arc::new(WindowManager::new(
            Arc::clone(&vault),
            materializer,
            "retained-sweep-test",
        ));
        let window_key = WindowKey::from_timestamp(learned_at);
        let window = manager.open_window(&window_key).unwrap();
        window.persist_state(&vault).unwrap();

        let retained = Arc::clone(&window);
        drop(window);
        assert!(manager.discard_window(&window_key));
        assert!(
            manager.loaded_keys().is_empty(),
            "the registry entry is gone while the external handle remains"
        );

        let outcome = vault
            .delete_entity_with_reason(&id, DeleteReason::GdprDelete)
            .unwrap();
        let receipt_id = outcome.receipt_id.expect("receipt id");
        let sweep_key = outcome.sweep_key.expect("sweep key");

        let run = run_hard_erase_sweep(&vault).unwrap();
        assert_eq!(run.jobs_processed, 0, "retained handle must not finalize");
        assert!(
            run.windows_deferred_live >= 1,
            "orphaned retained handle must defer the window"
        );
        assert_eq!(run.windows_compacted, 0);
        assert!(run.jobs_deferred >= 1);
        assert_eq!(run.jobs_failed, 0);
        assert!(
            h_rows(&vault).iter().any(|(k, _)| *k == sweep_key),
            "h: obligation must be kept while the handle can persist"
        );
        assert!(receipt_sweep_complete_at(&vault, &receipt_id).is_none());

        retained.persist_state(&vault).unwrap();
        assert!(
            h_rows(&vault).iter().any(|(k, _)| *k == sweep_key),
            "late persist cannot clobber a finalized shallow row because no finalization happened"
        );
        assert!(receipt_sweep_complete_at(&vault, &receipt_id).is_none());

        drop(retained);
        let run = run_hard_erase_sweep(&vault).unwrap();
        assert_eq!(run.jobs_processed, 1);
        assert!(run.windows_compacted >= 1);
        assert!(
            !h_rows(&vault).iter().any(|(k, _)| *k == sweep_key),
            "h: obligation is removed only after the handle is gone"
        );
        assert!(receipt_sweep_complete_at(&vault, &receipt_id).is_some());
    }

    /// Non-`sync` builds fail closed: with NO CRDT carrier rows the
    /// obligation finalizes (the active carriers were erased in the delete
    /// txn itself), but the moment any `d:w:` row exists the executor
    /// defers EVERYTHING — it cannot parse Loro docs without the feature.
    #[cfg(not(feature = "sync"))]
    #[test]
    fn sweep_without_sync_completes_clean_vault_and_defers_on_crdt_rows() {
        let (_dir, vault) = open_vault();
        let id = EntityId::now();
        put_entity(&vault, &id, 1_771_027_200, b"non-sync-body");
        let outcome = vault
            .delete_entity_with_reason(&id, DeleteReason::GdprDelete)
            .unwrap();
        let receipt_id = outcome.receipt_id.expect("receipt id");
        let run = run_hard_erase_sweep(&vault).unwrap();
        assert_eq!(run.jobs_processed, 1, "no CRDT carriers ⇒ jobs finalize");
        assert!(receipt_sweep_complete_at(&vault, &receipt_id).is_some());

        // Same vault, new delete — but now a CRDT carrier row exists
        // (e.g. written by an earlier sync-enabled boot): defer, loudly.
        let id2 = EntityId::now();
        put_entity(&vault, &id2, 1_771_027_200, b"non-sync-body-two");
        let outcome2 = vault
            .delete_entity_with_reason(&id2, DeleteReason::GdprDelete)
            .unwrap();
        let receipt_id2 = outcome2.receipt_id.expect("receipt id");
        let sweep_key2 = outcome2.sweep_key.expect("sweep key");
        {
            let mut wtxn = vault.store.env.write_txn().unwrap();
            vault
                .store
                .sync_state
                .put(&mut wtxn, "d:w:2026-02", b"opaque-crdt-snapshot")
                .unwrap();
            wtxn.commit().unwrap();
        }
        let run = run_hard_erase_sweep(&vault).unwrap();
        assert_eq!(run.jobs_processed, 0, "CRDT rows present ⇒ fail closed");
        assert!(run.jobs_deferred >= 1);
        assert!(
            h_rows(&vault).iter().any(|(k, _)| *k == sweep_key2),
            "obligation kept"
        );
        assert!(receipt_sweep_complete_at(&vault, &receipt_id2).is_none());
    }

    /// Pins the ONE-1087 replay-door exception comparator to EXACTLY the
    /// monotone finalization shape: identical envelope + fields, local
    /// `sweep_complete_at = Some(_)`, incoming nil. Every other pair —
    /// reversed direction (only craftable), a differing sibling field, a
    /// differing envelope byte — must stay on the quarantine path.
    #[cfg(feature = "sync")]
    #[test]
    fn stale_finalization_echo_comparator_pins_monotone_shape() {
        use crate::deletion::{
            RedactionReceiptInput, encode_redaction_audit_receipt,
            redaction_receipt_is_stale_finalization_echo,
        };

        let envelope = |body: &[u8]| -> Vec<u8> {
            let mut blob = Vec::with_capacity(25 + body.len());
            blob.push(ENTITY_TYPE_REDACTION_AUDIT);
            for _ in 0..3 {
                blob.extend_from_slice(&1_771_027_200_u64.to_be_bytes());
            }
            blob.extend_from_slice(body);
            blob
        };
        let input = |requested_at: u64| RedactionReceiptInput {
            request_id: uuid::Uuid::now_v7().to_string(),
            scope: RedactionScope::entity(&EntityId::now()),
            reason: DeleteReason::GdprDelete,
            requested_at,
            soft_complete_at: requested_at + 1,
            hard_purge_complete_at: requested_at + 1,
            sweep_queued_at: Some(requested_at + 1),
        };

        let identity = crate::identity::DeviceIdentity {
            client_id: 0x0123_4567_89ab_cdef,
            signing_key: ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]),
        };
        let receipt_id = EntityId::from_hex("000102030405060708090a0b0c0d0e0f").unwrap();
        let base = input(1_771_027_200);
        let pre = envelope(
            &encode_redaction_audit_receipt(base.clone(), &receipt_id, &identity).unwrap(),
        );
        // Finalize exactly the way the sweep does: decode → Some → re-encode.
        let mut rec =
            decode_redaction_audit_receipt(&pre[crate::batch::ENTITY_METADATA_HEADER_LEN..])
                .unwrap();
        rec.sweep_complete_at = Some(1_771_113_600);
        let body = rmp_serde::to_vec_named(&rec).unwrap();
        validate_redaction_receipt_body(&body).expect("finalized body must stay door-valid");
        let finalized = envelope(&body);

        assert!(
            redaction_receipt_is_stale_finalization_echo(&finalized, &pre),
            "local finalized vs incoming pre-finalization echo: skip"
        );
        assert!(
            !redaction_receipt_is_stale_finalization_echo(&pre, &finalized),
            "incoming Some over local nil is only craftable: quarantine"
        );
        assert!(
            !redaction_receipt_is_stale_finalization_echo(&pre, &pre),
            "both nil is not the finalization shape"
        );

        // A sibling-field divergence (different request) must NOT match.
        let mut other = base;
        other.request_id = uuid::Uuid::now_v7().to_string();
        let other_pre =
            envelope(&encode_redaction_audit_receipt(other, &receipt_id, &identity).unwrap());
        assert!(!redaction_receipt_is_stale_finalization_echo(
            &finalized, &other_pre
        ));

        // A differing envelope byte must NOT match.
        let mut shifted = pre;
        shifted[1] ^= 0x01;
        assert!(!redaction_receipt_is_stale_finalization_echo(
            &finalized, &shifted
        ));
    }

    /// Finding 1 (anti-clobber, carrier completeness): a `u:w:` row that
    /// appears AFTER the read phase — caught by the in-txn full set-equality
    /// re-read — DEFERS the window. The compaction write txn aborts
    /// uncommitted: the obligation is kept, the receipt stays nil, and the
    /// `d:w:` snapshot is NOT replaced by a shallow blob. A wrong impl that
    /// only flips `svf=0` and finalizes would delete the h: row.
    #[cfg(feature = "sync")]
    #[test]
    fn sweep_defers_when_uw_row_appears_after_read_phase() {
        let (_dir, vault) = open_vault();
        let id = EntityId::now();
        put_entity(&vault, &id, 1_771_027_200, b"raced-uw-body");
        let outcome = vault
            .delete_entity_with_reason(&id, DeleteReason::GdprDelete)
            .unwrap();
        let receipt_id = outcome.receipt_id.expect("receipt id");
        let sweep_key = outcome.sweep_key.expect("sweep key");
        let window = crate::deletion::window_label_from_timestamp(1_771_027_200);
        let dw_before = vault.sync_state_get(&format!("d:w:{window}")).unwrap();

        INJECT_RACE_BEFORE_COMPACT_WRITE.with(|c| c.set(RaceInjection::AppendUpdateRow));
        let run = run_hard_erase_sweep(&vault).unwrap();

        assert_eq!(run.jobs_processed, 0, "a raced window must not finalize");
        assert!(
            run.windows_deferred_raced >= 1,
            "the raced-in u:w: row must defer the window"
        );
        assert!(run.jobs_deferred >= 1, "the obligation defers, not fails");
        assert_eq!(run.jobs_failed, 0);
        assert!(
            h_rows(&vault).iter().any(|(k, _)| *k == sweep_key),
            "h: row must survive a raced defer"
        );
        assert!(receipt_sweep_complete_at(&vault, &receipt_id).is_none());
        let dw_after = vault.sync_state_get(&format!("d:w:{window}")).unwrap();
        assert_eq!(
            dw_after, dw_before,
            "the raced window's d:w: snapshot must be untouched (no shallow clobber)"
        );
    }

    /// Finding 4 (anti-clobber re-read): a DIFFERENT `d:w:` snapshot written
    /// between the read phase and the write txn must NOT be overwritten by
    /// the sweep's stale-based shallow. The run defers; the externally
    /// written snapshot (carrying a distinctive benign marker the shallow
    /// would not) survives byte-present. A wrong impl with the unconditional
    /// put clobbers it.
    #[cfg(feature = "sync")]
    #[test]
    fn sweep_defers_when_dw_snapshot_changes_between_read_and_write() {
        let (_dir, vault) = open_vault();
        let id = EntityId::now();
        put_entity(&vault, &id, 1_771_027_200, b"raced-dw-body");
        let outcome = vault
            .delete_entity_with_reason(&id, DeleteReason::GdprDelete)
            .unwrap();
        let receipt_id = outcome.receipt_id.expect("receipt id");
        let sweep_key = outcome.sweep_key.expect("sweep key");
        let window = crate::deletion::window_label_from_timestamp(1_771_027_200);

        INJECT_RACE_BEFORE_COMPACT_WRITE.with(|c| c.set(RaceInjection::ReplaceSnapshot));
        let run = run_hard_erase_sweep(&vault).unwrap();

        assert_eq!(run.jobs_processed, 0);
        assert!(
            run.windows_deferred_raced >= 1,
            "the changed d:w: snapshot must defer the window"
        );
        assert!(
            h_rows(&vault).iter().any(|(k, _)| *k == sweep_key),
            "h: row must survive"
        );
        assert!(receipt_sweep_complete_at(&vault, &receipt_id).is_none());
        let dw_after = vault
            .sync_state_get(&format!("d:w:{window}"))
            .unwrap()
            .expect("d:w: present");
        assert!(
            contains(&dw_after, RACE_BENIGN_MARKER),
            "the externally-written snapshot must survive (no shallow clobber)"
        );
    }

    /// Finding 2 (fail closed): an UNDECODABLE REDACTION_AUDIT receipt body
    /// encountered during a job's finalize txn aborts the WHOLE txn — the
    /// h: row is KEPT, the job is routed to retry (jobs_failed), and a
    /// CO-SCOPED valid receipt's `sweep_complete_at` ALSO stays nil
    /// (all-or-nothing). The audit counts the unreadable receipt.
    #[cfg(feature = "sync")]
    #[test]
    fn sweep_undecodable_receipt_keeps_h_row_and_does_not_finalize() {
        let (_dir, vault) = open_vault();
        let id = EntityId::now();
        put_entity(&vault, &id, 1_771_027_200, b"undecodable-finalize-body");
        let outcome = vault
            .delete_entity_with_reason(&id, DeleteReason::GdprDelete)
            .unwrap();
        // The real receipt is the CO-SCOPED valid receipt (scope == the due
        // job's scope) that would be finalized but for the abort.
        let valid_receipt_id = outcome.receipt_id.expect("receipt id");
        let sweep_key = outcome.sweep_key.expect("sweep key");

        // A separate, undecodable type-120 receipt finalize_job will hit.
        write_corrupt_redaction_receipt(&vault);

        let run = run_hard_erase_sweep(&vault).unwrap();
        assert_eq!(
            run.jobs_processed, 0,
            "no job finalizes past a corrupt receipt"
        );
        assert!(run.jobs_failed >= 1, "the job routes to retry");
        assert!(
            run.obligations_undecodable >= 1,
            "the unreadable receipt is a counted accountability signal"
        );
        assert!(
            h_rows(&vault).iter().any(|(k, _)| *k == sweep_key),
            "the obligation row must be kept on an undecodable-receipt abort"
        );
        assert!(
            receipt_sweep_complete_at(&vault, &valid_receipt_id).is_none(),
            "the co-scoped valid receipt must stay nil — all-or-nothing finalize"
        );
    }

    /// Finding 2 (audit half): an undecodable receipt body — even with a
    /// (not-due) covering h: row present — is NEVER silently "covered". The
    /// audit counts it in the SIBLING `obligations_undecodable`, distinct
    /// from `obligations_missing`.
    #[test]
    fn sweep_audit_counts_undecodable_receipt_as_missing() {
        let (_dir, vault) = open_vault();
        write_corrupt_redaction_receipt(&vault);
        // A not-due h: row: present (covering) but never reaches finalize.
        let future = crate::unix_seconds_now() + 86_400;
        let value = encode_hard_erase_sweep_job(
            RedactionScope::entity(&EntityId::now()),
            HardEraseSweepExtras::default(),
            future,
        )
        .unwrap();
        write_h_row(&vault, 4_242, &value);

        let run = run_hard_erase_sweep(&vault).unwrap();
        assert_eq!(run.jobs_processed, 0);
        assert!(
            run.obligations_undecodable >= 1,
            "an unreadable receipt must be counted by the audit, never silently covered"
        );
        assert_eq!(
            run.obligations_missing, 0,
            "present-but-corrupt is NOT a dropped obligation"
        );
    }

    /// Finding 3 (kept-and-loud): a decodable job whose `scope.entity_ids`
    /// fails `EntityId::from_hex` is NEVER compacted-and-finalized. Its h:
    /// row survives BYTE-IDENTICAL (no retry_state consumption), it defers,
    /// and nothing is finalized. The inverse of the undecodable-h:-row case.
    #[test]
    fn sweep_malformed_scope_job_kept_loud_not_finalized() {
        let (_dir, vault) = open_vault();
        let bad_scope = RedactionScope {
            entity_ids: vec!["zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz".to_owned()],
            revision_ids: Vec::new(),
        };
        let now = crate::unix_seconds_now();
        let value =
            encode_hard_erase_sweep_job(bad_scope, HardEraseSweepExtras::default(), now).unwrap();
        let key = write_h_row(&vault, 55, &value);

        let run = run_hard_erase_sweep(&vault).unwrap();
        assert_eq!(
            run.jobs_processed, 0,
            "a malformed-scope job must not finalize"
        );
        assert_eq!(run.receipts_finalized, 0);
        assert!(
            run.jobs_deferred >= 1,
            "the malformed job is kept and counted"
        );
        let rows = h_rows(&vault);
        let kept: Vec<_> = rows.iter().filter(|(k, _)| *k == key).collect();
        assert_eq!(kept.len(), 1, "the obligation row must survive");
        assert_eq!(
            kept[0].1, value,
            "the kept row must be BYTE-IDENTICAL (no retry_state consumption)"
        );
    }

    /// Finding 1/4 idempotency: once the race resolves (no further
    /// concurrent writes), a clean re-run compacts the previously-raced
    /// window, finalizes the receipt, deletes the h: row, and leaves ZERO
    /// erased-payload bytes — defer-and-retry never strands the obligation.
    #[cfg(feature = "sync")]
    #[test]
    fn sweep_raced_window_completes_on_clean_rerun() {
        use crate::sync::bridge::Materializer;
        use crate::sync::manager::WindowManager;
        use crate::sync::types::WindowKey;
        use std::sync::Arc;

        const UNIT_SENTINEL: &[u8] = b"UNIT-SWEEP-SENTINEL-3a9f17e2";

        let dir = tempfile::tempdir().unwrap();
        let vault = Arc::new(Vault::open(dir.path(), test_config()).unwrap());
        let id = EntityId::now();
        put_entity(&vault, &id, 1_771_027_200, UNIT_SENTINEL);

        // Mirror the entity into the CRDT so the persisted history is a REAL
        // sentinel carrier, then close the window so it is compactable.
        let materializer = Arc::new(Materializer::new());
        let manager = Arc::new(WindowManager::new(
            Arc::clone(&vault),
            materializer,
            "sweep-rerun",
        ));
        let window_key = WindowKey::from_timestamp(1_771_027_200);
        let window = manager.open_window(&window_key).unwrap();
        let outcome = vault
            .delete_entity_with_reason(&id, DeleteReason::GdprDelete)
            .unwrap();
        let receipt_id = outcome.receipt_id.expect("receipt id");
        let sweep_key = outcome.sweep_key.expect("sweep key");
        drop(window);
        assert!(manager.unload_window(&window_key).unwrap());

        // First run: the injected concurrent u:w: row defers the window.
        INJECT_RACE_BEFORE_COMPACT_WRITE.with(|c| c.set(RaceInjection::AppendUpdateRow));
        let run1 = run_hard_erase_sweep(&vault).unwrap();
        assert!(run1.windows_deferred_raced >= 1, "the race must defer");
        assert_eq!(run1.jobs_processed, 0);
        assert!(h_rows(&vault).iter().any(|(k, _)| *k == sweep_key));
        assert!(receipt_sweep_complete_at(&vault, &receipt_id).is_none());

        // Clean re-run (injection is one-shot): the quiesced window compacts.
        let run2 = run_hard_erase_sweep(&vault).unwrap();
        assert_eq!(
            run2.jobs_processed, 1,
            "the re-run completes the obligation"
        );
        assert_eq!(run2.receipts_finalized, 1);
        assert!(
            !h_rows(&vault).iter().any(|(k, _)| *k == sweep_key),
            "the h: row is deleted on the clean re-run"
        );
        assert!(receipt_sweep_complete_at(&vault, &receipt_id).is_some());
        assert!(
            !sync_rows_contain(&vault, UNIT_SENTINEL),
            "no erased-payload bytes may survive the idempotent re-run"
        );
    }

    /// R5 (ONE-1087/1091 final carrier fence — the SECOND TOCTOU): a `u:w:`
    /// row that appears AFTER window compaction committed (state =
    /// AllCompacted ⇒ zero u:w: rows anywhere) but BEFORE the finalize txn
    /// must DEFER the job. The in-txn fence (the FIRST step of the same write
    /// txn that would delete the h: row) sees the post-compaction carrier and
    /// aborts with NO mutation: the h: row is KEPT, the receipt stays nil,
    /// `jobs_deferred` is incremented, and — crucially — the job is NOT
    /// routed to retry (a transient race must never burn a retry attempt). A
    /// no-fence impl deletes the h: row and finalizes the receipt → fails.
    #[cfg(feature = "sync")]
    #[test]
    fn sweep_defers_when_uw_carrier_appears_after_compaction_before_finalize() {
        use crate::sync::bridge::Materializer;
        use crate::sync::manager::WindowManager;
        use crate::sync::types::WindowKey;
        use std::sync::Arc;

        let dir = tempfile::tempdir().unwrap();
        let vault = Arc::new(Vault::open(dir.path(), test_config()).unwrap());
        let id = EntityId::now();
        put_entity(&vault, &id, 1_771_027_200, b"final-fence-body");

        // Mirror the entity into a real CRDT window, then close it so the
        // sweep can compact it to AllCompacted (zero u:w: rows). This is the
        // ONLY state that reaches finalize_job — the fence's precondition.
        let materializer = Arc::new(Materializer::new());
        let manager = Arc::new(WindowManager::new(
            Arc::clone(&vault),
            materializer,
            "final-fence",
        ));
        let window_key = WindowKey::from_timestamp(1_771_027_200);
        let window = manager.open_window(&window_key).unwrap();
        let outcome = vault
            .delete_entity_with_reason(&id, DeleteReason::GdprDelete)
            .unwrap();
        let receipt_id = outcome.receipt_id.expect("receipt id");
        let sweep_key = outcome.sweep_key.expect("sweep key");
        let job_value_before = h_rows(&vault)
            .iter()
            .find(|(k, _)| *k == sweep_key)
            .expect("job row")
            .1
            .clone();
        drop(window);
        assert!(manager.unload_window(&window_key).unwrap());

        // Arm the seam: a valid u:w: row lands in the gap between
        // compaction-commit and the finalize txn (its own committed txn).
        let window_label = crate::deletion::window_label_from_timestamp(1_771_027_200);
        INJECT_UW_ROW_BEFORE_FINALIZE.with(|cell| *cell.borrow_mut() = Some(window_label.clone()));

        let run = run_hard_erase_sweep(&vault).unwrap();

        assert_eq!(
            run.jobs_processed, 0,
            "a post-compaction carrier must defer, not finalize"
        );
        assert_eq!(run.receipts_finalized, 0);
        assert!(
            run.jobs_deferred >= 1,
            "the raced-in u:w: carrier must defer the job"
        );
        assert_eq!(
            run.jobs_failed, 0,
            "a transient post-compaction race is NOT a failure (no retry consumed)"
        );

        // The h: row survives BYTE-IDENTICAL: the defer must not consume
        // retry_state (no rewrite_job_for_retry).
        let rows = h_rows(&vault);
        let kept: Vec<_> = rows.iter().filter(|(k, _)| *k == sweep_key).collect();
        assert_eq!(kept.len(), 1, "the obligation row must survive the fence");
        assert_eq!(
            kept[0].1, job_value_before,
            "deferral must not consume retry_state (byte-identical row)"
        );
        assert!(
            receipt_sweep_complete_at(&vault, &receipt_id).is_none(),
            "the receipt must stay nil — the fence aborts before any mutation"
        );
    }

    /// R6 (ONE-1087/1091 raw receipt validation before decode): a stored
    /// type-120 REDACTION_AUDIT body that carries every required field PLUS
    /// one UNKNOWN key decodes fine via Serde (which drops unknown fields)
    /// but is rejected by the raw `validate_redaction_receipt_body` — which
    /// `finalize_job` now runs on the STORED bytes BEFORE decode. The
    /// validator's `InvalidRedactionReceiptBody` is mapped to the exact
    /// `CorruptedIndex("redaction audit receipt body")` literal so the
    /// per-job retry arm catches it: the h: row is KEPT, the receipt stays
    /// nil, the job routes to retry, and the WHOLE run does NOT hard-error.
    /// The buggy re-encode-then-validate impl (validating only the
    /// already-stripped body) finalizes and deletes the h: row → fails.
    #[test]
    fn sweep_unknown_field_receipt_keeps_h_row_not_finalized() {
        use rmpv::Value;

        let (_dir, vault) = open_vault();
        let id = EntityId::now();
        put_entity(&vault, &id, 1_771_027_200, b"unknown-field-receipt-body");
        let outcome = vault
            .delete_entity_with_reason(&id, DeleteReason::GdprDelete)
            .unwrap();
        let receipt_id = outcome.receipt_id.expect("receipt id");
        let sweep_key = outcome.sweep_key.expect("sweep key");

        // Sanity: the receipt is a pending sweep target (queued, not yet
        // swept) — exactly what finalize_job would otherwise finalize.
        assert!(
            receipt_sweep_complete_at(&vault, &receipt_id).is_none(),
            "receipt must start unswept"
        );

        // Rewrite the STORED receipt body to add one UNKNOWN key. Start from
        // the real, valid body (so all required fields + types are present
        // and Serde still decodes it), then append a key outside the pinned
        // RECEIPT_BODY_KEYS set — the discriminator the raw validator rejects.
        let header_len = crate::batch::ENTITY_METADATA_HEADER_LEN;
        let raw = vault.get_raw(&receipt_id).unwrap().expect("receipt raw");
        let mut cursor = std::io::Cursor::new(&raw[header_len..]);
        let Value::Map(mut entries) = rmpv::decode::read_value(&mut cursor).unwrap() else {
            panic!("receipt body must be a map");
        };
        entries.push((
            Value::String("smuggled_unknown_field".into()),
            Value::Boolean(true),
        ));
        let mut tampered_body = Vec::new();
        rmpv::encode::write_value(&mut tampered_body, &Value::Map(entries)).unwrap();
        // The tampered body still Serde-decodes (unknown field ignored)...
        assert!(
            decode_redaction_audit_receipt(&tampered_body).is_ok(),
            "Serde must still decode (unknown field dropped) — the gap R6 closes"
        );
        // ...but the raw validator rejects it (the only safety net).
        assert!(
            validate_redaction_receipt_body(&tampered_body).is_err(),
            "the raw validator must reject the unknown field"
        );
        let mut rewritten = Vec::with_capacity(header_len + tampered_body.len());
        rewritten.extend_from_slice(&raw[..header_len]);
        rewritten.extend_from_slice(&tampered_body);
        {
            let mut wtxn = vault.store.env.write_txn().unwrap();
            vault
                .store
                .entities
                .put(&mut wtxn, receipt_id.as_bytes(), &rewritten)
                .unwrap();
            wtxn.commit().unwrap();
        }

        // The run must NOT hard-error (the .map_err keeps it a per-job retry).
        let run = run_hard_erase_sweep(&vault).expect("run must not hard-abort");
        assert_eq!(
            run.jobs_processed, 0,
            "an unknown-field receipt must not finalize"
        );
        assert_eq!(run.receipts_finalized, 0);
        assert!(run.jobs_failed >= 1, "the job must route to retry");

        // The obligation row is KEPT (fail-closed, undecodable-receipt
        // posture) and the receipt stays nil.
        assert!(
            h_rows(&vault).iter().any(|(k, _)| *k == sweep_key),
            "the h: row must be kept when the stored receipt body is invalid"
        );
        assert!(
            receipt_sweep_complete_at(&vault, &receipt_id).is_none(),
            "the receipt must stay nil — finalize aborts before mutation"
        );
    }
}
