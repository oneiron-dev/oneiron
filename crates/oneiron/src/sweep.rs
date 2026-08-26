//! ARCH-0038 historical-carrier sweep executor — ONE-1087 / ONE-1091
//! phase 1 (manual trigger via [`crate::maintain::MaintenanceBuilder`]).
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
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
#[cfg(feature = "sync")]
use crate::error::{SyncEngineContext, SyncProtocolPruneScope, SyncProtocolValidation};
use crate::registry::ENTITY_TYPE_REDACTION_AUDIT;

/// Retry backoff cap: a failed job is retried no later than 24 h out, so
/// the ≤30 d `deadline_at` SLA cannot be silently outwaited by backoff.
const RETRY_BACKOFF_CAP_SECS: u64 = 86_400;
/// Base retry backoff (doubles per attempt up to the cap).
const RETRY_BACKOFF_BASE_SECS: u64 = 60;

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
            .map(|value| value.to_vec());
        let mut rows: Vec<(String, Vec<u8>)> = Vec::new();
        let prefix = format!("u:w:{key}:");
        for entry in vault.store.sync_state.prefix_iter(&rtxn, &prefix)? {
            let (k, v) = entry?;
            rows.push((k.to_string(), v.to_vec()));
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
        .map_err(|e| Error::sync_engine(SyncEngineContext::LoroExportShallowSnapshot, e))?;
    let vv = doc_version_vector(&doc);

    let merged_keys: BTreeSet<String> = update_rows.iter().map(|(k, _)| k.clone()).collect();
    let prefix = format!("u:w:{key}:");
    for k in &merged_keys {
        if !k.starts_with(&prefix) {
            // Surgical scope (fail closed): never touch another family.
            return Err(Error::sync_protocol(SyncProtocolValidation::ScopedPrune {
                scope: SyncProtocolPruneScope::SweepUpdateRows,
                prefix,
                key: k.clone(),
            }));
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
            .map(|value| value.to_vec());
        if current_snapshot != snapshot_bytes {
            raced.set(true);
            return Err(Error::sync_protocol(
                SyncProtocolValidation::SweepSnapshotRace,
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
            current_keys.insert(k.to_string());
        }
        if current_keys != merged_keys {
            raced.set(true);
            return Err(Error::sync_protocol(
                SyncProtocolValidation::SweepUpdateRowsRace,
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
                .map_err(|e| Error::sync_engine(SyncEngineContext::LoroMapInsert, e))?;
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
                .map_err(|e| Error::sync_engine(SyncEngineContext::LoroMapInsert, e))?;
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

#[cfg(test)]
mod tests;
