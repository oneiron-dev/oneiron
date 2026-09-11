//! Builder flags, run() dispatch, and the aggregate maintenance report.

use crate::Vault;
use crate::error::Result;
use crate::hnsw::COUNT_KEY;

use super::attempt_lease;
use super::hnsw_rebuild::{decode_u64_opt, rebuild_hnsw};
use super::rebuild_hnsw_if_dropped;
use super::short_ids::recompute_short_id_hashes;
use super::text_ops::{cleanup_ppr_cache, clear_text_index, compact_postings};

/// Builder for running maintenance operations against a vault.
#[must_use = "MaintenanceBuilder performs no work until `.run()` is called"]
pub struct MaintenanceBuilder<'a> {
    vault: &'a Vault,
    do_rebuild_hnsw: bool,
    heal_invalid_vectors_on_rebuild: bool,
    do_cleanup_ppr: bool,
    ppr_max_age_secs: u64,
    do_compact_postings: bool,
    do_recompute_hashes: bool,
    do_clear_text_index: bool,
    do_hard_erase_sweep: bool,
    do_cleanup_attempt_queue: bool,
    attempt_queue_lease_timeout_secs: u64,
    do_backfill_gate_claim_index: bool,
}

/// Aggregate counters for maintenance operations.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct MaintenanceReport {
    /// Nodes omitted from the rebuilt HNSW graph versus the previously committed count.
    ///
    /// In heal mode this can overlap with skipped invalid rows only when those rows
    /// were already present in the previously committed graph; consult
    /// `hnsw_invalid_vectors_skipped` for the explicit invalid-row breakdown, and do
    /// not assume the two counters are mutually inclusive.
    pub hnsw_dead_nodes_removed: u64,
    /// Live HNSW nodes after the rebuild commits.
    pub hnsw_live_nodes: u64,
    /// Invalid stored vector rows skipped only by heal-mode rebuilds.
    pub hnsw_invalid_vectors_skipped: u64,
    pub ppr_caches_evicted: u64,
    pub ppr_deps_cleaned: u64,
    pub postings_compacted: u64,
    /// Orphaned or stale short-id mappings removed from the forward/reverse indexes.
    pub orphan_short_ids_deleted: u64,
    pub short_id_hashes_updated: u64,
    /// Posting-list rows removed by `clear_text_index`.
    pub text_postings_removed: u64,
    /// `text_meta` rows removed by `clear_text_index`. Includes the
    /// `TOTAL_DOCS_KEY` / `TOTAL_LENGTH_KEY` sentinel rows; absence of those
    /// keys is read by `bm25::read_total_docs` as zero, so the deletion is
    /// equivalent to a rewrite-to-zero.
    pub text_meta_removed: u64,
    /// Forward-index rows removed by `clear_text_index`.
    pub text_forward_removed: u64,
    /// Per-field length rows removed by `clear_text_index`.
    pub text_doc_field_lengths_removed: u64,
    /// Per-field stats rows removed by `clear_text_index`.
    pub text_bm25_field_stats_removed: u64,
    /// `h:` hard-erase sweep jobs completed (receipts finalized + row
    /// deleted) by `run_hard_erase_sweep` (ONE-1087).
    pub sweep_jobs_processed: u64,
    /// Jobs deferred without an attempt: not yet due (retry backoff), a
    /// live window blocked compaction, an undecodable/malformed `h:` row,
    /// or a non-`sync` build facing CRDT carrier rows (fail closed).
    pub sweep_jobs_deferred: u64,
    /// Jobs whose attempt FAILED this run — `retry_state` rewritten in
    /// place (attempt_count, next_attempt_at backoff, last_error_code);
    /// the row is never deleted on failure.
    pub sweep_jobs_failed: u64,
    /// Persisted window docs rebuilt through a shallow snapshot (history
    /// carriers dropped).
    pub sweep_windows_compacted: u64,
    /// Windows skipped because they are OPEN in a window registry — a live
    /// doc's next full-snapshot persist would resurrect the carrier.
    pub sweep_windows_deferred_live: u64,
    /// Windows deferred because a `u:w:` row appeared/vanished or the `d:w:`
    /// snapshot changed between the read phase and the compaction write txn
    /// (anti-clobber re-read guard). SIBLING of `sweep_windows_deferred_live`
    /// — a raced window is neither compacted nor a live-registry deferral.
    pub sweep_windows_deferred_raced: u64,
    /// REDACTION_AUDIT receipts whose `sweep_complete_at` was finalized.
    pub sweep_receipts_finalized: u64,
    /// Pending jobs observed past their `deadline_at` (queued_at + 30 d,
    /// GDPR Art. 12(3)) — each is also a `tracing::error`.
    pub sweep_deadline_breaches: u64,
    /// Stale `x:` quarantine rows evicted by the on-demand retention pass.
    pub sweep_quarantine_rows_expired: u64,
    /// ONE-1091 audit: receipts with `sweep_queued_at` set, no
    /// `sweep_complete_at`, and NO covering pending `h:` row — a dropped
    /// erasure obligation (each is also a `tracing::error`).
    pub sweep_obligations_missing: u64,
    /// Audit: REDACTION_AUDIT receipts whose stored body could not be
    /// decoded — present-but-corrupt accountability records. SIBLING of
    /// `sweep_obligations_missing`; an unreadable receipt is a distinct
    /// signal from a dropped one and is never folded into it.
    pub sweep_obligations_undecodable: u64,
    /// Attempt-queue lease cleanup counts. This is device-local runner-store
    /// state and carries only stable counters, never payloads or lease owners.
    pub attempt_queue_cleanup: crate::attempt_queue::AttemptQueueCleanupReport,
    /// ONE-1896 lease-expiry WARNING counts from the same lane, recorded BEFORE
    /// cleanup: a warned lease is still live work that was asked to land, while
    /// `attempt_queue_cleanup` counts leases already taken away.
    pub attempt_queue_lease_warnings: crate::attempt_queue::AttemptLeaseWarningReport,
    /// Pre-existing claim-bound Gate decision rows written into the ERASE-A
    /// (ONE-1637) claim index by `backfill_gate_decision_claim_index`.
    pub gate_claim_index_rows_backfilled: u64,
    /// The durable backfill-complete flag was already set, so the op was a
    /// no-op. SIBLING of `gate_claim_index_rows_backfilled`: a zero-row run on
    /// an unflagged empty ledger is a distinct signal from an already-complete
    /// one.
    pub gate_claim_index_backfill_already_complete: bool,
}

impl<'a> MaintenanceBuilder<'a> {
    pub(crate) fn new(vault: &'a Vault) -> Self {
        Self {
            vault,
            do_rebuild_hnsw: false,
            heal_invalid_vectors_on_rebuild: false,
            do_cleanup_ppr: false,
            ppr_max_age_secs: 0,
            do_compact_postings: false,
            do_recompute_hashes: false,
            do_clear_text_index: false,
            do_hard_erase_sweep: false,
            do_cleanup_attempt_queue: false,
            attempt_queue_lease_timeout_secs: 0,
            do_backfill_gate_claim_index: false,
        }
    }

    pub fn rebuild_hnsw(mut self) -> Self {
        self.do_rebuild_hnsw = true;
        self.heal_invalid_vectors_on_rebuild = false;
        self
    }

    pub fn rebuild_hnsw_heal_invalid_vectors(mut self) -> Self {
        self.do_rebuild_hnsw = true;
        self.heal_invalid_vectors_on_rebuild = true;
        self
    }

    /// Evicts stale, malformed, dead-seed, and over-age PPR cache rows.
    ///
    /// `max_age_secs` is a HARD age bound, independent of the recency-tiered
    /// serve TTL (ARCH-0019 / ARCH-0014: Active 24 h · Recent 72 h ·
    /// Dormant 168 h, decided per read from the seed set's most recent
    /// `learned_at`). Whether a row may be SERVED is decided exclusively by
    /// the read-time gate; to never evict a row the tiered gate could still
    /// serve, pass at least the longest tier (168 h = 604 800 s).
    pub fn cleanup_ppr_cache(mut self, max_age_secs: u64) -> Self {
        self.do_cleanup_ppr = true;
        self.ppr_max_age_secs = max_age_secs;
        self
    }

    pub fn compact_postings(mut self) -> Self {
        self.do_compact_postings = true;
        self
    }

    pub fn recompute_short_id_hashes(mut self) -> Self {
        self.do_recompute_hashes = true;
        self
    }

    /// Drop every text-index row and rewrite the analyzer manifest from
    /// the currently-discovered dict set. Use after
    /// [`StoreError::IncompatibleAnalyzer`](crate::error::StoreError::IncompatibleAnalyzer) or [`StoreError::Bm25FieldSchemaChanged`](crate::error::StoreError::Bm25FieldSchemaChanged)
    /// to rebuild under the current analyzer. Leaves entities, vectors,
    /// edges, and PPR cache untouched — only text-index state is cleared.
    ///
    /// After `clear_text_index` commits, callers must re-run their
    /// indexing pipeline (`batch.text(...)`) to repopulate the index.
    ///
    /// [`StoreError::IncompatibleAnalyzer`]: crate::error::StoreError::IncompatibleAnalyzer
    /// [`StoreError::Bm25FieldSchemaChanged`]: crate::error::StoreError::Bm25FieldSchemaChanged
    pub fn clear_text_index(mut self) -> Self {
        self.do_clear_text_index = true;
        self
    }

    /// Manual ARCH-0038 historical-carrier sweep (ONE-1087/ONE-1091 phase
    /// 1; scheduling is M6): drains pending `h:{seq:8BE}` hard-erase
    /// obligations, shallow-compacts every CLOSED persisted window doc
    /// (dropping the pre-delete Loro op history — the dominant residual
    /// byte carrier — while preserving live state, doc identity and VV),
    /// scrubs live-map residue for `dt:`-marked ids, finalizes matching
    /// receipts' `sweep_complete_at`, expires stale `x:` quarantine rows,
    /// and audits for dropped obligations. Fail closed throughout: open
    /// windows defer, failed windows keep the obligation rows with
    /// `retry_state` rewritten in place, and delete semantics are never
    /// weakened (receipts, `dt:` markers and tombstones are permanent).
    pub fn run_hard_erase_sweep(mut self) -> Self {
        self.do_hard_erase_sweep = true;
        self
    }

    /// Returns expired attempt leases to the ready index for recovery by the
    /// normal atomic claim path. `run` fails closed if the timeout is zero.
    pub fn cleanup_attempt_queue_leases(mut self, lease_timeout_secs: u64) -> Self {
        self.do_cleanup_attempt_queue = true;
        self.attempt_queue_lease_timeout_secs = lease_timeout_secs;
        self
    }

    /// One-time ERASE-A (ONE-1637) backfill of the claim-keyed Gate decision
    /// index for vaults created before the index existed. Idempotent: a no-op
    /// once the durable backfill-complete flag is set. Until it is set,
    /// per-claim discovery uses the keyspace-scan fallback — running this op
    /// changes cost, never correctness.
    pub fn backfill_gate_decision_claim_index(mut self) -> Self {
        self.do_backfill_gate_claim_index = true;
        self
    }

    pub fn run(self) -> Result<MaintenanceReport> {
        let mut report = MaintenanceReport::default();

        if self.do_rebuild_hnsw {
            // ONE-1933 / OF-447: a SLIM-dropped graph takes the marker-aware
            // guarded rehydrate in the builder's requested heal mode and skips
            // the ordinary path; an absent marker falls through unchanged.
            // Both builder methods stay pure `-> Self` flag setters.
            if rebuild_hnsw_if_dropped(self.vault, self.heal_invalid_vectors_on_rebuild)? {
                // A shed graph carries no committed `COUNT_KEY`, so there are
                // no dead nodes to remove; report the rehydrated live count.
                let rtxn = self.vault.store.env.read_txn()?;
                report.hnsw_live_nodes =
                    decode_u64_opt(self.vault.store.hnsw_meta.get(&rtxn, COUNT_KEY)?.as_deref())?
                        .unwrap_or(0);
                report.hnsw_invalid_vectors_skipped = self
                    .vault
                    .store
                    .vectors
                    .len(&rtxn)?
                    .saturating_sub(report.hnsw_live_nodes);
            } else {
                let (dead_removed, live_nodes, invalid_vectors_skipped) =
                    rebuild_hnsw(self.vault, self.heal_invalid_vectors_on_rebuild)?;
                report.hnsw_dead_nodes_removed = dead_removed;
                report.hnsw_live_nodes = live_nodes;
                report.hnsw_invalid_vectors_skipped = invalid_vectors_skipped;
            }
        }

        if self.do_cleanup_ppr {
            let (evicted, deps_cleaned) = cleanup_ppr_cache(self.vault, self.ppr_max_age_secs)?;
            report.ppr_caches_evicted = evicted;
            report.ppr_deps_cleaned = deps_cleaned;
        }

        if self.do_compact_postings {
            report.postings_compacted = compact_postings(self.vault)?;
        }

        if self.do_recompute_hashes {
            let (updated, deleted) = recompute_short_id_hashes(self.vault)?;
            report.short_id_hashes_updated = updated;
            report.orphan_short_ids_deleted = deleted;
        }

        if self.do_clear_text_index {
            let counts = clear_text_index(self.vault)?;
            report.text_postings_removed = counts.postings;
            report.text_meta_removed = counts.meta;
            report.text_forward_removed = counts.forward;
            report.text_doc_field_lengths_removed = counts.doc_field_lengths;
            report.text_bm25_field_stats_removed = counts.field_stats;
        }

        if self.do_hard_erase_sweep {
            let run = crate::sweep::run_hard_erase_sweep(self.vault)?;
            report.sweep_jobs_processed = run.jobs_processed;
            report.sweep_jobs_deferred = run.jobs_deferred;
            report.sweep_jobs_failed = run.jobs_failed;
            report.sweep_windows_compacted = run.windows_compacted;
            report.sweep_windows_deferred_live = run.windows_deferred_live;
            report.sweep_windows_deferred_raced = run.windows_deferred_raced;
            report.sweep_receipts_finalized = run.receipts_finalized;
            report.sweep_deadline_breaches = run.deadline_breaches;
            report.sweep_quarantine_rows_expired = run.quarantine_rows_expired;
            report.sweep_obligations_missing = run.obligations_missing;
            report.sweep_obligations_undecodable = run.obligations_undecodable;
        }

        if self.do_backfill_gate_claim_index {
            let backfill = self.vault.store.backfill_gate_decision_claim_index()?;
            report.gate_claim_index_rows_backfilled = backfill.rows_indexed;
            report.gate_claim_index_backfill_already_complete = backfill.already_complete;
        }

        if self.do_cleanup_attempt_queue {
            let (warnings, cleanup) = attempt_lease::sweep_attempt_leases(
                self.vault,
                crate::unix_seconds_now(),
                self.attempt_queue_lease_timeout_secs,
            )?;
            report.attempt_queue_lease_warnings = warnings;
            report.attempt_queue_cleanup = cleanup;
        }

        // Terminal bounded pass keeps unattended critical-write attachments from remaining Auto.
        self.vault.expire_critical_write_confirms()?;

        Ok(report)
    }
}
