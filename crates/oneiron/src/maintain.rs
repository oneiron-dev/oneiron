use std::collections::HashSet;

use xxhash_rust::xxh32::xxh32;

use crate::batch::{ENTITY_METADATA_HEADER_LEN, encode_short_id_forward_key, parse_short_id_value};
use crate::entity_id::{EntityId, parse_entity_id};
use crate::error::{Error, Result};
use crate::hnsw::{
    COUNT_KEY, LinkDiscipline, build_hnsw_graph_from_snapshot, mark_symmetric_links,
    read_vector_version, write_rebuilt_hnsw,
};
use crate::vault::write_text_index_manifest;
use crate::{Vault, le_bytes_to_f32_vec, ppr};

const ERR_VECTOR_KEY: &str = "vector key";
const ERR_SHORT_IDS_REVERSE_KEY: &str = "short_ids_reverse key";
const ERR_SHORT_IDS_FORWARD_VALUE: &str = "short_ids value";

struct PreparedHnswRebuild {
    old_count: u64,
    vector_version: u64,
    rebuilt: crate::hnsw::RebuiltHnswGraph,
    invalid_vectors_skipped: u64,
}

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
    /// [`Error::IncompatibleAnalyzer`] or [`Error::Bm25FieldSchemaChanged`]
    /// to rebuild under the current analyzer. Leaves entities, vectors,
    /// edges, and PPR cache untouched — only text-index state is cleared.
    ///
    /// After `clear_text_index` commits, callers must re-run their
    /// indexing pipeline (`batch.text(...)`) to repopulate the index.
    ///
    /// [`Error::IncompatibleAnalyzer`]: crate::Error::IncompatibleAnalyzer
    /// [`Error::Bm25FieldSchemaChanged`]: crate::Error::Bm25FieldSchemaChanged
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

    pub fn run(self) -> Result<MaintenanceReport> {
        let mut report = MaintenanceReport::default();

        if self.do_rebuild_hnsw {
            let (dead_removed, live_nodes, invalid_vectors_skipped) =
                rebuild_hnsw(self.vault, self.heal_invalid_vectors_on_rebuild)?;
            report.hnsw_dead_nodes_removed = dead_removed;
            report.hnsw_live_nodes = live_nodes;
            report.hnsw_invalid_vectors_skipped = invalid_vectors_skipped;
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

        if self.do_cleanup_attempt_queue {
            report.attempt_queue_cleanup = crate::attempt_queue::AttemptQueue::new(self.vault)
                .cleanup_leases(crate::attempt_queue::CleanupAttemptLeases {
                    now: crate::unix_seconds_now(),
                    lease_timeout_secs: self.attempt_queue_lease_timeout_secs,
                })?;
        }

        Ok(report)
    }
}

struct ClearTextIndexCounts {
    postings: u64,
    meta: u64,
    forward: u64,
    doc_field_lengths: u64,
    field_stats: u64,
}

fn clear_text_index(vault: &Vault) -> Result<ClearTextIndexCounts> {
    let mut wtxn = vault.store.env.write_txn()?;

    let postings = vault.store.text_postings.len(&wtxn)?;
    vault.store.text_postings.clear(&mut wtxn)?;

    let meta = vault.store.text_meta.len(&wtxn)?;
    vault.store.text_meta.clear(&mut wtxn)?;

    let forward = vault.store.text_forward.len(&wtxn)?;
    vault.store.text_forward.clear(&mut wtxn)?;

    let doc_field_lengths = vault.store.text_doc_field_lengths.len(&wtxn)?;
    vault.store.text_doc_field_lengths.clear(&mut wtxn)?;

    let field_stats = vault.store.text_bm25_field_stats.len(&wtxn)?;
    vault.store.text_bm25_field_stats.clear(&mut wtxn)?;

    write_text_index_manifest(&vault.store, &mut wtxn, &vault.analyzer)?;

    wtxn.commit()?;

    // The on-disk manifest now matches the in-memory analyzer; subsequent
    // search_text calls within the same Vault instance can proceed. See
    // `Vault::text_index_trusted`.
    vault
        .text_index_trusted
        .store(true, std::sync::atomic::Ordering::Release);

    Ok(ClearTextIndexCounts {
        postings,
        meta,
        forward,
        doc_field_lengths,
        field_stats,
    })
}

fn rebuild_hnsw(vault: &Vault, heal_invalid_vectors: bool) -> Result<(u64, u64, u64)> {
    let prepared = prepare_rebuild_hnsw(vault, heal_invalid_vectors)?;

    commit_rebuilt_hnsw(vault, &prepared.rebuilt, prepared.vector_version)?;

    let live_nodes = prepared.rebuilt.count;
    let invalid_vectors_skipped = prepared.invalid_vectors_skipped;
    let dead_nodes_removed = prepared.old_count.saturating_sub(live_nodes);
    Ok((dead_nodes_removed, live_nodes, invalid_vectors_skipped))
}

fn cleanup_ppr_cache(vault: &Vault, max_age_secs: u64) -> Result<(u64, u64)> {
    let mut wtxn = vault.store.env.write_txn()?;
    let now = crate::unix_seconds_now();
    let counts = ppr::cleanup_ppr_cache(&vault.store, &mut wtxn, max_age_secs, now)?;
    wtxn.commit()?;
    Ok(counts)
}

fn compact_postings(vault: &Vault) -> Result<u64> {
    let mut wtxn = vault.store.env.write_txn()?;
    // `text_postings` is DUP_SORT (storage ABI v4): `iter` yields one
    // (term, item) pair per duplicate. Remove only the degenerate empty
    // items — a term key whose sole duplicate is empty disappears with
    // it, while valid sibling duplicates are preserved.
    let mut empty_item_terms = Vec::new();
    for entry in vault.store.text_postings.iter(&wtxn)? {
        let (term, posting) = entry?;
        if posting.is_empty() {
            empty_item_terms.push(term.to_vec());
        }
    }

    for term in &empty_item_terms {
        vault
            .store
            .text_postings
            .delete_one_duplicate(&mut wtxn, term, &[])?;
    }

    wtxn.commit()?;
    Ok(empty_item_terms.len() as u64)
}

/// Recomputes short-id content hashes and reaps orphaned/stale mappings under
/// the pinned ARCH-0019 directions: `short_ids_reverse` (entity id ->
/// `short_id ‖ content_hash`) is the entity-keyed source of truth; `short_ids`
/// (`short_id ‖ content_hash` -> entity id) is repaired or pruned from it.
fn recompute_short_id_hashes(vault: &Vault) -> Result<(u64, u64)> {
    let mut wtxn = vault.store.env.write_txn()?;

    struct ShortIdHashUpdate {
        reverse_key: Vec<u8>,
        updated_value: Vec<u8>,
        owned_old_forward_key: Option<Vec<u8>>,
        new_forward_key: Vec<u8>,
    }

    // Pass 1: walk the entity-keyed reverse rows. Refresh drifted content
    // hashes (rewriting BOTH rows — the hash is part of the forward KEY),
    // repair missing/stale forward rows, and reap rows whose backing entity
    // record is gone or whose bytes are corrupt.
    let mut hash_updates: Vec<ShortIdHashUpdate> = Vec::new();
    // (forward key, entity id) rows to (re)write.
    let mut forward_repairs: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    // Forward keys written by this pass. Pass 2 consults this so an
    // intra-pass refresh/repair can never be collected from a stale view of
    // the reverse row it just fixed.
    let mut reserved_forward_keys: HashSet<Vec<u8>> = HashSet::new();
    // (reverse key, paired forward key when recoverable) rows to reap.
    let mut reverse_orphans: Vec<(Vec<u8>, Option<Vec<u8>>)> = Vec::new();

    for entry in vault.store.short_ids_reverse.iter(&wtxn)? {
        let (key, value) = entry?;

        let id = match parse_entity_id(key, ERR_SHORT_IDS_REVERSE_KEY) {
            Ok(id) => id,
            // `parse_entity_id` returns `CorruptedIndex` on length mismatch
            // and `InvalidKey` for reserved sentinel patterns. Both are
            // corrupt reverse rows that must be pruned, not propagated.
            Err(Error::CorruptedIndex(_)) | Err(Error::InvalidKey) => {
                // The reverse key is corrupt, so its value cannot safely name
                // a forward row. A corrupt/aliased value could point at a
                // healthy forward row for another entity. Fail closed: prune
                // only this reverse row; pass 2 owns forward-row reaping from
                // valid forward keys. (ONE-1114 delete-safety.)
                reverse_orphans.push((key.to_vec(), None));
                continue;
            }
            Err(other) => return Err(other),
        };

        let (short_id, current_hash) = match parse_short_id_value(value) {
            Ok(parsed) => parsed,
            Err(Error::CorruptedIndex(_)) => {
                reverse_orphans.push((key.to_vec(), None));
                continue;
            }
            Err(other) => return Err(other),
        };
        let current_forward_key = encode_short_id_forward_key(short_id, current_hash);

        let Some(blob) = vault.store.entities.get(&wtxn, id.as_bytes())? else {
            let owned_forward_key = match vault.store.short_ids.get(&wtxn, &current_forward_key)? {
                Some(forward_id) if forward_id == key => Some(current_forward_key),
                Some(_) => {
                    tracing::warn!(
                        "short-id maintenance skipped unowned reverse-derived forward reap"
                    );
                    None
                }
                None => None,
            };
            reverse_orphans.push((key.to_vec(), owned_forward_key));
            continue;
        };

        if blob.len() < ENTITY_METADATA_HEADER_LEN {
            return Err(Error::InvalidKey);
        }

        let payload = &blob[ENTITY_METADATA_HEADER_LEN..];
        let new_hash = (xxh32(payload, 0) % 256) as u8;
        if new_hash != current_hash {
            let mut updated_value = Vec::with_capacity(short_id.len() + 1);
            updated_value.extend_from_slice(short_id.as_bytes());
            updated_value.push(new_hash);
            let new_forward_key = encode_short_id_forward_key(short_id, new_hash);
            if let Some(forward_id) = vault.store.short_ids.get(&wtxn, &new_forward_key)?
                && forward_id != key
            {
                if forward_key_is_claimed_by_reverse(vault, &wtxn, forward_id, &new_forward_key)? {
                    tracing::warn!(
                        "short-id maintenance pruned backed reverse row with owned refreshed forward alias"
                    );
                    reverse_orphans.push((key.to_vec(), None));
                } else {
                    tracing::warn!(
                        "short-id maintenance skipped stale reverse-derived forward overwrite"
                    );
                }
                continue;
            }
            let owned_old_forward_key =
                match vault.store.short_ids.get(&wtxn, &current_forward_key)? {
                    Some(forward_id) if forward_id == key => Some(current_forward_key),
                    Some(_) => {
                        tracing::warn!(
                            "short-id maintenance skipped unowned reverse-derived forward delete"
                        );
                        None
                    }
                    None => None,
                };
            reserved_forward_keys.insert(new_forward_key.clone());
            hash_updates.push(ShortIdHashUpdate {
                reverse_key: key.to_vec(),
                updated_value,
                owned_old_forward_key,
                new_forward_key,
            });
            continue;
        }

        match vault.store.short_ids.get(&wtxn, &current_forward_key)? {
            Some(forward_id) if forward_id == key => {}
            Some(forward_id) => {
                if forward_key_is_claimed_by_reverse(
                    vault,
                    &wtxn,
                    forward_id,
                    &current_forward_key,
                )? {
                    tracing::warn!(
                        "short-id maintenance pruned backed reverse row with owned forward alias"
                    );
                    reverse_orphans.push((key.to_vec(), None));
                } else {
                    tracing::warn!(
                        "short-id maintenance skipped stale reverse-derived forward overwrite"
                    );
                }
            }
            None => {
                reserved_forward_keys.insert(current_forward_key.clone());
                forward_repairs.push((current_forward_key, key.to_vec()));
            }
        }
    }

    for update in &hash_updates {
        vault
            .store
            .short_ids_reverse
            .put(&mut wtxn, &update.reverse_key, &update.updated_value)?;
        if let Some(old_forward_key) = &update.owned_old_forward_key {
            vault.store.short_ids.delete(&mut wtxn, old_forward_key)?;
        }
        vault
            .store
            .short_ids
            .put(&mut wtxn, &update.new_forward_key, &update.reverse_key)?;
    }
    for (forward_key, id) in &forward_repairs {
        vault.store.short_ids.put(&mut wtxn, forward_key, id)?;
    }
    for (reverse_key, forward_key) in &reverse_orphans {
        // `Some(forward_key)` entries are queued only from validly keyed
        // reverse rows; corrupt-keyed rows prune only themselves.
        if let Some(forward_key) = forward_key {
            vault.store.short_ids.delete(&mut wtxn, forward_key)?;
        }
        vault
            .store
            .short_ids_reverse
            .delete(&mut wtxn, reverse_key)?;
    }

    // Pass 2: forward rows without a healthy reverse counterpart are orphans.
    // Runs after pass-1 writes so repaired/refreshed rows are not re-pruned.
    let mut forward_orphans = Vec::new();
    for entry in vault.store.short_ids.iter(&wtxn)? {
        let (key, value) = entry?;

        // The forward KEY shares the `(short_id ‖ content_hash)` shape with
        // the reverse VALUE; an unparsable key is a corrupt row to prune.
        if parse_short_id_value(key).is_err() {
            forward_orphans.push(key.to_vec());
            continue;
        }

        let id = match parse_entity_id(value, ERR_SHORT_IDS_FORWARD_VALUE) {
            Ok(id) => id,
            Err(Error::CorruptedIndex(_)) | Err(Error::InvalidKey) => {
                forward_orphans.push(key.to_vec());
                continue;
            }
            Err(other) => return Err(other),
        };

        match vault.store.short_ids_reverse.get(&wtxn, id.as_bytes())? {
            Some(reverse_value) if reverse_value == key => {}
            _ if reserved_forward_keys.contains(key) => {
                tracing::warn!(
                    "short-id maintenance kept in-pass reserved forward row despite stale reverse view"
                );
            }
            _ => forward_orphans.push(key.to_vec()),
        }
    }
    for forward_key in &forward_orphans {
        vault.store.short_ids.delete(&mut wtxn, forward_key)?;
    }

    wtxn.commit()?;
    Ok((
        hash_updates.len() as u64,
        (reverse_orphans.len() + forward_orphans.len()) as u64,
    ))
}

fn forward_key_is_claimed_by_reverse(
    vault: &Vault,
    txn: &heed::RwTxn<'_>,
    forward_id: &[u8],
    forward_key: &[u8],
) -> Result<bool> {
    let Ok(owner) = parse_entity_id(forward_id, ERR_SHORT_IDS_FORWARD_VALUE) else {
        return Ok(false);
    };
    Ok(matches!(
        vault.store.short_ids_reverse.get(txn, owner.as_bytes())?,
        Some(reverse_value) if reverse_value == forward_key
    ))
}

fn prepare_rebuild_hnsw(vault: &Vault, heal_invalid_vectors: bool) -> Result<PreparedHnswRebuild> {
    let rtxn = vault.store.env.read_txn()?;
    let old_count = decode_u64_opt(vault.store.hnsw_meta.get(&rtxn, COUNT_KEY)?)?.unwrap_or(0);
    let vector_version = read_vector_version(&vault.store, &rtxn)?;
    let mut vector_ids = Vec::<EntityId>::with_capacity(old_count.min(1_000_000) as usize);
    let mut invalid_vectors_skipped = 0_u64;

    for entry in vault.store.vectors.iter(&rtxn)? {
        let (id_bytes, vector_bytes) = entry?;
        let validation = validate_rebuild_vector(vault, id_bytes, vector_bytes);
        match validation {
            Ok(id) => vector_ids.push(id),
            Err(error) if heal_invalid_vectors && is_healable_rebuild_error(&error) => {
                invalid_vectors_skipped += 1;
            }
            Err(error) => return Err(error),
        }
    }

    // Maintenance rebuilds always produce a symmetric-link graph: this is
    // the one-time ONE-325 migration path for legacy vaults (and a no-op
    // re-assertion for already-migrated ones). Unmigratable vaults fail
    // closed: invalid vectors error out above unless heal mode skips them.
    let rebuilt = build_hnsw_graph_from_snapshot(
        &vault.store,
        &vault.config,
        &rtxn,
        &vector_ids,
        LinkDiscipline::Symmetric,
    )?;
    drop(rtxn);

    Ok(PreparedHnswRebuild {
        old_count,
        vector_version,
        rebuilt,
        invalid_vectors_skipped,
    })
}

fn validate_rebuild_vector(
    vault: &Vault,
    id_bytes: &[u8],
    vector_bytes: &[u8],
) -> Result<EntityId> {
    let id = parse_entity_id(id_bytes, ERR_VECTOR_KEY)?;
    let vector = le_bytes_to_f32_vec(vector_bytes)?;
    if vector.len() != vault.config.dimensions {
        return Err(Error::DimensionMismatch {
            expected: vault.config.dimensions,
            got: vector.len(),
        });
    }
    if let Some(error) = Error::invalid_vector_component(&vector) {
        return Err(error);
    }
    Ok(id)
}

fn is_healable_rebuild_error(error: &Error) -> bool {
    matches!(
        error,
        Error::InvalidKey
            | Error::InvalidVector { .. }
            | Error::DimensionMismatch { .. }
            | Error::CorruptedIndex(_)
    )
}

fn commit_rebuilt_hnsw(
    vault: &Vault,
    rebuilt: &crate::hnsw::RebuiltHnswGraph,
    expected_vector_version: u64,
) -> Result<()> {
    let mut wtxn = vault.store.env.write_txn()?;
    let current_vector_version = read_vector_version(&vault.store, &wtxn)?;
    if current_vector_version != expected_vector_version {
        return Err(Error::ConcurrentWrite(
            "vectors changed during hnsw rebuild; retry maintenance",
        ));
    }
    write_rebuilt_hnsw(&vault.store, &mut wtxn, rebuilt, LinkDiscipline::Symmetric)?;
    // The freshly written graph upholds the symmetric-link invariant; stamp
    // the marker so deletes and refreshes take the localized paths from now
    // on (one-time migration for pre-ONE-325 vaults).
    mark_symmetric_links(&vault.store, &mut wtxn)?;
    wtxn.commit()?;
    Ok(())
}

fn decode_u64_opt(raw: Option<&[u8]>) -> Result<Option<u64>> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let bytes: [u8; 8] = raw.try_into().map_err(|_| Error::InvalidKey)?;
    Ok(Some(u64::from_le_bytes(bytes)))
}

#[cfg(test)]
mod tests;
