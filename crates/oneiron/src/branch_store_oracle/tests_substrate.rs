//! Oracle fixtures (temp vault, base turn, zero-residue census) and the P2 ONE-1726 SessionOverlay substrate tests.

use std::ops::Bound;

use crate::config::VaultConfig;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::temporal::TimeRange;
use crate::vault::Vault;

use super::seam;

pub(super) fn temp_vault() -> (tempfile::TempDir, Vault) {
    let tmp = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(tmp.path(), VaultConfig::default()).expect("open vault");
    (tmp, vault)
}

pub(super) fn seed_base_turn(vault: &Vault, at: u64) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(
            &id,
            crate::registry::ENTITY_TYPE_TURN,
            TimeRange { start: at, end: at },
            at,
            b"branch-store oracle base turn",
        )
        .expect("seed base turn");
    id
}

/// Exact row counts across EVERY named database — the zero-residue census.
///
/// The array length is `DB_MANIFEST.len()`, not the authoring-time literal:
/// a manifest that grows a database must fail to compile here rather than
/// silently leave the new one uncensused (ONE-1730 acceptance).
pub(super) fn full_db_census(vault: &Vault) -> Result<[u64; crate::store::DB_MANIFEST.len()]> {
    let s = &vault.store;
    let rtxn = s.env.read_txn()?;
    Ok([
        s.entities.len(&rtxn)?,
        s.edges_out.len(&rtxn)?,
        s.edges_in.len(&rtxn)?,
        s.vectors.len(&rtxn)?,
        s.hnsw_neighbors.len(&rtxn)?,
        s.hnsw_meta.len(&rtxn)?,
        s.text_postings.len(&rtxn)?,
        s.text_meta.len(&rtxn)?,
        s.text_forward.len(&rtxn)?,
        s.text_bm25_field_stats.len(&rtxn)?,
        s.text_doc_field_lengths.len(&rtxn)?,
        s.vault_meta.len(&rtxn)?,
        s.ppr_cache.len(&rtxn)?,
        s.ppr_cache_deps.len(&rtxn)?,
        s.type_index.len(&rtxn)?,
        s.temporal_occurred_start.len(&rtxn)?,
        s.temporal_occurred_end.len(&rtxn)?,
        s.temporal_learned.len(&rtxn)?,
        s.temporal_long_intervals.len(&rtxn)?,
        s.phonetic_index.len(&rtxn)?,
        s.phonetic_forward.len(&rtxn)?,
        s.short_ids.len(&rtxn)?,
        s.short_ids_reverse.len(&rtxn)?,
        {
            let mut n = 0_u64;
            for row in s.sync_state.iter(&rtxn)? {
                row?;
                n += 1;
            }
            n
        },
        s.sync_queue.len(&rtxn)?,
        s.attempt_records.len(&rtxn)?,
        s.attempt_ready.len(&rtxn)?,
        s.attempt_dedupe.len(&rtxn)?,
    ])
}

// ─── P2 · ONE-1726 — SessionOverlay substrate ────────────────────────────

/// D2/R2: merged prefix iteration equals the model oracle's exact ordered
/// sequence (boundaries included; delete-markers subtract; overlay wins on
/// key collision).
#[test]
fn overlay_prefix_iter_matches_model_order_and_boundaries() -> Result<()> {
    let base: Vec<seam::ModelRow> = vec![
        (b"p:a".to_vec(), b"base-a".to_vec()),
        (b"p:c".to_vec(), b"base-c".to_vec()),
        (b"p:e".to_vec(), b"base-e".to_vec()),
        (b"q:x".to_vec(), b"outside".to_vec()),
    ];
    let script = vec![
        seam::OverlayOp::Put(b"p:b".to_vec(), b"ov-b".to_vec()),
        seam::OverlayOp::Put(b"p:c".to_vec(), b"ov-c-wins".to_vec()),
        seam::OverlayOp::Delete(b"p:e".to_vec()),
    ];
    let harness = seam::OverlayModelHarness::new(&base, &script);
    let merged = harness.prefix_iter(b"p:")?;
    let model = harness.model_prefix_iter(b"p:");
    assert_eq!(merged.len(), 3, "exactly a, b, c survive under prefix p:");
    assert_eq!(
        merged, model,
        "merged sequence must equal the model exactly"
    );
    Ok(())
}

/// D2/R2: reverse-range direction AND `RangeBounds` edge handling vs the
/// model — Included/Excluded/Unbounded each pinned as an exact ordered
/// sequence (codex F4: `(start, end)` slices could not express the edges).
#[test]
fn overlay_rev_range_matches_model_direction_and_bounds() -> Result<()> {
    let row = |k: &[u8], v: &[u8]| (k.to_vec(), v.to_vec());
    let base: Vec<seam::ModelRow> = vec![row(b"k1", b"v1"), row(b"k3", b"v3"), row(b"k5", b"v5")];
    let script = vec![
        seam::OverlayOp::Put(b"k2".to_vec(), b"v2".to_vec()),
        seam::OverlayOp::Put(b"k4".to_vec(), b"v4".to_vec()),
    ];
    let harness = seam::OverlayModelHarness::new(&base, &script);

    // Both bounds included: full merged set, reverse key order.
    let both = (Bound::Included(&b"k1"[..]), Bound::Included(&b"k5"[..]));
    let merged = harness.rev_range(both)?;
    assert_eq!(
        merged,
        vec![
            row(b"k5", b"v5"),
            row(b"k4", b"v4"),
            row(b"k3", b"v3"),
            row(b"k2", b"v2"),
            row(b"k1", b"v1"),
        ],
        "included/included must yield all five rows, newest key first"
    );
    assert_eq!(merged, harness.model_rev_range(both), "model agrees");

    // Excluded start bound: k1 itself must NOT surface (an overlay row k2
    // sits directly above the excluded edge — the merge must not readmit
    // the boundary key).
    let excl_start = (Bound::Excluded(&b"k1"[..]), Bound::Included(&b"k4"[..]));
    let merged = harness.rev_range(excl_start)?;
    assert_eq!(
        merged,
        vec![row(b"k4", b"v4"), row(b"k3", b"v3"), row(b"k2", b"v2")],
        "excluded start must drop exactly the boundary row"
    );
    assert_eq!(merged, harness.model_rev_range(excl_start), "model agrees");

    // Unbounded end: iteration runs to the last key in the union.
    let unbounded_end = (Bound::Included(&b"k3"[..]), Bound::Unbounded);
    let merged = harness.rev_range(unbounded_end)?;
    assert_eq!(
        merged,
        vec![row(b"k5", b"v5"), row(b"k4", b"v4"), row(b"k3", b"v3")],
        "unbounded end must run to the union's last key"
    );
    assert_eq!(
        merged,
        harness.model_rev_range(unbounded_end),
        "model agrees"
    );
    Ok(())
}

/// D2 (availability invariant, R2): merged `text_postings` duplicate items
/// stay strictly ascending by entity-id prefix per term — `search_text`
/// hard-errors the whole query on any violation, so this is availability,
/// not ranking quality.
#[test]
fn text_postings_merge_keeps_per_term_ascending_entity_id_order() -> Result<()> {
    // Base carries entities 02 and 04 for the term; overlay adds 01, 03, 05
    // — interleaved on both sides of every base item.
    let term = b"term".to_vec();
    let entry = |id: u8| -> Vec<u8> {
        let mut e = vec![0_u8; 16];
        e[15] = id;
        e.push(0); // field_count = 0 is enough for ordering shape
        e
    };
    let base: Vec<seam::ModelRow> = vec![(term.clone(), entry(2)), (term.clone(), entry(4))];
    let script = vec![
        seam::OverlayOp::DupAppend(term.clone(), entry(3)),
        seam::OverlayOp::DupAppend(term.clone(), entry(1)),
        seam::OverlayOp::DupAppend(term.clone(), entry(5)),
    ];
    let harness = seam::OverlayModelHarness::new(&base, &script);
    let items = harness.dup_items(&term)?;
    assert_eq!(items.len(), 5, "all five duplicate items must surface");
    let expected: Vec<Vec<u8>> = vec![entry(1), entry(2), entry(3), entry(4), entry(5)];
    assert_eq!(
        items, expected,
        "duplicate items must be strictly ascending by entity-id prefix"
    );
    Ok(())
}

/// D1 (txn segments): a write staged in the thread-local segment is visible
/// to reads under the SAME live base txn (segment -> snapshot -> base).
#[test]
fn overlay_read_your_writes_inside_txn_segment() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let session = seam::SessionVault::enter(&vault, "oracle-ryw").expect("enter session");
    let script = vec![seam::OverlayOp::Put(
        b"ryw-key".to_vec(),
        b"ryw-val".to_vec(),
    )];
    let read_back = seam::with_txn_segment_read_back(&vault, &session, &script, b"ryw-key")?;
    assert_eq!(
        read_back.as_deref(),
        Some(&b"ryw-val"[..]),
        "batch code must read what it just wrote inside the live txn"
    );
    Ok(())
}

/// D1 (journal atomicity): a segment dropped on base-txn abort leaves ZERO
/// overlay rows and ZERO typed-journal entries.
#[test]
fn overlay_segment_and_journal_drop_together_on_abort() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let session = seam::SessionVault::enter(&vault, "oracle-abort").expect("enter session");
    let script = vec![seam::OverlayOp::Put(b"aborted".to_vec(), b"x".to_vec())];
    let (overlay_rows, journal_entries) = seam::stage_then_abort(&vault, &session, &script)?;
    assert_eq!(
        overlay_rows, 0,
        "aborted segment must not apply to the overlay"
    );
    assert_eq!(
        journal_entries, 0,
        "journal is atomic with the overlay apply"
    );
    Ok(())
}

/// D1 (vault-safety fence): budget overflow returns the typed error, the
/// base vault is untouched, and the session stays alive for promote/close.
#[test]
fn overlay_budget_rejection_is_typed_and_never_crashes_vault() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let base_before = full_db_census(&vault)?;
    let session =
        seam::SessionVault::enter_with_budget(&vault, "oracle-budget", 64).expect("enter session");
    let error = seam::overflow_budget(&vault, &session, 64);
    assert_eq!(
        error,
        seam::SeamError::OverlayFull,
        "budget overflow must be the exact typed OffRecordOverlayFull refusal"
    );
    assert_eq!(
        full_db_census(&vault)?,
        base_before,
        "a rejected overlay insert must leave every base database untouched"
    );
    // Session survives: close still works and reports zero retained rows.
    let (transcript_deleted, receipts_deleted, _floor_kept) = session.close()?;
    assert_eq!(transcript_deleted, 0);
    assert_eq!(receipts_deleted, 0);
    Ok(())
}

/// D1 (snapshot isolation): a logical read iterates its Arc snapshot; a
/// concurrent overlay apply is invisible to it and visible to a fresh read.
#[test]
fn overlay_snapshot_read_never_sees_torn_union() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let session = seam::SessionVault::enter(&vault, "oracle-snapshot").expect("enter session");
    let script = vec![seam::OverlayOp::Put(b"s:new".to_vec(), b"late".to_vec())];
    let (snapshot_rows, fresh_rows) =
        seam::snapshot_vs_concurrent_apply(&vault, &session, &script, b"s:")?;
    assert_eq!(snapshot_rows.len(), 0, "snapshot predates the apply");
    assert_eq!(
        fresh_rows,
        vec![(b"s:new".to_vec(), b"late".to_vec())],
        "fresh read sees exactly the applied (key, value) row — identity, \
         not just count (codex F5)"
    );
    Ok(())
}

/// D1 (close finality): generation-stamped leases refuse typed after close.
#[test]
fn overlay_lease_refused_after_close() {
    let (_tmp, vault) = temp_vault();
    assert_eq!(
        seam::read_after_close(&vault, "oracle-lease"),
        seam::SeamError::LeaseClosed,
        "stale handles must get the exact typed lease refusal"
    );
}
