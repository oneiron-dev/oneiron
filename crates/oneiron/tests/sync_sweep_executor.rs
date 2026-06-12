//! ONE-1087 / ONE-1091 — historical-carrier sweep executor, end-to-end
//! delete-safety suite (phase 1).
//!
//! Contract under test (ARCH-0038 hard-erase sweep + owner rulings):
//! after `vault.maintain().run_hard_erase_sweep().run()`,
//! * the erased payload bytes are recoverable from NOTHING the vault
//!   persists — `d:w:` snapshot, remaining `u:w:` rows, the raw
//!   `sync_state`/`sync_queue` databases, the reloaded doc's full update
//!   export, or its live maps (byte-scan with a distinctive sentinel);
//! * live survivors are byte-exact, the doc identity/VV survive (peer
//!   convergence), and the permanent records — receipt, `dt:` marker,
//!   tombstone — are untouched;
//! * the per-node receipt's `sweep_complete_at` flips None→Some (the single
//!   sanctioned receipt mutation), `h:{seq:8BE}` obligations are consumed
//!   row-deletion-LAST, and the replay doors treat the pre-finalization
//!   CRDT echo as an idempotent skip — never an `x:` quarantine row.

use std::sync::Arc;

use loro::{ExportMode, LoroDoc, LoroValue, ValueOrContainer};
use oneiron::sync::bridge::Materializer;
use oneiron::sync::manager::WindowManager;
use oneiron::sync::types::WindowKey;
use oneiron::sync::window::forward_rematerialize;
use oneiron::sync::{export_updates_since, quarantined_records};
use oneiron::types::TimeRange;
use oneiron::{DeleteReason, EntityId, HnswConfig, Vault, VaultConfig};

/// 2026-02-15-ish — the same `YYYY-MM` literal family the deletion tests
/// pin (`window_label_from_timestamp(1_771_027_200) == "2026-02"`).
const LEARNED_FEB: u64 = 1_771_027_200;
const WINDOW_FEB: &str = "2026-02";
const LEARNED_MAR: u64 = LEARNED_FEB + 31 * 86_400;
const WINDOW_MAR: &str = "2026-03";

/// Distinctive erased-payload sentinel — long and unique so a byte-scan
/// hit can only be a real carrier.
const SENTINEL: &[u8] = b"SWEEP-SENTINEL-PAYLOAD-9f3acc41e7";
const SURVIVOR: &[u8] = b"SURVIVOR-PAYLOAD-77aa01";

fn test_config() -> VaultConfig {
    let mut cfg = VaultConfig::device();
    cfg.map_size = 16 * 1024 * 1024;
    cfg.dimensions = 4;
    cfg.embedding_model = Some("test-model-v1".to_owned());
    cfg.max_readers = 16;
    cfg.hnsw = HnswConfig::default();
    cfg
}

fn open_vault() -> (tempfile::TempDir, Arc<Vault>) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(dir.path(), test_config()).unwrap());
    (dir, vault)
}

fn time_range(ts: u64) -> TimeRange {
    TimeRange { start: ts, end: ts }
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Byte-scans EVERY persisted sync row — all `sync_state` values and all
/// `sync_queue` rows — for `needle`, returning the offending keys. LMDB
/// rejects empty prefixes, so the full key space is walked one leading
/// byte at a time (keys in both DBs start with a non-zero byte).
fn sync_rows_containing(vault: &Vault, needle: &[u8]) -> Vec<String> {
    let mut hits = Vec::new();
    for first in 1u8..=127 {
        let Ok(prefix) = std::str::from_utf8(&[first]).map(str::to_owned) else {
            continue;
        };
        for key in vault.sync_state_keys_with_prefix(&prefix).unwrap() {
            let value = vault.sync_state_get(&key).unwrap().unwrap_or_default();
            if contains_bytes(&value, needle) {
                hits.push(format!("sync_state:{key}"));
            }
        }
    }
    for first in 1u8..=255 {
        for (key, value) in vault.sync_queue_rows_with_prefix(&[first]).unwrap() {
            if contains_bytes(&value, needle) || contains_bytes(&key, needle) {
                hits.push(format!("sync_queue:{}", String::from_utf8_lossy(&key)));
            }
        }
    }
    hits
}

/// Byte-scans the binary values of a doc's three window maps.
fn doc_maps_contain(doc: &LoroDoc, needle: &[u8]) -> bool {
    let mut found = false;
    for map in ["entities", "edges", "tombstones"] {
        doc.get_map(map).for_each(|_, value| {
            if let ValueOrContainer::Value(LoroValue::Binary(bytes)) = value
                && contains_bytes(&bytes, needle)
            {
                found = true;
            }
        });
    }
    found
}

fn map_get_bytes(doc: &LoroDoc, map: &str, key: &str) -> Option<Vec<u8>> {
    match doc.get_map(map).get(key)? {
        ValueOrContainer::Value(LoroValue::Binary(bytes)) => Some(bytes.to_vec()),
        _ => None,
    }
}

fn receipt_body(vault: &Vault, receipt_id: &EntityId) -> serde_json::Value {
    let raw = vault.get_raw(receipt_id).unwrap().expect("receipt raw");
    rmp_serde::from_slice(&raw[25..]).expect("receipt body decodes")
}

/// End-to-end ONE-1087 acceptance: write → index → hard delete → sweep,
/// asserting the full pinned outcome set — byte-level erasure of the
/// historical carriers, byte-exact survivors, finalized receipt, consumed
/// obligation, and the PERMANENT records left standing.
#[test]
fn hard_delete_sweep_end_to_end_byte_scan() {
    let (_dir, vault) = open_vault();
    let erased = EntityId::now();
    let survivor = EntityId::now();
    let other_window = EntityId::now();

    vault
        .batch()
        .put(&erased, 1, time_range(LEARNED_FEB), LEARNED_FEB, SENTINEL)
        .text(&erased, &[("body", std::str::from_utf8(SENTINEL).unwrap())])
        .vector(&erased, &[0.1, 0.2, 0.3, 0.4])
        .commit()
        .unwrap();
    vault
        .batch()
        .put(
            &survivor,
            1,
            time_range(LEARNED_FEB + 60),
            LEARNED_FEB + 60,
            SURVIVOR,
        )
        .text(
            &survivor,
            &[("body", std::str::from_utf8(SURVIVOR).unwrap())],
        )
        .commit()
        .unwrap();
    vault
        .batch()
        .put(
            &other_window,
            1,
            time_range(LEARNED_MAR),
            LEARNED_MAR,
            b"march-window-body",
        )
        .commit()
        .unwrap();

    // Open both windows so reverse remat mirrors the entities into the
    // CRDT — the op history (persisted on unload) is then a REAL carrier.
    let materializer = Arc::new(Materializer::new());
    let manager = Arc::new(WindowManager::new(
        Arc::clone(&vault),
        materializer,
        "node-a",
    ));
    let feb = manager.open_window(&WindowKey::new(WINDOW_FEB)).unwrap();
    let mar = manager.open_window(&WindowKey::new(WINDOW_MAR)).unwrap();
    assert!(
        map_get_bytes(&feb.doc, "entities", &erased.to_hex()).is_some(),
        "fixture: the sentinel entity must be mirrored into the CRDT"
    );

    let outcome = vault
        .delete_entity_with_reason(&erased, DeleteReason::GdprDelete)
        .unwrap();
    assert!(outcome.existed);
    let receipt_id = outcome.receipt_id.expect("receipt id");
    let sweep_key = outcome.sweep_key.expect("sweep key");
    assert!(
        receipt_body(&vault, &receipt_id)["sweep_complete_at"].is_null(),
        "receipt is written with sweep_complete_at = nil at delete time"
    );

    drop(feb);
    drop(mar);
    assert!(manager.unload_window(&WindowKey::new(WINDOW_FEB)).unwrap());
    assert!(manager.unload_window(&WindowKey::new(WINDOW_MAR)).unwrap());

    // Vacuity guard: the persisted snapshot REALLY carries the payload in
    // its op history before the sweep (full-history doc, exportable ops).
    let survivor_raw_before = vault.get_raw(&survivor).unwrap().expect("survivor raw");
    let pre_snapshot = vault
        .sync_state_get(&format!("d:w:{WINDOW_FEB}"))
        .unwrap()
        .expect("persisted FEB snapshot");
    let pre_doc = LoroDoc::from_snapshot(&pre_snapshot).unwrap();
    assert!(!pre_doc.is_shallow(), "pre-sweep doc carries full history");
    let pre_history = pre_doc.export(ExportMode::all_updates()).unwrap();
    assert!(
        contains_bytes(&pre_history, SENTINEL),
        "vacuity guard: the erased payload must be IN the pre-sweep op history"
    );

    let report = vault.maintain().run_hard_erase_sweep().run().unwrap();
    assert_eq!(
        report.sweep_jobs_processed, 1,
        "the h: obligation completes"
    );
    assert_eq!(report.sweep_jobs_failed, 0);
    assert_eq!(report.sweep_receipts_finalized, 1);
    assert!(
        report.sweep_windows_compacted >= 2,
        "both persisted windows are compacted (got {})",
        report.sweep_windows_compacted
    );
    assert_eq!(report.sweep_obligations_missing, 0);

    // (a) ZERO payload bytes anywhere in the persisted sync rows…
    let hits = sync_rows_containing(&vault, SENTINEL);
    assert!(
        hits.is_empty(),
        "payload bytes survive the sweep in: {hits:?}"
    );
    // …nor recoverable from the swept snapshot: shallow doc, no payload in
    // the exportable history, none in the live maps.
    let post_snapshot = vault
        .sync_state_get(&format!("d:w:{WINDOW_FEB}"))
        .unwrap()
        .expect("swept FEB snapshot");
    assert!(!contains_bytes(&post_snapshot, SENTINEL));
    let post_doc = LoroDoc::from_snapshot(&post_snapshot).unwrap();
    assert!(post_doc.is_shallow(), "swept doc must have dropped history");
    let post_history = post_doc.export(ExportMode::all_updates()).unwrap();
    assert!(!contains_bytes(&post_history, SENTINEL));
    assert!(!doc_maps_contain(&post_doc, SENTINEL));

    // (b) Survivors byte-exact: LMDB record and CRDT mirror.
    assert_eq!(
        vault.get_raw(&survivor).unwrap().expect("survivor raw"),
        survivor_raw_before,
        "survivor LMDB record must be untouched"
    );
    assert_eq!(
        map_get_bytes(&post_doc, "entities", &survivor.to_hex()).as_deref(),
        Some(survivor_raw_before.as_slice()),
        "survivor CRDT mirror must be byte-exact across the sweep"
    );
    let mar_doc = LoroDoc::from_snapshot(
        &vault
            .sync_state_get(&format!("d:w:{WINDOW_MAR}"))
            .unwrap()
            .expect("swept MAR snapshot"),
    )
    .unwrap();
    assert_eq!(
        map_get_bytes(&mar_doc, "entities", &other_window.to_hex()).as_deref(),
        vault.get_raw(&other_window).unwrap().as_deref(),
        "other-window survivor intact"
    );

    // (c) Receipt finalized: sweep_complete_at populated, sibling fields
    // untouched, contract field set intact.
    let body = receipt_body(&vault, &receipt_id);
    assert!(
        body["sweep_complete_at"].as_u64().is_some(),
        "sweep_complete_at must be Some after the sweep"
    );
    assert!(body["sweep_queued_at"].as_u64().is_some());
    assert_eq!(body["reason"], "gdpr_delete");
    assert_eq!(body["scope"]["entity_ids"][0], erased.to_hex());

    // (d) The h: obligation row is gone.
    assert!(
        !vault
            .sync_queue_rows_with_prefix(b"h:")
            .unwrap()
            .iter()
            .any(|(k, _)| *k == sweep_key),
        "completed h: row must be deleted"
    );

    // (e) PERMANENT records stand: dt: marker, tombstone, receipt entity.
    assert!(
        vault
            .sync_state_get(&format!("dt:{}", erased.to_hex()))
            .unwrap()
            .is_some(),
        "dt: marker is permanent — never a sweep target"
    );
    let tombstone =
        map_get_bytes(&post_doc, "tombstones", &erased.to_hex()).expect("tombstone survives");
    assert_eq!(tombstone.len(), 25);
    assert_eq!(tombstone[0], 3, "gdpr_delete wire byte");
    assert!(vault.get_raw(&receipt_id).unwrap().is_some());

    // Wire/SLA pin: the swept window demands a full resync.
    assert_eq!(
        vault
            .sync_state_get(&format!("fr:w:{WINDOW_FEB}"))
            .unwrap()
            .as_deref(),
        Some([1u8].as_slice()),
        "fr:w: full-resync marker must be asserted on the swept window"
    );
}

/// Convergence across the sweep (the OWNER-DECISION's correctness bar):
/// the shallow snapshot preserves doc identity + VV, so (i) a fresh node
/// importing the swept snapshot sees EXACTLY the replica state, (ii) a
/// stale peer's echo of pre-sweep ops cannot resurrect the payload, and
/// (iii) post-sweep deltas keep flowing.
#[test]
fn swept_node_converges_with_fresh_import_and_stale_echo() {
    let (_dir_a, vault_a) = open_vault();
    let (_dir_b, vault_b) = open_vault();
    let erased = EntityId::now();

    vault_a
        .batch()
        .put(&erased, 1, time_range(LEARNED_FEB), LEARNED_FEB, SENTINEL)
        .commit()
        .unwrap();
    let materializer_a = Arc::new(Materializer::new());
    let manager_a = Arc::new(WindowManager::new(
        Arc::clone(&vault_a),
        materializer_a,
        "node-a",
    ));
    let window_a = manager_a.open_window(&WindowKey::new(WINDOW_FEB)).unwrap();

    // B replicates the pre-delete state through a real observed window.
    let materializer_b = Arc::new(Materializer::new());
    let window_b = oneiron::sync::window::LoadedWindow::new(
        "node-b",
        WindowKey::new(WINDOW_FEB),
        &vault_b,
        &materializer_b,
    );
    let frame_full = window_a.doc.export(ExportMode::all_updates()).unwrap();
    window_b.doc.import(&frame_full).unwrap();
    assert!(
        vault_b.get_raw(&erased).unwrap().is_some(),
        "fixture: B materialized the entity pre-delete"
    );
    let vv_b = window_b.doc.oplog_vv().encode();

    // Hard delete on A; B applies the delta (reason-aware replay purge).
    vault_a
        .delete_entity_with_reason(&erased, DeleteReason::GdprDelete)
        .unwrap();
    let delta = export_updates_since(&window_a.doc, &vv_b).unwrap();
    window_b.doc.import(&delta).unwrap();
    assert!(
        vault_b.get_raw(&erased).unwrap().is_none(),
        "replica purged by the replayed tombstone"
    );

    drop(window_a);
    assert!(
        manager_a
            .unload_window(&WindowKey::new(WINDOW_FEB))
            .unwrap()
    );
    let report = vault_a.maintain().run_hard_erase_sweep().run().unwrap();
    assert_eq!(report.sweep_jobs_processed, 1);

    let swept_snapshot = vault_a
        .sync_state_get(&format!("d:w:{WINDOW_FEB}"))
        .unwrap()
        .expect("swept snapshot");

    // (i) Fresh node: the swept snapshot reproduces the replica state.
    let fresh = LoroDoc::from_snapshot(&swept_snapshot).unwrap();
    assert!(
        fresh.get_map("entities").get(&erased.to_hex()).is_none(),
        "fresh import must not see the erased entity"
    );
    let fresh_tombstone =
        map_get_bytes(&fresh, "tombstones", &erased.to_hex()).expect("tombstone on fresh node");
    let replica_tombstone =
        map_get_bytes(&window_b.doc, "tombstones", &erased.to_hex()).expect("tombstone on replica");
    assert_eq!(
        fresh_tombstone, replica_tombstone,
        "fresh node and replica converge on the tombstone value"
    );
    assert!(!doc_maps_contain(&fresh, SENTINEL));

    // (ii) Stale echo: the full pre-sweep frame is VV-covered — whether the
    // import reports Ok or a typed error, the payload must NOT come back
    // (the fr:w: marker, asserted below, is the designed heal path).
    let swept = LoroDoc::from_snapshot(&swept_snapshot).unwrap();
    let _ = swept.import(&frame_full);
    assert!(
        swept.get_map("entities").get(&erased.to_hex()).is_none(),
        "a stale peer echo must not resurrect the erased entity"
    );
    assert!(!doc_maps_contain(&swept, SENTINEL));
    let re_export = swept.export(ExportMode::all_updates()).unwrap();
    assert!(
        !contains_bytes(&re_export, SENTINEL),
        "the echo must not re-contaminate the swept history"
    );

    // (iii) Forward continuity: a NEW post-sweep commit from the replica
    // imports cleanly into the swept doc (identity/VV preserved).
    let newcomer = EntityId::now();
    let mut blob = Vec::with_capacity(25 + 9);
    blob.push(1u8);
    for _ in 0..3 {
        blob.extend_from_slice(&(LEARNED_FEB + 120).to_be_bytes());
    }
    blob.extend_from_slice(b"new-after");
    window_b
        .doc
        .get_map("entities")
        .insert(newcomer.to_hex().as_str(), blob.as_slice())
        .unwrap();
    window_b.doc.commit();
    let forward = export_updates_since(&window_b.doc, &swept.oplog_vv().encode()).unwrap();
    swept
        .import(&forward)
        .expect("post-sweep deltas must keep flowing");
    assert_eq!(
        map_get_bytes(&swept, "entities", &newcomer.to_hex()).as_deref(),
        Some(blob.as_slice())
    );

    assert_eq!(
        vault_a
            .sync_state_get(&format!("fr:w:{WINDOW_FEB}"))
            .unwrap()
            .as_deref(),
        Some([1u8].as_slice())
    );
}

/// §8c.3 (M4 handoff, folded into the executor scope): a receiver that
/// NEVER materialized the entity has a `dt:` marker but NO `h:` row and NO
/// receipt — its obligation is carrier-scrub only. The sweep clears its
/// imported history without a job and without fabricating a receipt.
#[test]
fn receiver_that_never_materialized_sweeps_history_8c3() {
    let (_dir_a, vault_a) = open_vault();
    let (_dir_b, vault_b) = open_vault();
    let erased = EntityId::now();

    // Origin A: entity + hard delete, full history frame captured.
    vault_a
        .batch()
        .put(&erased, 1, time_range(LEARNED_FEB), LEARNED_FEB, SENTINEL)
        .commit()
        .unwrap();
    let materializer_a = Arc::new(Materializer::new());
    let manager_a = Arc::new(WindowManager::new(
        Arc::clone(&vault_a),
        materializer_a,
        "node-a",
    ));
    let window_a = manager_a.open_window(&WindowKey::new(WINDOW_FEB)).unwrap();
    vault_a
        .delete_entity_with_reason(&erased, DeleteReason::GdprDelete)
        .unwrap();
    let full_history = window_a.doc.export(ExportMode::all_updates()).unwrap();
    assert!(contains_bytes(&full_history, SENTINEL), "vacuity guard");

    // Receiver B: imports the merged history into a BARE doc (net state:
    // tombstone present, entities key already deleted — the entity is
    // never materialized locally), then runs the production recovery pass.
    let window_key = WindowKey::new(WINDOW_FEB);
    let doc_b = LoroDoc::new();
    doc_b.import(&full_history).unwrap();
    assert!(doc_b.get_map("entities").get(&erased.to_hex()).is_none());
    vault_b
        .sync_state_put(
            &format!("d:w:{WINDOW_FEB}"),
            &doc_b.export(ExportMode::Snapshot).unwrap(),
        )
        .unwrap();

    let materializer_b = Materializer::new();
    forward_rematerialize(&vault_b, &doc_b, &materializer_b, &window_key).unwrap();

    // §8c.3 asymmetry pinned: dt: marker, no h: row, no receipt, nothing
    // ever materialized.
    assert!(
        vault_b
            .sync_state_get(&format!("dt:{}", erased.to_hex()))
            .unwrap()
            .is_some(),
        "never-materialized hard apply still writes the permanent dt: marker"
    );
    assert!(
        vault_b
            .sync_queue_rows_with_prefix(b"h:")
            .unwrap()
            .is_empty(),
        "erased == false ⇒ no h: obligation row"
    );
    assert!(
        vault_b
            .entities_by_type(oneiron::types::ENTITY_TYPE_REDACTION_AUDIT)
            .unwrap()
            .is_empty(),
        "erased == false ⇒ no receipt"
    );
    assert!(vault_b.get_raw(&erased).unwrap().is_none());

    // Pre-sweep: B's persisted snapshot still CARRIES the payload bytes in
    // its imported op history.
    let pre = vault_b
        .sync_state_get(&format!("d:w:{WINDOW_FEB}"))
        .unwrap()
        .unwrap();
    let pre_history = LoroDoc::from_snapshot(&pre)
        .unwrap()
        .export(ExportMode::all_updates())
        .unwrap();
    assert!(contains_bytes(&pre_history, SENTINEL), "vacuity guard");

    let report = vault_b.maintain().run_hard_erase_sweep().run().unwrap();
    assert_eq!(
        report.sweep_jobs_processed, 0,
        "no job — carrier-scrub only"
    );
    assert!(report.sweep_windows_compacted >= 1);
    assert_eq!(report.sweep_receipts_finalized, 0);

    let hits = sync_rows_containing(&vault_b, SENTINEL);
    assert!(hits.is_empty(), "§8c.3 payload bytes survive in: {hits:?}");
    let post = vault_b
        .sync_state_get(&format!("d:w:{WINDOW_FEB}"))
        .unwrap()
        .unwrap();
    let post_doc = LoroDoc::from_snapshot(&post).unwrap();
    assert!(post_doc.is_shallow());
    assert!(
        !contains_bytes(
            &post_doc.export(ExportMode::all_updates()).unwrap(),
            SENTINEL
        ),
        "imported history scrubbed on the never-materialized receiver"
    );
    assert!(
        vault_b
            .sync_state_get(&format!("dt:{}", erased.to_hex()))
            .unwrap()
            .is_some(),
        "dt: marker survives the sweep"
    );
    assert!(
        vault_b
            .entities_by_type(oneiron::types::ENTITY_TYPE_REDACTION_AUDIT)
            .unwrap()
            .is_empty(),
        "the sweep must not fabricate a receipt where nothing was erased"
    );
}

/// ONE-1087 replay-door exception, full-stack: after finalization the CRDT
/// mirror still replays the PRE-finalization receipt bytes — that exact
/// monotone echo must be an idempotent skip (no `x:` row, local finalized
/// bytes kept), while any OTHER divergence still quarantines (M4-07).
#[test]
fn replay_door_skips_stale_receipt_echo_after_finalization() {
    let (_dir, vault) = open_vault();
    let erased = EntityId::now();
    vault
        .batch()
        .put(&erased, 1, time_range(LEARNED_FEB), LEARNED_FEB, SENTINEL)
        .commit()
        .unwrap();
    let outcome = vault
        .delete_entity_with_reason(&erased, DeleteReason::GdprDelete)
        .unwrap();
    let receipt_id = outcome.receipt_id.expect("receipt id");
    let pre_finalization_raw = vault.get_raw(&receipt_id).unwrap().expect("receipt raw");

    let report = vault.maintain().run_hard_erase_sweep().run().unwrap();
    assert_eq!(report.sweep_receipts_finalized, 1);
    let finalized_raw = vault.get_raw(&receipt_id).unwrap().expect("receipt raw");
    assert_ne!(pre_finalization_raw, finalized_raw);

    // A window doc replaying the STALE pre-finalization receipt echo.
    let window_key = WindowKey::new(WINDOW_FEB);
    let doc = LoroDoc::new();
    doc.get_map("entities")
        .insert(
            receipt_id.to_hex().as_str(),
            pre_finalization_raw.as_slice(),
        )
        .unwrap();
    doc.commit();
    let quarantine_before = quarantined_records(&vault).unwrap().len();
    let materializer = Materializer::new();
    forward_rematerialize(&vault, &doc, &materializer, &window_key).unwrap();
    assert_eq!(
        quarantined_records(&vault).unwrap().len(),
        quarantine_before,
        "the monotone stale echo must NOT be quarantined"
    );
    assert_eq!(
        vault.get_raw(&receipt_id).unwrap().expect("receipt raw"),
        finalized_raw,
        "the finalized local receipt must be kept"
    );

    // A REAL divergence (valid body, different requested_at) still
    // quarantines — the exception is exactly one shape wide.
    let mut divergent_body: serde_json::Value =
        rmp_serde::from_slice(&pre_finalization_raw[25..]).unwrap();
    divergent_body["requested_at"] =
        serde_json::Value::from(divergent_body["requested_at"].as_u64().unwrap() + 1);
    let mut divergent_raw = pre_finalization_raw[..25].to_vec();
    divergent_raw.extend_from_slice(&rmp_serde::to_vec_named(&divergent_body).unwrap());
    let doc2 = LoroDoc::new();
    doc2.get_map("entities")
        .insert(receipt_id.to_hex().as_str(), divergent_raw.as_slice())
        .unwrap();
    doc2.commit();
    forward_rematerialize(&vault, &doc2, &materializer, &window_key).unwrap();
    let records = quarantined_records(&vault).unwrap();
    assert_eq!(
        records.len(),
        quarantine_before + 1,
        "a real receipt divergence must still quarantine"
    );
    assert_eq!(
        records.last().unwrap().1.reason_code,
        "RedactionReceiptDivergence"
    );
    assert_eq!(
        vault.get_raw(&receipt_id).unwrap().expect("receipt raw"),
        finalized_raw
    );
}
