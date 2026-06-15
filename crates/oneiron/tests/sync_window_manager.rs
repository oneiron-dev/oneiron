//! Integration tests for the production window manager (ONE-1125).
//!
//! Pins the ARCH-0023b startup ordering invariant through
//! `WindowManager::open_window` — steps 3 → 4 → 5 (pm replay → reverse
//! remat → forward remat) on the bare doc, observers attached LAST (step
//! 6) — plus the one-live-doc-per-key registry, the defensive `rm:w:{key}`
//! consumer, and the unload path (persist + subscription drop; ONE-1150
//! typed refusal while external `Arc` handles are outstanding).

#![cfg(feature = "sync")]

use std::sync::Arc;

use loro::{ExportMode, LoroDoc, LoroMap, LoroValue, ValueOrContainer};
use oneiron::sync::bridge::Materializer;
use oneiron::sync::manager::WindowManager;
use oneiron::sync::types::WindowKey;
use oneiron::sync::window;
use oneiron::types::TimeRange;
use oneiron::{EntityId, Error, ErrorKind, HnswConfig, Vault, VaultConfig};

fn test_config() -> VaultConfig {
    let mut cfg = VaultConfig::device();
    cfg.map_size = 16 * 1024 * 1024;
    cfg.dimensions = 4;
    cfg.embedding_model = None;
    cfg.max_readers = 16;
    cfg.hnsw = HnswConfig::default();
    cfg
}

fn test_vault() -> (tempfile::TempDir, Arc<Vault>) {
    let temp = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(temp.path(), test_config()).unwrap());
    (temp, vault)
}

/// Entity envelope per the pinned 25-byte layout: `type u8` +
/// `occurred_start u64 BE` + `occurred_end u64 BE` + `learned_at u64 BE` +
/// body. `occurred == learned` here, matching the LMDB envelope a
/// `put(.., TimeRange { start: t, end: t }, t, ..)` produces, so CRDT-vs-LMDB
/// byte-equality assertions are exact.
fn make_entity_blob(entity_type: u8, learned_at: u64, data: &[u8]) -> Vec<u8> {
    let mut blob = Vec::with_capacity(25 + data.len());
    blob.push(entity_type);
    blob.extend_from_slice(&learned_at.to_be_bytes()); // occurred_start
    blob.extend_from_slice(&learned_at.to_be_bytes()); // occurred_end
    blob.extend_from_slice(&learned_at.to_be_bytes()); // learned_at
    blob.extend_from_slice(data);
    blob
}

fn map_get_bytes(map: &LoroMap, key: &str) -> Option<Vec<u8>> {
    match map.get(key)? {
        ValueOrContainer::Value(LoroValue::Binary(bytes)) => Some(bytes.to_vec()),
        _ => None,
    }
}

fn put_lmdb_entity(vault: &Vault, id: &EntityId, learned_at: u64, data: &[u8]) {
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
            data,
        )
        .commit()
        .unwrap();
}

/// Writes a window doc snapshot to `d:w:{key}` directly (the persisted-state
/// fixture for open), bypassing observers entirely.
fn persist_setup_doc(vault: &Vault, key: &WindowKey, doc: &LoroDoc) {
    let snapshot = doc.export(ExportMode::Snapshot).unwrap();
    vault
        .sync_state_put(&format!("d:w:{key}"), &snapshot)
        .unwrap();
}

/// AC test (a) — order pin. The fixture holds every divergence class the
/// pinned order exists for; the pm-marked entity with byte-divergent copies
/// is the order DISCRIMINATOR: an implementation that runs forward remat
/// (step 5) before pm replay (step 3) overwrites the fresh LMDB bytes with
/// the stale CRDT copy, then pm replay byte-compares equal and clears the
/// marker — `vault.get(pm_entity)` would return the STALE bytes and this
/// test fails.
#[test]
fn open_window_runs_pinned_recovery_order_and_converges() {
    let (_temp, vault) = test_vault();
    let key = WindowKey::new("2026-03");
    let t = key.start_timestamp().unwrap() + 60;

    let pm_entity = EntityId::now(); // LMDB-ahead (pm: marker), stale copy in CRDT
    let lmdb_only = EntityId::now(); // in LMDB, missing from CRDT
    let crdt_only = EntityId::now(); // in CRDT, missing from LMDB
    let tombstoned = EntityId::now(); // tombstoned in CRDT, still in LMDB + pm: marker

    // LMDB side. No pm: producer exists yet (M4-10); markers are set
    // manually as the crash fixture ARCH-0023b §4.4 step 1 would leave.
    put_lmdb_entity(&vault, &pm_entity, t, b"pm-v2-fresh");
    put_lmdb_entity(&vault, &lmdb_only, t, b"lmdb-only");
    put_lmdb_entity(&vault, &tombstoned, t, b"deleted-on-peer");
    vault
        .sync_state_put(&format!("pm:{key}:{}", pm_entity.to_hex()), &[1u8])
        .unwrap();
    vault
        .sync_state_put(&format!("pm:{key}:{}", tombstoned.to_hex()), &[1u8])
        .unwrap();

    // CRDT side: persisted snapshot with a stale pm_entity copy, a
    // CRDT-only entity, and a tombstone.
    let setup_doc = LoroDoc::new();
    let entities = setup_doc.get_map("entities");
    let tombstones = setup_doc.get_map("tombstones");
    entities
        .insert(
            pm_entity.to_hex().as_str(),
            make_entity_blob(1, t, b"pm-v1-stale").as_slice(),
        )
        .unwrap();
    entities
        .insert(
            crdt_only.to_hex().as_str(),
            make_entity_blob(1, t, b"crdt-only").as_slice(),
        )
        .unwrap();
    tombstones
        .insert(tombstoned.to_hex().as_str(), 42u64.to_le_bytes().as_slice())
        .unwrap();
    setup_doc.commit();
    persist_setup_doc(&vault, &key, &setup_doc);

    let materializer = Arc::new(Materializer::new());
    let manager = Arc::new(WindowManager::new(
        Arc::clone(&vault),
        materializer,
        "test-user",
    ));
    let win = manager.open_window(&key).unwrap();
    let entities = win.doc.get_map("entities");

    // pm-replayed entity: LMDB-ahead bytes won on BOTH sides (3 before 5).
    assert_eq!(
        vault.get(&pm_entity).unwrap().unwrap(),
        b"pm-v2-fresh",
        "step 5 before step 3 overwrites LMDB with the stale CRDT copy"
    );
    assert_eq!(
        map_get_bytes(&entities, &pm_entity.to_hex()).unwrap(),
        make_entity_blob(1, t, b"pm-v2-fresh"),
        "pm replay must mirror the LMDB-ahead envelope into the CRDT"
    );
    assert!(
        vault
            .sync_state_get(&format!("pm:{key}:{}", pm_entity.to_hex()))
            .unwrap()
            .is_none(),
        "pm marker must be cleared after replay"
    );

    // LMDB-only entity mirrored into the CRDT (step 4).
    assert_eq!(
        map_get_bytes(&entities, &lmdb_only.to_hex()).unwrap(),
        make_entity_blob(1, t, b"lmdb-only"),
        "reverse remat must mirror LMDB-only entities"
    );

    // CRDT-only entity materialized into LMDB (step 5).
    assert_eq!(
        vault.get(&crdt_only).unwrap().unwrap(),
        b"crdt-only",
        "forward remat must materialize CRDT-only entities"
    );

    // Tombstoned entity: purged from LMDB, NOT resurrected into the CRDT
    // entities map, pm marker cleared without mirroring — delete wins.
    assert!(
        vault.get(&tombstoned).unwrap().is_none(),
        "forward remat must purge tombstoned entities from LMDB"
    );
    assert!(
        map_get_bytes(&entities, &tombstoned.to_hex()).is_none(),
        "recovery must never resurrect a tombstoned entity into the CRDT"
    );
    assert!(
        vault
            .sync_state_get(&format!("pm:{key}:{}", tombstoned.to_hex()))
            .unwrap()
            .is_none(),
        "pm marker for a tombstoned entity must be cleared, not mirrored"
    );
}

/// AC test (b) — observers attach AFTER recovery. Recovery commits (pm
/// replay + reverse remat) happen on the bare doc, so Observer A — which
/// fires for ALL local commits regardless of origin — must see none of
/// them: no `u:w:{key}:*` rows, no `m:u_seq:w:{key}` row. An implementation
/// that attaches observers before steps 3-5 persists the recovery commits
/// and fails here. The CRDT-ahead entity is materialized by step 5 exactly
/// once, with no double-apply via Observer B.
#[test]
fn observers_attach_after_recovery_with_no_replay_side_effects() {
    let (_temp, vault) = test_vault();
    let key = WindowKey::new("2026-03");
    let t = key.start_timestamp().unwrap() + 60;

    let crdt_only = EntityId::now();
    let pm_entity = EntityId::now();

    // Step-3 work (pm marker, divergent bytes) AND step-4 work (CRDT-ahead
    // entity) so a premature Observer A would fire for both recovery commits.
    put_lmdb_entity(&vault, &pm_entity, t, b"pm-fresh");
    vault
        .sync_state_put(&format!("pm:{key}:{}", pm_entity.to_hex()), &[1u8])
        .unwrap();

    let setup_doc = LoroDoc::new();
    let entities = setup_doc.get_map("entities");
    entities
        .insert(
            crdt_only.to_hex().as_str(),
            make_entity_blob(1, t, b"crdt-only").as_slice(),
        )
        .unwrap();
    entities
        .insert(
            pm_entity.to_hex().as_str(),
            make_entity_blob(1, t, b"pm-stale").as_slice(),
        )
        .unwrap();
    setup_doc.commit();
    persist_setup_doc(&vault, &key, &setup_doc);

    let u_prefix = format!("u:w:{key}:");
    let seq_key = format!("m:u_seq:w:{key}");
    assert_eq!(
        vault.sync_state_keys_with_prefix(&u_prefix).unwrap().len(),
        0
    );
    assert!(vault.sync_state_get(&seq_key).unwrap().is_none());

    let materializer = Arc::new(Materializer::new());
    let manager = Arc::new(WindowManager::new(
        Arc::clone(&vault),
        materializer,
        "test-user",
    ));
    let win = manager.open_window(&key).unwrap();

    // CRDT-ahead entity materialized by step 5, exactly once (bytes exact).
    assert_eq!(vault.get(&crdt_only).unwrap().unwrap(), b"crdt-only");

    // No observer side effects from the recovery commits.
    assert_eq!(
        vault.sync_state_keys_with_prefix(&u_prefix).unwrap().len(),
        0,
        "Observer A persisted recovery commits — observers attached before steps 3-5"
    );
    assert!(
        vault.sync_state_get(&seq_key).unwrap().is_none(),
        "u_seq row written during recovery — observers attached before steps 3-5"
    );

    // ...but observers ARE live after open: a post-open commit fires both
    // Observer A (u:w row) and Observer B (LMDB materialization).
    let post_open = EntityId::now();
    let entities = win.doc.get_map("entities");
    entities
        .insert(
            post_open.to_hex().as_str(),
            make_entity_blob(1, t, b"post-open").as_slice(),
        )
        .unwrap();
    win.doc.commit();

    assert_eq!(
        vault.get(&post_open).unwrap().unwrap(),
        b"post-open",
        "Observer B must be live after open"
    );
    assert_eq!(
        vault.sync_state_keys_with_prefix(&u_prefix).unwrap().len(),
        1,
        "Observer A must be live after open"
    );
}

/// Open of a window with NO persisted CRDT state must still run recovery on
/// the fresh bare doc: reverse remat mirrors LMDB-ahead entities before
/// observers attach (no `u:w` rows), instead of starting from an empty doc.
#[test]
fn open_fresh_window_recovers_lmdb_ahead_entities_before_observers() {
    let (_temp, vault) = test_vault();
    let key = WindowKey::new("2026-05");
    let t = key.start_timestamp().unwrap() + 60;

    let lmdb_only = EntityId::now();
    put_lmdb_entity(&vault, &lmdb_only, t, b"pre-existing");

    let materializer = Arc::new(Materializer::new());
    let manager = Arc::new(WindowManager::new(
        Arc::clone(&vault),
        materializer,
        "test-user",
    ));
    let win = manager.open_window(&key).unwrap();

    let entities = win.doc.get_map("entities");
    assert_eq!(
        map_get_bytes(&entities, &lmdb_only.to_hex()).unwrap(),
        make_entity_blob(1, t, b"pre-existing"),
        "fresh window must pick up LMDB-ahead entities via reverse remat"
    );
    assert_eq!(
        vault
            .sync_state_keys_with_prefix(&format!("u:w:{key}:"))
            .unwrap()
            .len(),
        0,
        "the reverse-remat mirror commit ran before Observer A attached"
    );
}

/// AC test (c) — double-open returns the same live instance (exactly one
/// live doc per window key per process), and the registry lookup seam
/// observes it too.
#[test]
fn double_open_returns_the_same_live_instance() {
    let (_temp, vault) = test_vault();
    let key = WindowKey::new("2026-03");
    let t = key.start_timestamp().unwrap() + 60;

    let materializer = Arc::new(Materializer::new());
    let manager = Arc::new(WindowManager::new(
        Arc::clone(&vault),
        materializer,
        "test-user",
    ));

    let w1 = manager.open_window(&key).unwrap();
    let w2 = manager.open_window(&key).unwrap();
    assert!(
        Arc::ptr_eq(&w1, &w2),
        "double-open must return the registry-owned instance"
    );

    let w3 = manager.window(&key).unwrap();
    assert!(
        Arc::ptr_eq(&w1, &w3),
        "registry lookup must observe the same instance"
    );
    assert_eq!(manager.loaded_keys(), [key]);

    // Same underlying doc: a write through w1 is visible through w2 and
    // materializes exactly once.
    let id = EntityId::now();
    let entities = w1.doc.get_map("entities");
    entities
        .insert(
            id.to_hex().as_str(),
            make_entity_blob(1, t, b"shared-doc").as_slice(),
        )
        .unwrap();
    w1.doc.commit();

    let entities_via_w2 = w2.doc.get_map("entities");
    assert_eq!(
        map_get_bytes(&entities_via_w2, &id.to_hex()).unwrap(),
        make_entity_blob(1, t, b"shared-doc")
    );
    assert_eq!(vault.get(&id).unwrap().unwrap(), b"shared-doc");
}

/// AC test (d) — unload persists Doc state and drops the observer
/// subscriptions: subsequent doc commits trigger no observer effects.
#[test]
fn unload_persists_state_and_drops_observer_subscriptions() {
    let (_temp, vault) = test_vault();
    let key = WindowKey::new("2026-04");
    let t = key.start_timestamp().unwrap() + 60;

    let materializer = Arc::new(Materializer::new());
    let manager = Arc::new(WindowManager::new(
        Arc::clone(&vault),
        materializer,
        "test-user",
    ));
    let win = manager.open_window(&key).unwrap();

    let pre_unload = EntityId::now();
    let entities = win.doc.get_map("entities");
    entities
        .insert(
            pre_unload.to_hex().as_str(),
            make_entity_blob(1, t, b"pre-unload").as_slice(),
        )
        .unwrap();
    win.doc.commit();
    assert_eq!(vault.get(&pre_unload).unwrap().unwrap(), b"pre-unload");

    // Keep a doc handle to prove the subscriptions died with the
    // LoadedWindow, then drop our Arc so the registry holds the last
    // reference (the documented drop semantics).
    let doc = win.doc.clone();
    drop(win);

    assert!(manager.unload_window(&key).unwrap());
    assert!(manager.window(&key).is_none(), "unload must deregister");
    assert!(manager.loaded_keys().is_empty());

    // persist_state wrote the snapshot: a reload sees the pre-unload entity.
    let reloaded = window::load_window_from_state(&vault, "test-user", &key).unwrap();
    let reloaded_entities = reloaded.get_map("entities");
    assert_eq!(
        map_get_bytes(&reloaded_entities, &pre_unload.to_hex()).unwrap(),
        make_entity_blob(1, t, b"pre-unload"),
        "unload must persist the window Doc state"
    );

    // Subscriptions dropped: post-unload commits trigger no observer effects.
    let u_prefix = format!("u:w:{key}:");
    let updates_at_unload = vault.sync_state_keys_with_prefix(&u_prefix).unwrap().len();
    let post_unload = EntityId::now();
    let entities = doc.get_map("entities");
    entities
        .insert(
            post_unload.to_hex().as_str(),
            make_entity_blob(1, t, b"post-unload").as_slice(),
        )
        .unwrap();
    doc.commit();

    assert!(
        vault.get(&post_unload).unwrap().is_none(),
        "Observer B must be dropped on unload"
    );
    assert_eq!(
        vault.sync_state_keys_with_prefix(&u_prefix).unwrap().len(),
        updates_at_unload,
        "Observer A must be dropped on unload"
    );

    // Unloading a window that is not loaded is a no-op.
    assert!(!manager.unload_window(&key).unwrap());
}

/// ONE-1150 — unload with an outstanding external handle is REFUSED with
/// the typed [`Error::WindowBusy`], side-effect-free (nothing persisted,
/// nothing deregistered), and the second-live-doc trap stays closed: the
/// window remains discoverable via `window()` and `Vault::delete_entity`
/// still commits its tombstone through the LIVE doc. The pre-ONE-1150
/// warn-and-deregister implementation FAILS here: unload returns
/// `Ok(true)`, `window()` goes empty, and the delete takes the transient
/// path that never touches the held doc.
#[test]
fn unload_refuses_with_outstanding_handles_and_keeps_delete_routing_live() {
    let (_temp, vault) = test_vault();
    let key = WindowKey::new("2026-03");
    let t = key.start_timestamp().unwrap() + 60;

    // Entity in LMDB before open: step-4 reverse remat mirrors it into the
    // live doc, giving the delete below a live-doc copy to tombstone.
    let id = EntityId::now();
    put_lmdb_entity(&vault, &id, t, b"held-handle-body");

    let materializer = Arc::new(Materializer::new());
    let manager = Arc::new(WindowManager::new(
        Arc::clone(&vault),
        materializer,
        "test-user",
    ));
    // `win` is the outstanding external handle for the whole test.
    let win = manager.open_window(&key).unwrap();
    assert!(
        map_get_bytes(&win.doc.get_map("entities"), &id.to_hex()).is_some(),
        "fixture: reverse remat must mirror the entity into the live doc"
    );

    // Refused: typed variant, exact fields, stable kind, retryable.
    let err = manager.unload_window(&key).unwrap_err();
    match &err {
        Error::WindowBusy {
            window_key,
            outstanding_handles,
        } => {
            assert_eq!(window_key.as_str(), "2026-03");
            assert_eq!(
                *outstanding_handles, 1,
                "external holders only — the registry's own Arc is excluded"
            );
        }
        other => panic!("expected Error::WindowBusy, got {other:?}"),
    }
    assert_eq!(err.kind(), ErrorKind::WindowBusy);
    assert!(
        err.is_retryable(),
        "WindowBusy clears once the last handle drops"
    );

    // Side-effect-free refusal: no persist ran (this window has never been
    // persisted, so any `d:w:` row could only come from the refused call)…
    assert!(
        vault
            .sync_state_get(&format!("d:w:{key}"))
            .unwrap()
            .is_none(),
        "a refused unload must not persist doc state"
    );
    // …and nothing was deregistered: the SAME instance stays discoverable.
    let still = manager.window(&key).expect("window must stay discoverable");
    assert!(
        Arc::ptr_eq(&still, &win),
        "registry must still own the same live instance"
    );
    drop(still);
    assert_eq!(manager.loaded_keys(), [key.clone()]);

    // The trap scenario, asserted closed: with the refusal in place a vault
    // delete still routes through the registry-owned LIVE doc — tombstone
    // visible through the held handle, entities copy removed in the same
    // commit — never the transient path.
    assert!(vault.delete_entity(&id).unwrap());
    assert!(
        map_get_bytes(&win.doc.get_map("tombstones"), &id.to_hex()).is_some(),
        "delete must still route through the registry-owned live doc"
    );
    assert!(
        map_get_bytes(&win.doc.get_map("entities"), &id.to_hex()).is_none(),
        "live entities-map copy removed in the delete commit"
    );
    assert!(
        vault.get(&id).unwrap().is_none(),
        "LMDB purge ran (delete semantics untouched by the refusal)"
    );

    // Still held → still refused: the refusal is a stable, pollable state.
    assert!(matches!(
        manager.unload_window(&key),
        Err(Error::WindowBusy { .. })
    ));
}

/// ONE-1150 — once the last external handle drops, the previously refused
/// unload succeeds: the retry persists the doc state and deregisters.
#[test]
fn unload_succeeds_after_last_external_handle_drops() {
    let (_temp, vault) = test_vault();
    let key = WindowKey::new("2026-04");
    let t = key.start_timestamp().unwrap() + 60;

    let materializer = Arc::new(Materializer::new());
    let manager = Arc::new(WindowManager::new(
        Arc::clone(&vault),
        materializer,
        "test-user",
    ));
    let win = manager.open_window(&key).unwrap();

    let id = EntityId::now();
    win.doc
        .get_map("entities")
        .insert(
            id.to_hex().as_str(),
            make_entity_blob(1, t, b"survives-retry").as_slice(),
        )
        .unwrap();
    win.doc.commit();

    // Held → refused. Dropped → the retry succeeds and deregisters.
    assert!(matches!(
        manager.unload_window(&key),
        Err(Error::WindowBusy { .. })
    ));
    drop(win);
    assert!(manager.unload_window(&key).unwrap());
    assert!(
        manager.window(&key).is_none(),
        "retry after the last drop must deregister"
    );
    assert!(manager.loaded_keys().is_empty());

    // The successful retry persisted the state the refused call did not.
    let reloaded = window::load_window_from_state(&vault, "test-user", &key).unwrap();
    assert_eq!(
        map_get_bytes(&reloaded.get_map("entities"), &id.to_hex()).unwrap(),
        make_entity_blob(1, t, b"survives-retry"),
        "unload-after-drop must persist the window Doc state"
    );
}

/// AC 3 — `rm:w:{key}` consumer: when the needs-rematerialization flag is
/// set (Observer B failure on a previous run; producer is M4-04), open
/// forces forward remat — subsumed by the pinned order, which always runs
/// step 5 — and clears the marker on success.
#[test]
fn open_consumes_rm_marker_after_forward_remat_succeeds() {
    let (_temp, vault) = test_vault();
    let key = WindowKey::new("2026-03");
    let t = key.start_timestamp().unwrap() + 60;

    // A CRDT-ahead entity the failed Observer B never materialized.
    let crdt_only = EntityId::now();
    let setup_doc = LoroDoc::new();
    let entities = setup_doc.get_map("entities");
    entities
        .insert(
            crdt_only.to_hex().as_str(),
            make_entity_blob(1, t, b"missed-by-observer-b").as_slice(),
        )
        .unwrap();
    setup_doc.commit();
    persist_setup_doc(&vault, &key, &setup_doc);

    let rm_key = format!("rm:w:{key}");
    vault.sync_state_put(&rm_key, &[1u8]).unwrap();

    let materializer = Arc::new(Materializer::new());
    let manager = Arc::new(WindowManager::new(
        Arc::clone(&vault),
        materializer,
        "test-user",
    ));
    let _win = manager.open_window(&key).unwrap();

    assert_eq!(
        vault.get(&crdt_only).unwrap().unwrap(),
        b"missed-by-observer-b",
        "forced forward remat must heal the missed materialization"
    );
    assert!(
        vault.sync_state_get(&rm_key).unwrap().is_none(),
        "rm: marker must be consumed after forward remat succeeds"
    );
}

/// Fail-closed: a corrupt persisted snapshot aborts the open with nothing
/// registered, no observers attached, and the `rm:w:{key}` marker (if any)
/// left in place for the next attempt.
#[test]
fn open_fails_closed_on_corrupt_persisted_snapshot() {
    let (_temp, vault) = test_vault();
    let key = WindowKey::new("2026-03");

    vault
        .sync_state_put(&format!("d:w:{key}"), b"not-a-loro-snapshot")
        .unwrap();
    let rm_key = format!("rm:w:{key}");
    vault.sync_state_put(&rm_key, &[1u8]).unwrap();

    let materializer = Arc::new(Materializer::new());
    let manager = Arc::new(WindowManager::new(
        Arc::clone(&vault),
        materializer,
        "test-user",
    ));

    assert!(manager.open_window(&key).is_err());
    assert!(
        manager.window(&key).is_none(),
        "failed open must register nothing"
    );
    assert_eq!(
        vault.sync_state_get(&rm_key).unwrap().unwrap(),
        vec![1u8],
        "rm: marker must survive a failed open"
    );
}

/// ARCH-0023b window policy: 2 default loaded windows (current + previous
/// month); the walk-back stops at the epoch boundary.
#[test]
fn open_default_windows_loads_current_and_previous_month() {
    let (_temp, vault) = test_vault();
    let materializer = Arc::new(Materializer::new());
    let manager = Arc::new(WindowManager::new(
        Arc::clone(&vault),
        materializer,
        "test-user",
    ));

    let now = WindowKey::new("2026-03").start_timestamp().unwrap() + 60;
    let opened = manager.open_default_windows(now).unwrap();
    assert_eq!(opened.len(), 2);
    assert_eq!(opened[0].key.as_str(), "2026-03");
    assert_eq!(opened[1].key.as_str(), "2026-02");
    assert!(manager.window(&WindowKey::new("2026-03")).is_some());
    assert!(manager.window(&WindowKey::new("2026-02")).is_some());

    // Epoch boundary: 1970-01 has no previous month.
    let (_temp2, vault2) = test_vault();
    let manager2 = Arc::new(WindowManager::new(
        vault2,
        Arc::new(Materializer::new()),
        "test-user",
    ));
    let opened = manager2.open_default_windows(0).unwrap();
    assert_eq!(opened.len(), 1);
    assert_eq!(opened[0].key.as_str(), "1970-01");
}
