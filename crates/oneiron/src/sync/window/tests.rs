use super::*;
use rmpv::Value;

use crate::affect::Vad;
use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::companion::{
    CompanionExportClassification, CompanionProvenance, CompanionRecord, CompanionScope,
    encode_companion_record_body,
};
use crate::config::VaultConfig;
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::off_record::OffRecordBackendClass;
use crate::registry::ENTITY_TYPE_TURN;
use crate::sync::WindowManager;
use crate::temporal::TimeRange;

fn test_vault() -> (tempfile::TempDir, Arc<Vault>) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).unwrap());
    (dir, vault)
}

/// Pinned 25-byte entity envelope: type u8 + occurred_start/end u64 BE +
/// learned_at u64 BE + body (`occurred == learned` so CRDT-vs-LMDB
/// byte-equality is exact).
fn make_entity_blob(entity_type: u8, learned_at: u64, data: &[u8]) -> Vec<u8> {
    let mut blob = Vec::with_capacity(25 + data.len());
    blob.push(entity_type);
    blob.extend_from_slice(&learned_at.to_be_bytes());
    blob.extend_from_slice(&learned_at.to_be_bytes());
    blob.extend_from_slice(&learned_at.to_be_bytes());
    blob.extend_from_slice(data);
    blob
}

fn commit_entity(window: &LoadedWindow, learned_at: u64, data: &[u8]) -> EntityId {
    let id = EntityId::now();
    map_insert_bytes(
        &window.doc.get_map("entities"),
        &id.to_hex(),
        &make_entity_blob(1, learned_at, data),
    )
    .unwrap();
    window.doc.commit();
    id
}

fn companion_record(
    persona_ref: EntityId,
    export_classification: CompanionExportClassification,
) -> CompanionRecord {
    CompanionRecord::persona(
        CompanionScope::neutral(),
        persona_ref,
        Value::from("private companion tuning"),
        CompanionProvenance::new(
            EntityId::from_bytes([0xB9; 16]).unwrap(),
            EdgeActorClass::Agent,
            ClaimSource::UserStated,
            ClaimApprovalStatus::Approved,
            Value::from("private provenance"),
        ),
        export_classification,
    )
}

#[test]
fn off_record_fence_defers_window_packing_until_only_the_promoted_turn_releases() -> Result<()> {
    let (_dir, vault) = test_vault();
    let window_key = WindowKey::new("2026-03");
    let learned_at = window_key.start_timestamp().unwrap() + 60;
    let promoted = EntityId::from_bytes([0x41; 16])?;
    let still_fenced = EntityId::from_bytes([0x42; 16])?;
    let ordinary = EntityId::from_bytes([0x43; 16])?;

    vault.enter_off_record_session("sess-defer-sync", OffRecordBackendClass::Local)?;
    for id in [&promoted, &still_fenced] {
        // Tag before the entity write: this is the live-session path that
        // must remain writable while it is held out of sync.
        vault.tag_turn_off_record("sess-defer-sync", id)?;
        vault.put_entity(
            id,
            ENTITY_TYPE_TURN,
            TimeRange {
                start: learned_at,
                end: learned_at,
            },
            learned_at,
            b"off-record turn",
        )?;
    }
    vault.put_entity(
        &ordinary,
        ENTITY_TYPE_TURN,
        TimeRange {
            start: learned_at,
            end: learned_at,
        },
        learned_at,
        b"ordinary turn",
    )?;
    vault.put_edge(&ordinary, EdgeKind::Mentions, &promoted, 0.5)?;
    vault.put_edge(&ordinary, EdgeKind::Mentions, &still_fenced, 0.5)?;

    let promoted_marker = format!("pm:{window_key}:{}", promoted.to_hex());
    let fenced_marker = format!("pm:{window_key}:{}", still_fenced.to_hex());
    vault.sync_state_put(&promoted_marker, &[1])?;
    vault.sync_state_put(&fenced_marker, &[1])?;

    let doc = create_window_doc("source", &window_key);
    let entities = doc.get_map("entities");
    let edges = doc.get_map("edges");
    let promoted_edge = format_edge_key(&ordinary, EdgeKind::Mentions, &promoted);
    let fenced_edge = format_edge_key(&ordinary, EdgeKind::Mentions, &still_fenced);

    // Exercise both packing paths in a live session. Neither fenced body nor
    // the edges that name it can enter the window; the pm rows stay deferred.
    assert_eq!(replay_pending_mirrors(&vault, &doc, &window_key)?, 0);
    assert_eq!(reverse_rematerialize(&vault, &doc, &window_key)?, 1);
    assert!(map_get_bytes(&entities, &promoted.to_hex()).is_none());
    assert!(map_get_bytes(&entities, &still_fenced.to_hex()).is_none());
    assert!(map_get_bytes(&entities, &ordinary.to_hex()).is_some());
    assert!(map_get_bytes(&edges, &promoted_edge).is_none());
    assert!(map_get_bytes(&edges, &fenced_edge).is_none());
    assert!(vault.sync_state_get(&promoted_marker)?.is_some());
    assert!(vault.sync_state_get(&fenced_marker)?.is_some());

    vault.promote_off_record_turn("sess-defer-sync", &promoted)?;

    // Promotion lifts exactly one fence. Its pending mirror can now flow;
    // the other fenced body remains device-local, and reverse packing only
    // releases the edge whose target was explicitly promoted.
    assert_eq!(replay_pending_mirrors(&vault, &doc, &window_key)?, 1);
    assert!(map_get_bytes(&entities, &promoted.to_hex()).is_some());
    assert!(map_get_bytes(&entities, &still_fenced.to_hex()).is_none());
    assert!(vault.sync_state_get(&promoted_marker)?.is_none());
    assert!(vault.sync_state_get(&fenced_marker)?.is_some());
    assert_eq!(reverse_rematerialize(&vault, &doc, &window_key)?, 0);
    assert!(map_get_bytes(&edges, &promoted_edge).is_some());
    assert!(map_get_bytes(&edges, &fenced_edge).is_none());

    Ok(())
}

/// A promotion must refresh the registry-owned document when the relevant
/// window was already open. Otherwise its deferred `pm:` row would survive
/// until unload/reopen even though the user explicitly released the turn.
#[test]
fn off_record_promotion_catches_up_an_already_open_window() -> Result<()> {
    let (_dir, vault) = test_vault();
    let window_key = WindowKey::new("2026-03");
    let learned_at = window_key.start_timestamp().unwrap() + 60;
    let promoted = EntityId::from_bytes([0x51; 16])?;
    let still_fenced = EntityId::from_bytes([0x52; 16])?;
    let ordinary = EntityId::from_bytes([0x53; 16])?;

    vault.enter_off_record_session("sess-live-promotion", OffRecordBackendClass::Local)?;
    for id in [&promoted, &still_fenced] {
        vault.tag_turn_off_record("sess-live-promotion", id)?;
        vault.put_entity(
            id,
            ENTITY_TYPE_TURN,
            TimeRange {
                start: learned_at,
                end: learned_at,
            },
            learned_at,
            b"fenced live-window fixture",
        )?;
    }
    vault.put_entity(
        &ordinary,
        ENTITY_TYPE_TURN,
        TimeRange {
            start: learned_at,
            end: learned_at,
        },
        learned_at,
        b"ordinary live-window fixture",
    )?;
    vault.put_edge(&ordinary, EdgeKind::Mentions, &promoted, 0.5)?;
    vault.put_edge(&ordinary, EdgeKind::Mentions, &still_fenced, 0.5)?;

    let promoted_marker = format!("pm:{window_key}:{}", promoted.to_hex());
    let fenced_marker = format!("pm:{window_key}:{}", still_fenced.to_hex());
    vault.sync_state_put(&promoted_marker, &[1])?;
    vault.sync_state_put(&fenced_marker, &[1])?;

    let manager = Arc::new(WindowManager::new(
        Arc::clone(&vault),
        Arc::new(Materializer::new()),
        "source",
    ));
    let window = manager.open_window(&window_key)?;
    let entities = window.doc.get_map("entities");
    let edges = window.doc.get_map("edges");
    let promoted_edge = format_edge_key(&ordinary, EdgeKind::Mentions, &promoted);
    let fenced_edge = format_edge_key(&ordinary, EdgeKind::Mentions, &still_fenced);

    // The open-time recovery honours the fences and leaves both `pm:` rows
    // pending; only the ordinary record reaches the registered doc.
    assert!(map_get_bytes(&entities, &promoted.to_hex()).is_none());
    assert!(map_get_bytes(&entities, &still_fenced.to_hex()).is_none());
    assert!(map_get_bytes(&entities, &ordinary.to_hex()).is_some());
    assert!(map_get_bytes(&edges, &promoted_edge).is_none());
    assert!(map_get_bytes(&edges, &fenced_edge).is_none());

    vault.promote_off_record_turn("sess-live-promotion", &promoted)?;

    // No unload/reopen is needed: the explicit promotion catches up the same
    // registry-owned doc, clears only its marker, and backfills only the edge
    // whose target is no longer fenced.
    assert!(map_get_bytes(&entities, &promoted.to_hex()).is_some());
    assert!(map_get_bytes(&entities, &still_fenced.to_hex()).is_none());
    assert!(map_get_bytes(&edges, &promoted_edge).is_some());
    assert!(map_get_bytes(&edges, &fenced_edge).is_none());
    assert!(vault.sync_state_get(&promoted_marker)?.is_none());
    assert!(vault.sync_state_get(&fenced_marker)?.is_some());

    Ok(())
}

/// A fence must scrub a carrier that reached the window before the fence was
/// observed. Both production packing paths are covered: pending-mirror replay
/// owns a source carrier, while reverse rematerialization owns an in-range
/// local source plus an incident edge from an ordinary neighbor.
#[test]
fn off_record_fence_scrubs_preexisting_window_carriers() -> Result<()> {
    let (_dir, vault) = test_vault();
    let window_key = WindowKey::new("2026-03");
    let learned_at = window_key.start_timestamp().unwrap() + 60;
    let fenced = EntityId::from_bytes([0x44; 16])?;
    let ordinary = EntityId::from_bytes([0x45; 16])?;

    for id in [&fenced, &ordinary] {
        vault.put_entity(
            id,
            ENTITY_TYPE_TURN,
            TimeRange {
                start: learned_at,
                end: learned_at,
            },
            learned_at,
            b"window carrier fixture",
        )?;
    }
    vault.put_edge(&ordinary, EdgeKind::Mentions, &fenced, 0.5)?;
    vault.enter_off_record_session("sess-scrub-carrier", OffRecordBackendClass::Local)?;
    vault.tag_turn_off_record("sess-scrub-carrier", &fenced)?;

    let fenced_raw = vault.get_raw(&fenced)?.expect("fenced fixture body");
    let edge_key = format_edge_key(&ordinary, EdgeKind::Mentions, &fenced);
    let pending_marker = format!("pm:{window_key}:{}", fenced.to_hex());
    vault.sync_state_put(&pending_marker, &[1])?;

    let replay_doc = create_window_doc("source", &window_key);
    map_insert_bytes(
        &replay_doc.get_map("entities"),
        &fenced.to_hex(),
        &fenced_raw,
    )?;
    map_insert_bytes(
        &replay_doc.get_map("edges"),
        &edge_key,
        b"stale edge carrier",
    )?;
    replay_doc.commit();

    assert_eq!(replay_pending_mirrors(&vault, &replay_doc, &window_key)?, 0);
    assert!(
        map_get_bytes(&replay_doc.get_map("entities"), &fenced.to_hex()).is_none(),
        "pending replay must remove the pre-fence body carrier"
    );
    assert!(
        map_get_bytes(&replay_doc.get_map("edges"), &edge_key).is_none(),
        "pending replay must remove the pre-fence incident edge carrier"
    );
    assert!(
        vault.sync_state_get(&pending_marker)?.is_some(),
        "the pending marker stays deferred until explicit promotion"
    );

    let reverse_doc = create_window_doc("source", &window_key);
    map_insert_bytes(
        &reverse_doc.get_map("entities"),
        &fenced.to_hex(),
        &fenced_raw,
    )?;
    map_insert_bytes(
        &reverse_doc.get_map("edges"),
        &edge_key,
        b"stale edge carrier",
    )?;
    reverse_doc.commit();

    assert_eq!(reverse_rematerialize(&vault, &reverse_doc, &window_key)?, 1);
    assert!(
        map_get_bytes(&reverse_doc.get_map("entities"), &fenced.to_hex()).is_none(),
        "reverse rematerialization must remove the pre-fence body carrier"
    );
    assert!(
        map_get_bytes(&reverse_doc.get_map("edges"), &edge_key).is_none(),
        "reverse rematerialization must remove the pre-fence incident edge carrier"
    );

    Ok(())
}

/// ONE-1151 prune: `persist_state` deletes exactly the `u:w:{key}:*`
/// rows its snapshot subsumed — in the same transaction as the `d:w:`
/// write — while `m:u_seq:w:{key}` keeps its high-water mark
/// (ARCH-0023b: monotonic, missing=0) and every other row family
/// survives byte-identical: the neighbor window's `u:w:` rows, a
/// prefix-adjacent `u:w:` key (exact `u:w:{key}:` scope, not a sloppy
/// substring match), the `dt:` local hard-delete marker (sync_state),
/// and the `q:`/`d:`/`h:` sync_queue families a delete-bearing path
/// owns. The window must then reopen from `d:w:` ALONE.
#[test]
fn persist_state_prunes_subsumed_rows_and_spares_other_families() {
    let (_dir, vault) = test_vault();
    let materializer = Arc::new(Materializer::new());
    let key = WindowKey::new("2026-03");
    let t = key.start_timestamp().unwrap() + 60;

    let window = LoadedWindow::new("local", key.clone(), &vault, &materializer);
    let id_a = commit_entity(&window, t, b"prune-a");
    let id_b = commit_entity(&window, t, b"prune-b");

    // Observer A persisted the contract rows (ARCH-0023b key table).
    assert!(
        vault
            .sync_state_get("u:w:2026-03:00000001")
            .unwrap()
            .is_some()
    );
    assert!(
        vault
            .sync_state_get("u:w:2026-03:00000002")
            .unwrap()
            .is_some()
    );
    assert_eq!(
        vault
            .sync_state_get("m:u_seq:w:2026-03")
            .unwrap()
            .as_deref(),
        Some(2u32.to_le_bytes().as_slice())
    );

    // Sentinels the prune must NOT touch. sync_state families:
    vault
        .sync_state_put("u:w:2026-02:00000001", b"neighbor-window-update")
        .unwrap();
    vault
        .sync_state_put("u:w:2026-030:00000001", b"prefix-adjacent-update")
        .unwrap();
    let dt_key = format!("dt:{}", EntityId::now().to_hex());
    vault.sync_state_put(&dt_key, &[2u8; 26]).unwrap();
    // sync_queue families (`q:{seq:8BE}` update row, `d:{seq:8BE}`
    // delete-bearing sidecar, `h:{seq:8BE}` hard-erase sweep job):
    let q_key = [b'q', b':', 0, 0, 0, 0, 0, 0, 0, 1];
    let d_key = [b'd', b':', 0, 0, 0, 0, 0, 0, 0, 1];
    let h_key = [b'h', b':', 0, 0, 0, 0, 0, 0, 0, 1];
    {
        let mut wtxn = vault.store.env.write_txn().unwrap();
        vault
            .store
            .sync_queue
            .put(&mut wtxn, &q_key, &[1u8])
            .unwrap();
        vault
            .store
            .sync_queue
            .put(&mut wtxn, &d_key, &[1u8])
            .unwrap();
        vault
            .store
            .sync_queue
            .put(&mut wtxn, &h_key, &[7u8])
            .unwrap();
        wtxn.commit().unwrap();
    }

    window.persist_state(&vault).unwrap();

    // Subsumed rows pruned; the high-water mark is NOT reset.
    assert!(
        vault
            .sync_state_get("u:w:2026-03:00000001")
            .unwrap()
            .is_none(),
        "subsumed u:w: row must be pruned after the snapshot persist"
    );
    assert!(
        vault
            .sync_state_get("u:w:2026-03:00000002")
            .unwrap()
            .is_none()
    );
    assert_eq!(
        vault
            .sync_state_get("m:u_seq:w:2026-03")
            .unwrap()
            .as_deref(),
        Some(2u32.to_le_bytes().as_slice()),
        "m:u_seq:w: must stay monotonic — never reset by the prune"
    );
    assert!(vault.sync_state_get("d:w:2026-03").unwrap().is_some());
    // Positive control for the ONE-1151 svf recompute: with every u:w:
    // row subsumed and pruned, the post-prune probe finds zero rows, so
    // freshness is written FRESH ([1]) — proving the fix is not a blanket
    // svf=0 (see persist_state_marks_svf_stale_when_a_post_merge_uw_row_survives
    // for the surviving-row counterpart).
    assert_eq!(
        vault.sync_state_get("svf:w:2026-03").unwrap().as_deref(),
        Some([1u8].as_slice()),
        "all rows subsumed → svf recomputes FRESH"
    );

    // Every sentinel survives byte-identical.
    assert_eq!(
        vault
            .sync_state_get("u:w:2026-02:00000001")
            .unwrap()
            .as_deref(),
        Some(b"neighbor-window-update".as_slice()),
        "the neighbor window's u:w: rows are out of scope"
    );
    assert_eq!(
        vault
            .sync_state_get("u:w:2026-030:00000001")
            .unwrap()
            .as_deref(),
        Some(b"prefix-adjacent-update".as_slice()),
        "prune scope is exactly `u:w:{{key}}:` — never a substring match"
    );
    assert_eq!(
        vault.sync_state_get(&dt_key).unwrap().as_deref(),
        Some([2u8; 26].as_slice()),
        "dt: local hard-delete markers are out of scope (delete safety)"
    );
    {
        let rtxn = vault.store.env.read_txn().unwrap();
        assert_eq!(
            vault.store.sync_queue.get(&rtxn, &q_key).unwrap(),
            Some([1u8].as_slice()),
            "q: update rows are out of scope"
        );
        assert_eq!(
            vault.store.sync_queue.get(&rtxn, &d_key).unwrap(),
            Some([1u8].as_slice()),
            "d: delete-bearing sidecars are out of scope (delete safety)"
        );
        assert_eq!(
            vault.store.sync_queue.get(&rtxn, &h_key).unwrap(),
            Some([7u8].as_slice()),
            "h: hard-erase sweep rows are out of scope (delete safety)"
        );
    }

    // The window reopens from d:w: ALONE (no u:w: rows left to replay).
    drop(window);
    assert_eq!(
        vault
            .sync_state_keys_with_prefix("u:w:2026-03:")
            .unwrap()
            .len(),
        0
    );
    let reloaded = load_window_from_state(&vault, "local", &key).unwrap();
    let entities = reloaded.get_map("entities");
    assert_eq!(
        map_get_bytes(&entities, &id_a.to_hex()).as_deref(),
        Some(make_entity_blob(1, t, b"prune-a").as_slice()),
        "pruned ops must reload from the d:w: snapshot"
    );
    assert!(map_get_bytes(&entities, &id_b.to_hex()).is_some());
}

#[test]
fn companion_register_api_reverse_remat_excludes_local_only_records() -> Result<()> {
    let (_dir, vault) = test_vault();
    let window_key = WindowKey::new("2026-03");
    let learned_at = window_key.start_timestamp().unwrap() + 60;
    let local_id = EntityId::from_bytes([0x31; 16]).unwrap();
    let portable_id = EntityId::from_bytes([0x32; 16]).unwrap();
    let external_local_id = EntityId::from_bytes([0x35; 16]).unwrap();
    let local = companion_record(local_id, CompanionExportClassification::LocalOnly);
    let portable = companion_record(portable_id, CompanionExportClassification::Portable);
    let external_local =
        companion_record(external_local_id, CompanionExportClassification::LocalOnly);

    vault.create_companion_record(&local_id, &local, learned_at)?;
    vault.create_companion_record(&portable_id, &portable, learned_at)?;
    vault.create_companion_record(
        &external_local_id,
        &external_local,
        window_key.end_timestamp().unwrap() + 60,
    )?;
    vault.put_edge(&portable_id, EdgeKind::Mentions, &external_local_id, 0.8)?;

    let doc = create_window_doc("source", &window_key);
    let entities = doc.get_map("entities");
    let edges = doc.get_map("edges");
    let mut stale_local_blob = Vec::new();
    stale_local_blob.push(ENTITY_TYPE_COMPANION_REGISTER);
    stale_local_blob.extend_from_slice(&learned_at.to_be_bytes());
    stale_local_blob.extend_from_slice(&learned_at.to_be_bytes());
    stale_local_blob.extend_from_slice(&learned_at.to_be_bytes());
    stale_local_blob.extend_from_slice(&encode_companion_record_body(
        &local.created_at(learned_at)?,
    )?);
    map_insert_bytes(&entities, &local_id.to_hex(), &stale_local_blob)?;
    let local_edge_key = format_edge_key(&local_id, EdgeKind::Mentions, &portable_id);
    map_insert_bytes(
        &edges,
        &local_edge_key,
        &encode_edge_value_for_crdt(
            EdgeKind::Mentions,
            0.7,
            learned_at,
            Some(Vad::NEUTRAL),
            None,
        )?,
    )?;
    doc.commit();

    reverse_rematerialize(&vault, &doc, &window_key)?;
    let external_local_edge_key =
        format_edge_key(&portable_id, EdgeKind::Mentions, &external_local_id);

    assert!(
        map_get_bytes(&entities, &local_id.to_hex()).is_none(),
        "reverse remat must remove stale local-only companion register rows"
    );
    assert!(
        map_get_bytes(&entities, &portable_id.to_hex()).is_some(),
        "reverse remat should mirror syncable companion register rows"
    );
    assert!(
        map_get_bytes(&edges, &local_edge_key).is_none(),
        "reverse remat must remove edges touching local-only companion register rows"
    );
    assert!(
        map_get_bytes(&edges, &external_local_edge_key).is_none(),
        "reverse remat must not backfill edges to out-of-window local-only companion targets"
    );
    Ok(())
}

#[test]
fn companion_register_api_forward_remat_excludes_local_only_records() -> Result<()> {
    let (_dir, vault) = test_vault();
    let window_key = WindowKey::new("2026-03");
    let learned_at = window_key.start_timestamp().unwrap() + 90;
    let local_id = EntityId::from_bytes([0x33; 16]).unwrap();
    let portable_id = EntityId::from_bytes([0x34; 16]).unwrap();
    let local = companion_record(local_id, CompanionExportClassification::LocalOnly);
    let portable = companion_record(portable_id, CompanionExportClassification::Portable);

    let doc = create_window_doc("remote", &window_key);
    let entities = doc.get_map("entities");
    let edges = doc.get_map("edges");
    map_insert_bytes(
        &entities,
        &local_id.to_hex(),
        &make_entity_blob(
            ENTITY_TYPE_COMPANION_REGISTER,
            learned_at,
            &encode_companion_record_body(&local.created_at(learned_at)?)?,
        ),
    )?;
    map_insert_bytes(
        &entities,
        &portable_id.to_hex(),
        &make_entity_blob(
            ENTITY_TYPE_COMPANION_REGISTER,
            learned_at,
            &encode_companion_record_body(&portable.created_at(learned_at)?)?,
        ),
    )?;
    let local_edge_key = format_edge_key(&portable_id, EdgeKind::Mentions, &local_id);
    map_insert_bytes(
        &edges,
        &local_edge_key,
        &encode_edge_value_for_crdt(
            EdgeKind::Mentions,
            0.8,
            learned_at,
            Some(Vad::NEUTRAL),
            None,
        )?,
    )?;
    doc.commit();

    let materializer = Materializer::new();
    let rematerialized = forward_rematerialize(&vault, &doc, &materializer, &window_key)?;
    assert_eq!(rematerialized, 1);
    assert!(
        map_get_bytes(&entities, &local_id.to_hex()).is_none(),
        "forward remat must remove local-only companion register rows"
    );
    assert!(
        vault.get_companion_record(&local_id)?.is_none(),
        "forward remat must not materialize local-only companion records"
    );
    assert!(
        vault.get_companion_record(&portable_id)?.is_some(),
        "forward remat should materialize syncable companion register rows"
    );
    assert!(
        map_get_bytes(&edges, &local_edge_key).is_none(),
        "forward remat must remove edges touching local-only companion register rows"
    );
    Ok(())
}

#[test]
fn companion_register_api_pending_mirror_replay_excludes_local_only_edges() -> Result<()> {
    let (_dir, vault) = test_vault();
    let window_key = WindowKey::new("2026-03");
    let learned_at = window_key.start_timestamp().unwrap() + 120;
    let local_id = EntityId::from_bytes([0x35; 16]).unwrap();
    let portable_id = EntityId::from_bytes([0x36; 16]).unwrap();
    let local = companion_record(local_id, CompanionExportClassification::LocalOnly);
    let portable = companion_record(portable_id, CompanionExportClassification::Portable);

    vault.create_companion_record(&local_id, &local, learned_at)?;
    vault.create_companion_record(&portable_id, &portable, learned_at)?;
    let marker_key = format!("pm:{window_key}:{}", local_id.to_hex());
    vault.sync_state_put(&marker_key, &[1])?;

    let doc = create_window_doc("source", &window_key);
    let entities = doc.get_map("entities");
    let edges = doc.get_map("edges");
    map_insert_bytes(
        &entities,
        &local_id.to_hex(),
        &make_entity_blob(
            ENTITY_TYPE_COMPANION_REGISTER,
            learned_at,
            &encode_companion_record_body(&local.created_at(learned_at)?)?,
        ),
    )?;
    let local_edge_key = format_edge_key(&local_id, EdgeKind::Mentions, &portable_id);
    map_insert_bytes(
        &edges,
        &local_edge_key,
        &encode_edge_value_for_crdt(
            EdgeKind::Mentions,
            0.9,
            learned_at,
            Some(Vad::NEUTRAL),
            None,
        )?,
    )?;
    doc.commit();

    assert_eq!(replay_pending_mirrors(&vault, &doc, &window_key)?, 0);
    assert!(
        map_get_bytes(&entities, &local_id.to_hex()).is_none(),
        "pending mirror replay must remove stale local-only companion register rows"
    );
    assert!(
        map_get_bytes(&edges, &local_edge_key).is_none(),
        "pending mirror replay must remove edges touching local-only companion register rows"
    );
    assert!(
        vault.sync_state_get(&marker_key)?.is_none(),
        "local-only pending mirror markers should clear after the CRDT carriers are scrubbed"
    );
    Ok(())
}

/// ONE-1151 concurrency seam: a `u:w:` row persisted AFTER the merge
/// captured its subsumption inventory (a transient delete-path doc
/// persisting in parallel — its ops are in neither the merged set nor
/// the exported snapshot) gets a higher seq, is absent from the merged
/// key list, and MUST survive the prune; recovery still replays it.
#[test]
fn prune_spares_updates_persisted_after_the_merge() {
    let (_dir, vault) = test_vault();
    let materializer = Arc::new(Materializer::new());
    let key = WindowKey::new("2026-03");
    let t = key.start_timestamp().unwrap() + 60;

    let window = LoadedWindow::new("local", key.clone(), &vault, &materializer);
    commit_entity(&window, t, b"merged-op");

    // Snapshot-persist sequence as persist_state runs it, with a
    // concurrent writer landing BETWEEN the merge and the write txn.
    let merged = merge_persisted_state_into_doc(&vault, &window.doc, &key).unwrap();
    assert_eq!(merged, vec!["u:w:2026-03:00000001".to_string()]);

    let transient = create_window_doc("transient", &key);
    let late_id = EntityId::now();
    map_insert_bytes(
        &transient.get_map("entities"),
        &late_id.to_hex(),
        &make_entity_blob(1, t, b"late-op"),
    )
    .unwrap();
    transient.commit();
    let late_bytes = export_updates_from(&transient, &loro::VersionVector::default()).unwrap();
    bridge::persist_window_update(&vault, "2026-03", &late_bytes).unwrap();

    let state = export_snapshot(&window.doc).unwrap();
    let vv = doc_version_vector(&window.doc);
    vault
        .with_write_txn(|wtxn| {
            persist_window_doc_in_txn(&vault, wtxn, &key, &state, &vv)?;
            prune_subsumed_window_updates_in_txn(&vault, wtxn, &key, &merged)
        })
        .unwrap();

    assert!(
        vault
            .sync_state_get("u:w:2026-03:00000001")
            .unwrap()
            .is_none(),
        "the merged row is subsumed and pruned"
    );
    assert_eq!(
        vault
            .sync_state_get("u:w:2026-03:00000002")
            .unwrap()
            .as_deref(),
        Some(late_bytes.as_slice()),
        "a row persisted after the merge is NOT in the snapshot and must survive"
    );

    // Recovery = d:w: + surviving u:w: replay — the late op is intact.
    let recovered = load_window_from_state(&vault, "local", &key).unwrap();
    assert!(
        map_get_bytes(&recovered.get_map("entities"), &late_id.to_hex()).is_some(),
        "recovery must replay the surviving post-merge row"
    );
}

/// ONE-1151 svf-freshness fix: the prune_spares scenario driven through
/// the production `persist_state` path. A post-merge `u:w:` row lands
/// DURING the merge import (a one-shot subscription standing in for the
/// transient delete-path writer that persists in parallel), so it is
/// absent from the prune's subsumed-key inventory and survives. Because a
/// pending `u:w:` row then sits on top of `sv:w:`, `svf:w:` MUST be
/// written STALE (`[0]`) — a plausible-wrong impl that keeps the old
/// unconditional `svf=1` fails on the literal `[0]`.
#[test]
fn persist_state_marks_svf_stale_when_a_post_merge_uw_row_survives() {
    use loro::ContainerTrait;
    use std::sync::atomic::{AtomicBool, Ordering};

    let (_dir, vault) = test_vault();
    let materializer = Arc::new(Materializer::new());
    let key = WindowKey::new("2026-03");
    let t = key.start_timestamp().unwrap() + 60;

    let window = LoadedWindow::new("local", key.clone(), &vault, &materializer);

    // Pre-seed `u:w:2026-03:00000001` with an op the LIVE doc does NOT
    // hold, so `persist_state`'s merge import produces a diff (and fires
    // the injection below). This row IS in the merge inventory → pruned.
    let seed = create_window_doc("seed", &key);
    let seed_id = EntityId::now();
    map_insert_bytes(
        &seed.get_map("entities"),
        &seed_id.to_hex(),
        &make_entity_blob(1, t, b"seed-op"),
    )
    .unwrap();
    seed.commit();
    let seed_bytes = export_updates_from(&seed, &loro::VersionVector::default()).unwrap();
    bridge::persist_window_update(&vault, "2026-03", &seed_bytes).unwrap();

    // The survivor op (transient parallel writer): not in the merge
    // inventory, not in the exported snapshot.
    let late = create_window_doc("late", &key);
    let late_id = EntityId::now();
    map_insert_bytes(
        &late.get_map("entities"),
        &late_id.to_hex(),
        &make_entity_blob(1, t, b"late-op"),
    )
    .unwrap();
    late.commit();
    let late_bytes = export_updates_from(&late, &loro::VersionVector::default()).unwrap();

    // Inject the survivor row DURING the merge import (after the prune's
    // inventory was captured, before the write txn) — exactly the seam
    // prune_spares models manually, now exercised through persist_state.
    let injected = Arc::new(AtomicBool::new(false));
    let cb_vault = Arc::clone(&vault);
    let cb_bytes = late_bytes;
    let cb_flag = Arc::clone(&injected);
    let entities_cid = window.doc.get_map("entities").id();
    let _inj = window.doc.subscribe(
        &entities_cid,
        Arc::new(move |_event| {
            if cb_flag.swap(true, Ordering::SeqCst) {
                return;
            }
            bridge::persist_window_update(&cb_vault, "2026-03", &cb_bytes)
                .expect("inject post-merge survivor row");
        }),
    );

    window.persist_state(&vault).unwrap();
    assert!(injected.load(Ordering::SeqCst), "injection must have fired");

    // The merged row is pruned …
    assert!(
        vault
            .sync_state_get("u:w:2026-03:00000001")
            .unwrap()
            .is_none(),
        "the merged row is subsumed and pruned"
    );
    // … the post-merge row survives …
    assert!(
        vault
            .sync_state_get("u:w:2026-03:00000002")
            .unwrap()
            .is_some(),
        "a row persisted during the merge import escapes the prune"
    );
    // … the high-water mark stays monotonic …
    assert_eq!(
        vault
            .sync_state_get("m:u_seq:w:2026-03")
            .unwrap()
            .as_deref(),
        Some(2u32.to_le_bytes().as_slice()),
        "m:u_seq:w: must stay monotonic"
    );
    // … and svf is STALE: the fast-reconnect reader must NOT trust sv:w:.
    assert_eq!(
        vault.sync_state_get("svf:w:2026-03").unwrap().as_deref(),
        Some([0u8].as_slice()),
        "a surviving post-merge u:w: row forces svf STALE ([0])"
    );
}

/// ONE-1151 scope extension: the soft-only `pt:` replay branch keeps the
/// merged `u:w:` rows (only the hard branch scrubs them), so after a soft
/// replay a pending row still sits on top of `sv:w:` — `svf:w:` MUST be
/// written STALE. A wrong impl that writes `svf=1` in the soft branch
/// fails. (Delete-safety-adjacent.)
#[test]
fn replay_pending_tombstones_soft_keeps_svf_stale_when_merged_uw_survives() {
    let (_dir, vault) = test_vault();
    let materializer = Arc::new(Materializer::new());
    let key = WindowKey::new("2026-03");
    let t = key.start_timestamp().unwrap() + 60;

    // A live window with one committed entity → Observer A persists a
    // `u:w:` row the SOFT branch must NOT scrub.
    let window = LoadedWindow::new("local", key.clone(), &vault, &materializer);
    let _id = commit_entity(&window, t, b"keep-me");
    assert!(
        vault
            .sync_state_get("u:w:2026-03:00000001")
            .unwrap()
            .is_some()
    );

    // A SOFT pending-tombstone marker (user_delete, wire byte 1 = soft).
    let victim = EntityId::now();
    let mut soft = vec![1_u8]; // user_delete (soft)
    soft.extend_from_slice(&t.to_le_bytes());
    soft.extend_from_slice(&[0x11; 16]);
    let marker_key = format!("pt:2026-03:{}", victim.to_hex());
    vault.sync_state_put(&marker_key, &soft).unwrap();

    let replayed = replay_pending_tombstones(&vault, &window.doc, &key).unwrap();
    assert_eq!(replayed, 1);

    // The merged u:w: row survives the soft branch …
    assert!(
        vault
            .sync_state_get("u:w:2026-03:00000001")
            .unwrap()
            .is_some(),
        "soft replay must not scrub surviving u:w: rows"
    );
    // … so svf is STALE.
    assert_eq!(
        vault.sync_state_get("svf:w:2026-03").unwrap().as_deref(),
        Some([0u8].as_slice()),
        "a surviving u:w: row after a soft replay forces svf STALE"
    );
    // fr:w: full-resync is a HARD-only concern — untouched by soft replay.
    assert!(vault.sync_state_get("fr:w:2026-03").unwrap().is_none());
}

/// Fail-closed scope guard: a key outside the window's own
/// `u:w:{key}:` family is a TYPED error and the transaction deletes
/// nothing — not even the in-scope keys validated alongside it.
#[test]
fn prune_refuses_keys_outside_the_window_family() {
    let (_dir, vault) = test_vault();
    let key = WindowKey::new("2026-03");
    vault
        .sync_state_put("u:w:2026-03:00000001", b"in-scope")
        .unwrap();
    vault
        .sync_state_put("u:w:2026-02:00000001", b"foreign")
        .unwrap();

    let keys = vec![
        "u:w:2026-03:00000001".to_string(),
        "u:w:2026-02:00000001".to_string(),
    ];
    let err = vault
        .with_write_txn(|wtxn| prune_subsumed_window_updates_in_txn(&vault, wtxn, &key, &keys))
        .expect_err("a foreign key must fail the prune closed");
    assert!(
        matches!(
            err,
            Error::SyncProtocolError {
                context: SyncProtocolValidation::ScopedPrune { .. }
            }
        ),
        "typed error, got: {err:?}"
    );
    assert_eq!(
        vault
            .sync_state_get("u:w:2026-03:00000001")
            .unwrap()
            .as_deref(),
        Some(b"in-scope".as_slice()),
        "validate-before-delete: the aborted txn must delete nothing"
    );
    assert_eq!(
        vault
            .sync_state_get("u:w:2026-02:00000001")
            .unwrap()
            .as_deref(),
        Some(b"foreign".as_slice())
    );
}

/// The single constructor of [`DeleteBearingUpdate`] (ONE-1135 review
/// item 14): a no-op tombstone commit exports nothing (no q:/d: rows
/// queued); a real tombstone commit exports a non-empty delta.
#[test]
fn export_tombstone_commit_delta_none_on_noop_some_on_commit() {
    let doc = create_window_doc("local", &WindowKey::from_timestamp(1_750_000_000_000));
    let vv_before = doc.oplog_vv();
    assert!(
        export_tombstone_commit_delta(&doc, &vv_before)
            .unwrap()
            .is_none(),
        "unchanged doc must export no delete-bearing update"
    );

    let id = EntityId::now();
    apply_tombstone_to_window_doc(&doc, &id, &[1, 2, 3]).unwrap();
    doc.commit();
    let delta = export_tombstone_commit_delta(&doc, &vv_before)
        .unwrap()
        .expect("tombstone commit must export a delete-bearing update");
    assert!(!delta.as_bytes().is_empty());
}

#[test]
fn default_policy_manifest_not_mirrored_to_crdt() {
    let (_dir, vault) = test_vault();
    let manifest_id = crate::gate::default_policy_manifest_id().unwrap();
    let window_key = WindowKey::from_timestamp(crate::gate::DEFAULT_POLICY_MANIFEST_TIMESTAMP);
    let doc = create_window_doc("local", &window_key);

    let mirrored = reverse_rematerialize(&vault, &doc, &window_key).unwrap();

    assert_eq!(mirrored, 0);
    assert!(
        map_get_bytes(&doc.get_map("entities"), &manifest_id.to_hex()).is_none(),
        "the engine-seeded policy manifest must stay out of ordinary sync windows"
    );
}

#[test]
fn default_policy_manifest_tombstone_not_replayed_from_crdt() {
    let (_dir, vault) = test_vault();
    let materializer = Materializer::new();
    let manifest_id = crate::gate::default_policy_manifest_id().unwrap();
    let window_key = WindowKey::from_timestamp(crate::gate::DEFAULT_POLICY_MANIFEST_TIMESTAMP);
    let doc = create_window_doc("remote", &window_key);
    apply_tombstone_to_window_doc(&doc, &manifest_id, &[1, 2, 3]).unwrap();
    doc.commit();

    let rematerialized = forward_rematerialize(&vault, &doc, &materializer, &window_key).unwrap();

    assert_eq!(rematerialized, 0);
    assert!(
        vault.get_raw(&manifest_id).unwrap().is_some(),
        "incoming policy-manifest tombstones must not delete local engine policy"
    );
}

#[test]
fn finalized_receipt_not_mirrored_to_crdt() {
    use crate::deletion::{
        RedactionReceiptInput, RedactionScope, decode_redaction_audit_receipt,
        encode_redaction_audit_receipt,
    };
    use crate::registry::ENTITY_TYPE_REDACTION_AUDIT;
    use crate::temporal::TimeRange;
    use ed25519_dalek::SigningKey;

    let (_dir, vault) = test_vault();
    let learned_at = 1_772_400_000u64;
    let window_key = WindowKey::from_timestamp(learned_at);
    let occurred = TimeRange {
        start: learned_at,
        end: learned_at,
    };
    let identity = crate::identity::DeviceIdentity {
        client_id: 0x0123_4567_89ab_cdefu64,
        signing_key: SigningKey::from_bytes(&[44u8; 32]),
    };

    let make_receipt_body = |receipt_id: &EntityId, subject: &EntityId, request_id: &str| {
        encode_redaction_audit_receipt(
            RedactionReceiptInput {
                request_id: request_id.to_owned(),
                scope: RedactionScope::entity(subject),
                reason: crate::DeleteReason::GdprDelete,
                requested_at: learned_at - 10,
                soft_complete_at: learned_at - 9,
                hard_purge_complete_at: learned_at,
                sweep_queued_at: Some(learned_at - 8),
            },
            receipt_id,
            &identity,
        )
        .unwrap()
    };

    let finalized_id = EntityId::now();
    let finalized_subject = EntityId::now();
    let finalized_pre_body = make_receipt_body(
        &finalized_id,
        &finalized_subject,
        "018f3a2b-7c4d-7e5f-8a9b-0c1d2e3f4a5b",
    );
    let mut finalized_receipt = decode_redaction_audit_receipt(&finalized_pre_body).unwrap();
    finalized_receipt.sweep_complete_at = Some(learned_at + 1);
    let finalized_body = rmp_serde::to_vec_named(&finalized_receipt).unwrap();
    vault
        .batch()
        .put_replicated(
            &finalized_id,
            ENTITY_TYPE_REDACTION_AUDIT,
            occurred,
            learned_at,
            &finalized_body,
        )
        .commit()
        .unwrap();

    let pending_id = EntityId::now();
    let pending_subject = EntityId::now();
    let pending_body = make_receipt_body(
        &pending_id,
        &pending_subject,
        "018f3a2b-7c4d-7e5f-8a9b-0c1d2e3f4a5c",
    );
    vault
        .batch()
        .put_replicated(
            &pending_id,
            ENTITY_TYPE_REDACTION_AUDIT,
            occurred,
            learned_at,
            &pending_body,
        )
        .commit()
        .unwrap();

    let corrupt_id = EntityId::now();
    vault
        .batch()
        .put_replicated(
            &corrupt_id,
            ENTITY_TYPE_REDACTION_AUDIT,
            occurred,
            learned_at,
            b"invalid-receipt-body",
        )
        .commit()
        .unwrap();

    let ordinary_id = EntityId::now();
    vault
        .batch()
        .put_replicated(&ordinary_id, 1, occurred, learned_at, b"ordinary-body")
        .commit()
        .unwrap();

    let doc = create_window_doc("local", &window_key);
    let mirrored = reverse_rematerialize(&vault, &doc, &window_key).unwrap();
    assert_eq!(
        mirrored, 2,
        "only the pending receipt and ordinary entity should mirror"
    );

    let entities = doc.get_map("entities");
    assert!(
        map_get_bytes(&entities, &finalized_id.to_hex()).is_none(),
        "finalized type-120 receipt is local-only and must not mirror"
    );
    assert!(
        map_get_bytes(&entities, &corrupt_id.to_hex()).is_none(),
        "undecodable type-120 receipt must fail closed instead of mirroring raw"
    );

    let pending_raw =
        map_get_bytes(&entities, &pending_id.to_hex()).expect("pending receipt should mirror");
    assert_eq!(
        pending_raw,
        vault.get_raw(&pending_id).unwrap().expect("pending raw"),
        "non-finalized type-120 receipt mirrors byte-exactly"
    );
    let pending_receipt =
        decode_redaction_audit_receipt(&pending_raw[ENTITY_METADATA_HEADER_LEN..]).unwrap();
    assert!(pending_receipt.sweep_complete_at.is_none());

    let ordinary_raw =
        map_get_bytes(&entities, &ordinary_id.to_hex()).expect("ordinary entity should mirror");
    assert_eq!(
        ordinary_raw,
        vault.get_raw(&ordinary_id).unwrap().expect("ordinary raw"),
        "ordinary entities mirror exactly as before"
    );
}

#[test]
fn finalized_receipt_not_mirrored_by_pending_mirror_replay() {
    use crate::deletion::{
        RedactionReceiptInput, RedactionScope, decode_redaction_audit_receipt,
        encode_redaction_audit_receipt,
    };
    use crate::registry::ENTITY_TYPE_REDACTION_AUDIT;
    use crate::temporal::TimeRange;
    use ed25519_dalek::SigningKey;

    let (_dir, vault) = test_vault();
    let learned_at = 1_772_400_000u64;
    let window_key = WindowKey::from_timestamp(learned_at);
    let occurred = TimeRange {
        start: learned_at,
        end: learned_at,
    };
    let identity = crate::identity::DeviceIdentity {
        client_id: 0x0123_4567_89ab_cdefu64,
        signing_key: SigningKey::from_bytes(&[44u8; 32]),
    };

    let make_receipt_body = |receipt_id: &EntityId, subject: &EntityId, request_id: &str| {
        encode_redaction_audit_receipt(
            RedactionReceiptInput {
                request_id: request_id.to_owned(),
                scope: RedactionScope::entity(subject),
                reason: crate::DeleteReason::GdprDelete,
                requested_at: learned_at - 10,
                soft_complete_at: learned_at - 9,
                hard_purge_complete_at: learned_at,
                sweep_queued_at: Some(learned_at - 8),
            },
            receipt_id,
            &identity,
        )
        .unwrap()
    };

    let finalized_id = EntityId::now();
    let finalized_subject = EntityId::now();
    let finalized_pre_body = make_receipt_body(
        &finalized_id,
        &finalized_subject,
        "018f3a2b-7c4d-7e5f-8a9b-0c1d2e3f4a5b",
    );
    let mut finalized_receipt = decode_redaction_audit_receipt(&finalized_pre_body).unwrap();
    finalized_receipt.sweep_complete_at = Some(learned_at + 1);
    let finalized_body = rmp_serde::to_vec_named(&finalized_receipt).unwrap();
    vault
        .batch()
        .put_replicated(
            &finalized_id,
            ENTITY_TYPE_REDACTION_AUDIT,
            occurred,
            learned_at,
            &finalized_body,
        )
        .commit()
        .unwrap();

    let pending_id = EntityId::now();
    let pending_subject = EntityId::now();
    let pending_body = make_receipt_body(
        &pending_id,
        &pending_subject,
        "018f3a2b-7c4d-7e5f-8a9b-0c1d2e3f4a5c",
    );
    vault
        .batch()
        .put_replicated(
            &pending_id,
            ENTITY_TYPE_REDACTION_AUDIT,
            occurred,
            learned_at,
            &pending_body,
        )
        .commit()
        .unwrap();

    let corrupt_id = EntityId::now();
    vault
        .batch()
        .put_replicated(
            &corrupt_id,
            ENTITY_TYPE_REDACTION_AUDIT,
            occurred,
            learned_at,
            b"invalid-receipt-body",
        )
        .commit()
        .unwrap();

    let ordinary_id = EntityId::now();
    vault
        .batch()
        .put_replicated(&ordinary_id, 1, occurred, learned_at, b"ordinary-body")
        .commit()
        .unwrap();

    for id in [&finalized_id, &pending_id, &corrupt_id, &ordinary_id] {
        vault
            .sync_state_put(&format!("pm:{window_key}:{}", id.to_hex()), &[1u8])
            .unwrap();
    }

    let doc = create_window_doc("local", &window_key);
    let replayed = replay_pending_mirrors(&vault, &doc, &window_key).unwrap();
    assert_eq!(
        replayed, 2,
        "only the pending receipt and ordinary entity should replay"
    );

    let entities = doc.get_map("entities");
    assert!(
        map_get_bytes(&entities, &finalized_id.to_hex()).is_none(),
        "finalized type-120 receipt is local-only and must not replay"
    );
    assert!(
        map_get_bytes(&entities, &corrupt_id.to_hex()).is_none(),
        "undecodable type-120 receipt must fail closed instead of replaying raw"
    );

    let pending_raw =
        map_get_bytes(&entities, &pending_id.to_hex()).expect("pending receipt should replay");
    assert_eq!(
        pending_raw,
        vault.get_raw(&pending_id).unwrap().expect("pending raw"),
        "non-finalized type-120 receipt replays byte-exactly"
    );
    let pending_receipt =
        decode_redaction_audit_receipt(&pending_raw[ENTITY_METADATA_HEADER_LEN..]).unwrap();
    assert!(pending_receipt.sweep_complete_at.is_none());

    let ordinary_raw =
        map_get_bytes(&entities, &ordinary_id.to_hex()).expect("ordinary entity should replay");
    assert_eq!(
        ordinary_raw,
        vault.get_raw(&ordinary_id).unwrap().expect("ordinary raw"),
        "ordinary entities replay exactly as before"
    );

    for id in [&finalized_id, &pending_id, &corrupt_id, &ordinary_id] {
        assert!(
            vault
                .sync_state_get(&format!("pm:{window_key}:{}", id.to_hex()))
                .unwrap()
                .is_none(),
            "processed pm marker should be cleared for {}",
            id.to_hex()
        );
    }
}

#[test]
fn forward_remat_quarantines_receipt_when_lease_revoked_between_check_and_write() {
    use ed25519_dalek::SigningKey;

    let (_dir, vault) = test_vault();
    let materializer = Materializer::new();
    let learned_at = 1_772_400_000u64;
    let window_key = WindowKey::from_timestamp(learned_at);
    let receipt_id = EntityId::from_hex("000102030405060708090a0b0c0d0e0f").unwrap();
    let subject = EntityId::from_hex("101112131415161718191a1b1c1d1e1f").unwrap();
    let client_id = 0x0123_4567_89ab_cdefu64;
    let signing_key = SigningKey::from_bytes(&[44u8; 32]);
    let pubkey = signing_key.verifying_key().to_bytes();
    let identity = crate::identity::DeviceIdentity {
        client_id,
        signing_key,
    };
    let vault_id = crate::sync::lease::DEFAULT_LEASE_VAULT_ID;
    let input = crate::deletion::RedactionReceiptInput {
        request_id: "018f3a2b-7c4d-7e5f-8a9b-0c1d2e3f4a5b".to_owned(),
        scope: crate::deletion::RedactionScope::entity(&subject),
        reason: crate::DeleteReason::GdprDelete,
        requested_at: 100,
        soft_complete_at: 101,
        hard_purge_complete_at: learned_at,
        sweep_queued_at: Some(102),
    };
    let body =
        crate::deletion::encode_redaction_audit_receipt(input, &receipt_id, &identity).unwrap();
    let mut blob = crate::deletion::receipt_envelope_header(learned_at).to_vec();
    blob.extend_from_slice(&body);

    let active = crate::sync::lease::LeaseRecord {
        vault_id,
        status: crate::sync::lease::LeaseStatus::Active,
        pubkey,
        granted_at: 1,
        renewed_at: 2,
        expires_at: 3,
    };
    let revoked = crate::sync::lease::LeaseRecord {
        status: crate::sync::lease::LeaseStatus::Revoked,
        ..active
    };
    let lease_key = crate::sync::lease::lease_key(vault_id, client_id);
    vault
        .sync_state_put(
            &lease_key,
            &crate::sync::lease::encode_lease_record(&active),
        )
        .unwrap();

    let doc = create_window_doc("local", &window_key);
    doc.get_map("entities")
        .insert(receipt_id.to_hex().as_str(), blob.as_slice())
        .unwrap();
    doc.commit();

    test_hooks::arm_receipt_revocation_race(
        lease_key,
        crate::sync::lease::encode_lease_record(&revoked).to_vec(),
    );
    let count = forward_rematerialize(&vault, &doc, &materializer, &window_key).unwrap();
    assert_eq!(count, 0, "the revoked receipt is quarantined, not written");
    assert!(
        vault.get_raw(&receipt_id).unwrap().is_none(),
        "the stale-read race must not write the receipt entity"
    );
    let records = quarantine::quarantined_records(&vault).unwrap();
    assert_eq!(records.len(), 1);
    let record = &records[0].1;
    assert_eq!(record.window_key, window_key.as_str());
    assert_eq!(record.container, QuarantineContainer::Entities);
    assert_eq!(record.reason_code, "ReceiptLeaseRevoked");
}

#[test]
fn forward_remat_quarantines_divergent_receipt_landing_mid_flight() {
    use ed25519_dalek::SigningKey;

    let (_dir, vault) = test_vault();
    let materializer = Materializer::new();
    let learned_at = 1_772_400_000u64;
    let window_key = WindowKey::from_timestamp(learned_at);
    let receipt_id = EntityId::from_hex("202122232425262728292a2b2c2d2e2f").unwrap();
    let subject = EntityId::from_hex("303132333435363738393a3b3c3d3e3f").unwrap();
    let client_id = 0x0fed_cba9_8765_4321u64;
    let vault_id = crate::sync::lease::DEFAULT_LEASE_VAULT_ID;
    let signing_key = SigningKey::from_bytes(&[45u8; 32]);
    let pubkey = signing_key.verifying_key().to_bytes();
    let identity = crate::identity::DeviceIdentity {
        client_id,
        signing_key,
    };

    let remote_input = crate::deletion::RedactionReceiptInput {
        request_id: "018f3a2b-7c4d-7e5f-8a9b-0c1d2e3f4a5c".to_owned(),
        scope: crate::deletion::RedactionScope::entity(&subject),
        reason: crate::DeleteReason::GdprDelete,
        requested_at: 100,
        soft_complete_at: 101,
        hard_purge_complete_at: learned_at,
        sweep_queued_at: Some(102),
    };
    let remote_body =
        crate::deletion::encode_redaction_audit_receipt(remote_input, &receipt_id, &identity)
            .unwrap();
    let mut remote_blob = crate::deletion::receipt_envelope_header(learned_at).to_vec();
    remote_blob.extend_from_slice(&remote_body);

    let local_input = crate::deletion::RedactionReceiptInput {
        request_id: "018f3a2b-7c4d-7e5f-8a9b-0c1d2e3f4a5d".to_owned(),
        scope: crate::deletion::RedactionScope::entity(&subject),
        reason: crate::DeleteReason::GdprDelete,
        requested_at: 100,
        soft_complete_at: 101,
        hard_purge_complete_at: learned_at,
        sweep_queued_at: Some(102),
    };
    let local_body =
        crate::deletion::encode_redaction_audit_receipt(local_input, &receipt_id, &identity)
            .unwrap();
    let mut local_blob = crate::deletion::receipt_envelope_header(learned_at).to_vec();
    local_blob.extend_from_slice(&local_body);
    assert_ne!(local_blob, remote_blob);

    let active = crate::sync::lease::LeaseRecord {
        vault_id,
        status: crate::sync::lease::LeaseStatus::Active,
        pubkey,
        granted_at: 1,
        renewed_at: 2,
        expires_at: 3,
    };
    vault
        .sync_state_put(
            &crate::sync::lease::lease_key(vault_id, client_id),
            &crate::sync::lease::encode_lease_record(&active),
        )
        .unwrap();

    let doc = create_window_doc("local", &window_key);
    doc.get_map("entities")
        .insert(receipt_id.to_hex().as_str(), remote_blob.as_slice())
        .unwrap();
    doc.commit();

    test_hooks::arm_receipt_local_write_race(receipt_id, local_blob.clone());
    let count = forward_rematerialize(&vault, &doc, &materializer, &window_key).unwrap();
    assert_eq!(
        count, 0,
        "the divergent remote receipt is quarantined, not written"
    );
    assert_eq!(
        vault.get_raw(&receipt_id).unwrap().as_deref(),
        Some(local_blob.as_slice()),
        "the in-txn recheck must keep the mid-flight local receipt bytes"
    );
    let records = quarantine::quarantined_records(&vault).unwrap();
    assert_eq!(records.len(), 1);
    let record = &records[0].1;
    assert_eq!(record.window_key, window_key.as_str());
    assert_eq!(record.container, QuarantineContainer::Entities);
    assert_eq!(record.reason_code, "RedactionReceiptDivergence");
}
