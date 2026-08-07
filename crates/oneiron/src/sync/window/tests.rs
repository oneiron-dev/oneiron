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

/// THE EGRESS REGRESSION (ARCH-0052 P6, ONE-1731 / R-20260807-06).
///
/// The sync window-packing door skips live session-overlay members through
/// BOTH packing paths, while an ordinary base write COMMISSIONED during the
/// same live session packs normally. That asymmetry is the whole contract:
/// the door asks about membership in a room, not about whether a room exists.
///
/// A `pm:` marker for an excluded id stays PENDING rather than being cleared,
/// so a later P5 promote releases the turn to sync through this same ordinary
/// path instead of needing a special release verb.
///
/// The fixture takes an already-base-resident id into the overlay directly,
/// because that is the only way to hand the DOOR an id that packing can also
/// see. Production never reaches that state — the K4 taint guard refuses a
/// base write at a live overlay id — which is exactly why an unexercised door
/// would be an untested one.
#[test]
fn window_packing_door_skips_overlay_members_and_packs_commissioned_writes() -> Result<()> {
    let (_dir, vault) = test_vault();
    let window_key = WindowKey::new("2026-03");
    let learned_at = window_key.start_timestamp().unwrap() + 60;
    let room_member = EntityId::from_bytes([0x41; 16])?;
    let commissioned = EntityId::from_bytes([0x43; 16])?;

    for id in [&room_member, &commissioned] {
        vault.put_entity(
            id,
            ENTITY_TYPE_TURN,
            TimeRange {
                start: learned_at,
                end: learned_at,
            },
            learned_at,
            b"packing fixture turn",
        )?;
    }

    let session = vault
        .off_record_session_vault()
        .enter("sess-egress-door", OffRecordBackendClass::Local)?;
    let overlay = session.overlay();
    let segment = overlay.install_txn_segment()?;
    overlay.put(
        crate::session_overlay::OverlayKeyspace::Entities,
        room_member.as_bytes(),
        b"live session overlay entity",
    )?;
    segment.commit()?;

    assert!(crate::sync::window::window_packing_excludes_entity(
        &vault,
        &room_member
    )?);
    assert!(!crate::sync::window::window_packing_excludes_entity(
        &vault,
        &commissioned
    )?);

    let member_marker = format!("pm:{window_key}:{}", room_member.to_hex());
    let commissioned_marker = format!("pm:{window_key}:{}", commissioned.to_hex());
    vault.sync_state_put(&member_marker, &[1])?;
    vault.sync_state_put(&commissioned_marker, &[1])?;

    let doc = create_window_doc("source", &window_key);
    let entities = doc.get_map("entities");

    // Path 1 — pm: replay. The commissioned write mirrors and clears its
    // marker; the overlay member neither mirrors nor loses its marker.
    assert_eq!(replay_pending_mirrors(&vault, &doc, &window_key)?, 1);
    assert!(map_get_bytes(&entities, &room_member.to_hex()).is_none());
    assert!(map_get_bytes(&entities, &commissioned.to_hex()).is_some());
    assert!(vault.sync_state_get(&member_marker)?.is_some());
    assert!(vault.sync_state_get(&commissioned_marker)?.is_none());

    // Path 2 — reverse rematerialization. Same verdict, and re-running is a
    // standing predicate rather than a one-shot skip.
    assert_eq!(reverse_rematerialize(&vault, &doc, &window_key)?, 0);
    assert!(map_get_bytes(&entities, &room_member.to_hex()).is_none());

    // Closing the room drops membership, and the deferred turn joins sync
    // through the ordinary path with no release verb of its own.
    session.close()?;
    assert!(!crate::sync::window::window_packing_excludes_entity(
        &vault,
        &room_member
    )?);
    assert_eq!(replay_pending_mirrors(&vault, &doc, &window_key)?, 1);
    assert!(map_get_bytes(&entities, &room_member.to_hex()).is_some());
    assert!(vault.sync_state_get(&member_marker)?.is_none());
    Ok(())
}

fn put_local_type_76_event(
    vault: &Vault,
    learned_at: u64,
    participant_seed: u8,
) -> Result<(EntityId, Vec<u8>)> {
    use crate::identity_topology::{
        IdentityOpEvidence, IdentityOpOutcome, IdentityOpWrite, IdentityTopologyOp, MergeOp,
        SurvivorshipPlan,
    };

    let source = EntityId::from_bytes([participant_seed; 16])?;
    let survivor = EntityId::from_bytes([participant_seed.wrapping_add(1); 16])?;
    for id in [&source, &survivor] {
        vault.put_entity(
            id,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"protected outbound fixture",
        )?;
    }
    let outcome = vault.apply_identity_topology_op(
        &IdentityTopologyOp::Merge(MergeOp {
            sources: vec![source],
            survivor,
            evidence: IdentityOpEvidence {
                refs: Vec::new(),
                rationale: "protected outbound tombstone fixture".to_owned(),
            },
            survivorship_plan: SurvivorshipPlan::ReadThrough,
        }),
        &IdentityOpWrite::auto(ClaimSource::Inferred),
        learned_at,
    )?;
    let event = match outcome {
        IdentityOpOutcome::Applied { event, .. } => event,
        other => panic!("fixture merge must apply, got {other:?}"),
    };
    let raw = vault.get_raw(&event)?.expect("type-76 event carrier");
    Ok((event, raw))
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
            vault
                .store
                .sync_queue
                .get(&rtxn, &q_key)
                .unwrap()
                .as_deref(),
            Some([1u8].as_slice()),
            "q: update rows are out of scope"
        );
        assert_eq!(
            vault
                .store
                .sync_queue
                .get(&rtxn, &d_key)
                .unwrap()
                .as_deref(),
            Some([1u8].as_slice()),
            "d: delete-bearing sidecars are out of scope (delete safety)"
        );
        assert_eq!(
            vault
                .store
                .sync_queue
                .get(&rtxn, &h_key)
                .unwrap()
                .as_deref(),
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

    reverse_rematerialize(&vault, &doc, &window_key).unwrap();

    // ONE-1890's seeded AGENT_DEF rows share this timestamp-0 window and DO
    // mirror — they are ordinary byte-17 entities whose user edits must sync.
    // The manifest is the one engine-seeded row held back.
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
        "finalized REDACTION_AUDIT receipt is local-only and must not mirror"
    );
    assert!(
        map_get_bytes(&entities, &corrupt_id.to_hex()).is_none(),
        "undecodable REDACTION_AUDIT receipt must fail closed instead of mirroring raw"
    );

    let pending_raw =
        map_get_bytes(&entities, &pending_id.to_hex()).expect("pending receipt should mirror");
    assert_eq!(
        pending_raw,
        vault.get_raw(&pending_id).unwrap().expect("pending raw"),
        "non-finalized REDACTION_AUDIT receipt mirrors byte-exactly"
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
        "finalized REDACTION_AUDIT receipt is local-only and must not replay"
    );
    assert!(
        map_get_bytes(&entities, &corrupt_id.to_hex()).is_none(),
        "undecodable REDACTION_AUDIT receipt must fail closed instead of replaying raw"
    );

    let pending_raw =
        map_get_bytes(&entities, &pending_id.to_hex()).expect("pending receipt should replay");
    assert_eq!(
        pending_raw,
        vault.get_raw(&pending_id).unwrap().expect("pending raw"),
        "non-finalized REDACTION_AUDIT receipt replays byte-exactly"
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

/// MS-01 (ARCH-0055 trust perimeter): forward rematerialization routes
/// type-76 identity-topology events through the SAME fail-closed
/// single-writer ingest door as Observer B — an accepted record derives its
/// shell edge, DIVERGENT remote bytes quarantine-and-continue instead of
/// LWW-overwriting the accepted local event (the pre-fix generic
/// `put_replicated` arm), and an unledgered reserved-kind edges-map row is
/// quarantined, never materialized.
#[test]
fn forward_rematerialization_routes_type_76_through_the_ingest_door() -> Result<()> {
    use crate::identity_topology::{
        EntityLifecycleState, StoredIdentityOpAction, StoredIdentityOpEvent,
    };

    let (_dir, vault) = test_vault();
    let window_key = WindowKey::new("2026-03");
    let survivor = EntityId::from_bytes([0x61; 16])?;
    let loser = EntityId::from_bytes([0x62; 16])?;
    let stranger = EntityId::from_bytes([0x63; 16])?;
    for id in [&survivor, &loser, &stranger] {
        vault.put_entity(
            id,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"person fixture",
        )?;
    }

    let event_id = EntityId::from_bytes([0x70; 16])?;
    let record = StoredIdentityOpEvent {
        seq: 50,
        at: 200,
        actor: None,
        source: ClaimSource::Inferred,
        approval: ClaimApprovalStatus::Auto,
        confidence: 1.0,
        evidence: None,
        action: StoredIdentityOpAction::Merge {
            sources: vec![loser],
            survivor,
        },
    };
    let body = crate::identity_topology::encode_identity_topology_event_body(&record)?;
    let doc = create_window_doc("remote", &window_key);
    let entities = doc.get_map("entities");
    let edges = doc.get_map("edges");
    map_insert_bytes(
        &entities,
        &event_id.to_hex(),
        &make_entity_blob(
            crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT,
            200,
            &body,
        ),
    )?;
    // A forged reserved-kind row no ledger event mandates.
    let forged_key = format_edge_key(&stranger, EdgeKind::MergedInto, &survivor);
    map_insert_bytes(
        &edges,
        &forged_key,
        &encode_edge_value_for_crdt(EdgeKind::MergedInto, 0.3, 10, None, None)?,
    )?;
    doc.commit();

    forward_rematerialize(&vault, &doc, &Materializer::new(), &window_key)?;

    // The accepted record materialized AND derived its shell edge; the
    // forged row never landed but left quarantine evidence.
    assert!(vault.identity_topology_event(&event_id)?.is_some());
    assert!(vault.edge_exists(&loser, EdgeKind::MergedInto, &survivor)?);
    assert_eq!(
        vault.entity_lifecycle_state(&loser)?,
        EntityLifecycleState::Merged
    );
    assert!(!vault.edge_exists(&stranger, EdgeKind::MergedInto, &survivor)?);
    assert!(
        !crate::sync::quarantine::quarantined_records(&vault)?.is_empty(),
        "the forged shell row must leave hashed quarantine evidence"
    );

    // Divergent bytes for the SAME event id: the door keeps the accepted
    // local bytes and quarantines-and-continues — remat must not abort and
    // must not silently LWW-overwrite.
    let mut divergent = record;
    divergent.at = 999;
    let divergent_body = crate::identity_topology::encode_identity_topology_event_body(&divergent)?;
    map_insert_bytes(
        &entities,
        &event_id.to_hex(),
        &make_entity_blob(
            crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT,
            200,
            &divergent_body,
        ),
    )?;
    doc.commit();
    forward_rematerialize(&vault, &doc, &Materializer::new(), &window_key)?;
    assert_eq!(
        vault.identity_topology_event(&event_id)?.map(|r| r.at),
        Some(200),
        "divergent remote bytes must never overwrite the accepted event"
    );
    assert!(
        vault.edge_exists(&loser, EdgeKind::MergedInto, &survivor)?,
        "the mandated shell edge survives the rejected divergence"
    );
    Ok(())
}

#[test]
fn forward_rematerialization_quarantines_forged_shell_and_continues_edge_pass() -> Result<()> {
    let (_dir, vault) = test_vault();
    let window_key = WindowKey::new("2026-03");
    let forged_source = EntityId::from_bytes([0x81; 16])?;
    let ordinary_source = EntityId::from_bytes([0x82; 16])?;
    let target = EntityId::from_bytes([0x83; 16])?;
    for id in [&forged_source, &ordinary_source, &target] {
        vault.put_entity(
            id,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"person fixture",
        )?;
    }

    let doc = create_window_doc("remote", &window_key);
    let edges = doc.get_map("edges");
    let forged_key = format_edge_key(&forged_source, EdgeKind::MergedInto, &target);
    let forged_value = encode_edge_value_for_crdt(EdgeKind::MergedInto, 0.3, 10, None, None)?;
    map_insert_bytes(&edges, &forged_key, &forged_value)?;
    let ordinary_key = format_edge_key(&ordinary_source, EdgeKind::Mentions, &target);
    let ordinary_value = encode_edge_value_for_crdt(EdgeKind::Mentions, 0.4, 11, None, None)?;
    map_insert_bytes(&edges, &ordinary_key, &ordinary_value)?;
    doc.commit();

    let count = forward_rematerialize(&vault, &doc, &Materializer::new(), &window_key)?;
    assert_eq!(
        count, 1,
        "the forged shell is skipped while the other N-1 edge still heals"
    );
    assert!(
        !vault.edge_exists(&forged_source, EdgeKind::MergedInto, &target)?,
        "an unledgered reserved edge must never land"
    );
    assert!(
        vault.edge_exists(&ordinary_source, EdgeKind::Mentions, &target)?,
        "one poisoned edge must not abort the rest of the rematerialization pass"
    );
    let quarantined = crate::sync::quarantine::quarantined_records(&vault)?;
    assert_eq!(quarantined.len(), 1);
    let record = &quarantined[0].1;
    assert_eq!(record.container, QuarantineContainer::Edges);
    assert_eq!(record.reason_code, "ReservedEdgeKind");
    assert_eq!(
        (record.crdt_key_hash, record.crdt_key_len),
        crate::sync::quarantine::crdt_key_metadata(&forged_key)
    );
    assert_eq!(
        record.payload_hash,
        crate::sync::quarantine::payload_hash(&forged_value)
    );
    Ok(())
}

#[test]
fn forward_remat_quarantines_replicated_secret_custody_carrier() -> Result<()> {
    // C1 APPLY-TIME SEAL, end to end: a peer files a SECRET_CUSTODY body in
    // the window doc. The generic `put_replicated` arm used to admit byte 77
    // straight into LMDB (the replicated type gate named only POLICY_MANIFEST
    // / ACCESS_GRANT / OUTBOUND_GRANT), materializing peer-authored plaintext
    // `value_bytes`. It must now quarantine the row and continue the pass.
    use crate::secret_custody::{
        CustodyClass, SECRET_CUSTODY_SCHEMA_VERSION, SecretCustodyFloor, SecretCustodyRecord,
        SecretCustodyStatus, encode_secret_custody_body,
    };

    let (_dir, vault) = test_vault();
    let window_key = WindowKey::new("2026-03");
    let learned_at = window_key.start_timestamp().unwrap() + 60;
    let custody_id = EntityId::from_bytes([0x51; 16])?;
    let ordinary_id = EntityId::from_bytes([0x52; 16])?;

    let body = encode_secret_custody_body(&SecretCustodyRecord {
        schema_version: SECRET_CUSTODY_SCHEMA_VERSION,
        name: "peer-authored".to_owned(),
        class: CustodyClass::CustodyPortable,
        device_only: false,
        value_bytes: b"peer-plaintext-value".to_vec(),
        status: SecretCustodyStatus::Active,
        registered_at: learned_at,
        rotated_at: None,
        rotation_generation: 0,
        bindings: Vec::new(),
        manifest_ref: String::new(),
        declared_paths: Vec::new(),
        policy_floor_snapshot: SecretCustodyFloor::default(),
    })?;
    let custody_blob = make_entity_blob(ENTITY_TYPE_SECRET_CUSTODY, learned_at, &body);
    let ordinary_blob = make_entity_blob(ENTITY_TYPE_TURN, learned_at, b"ordinary turn body");

    let doc = create_window_doc("remote", &window_key);
    let entities = doc.get_map("entities");
    map_insert_bytes(&entities, &custody_id.to_hex(), &custody_blob)?;
    map_insert_bytes(&entities, &ordinary_id.to_hex(), &ordinary_blob)?;
    doc.commit();

    let count = forward_rematerialize(&vault, &doc, &Materializer::new(), &window_key)?;

    assert_eq!(count, 1, "the ordinary row still materializes");
    assert!(
        vault
            .store
            .entities
            .get(&vault.store.env.read_txn()?, custody_id.as_bytes())?
            .is_none(),
        "a replicated custody body must never reach LMDB"
    );
    assert!(
        vault.get_raw(&ordinary_id)?.is_some(),
        "one sealed custody row must not wedge the rest of the pass"
    );
    let quarantined = crate::sync::quarantine::quarantined_records(&vault)?;
    assert_eq!(quarantined.len(), 1);
    assert_eq!(quarantined[0].1.container, QuarantineContainer::Entities);
    assert_eq!(
        quarantined[0].1.reason_code, "InvalidSecretCustodyBody",
        "the custody seal must classify as a remote rejection, not a local failure"
    );
    Ok(())
}

#[test]
fn forward_rematerialization_admits_byte_exact_mandated_shell_echo() -> Result<()> {
    use crate::identity_topology::{
        IdentityOpEvidence, IdentityOpOutcome, IdentityOpWrite, IdentityTopologyOp, MergeOp,
        SurvivorshipPlan,
    };

    let (_dir, vault) = test_vault();
    let window_key = WindowKey::new("2026-03");
    let survivor = EntityId::from_bytes([0x91; 16])?;
    let loser = EntityId::from_bytes([0x92; 16])?;
    for id in [&survivor, &loser] {
        vault.put_entity(
            id,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"person fixture",
        )?;
    }
    let outcome = vault.apply_identity_topology_op(
        &IdentityTopologyOp::Merge(MergeOp {
            sources: vec![loser],
            survivor,
            evidence: IdentityOpEvidence {
                refs: Vec::new(),
                rationale: "mandated echo fixture".to_owned(),
            },
            survivorship_plan: SurvivorshipPlan::ReadThrough,
        }),
        &IdentityOpWrite::auto(ClaimSource::Inferred),
        200,
    )?;
    assert!(matches!(outcome, IdentityOpOutcome::Applied { .. }));
    assert!(vault.edge_exists(&loser, EdgeKind::MergedInto, &survivor)?);

    // Simulate a replica whose ledger event survived but whose derived edge
    // indexes did not. Only the byte-exact door echo in the CRDT may heal it.
    let out_key = Store::encode_edge_key(&loser, EdgeKind::MergedInto, &survivor);
    let in_key = Store::encode_edge_key(&survivor, EdgeKind::MergedInto, &loser);
    vault.with_write_txn(|wtxn| {
        vault.store.edges_out.delete(wtxn, &out_key)?;
        vault.store.edges_in.delete(wtxn, &in_key)?;
        Ok(())
    })?;
    assert!(!vault.edge_exists(&loser, EdgeKind::MergedInto, &survivor)?);

    let doc = create_window_doc("remote", &window_key);
    let shell_key = format_edge_key(&loser, EdgeKind::MergedInto, &survivor);
    let shell_value = encode_edge_value_for_crdt(
        EdgeKind::MergedInto,
        EdgeKind::MergedInto.default_weight().expect("shell weight"),
        200,
        None,
        None,
    )?;
    map_insert_bytes(&doc.get_map("edges"), &shell_key, &shell_value)?;
    doc.commit();

    let count = forward_rematerialize(&vault, &doc, &Materializer::new(), &window_key)?;
    assert_eq!(count, 1, "the mandated echo must heal the missing edge");
    assert!(vault.edge_exists(&loser, EdgeKind::MergedInto, &survivor)?);
    let rtxn = vault.store.env.read_txn()?;
    let healed_out = vault
        .store
        .edges_out
        .get(&rtxn, &out_key)?
        .expect("outbound shell index healed");
    let healed_in = vault
        .store
        .edges_in
        .get(&rtxn, &in_key)?
        .expect("inbound shell index healed");
    assert_eq!(healed_out.as_ref(), shell_value.as_slice());
    assert_eq!(healed_in.as_ref(), shell_value.as_slice());
    drop(rtxn);
    assert!(
        crate::sync::quarantine::quarantined_records(&vault)?.is_empty(),
        "a byte-exact mandated echo must be admitted, not quarantined"
    );
    Ok(())
}

#[test]
fn reverse_rematerialization_restores_protected_row_against_hostile_tombstone() -> Result<()> {
    let (_dir, vault) = test_vault();
    let window_key = WindowKey::new("2026-03");
    let learned_at = window_key.start_timestamp().unwrap() + 60;
    // Seed a NON-reserved participant id: [0xA1;16]..[0xA5;16] are the
    // write-door-reserved system-agent preset ids (batch.rs put guard), so
    // put_entity on 0xA1/0xA2 fails InvalidKey in setup. 0xB1 is the sibling's.
    let (event, raw) = put_local_type_76_event(&vault, learned_at, 0xC1)?;
    let tombstone = learned_at.to_be_bytes();

    // Model a hostile peer update that retained only delete authority in the
    // window. Reverse recovery must type-classify the local row before that
    // tombstone can suppress its carrier fleet-wide.
    let doc = create_window_doc("hostile-reverse", &window_key);
    map_insert_bytes(&doc.get_map("tombstones"), &event.to_hex(), &tombstone)?;
    doc.commit();

    assert_eq!(reverse_rematerialize(&vault, &doc, &window_key)?, 1);
    assert_eq!(
        map_get_bytes(&doc.get_map("entities"), &event.to_hex()),
        Some(raw),
        "reverse recovery must restore the protected type-76 carrier"
    );
    assert!(
        tombstone_map_contains_id(&doc.get_map("tombstones"), &event),
        "recovery denies delete authority without rewriting remote history"
    );
    let quarantined = quarantine::quarantined_records(&vault)?;
    assert_eq!(quarantined.len(), 1);
    assert_eq!(quarantined[0].1.container, QuarantineContainer::Tombstones);
    assert_eq!(quarantined[0].1.reason_code, "MaintenanceKindNotWritable");
    assert_eq!(
        quarantined[0].1.payload_hash,
        quarantine::payload_hash(&tombstone)
    );
    Ok(())
}

#[test]
fn pending_mirror_replays_protected_row_against_hostile_tombstone() -> Result<()> {
    let (_dir, vault) = test_vault();
    let window_key = WindowKey::new("2026-03");
    let learned_at = window_key.start_timestamp().unwrap() + 60;
    let (event, raw) = put_local_type_76_event(&vault, learned_at, 0xB1)?;
    let marker = format!("pm:{window_key}:{}", event.to_hex());
    vault.sync_state_put(&marker, &[1])?;
    let tombstone = learned_at.to_be_bytes();

    let doc = create_window_doc("hostile-pending", &window_key);
    map_insert_bytes(&doc.get_map("tombstones"), &event.to_hex(), &tombstone)?;
    doc.commit();

    assert_eq!(replay_pending_mirrors(&vault, &doc, &window_key)?, 1);
    assert_eq!(
        map_get_bytes(&doc.get_map("entities"), &event.to_hex()),
        Some(raw),
        "pending recovery must mirror the protected type-76 carrier"
    );
    assert!(
        vault.sync_state_get(&marker)?.is_none(),
        "the pending marker clears only after the protected carrier is mirrored"
    );
    let quarantined = quarantine::quarantined_records(&vault)?;
    assert_eq!(quarantined.len(), 1);
    assert_eq!(quarantined[0].1.container, QuarantineContainer::Tombstones);
    assert_eq!(quarantined[0].1.reason_code, "MaintenanceKindNotWritable");
    assert_eq!(
        quarantined[0].1.payload_hash,
        quarantine::payload_hash(&tombstone)
    );
    Ok(())
}

#[test]
fn forward_rematerialization_quarantines_concurrent_type_76_tombstone() -> Result<()> {
    use crate::identity_topology::{StoredIdentityOpAction, StoredIdentityOpEvent};

    let (_dir, vault) = test_vault();
    let window_key = WindowKey::new("2026-03");
    let event_id = EntityId::from_bytes([0x70; 16])?;
    let record = StoredIdentityOpEvent {
        seq: 50,
        at: 200,
        actor: None,
        source: ClaimSource::Inferred,
        approval: ClaimApprovalStatus::Auto,
        confidence: 1.0,
        evidence: None,
        action: StoredIdentityOpAction::Merge {
            sources: vec![EntityId::from_bytes([0x61; 16])?],
            survivor: EntityId::from_bytes([0x62; 16])?,
        },
    };
    let body = crate::identity_topology::encode_identity_topology_event_body(&record)?;
    let event_blob = make_entity_blob(
        crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT,
        record.at,
        &body,
    );
    let doc = create_window_doc("remote", &window_key);
    map_insert_bytes(&doc.get_map("entities"), &event_id.to_hex(), &event_blob)?;
    map_insert_bytes(
        &doc.get_map("tombstones"),
        &event_id.to_hex(),
        &record.at.to_be_bytes(),
    )?;
    doc.commit();

    let expected_event = record.clone();
    forward_rematerialize(&vault, &doc, &Materializer::new(), &window_key)?;
    assert_eq!(
        vault.identity_topology_event(&event_id)?,
        Some(expected_event),
        "the protected entity blob must materialize despite its hostile concurrent tombstone"
    );
    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault
            .store
            .sync_state
            .get(&rtxn, &crate::deletion::local_hard_delete_key(&event_id))?
            .is_none(),
        "a protected-record tombstone must not mint a permanent dt: poison marker"
    );
    drop(rtxn);
    let quarantined = crate::sync::quarantine::quarantined_records(&vault)?;
    assert_eq!(quarantined.len(), 1);
    assert_eq!(quarantined[0].1.container, QuarantineContainer::Tombstones);
    assert_eq!(quarantined[0].1.reason_code, "MaintenanceKindNotWritable");

    // A replica that ran the pre-fix headerless tombstone path may already
    // carry a `dt:` marker. Protected event arrival must bypass AND
    // neutralize that stale poison: it never represented valid delete
    // authority for a type-76 row.
    let (_poison_dir, poisoned_vault) = test_vault();
    let poisoned_id = EntityId::from_bytes([0x71; 16])?;
    poisoned_vault.with_write_txn(|wtxn| {
        poisoned_vault.store.sync_state.put(
            wtxn,
            &crate::deletion::local_hard_delete_key(&poisoned_id),
            &[0_u8; crate::deletion::TOMBSTONE_VALUE_V2_LEN],
        )?;
        Ok(())
    })?;
    let poisoned_doc = create_window_doc("remote-poisoned", &window_key);
    map_insert_bytes(
        &poisoned_doc.get_map("entities"),
        &poisoned_id.to_hex(),
        &event_blob,
    )?;
    poisoned_doc.commit();
    let expected_poisoned_event = record;
    forward_rematerialize(
        &poisoned_vault,
        &poisoned_doc,
        &Materializer::new(),
        &window_key,
    )?;
    assert_eq!(
        poisoned_vault.identity_topology_event(&poisoned_id)?,
        Some(expected_poisoned_event),
        "a preexisting dt: marker must not suppress a later protected event"
    );
    let rtxn = poisoned_vault.store.env.read_txn()?;
    assert!(
        poisoned_vault
            .store
            .sync_state
            .get(&rtxn, &crate::deletion::local_hard_delete_key(&poisoned_id))?
            .is_none(),
        "protected event admission must neutralize a preexisting dt: poison marker"
    );
    Ok(())
}

#[test]
fn forward_rematerialization_malformed_type_76_envelope_preserves_delete_wins() -> Result<()> {
    let (_dir, vault) = test_vault();
    let window_key = WindowKey::new("2026-03");
    let entity_id = EntityId::from_bytes([0x72; 16])?;
    let tombstone = crate::deletion::TombstoneValueV2 {
        reason: crate::deletion::TombstoneReason::UserHardDelete,
        deleted_at: 200,
        request_id: [0x42; 16],
    }
    .encode();
    let doc = create_window_doc("remote-malformed-protected", &window_key);
    map_insert_bytes(
        &doc.get_map("entities"),
        &entity_id.to_hex(),
        &make_entity_blob(
            crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT,
            200,
            b"malformed type-76 body",
        ),
    )?;
    map_insert_bytes(&doc.get_map("tombstones"), &entity_id.to_hex(), &tombstone)?;
    doc.commit();

    forward_rematerialize(&vault, &doc, &Materializer::new(), &window_key)?;
    assert!(vault.get(&entity_id)?.is_none());
    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault.local_hard_delete_marker_exists_in_txn(&rtxn, &entity_id)?,
        "a malformed protected envelope must run the normal tombstone path"
    );
    drop(rtxn);

    doc.get_map("tombstones")
        .delete(&entity_id.to_hex())
        .unwrap();
    map_insert_bytes(
        &doc.get_map("entities"),
        &entity_id.to_hex(),
        &make_entity_blob(
            crate::registry::ENTITY_TYPE_TASK,
            201,
            &crate::habit::task_body_for_test(crate::habit::TaskRole::Task),
        ),
    )?;
    doc.commit();

    forward_rematerialize(&vault, &doc, &Materializer::new(), &window_key)?;
    assert!(
        vault.get(&entity_id)?.is_none(),
        "the permanent dt: marker must block later ordinary resurrection"
    );
    Ok(())
}

#[cfg(feature = "sync")]
fn authority_genesis_fixture_for_window(seed: u8) -> crate::authority::AuthorityLogEntry {
    use ed25519_dalek::{Signer, SigningKey};

    let signing = SigningKey::from_bytes(&[seed; 32]);
    let key = crate::authority::AuthorityKey::Ed25519(signing.verifying_key().to_bytes());
    let mut entry = crate::authority::AuthorityLogEntry {
        schema_version: crate::authority::AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: None,
        seq: 0,
        parent_hashes: Vec::new(),
        op: crate::authority::AuthorityOp::Genesis {
            device: crate::authority::DeviceAuthority {
                key: key.clone(),
                transport_key_binding: [0; 32],
                attestation: crate::authority::AuthorityAttestation {
                    kind: "SoftwareArgon2id".to_owned(),
                    evidence: vec![1, 2, 3],
                },
                tier: crate::authority::AuthorityTier::Software,
                roles: crate::authority::ROLE_OWNER,
            },
            genesis_nonce: [seed.wrapping_add(1); 32],
            tier_floor: crate::authority::AuthorityTier::Software,
            pending_widen_delay_secs: crate::authority::DEFAULT_PENDING_WIDEN_DELAY_SECS,
        },
        signer: crate::authority::AuthoritySignature {
            suite: key.suite(),
            public_key: key,
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts: u64::from(seed),
    };
    let transcript = crate::authority::authority_transcript(&entry).expect("transcript");
    entry.signer.signature = signing.sign(&transcript).to_bytes().to_vec();
    entry
}

/// A cosigned RevokeDevice naming `revoked_seed`'s key, parented on `genesis`.
/// `put_authority_log_entry` validates canonical bytes + origin signature +
/// the store-key bind, so this needs no full roster ancestry to materialize —
/// which is all the reverse-remat door reads.
#[cfg(feature = "sync")]
fn authority_revoke_fixture_for_window(
    genesis: &crate::authority::AuthorityLogEntry,
    signer_seed: u8,
    cosigner_seed: u8,
    revoked_seed: u8,
) -> crate::authority::AuthorityLogEntry {
    use ed25519_dalek::{Signer, SigningKey};

    let ed_key = |seed: u8| SigningKey::from_bytes(&[seed; 32]);
    let authority_key = |signing: &SigningKey| {
        crate::authority::AuthorityKey::Ed25519(signing.verifying_key().to_bytes())
    };
    let signature_for =
        |key: &crate::authority::AuthorityKey| crate::authority::AuthoritySignature {
            suite: key.suite(),
            public_key: key.clone(),
            signature: vec![0; 64],
        };

    let (signer, cosigner) = (ed_key(signer_seed), ed_key(cosigner_seed));
    let (signer_key, cosigner_key) = (authority_key(&signer), authority_key(&cosigner));
    let mut entry = crate::authority::AuthorityLogEntry {
        schema_version: crate::authority::AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: Some(crate::authority::genesis_vault_id(genesis).expect("vault id")),
        seq: 1,
        parent_hashes: vec![crate::authority::authority_entry_hash(genesis).expect("genesis hash")],
        op: crate::authority::AuthorityOp::RevokeDevice {
            revoked_key: authority_key(&ed_key(revoked_seed)),
        },
        signer: signature_for(&signer_key),
        cosigns: vec![signature_for(&cosigner_key)],
        ts: 900,
    };
    let transcript = crate::authority::authority_transcript(&entry).expect("transcript");
    entry.signer.signature = signer.sign(&transcript).to_bytes().to_vec();
    for cosign in &mut entry.cosigns {
        cosign.signature = cosigner.sign(&transcript).to_bytes().to_vec();
    }
    entry
}

/// Wraps `data` in the pinned 25-byte envelope with an explicitly chosen
/// occurred range, so a test can mint the INVERTED range a hostile peer parks
/// on a CRDT carrier (`put_replicated` rejects `start > end` with
/// `InvalidTimeRange` before the authority validator ever runs).
#[cfg(feature = "sync")]
fn make_entity_blob_with_range(
    entity_type: u8,
    occurred_start: u64,
    occurred_end: u64,
    learned_at: u64,
    data: &[u8],
) -> Vec<u8> {
    let mut blob = Vec::with_capacity(25 + data.len());
    blob.push(entity_type);
    blob.extend_from_slice(&occurred_start.to_be_bytes());
    blob.extend_from_slice(&occurred_end.to_be_bytes());
    blob.extend_from_slice(&learned_at.to_be_bytes());
    blob.extend_from_slice(data);
    blob
}

/// Rewrites a MessagePack authority payload into its LEGACY-GENESIS shape by
/// dropping the `pending_widen_delay_secs` field wherever it appears (only the
/// genesis op map carries it). That is exactly the delta between the current
/// and legacy encodings/transcripts, so signing over the stripped transcript
/// mints a genuinely legacy-signed entry without reaching into the private
/// authority encoders.
#[cfg(feature = "sync")]
fn strip_genesis_delay_field(value: &Value) -> Value {
    match value {
        Value::Map(fields) => Value::Map(
            fields
                .iter()
                .filter(|(key, _)| key.as_str() != Some("pending_widen_delay_secs"))
                .map(|(key, val)| (key.clone(), strip_genesis_delay_field(val)))
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(strip_genesis_delay_field).collect()),
        other => other.clone(),
    }
}

/// ONE-1604-D1/D5 T9 (fix-leg 1, P2-b): the window-path twin of the bridge
/// tombstone regression, covering the neutralize-parity call this lane adds
/// to the window's AUTHORITY_LOG arm — pinned at the state the pre-fix code
/// could NOT repair.
///
/// The replica is in the exact pre-fix shape: the authority row is already
/// materialized BYTE-FOR-BYTE (local blob == CRDT blob, so the fast path
/// fires) while a tombstone-first replay left a `dt:` marker behind. When the
/// byte comparison ran in the shared pre-door pass, this replica returned
/// early and kept the false delete marker forever — and the ARCH-0038
/// hard-erase sweep would later treat the id as erased and scrub append-only
/// authority evidence. Routing the comparison through this door's own write
/// txn (type-76 parity) lets the exact match still neutralize the marker.
#[cfg(feature = "sync")]
#[test]
fn window_authority_row_admission_neutralizes_stale_dt_marker() -> Result<()> {
    let (_dir, vault) = test_vault();
    let window_key = WindowKey::new("2026-03");
    let genesis = authority_genesis_fixture_for_window(0x67);
    let id = crate::authority::authority_log_entity_id(&genesis)?;
    let body = crate::authority::encode_authority_log_entry_body(&genesis)?;

    // `make_entity_blob` stamps occurred_start == occurred_end == learned_at,
    // so putting with the same value makes the local row and the CRDT
    // carrier byte-identical — the fast path this fix must not exit through.
    let blob = make_entity_blob(ENTITY_TYPE_AUTHORITY_LOG, 2, &body);
    vault.put_authority_log_entry(&genesis, TimeRange { start: 2, end: 2 }, 2)?;
    assert_eq!(
        vault.get_raw(&id)?.as_deref(),
        Some(blob.as_slice()),
        "the local row must be byte-identical to the arriving carrier"
    );

    // A tombstone-first replay on this replica left `dt:` poison behind.
    vault.with_write_txn(|wtxn| {
        vault.store.sync_state.put(
            wtxn,
            &crate::deletion::local_hard_delete_key(&id),
            &[0_u8; crate::deletion::TOMBSTONE_VALUE_V2_LEN],
        )?;
        Ok(())
    })?;

    let doc = create_window_doc("remote-poisoned-authority", &window_key);
    map_insert_bytes(&doc.get_map("entities"), &id.to_hex(), &blob)?;
    map_insert_bytes(
        &doc.get_map("tombstones"),
        &id.to_hex(),
        &2_u64.to_be_bytes(),
    )?;
    doc.commit();
    forward_rematerialize(&vault, &doc, &Materializer::new(), &window_key)?;

    assert_eq!(
        vault.get_authority_log_entry(&id)?,
        Some(genesis),
        "the authority row must survive a stale dt: marker"
    );
    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault
            .store
            .sync_state
            .get(&rtxn, &crate::deletion::local_hard_delete_key(&id))?
            .is_none(),
        "a byte-identical authority carrier must still neutralize the stale dt: poison marker"
    );
    drop(rtxn);
    let quarantined = quarantine::quarantined_records(&vault)?;
    assert_eq!(quarantined.len(), 1);
    assert_eq!(quarantined[0].1.container, QuarantineContainer::Tombstones);
    assert_eq!(quarantined[0].1.reason_code, "MaintenanceKindNotWritable");
    Ok(())
}

/// ONE-1604-D1 (fix-leg 1, P2-a — outbound half): the presence-only carrier
/// check let a cross-type squatter keep the CRDT slot at an authority row's
/// content-derived key even after the local write door evicted it. That
/// re-exports the row the authority substrate refused and re-imports it onto
/// peers that have not seen the entry yet. A local type-122 row now
/// overwrites a NON-authority carrier at its own key; ordinary rows keep
/// presence-only semantics.
#[cfg(feature = "sync")]
#[test]
fn reverse_rematerialization_replaces_cross_type_authority_key_squatter() -> Result<()> {
    let (_dir, vault) = test_vault();
    let window_key = WindowKey::new("2026-03");
    let learned_at = window_key.start_timestamp().unwrap() + 60;
    let genesis = authority_genesis_fixture_for_window(0x68);
    let id = crate::authority::authority_log_entity_id(&genesis)?;
    vault.put_authority_log_entry(
        &genesis,
        TimeRange {
            start: learned_at,
            end: learned_at,
        },
        learned_at,
    )?;
    let local = vault.get_raw(&id)?.expect("authority row stored");

    // The window still carries the attacker's ordinary row at that key.
    let doc = create_window_doc("squatted-window", &window_key);
    let squatter = make_entity_blob(crate::registry::ENTITY_TYPE_EVENT, learned_at, b"squatter");
    map_insert_bytes(&doc.get_map("entities"), &id.to_hex(), &squatter)?;
    doc.commit();

    reverse_rematerialize(&vault, &doc, &window_key)?;

    assert_eq!(
        map_get_bytes(&doc.get_map("entities"), &id.to_hex()),
        Some(local),
        "the validated authority row must replace the cross-type carrier at its derived key"
    );
    Ok(())
}

/// ONE-1604-D1 (fix-leg 4, outbound half): replacing the dominated carrier's
/// ENTITY row left its INCIDENT EDGES behind. Edge entries are keyed
/// independently of the entity (`src:kind:tgt`), so the squatter's graph
/// residue survived the overwrite and kept traversing on every peer that
/// imported the window — the exact residue the LMDB door already sweeps with
/// `delete_related_edges`. Both directions are asserted: the squatter as edge
/// SOURCE and as edge TARGET.
#[cfg(feature = "sync")]
#[test]
fn reverse_rematerialization_evicts_dominated_squatter_incident_edges() -> Result<()> {
    let (_dir, vault) = test_vault();
    let window_key = WindowKey::new("2026-03");
    let learned_at = window_key.start_timestamp().unwrap() + 60;
    let genesis = authority_genesis_fixture_for_window(0x6A);
    let id = crate::authority::authority_log_entity_id(&genesis)?;
    let neighbor = EntityId::from_bytes([0xC2; 16])?;
    vault.put_authority_log_entry(
        &genesis,
        TimeRange {
            start: learned_at,
            end: learned_at,
        },
        learned_at,
    )?;
    let local = vault.get_raw(&id)?.expect("authority row stored");

    let doc = create_window_doc("squatted-window", &window_key);
    let squatter = make_entity_blob(crate::registry::ENTITY_TYPE_EVENT, learned_at, b"squatter");
    map_insert_bytes(&doc.get_map("entities"), &id.to_hex(), &squatter)?;
    let out_key = format_edge_key(&id, EdgeKind::Mentions, &neighbor);
    let in_key = format_edge_key(&neighbor, EdgeKind::Mentions, &id);
    let edge_value = encode_edge_value_for_crdt(EdgeKind::Mentions, 0.7, 1, None, None)?;
    for key in [&out_key, &in_key] {
        map_insert_bytes(&doc.get_map("edges"), key, &edge_value)?;
    }
    doc.commit();

    reverse_rematerialize(&vault, &doc, &window_key)?;

    assert_eq!(
        map_get_bytes(&doc.get_map("entities"), &id.to_hex()),
        Some(local),
        "the validated authority row must still replace the carrier"
    );
    let edges = doc.get_map("edges");
    assert!(
        map_get_bytes(&edges, &out_key).is_none(),
        "the squatter's outbound edge carrier must go with the dominated entity"
    );
    assert!(
        map_get_bytes(&edges, &in_key).is_none(),
        "the squatter's inbound edge carrier must go with the dominated entity"
    );
    Ok(())
}

/// ONE-1604-D1 (fix-leg 5, P2 — phase ordering): the dominance sweep deletes
/// EVERY CRDT edge incident to the evicted id, and cannot tell the dominated
/// carrier's residue apart from a LOCALLY BACKED inbound edge. While the
/// sweep and the `edges_out` backfill were interleaved in one `learned_at`
/// walk, a legitimate local source ordered BEFORE the attacker-parked
/// authority id had its valid `S→A` edge swept after its own backfill, and
/// only `edges_out(A)` replayed afterwards — so the locally backed edge
/// stayed deleted and the committed update propagated that
/// attacker-triggered deletion to every peer.
///
/// The fixture pins exactly that order: `source` learns 60 s before the
/// authority row, holds a real LMDB `source→authority` edge, and its CRDT
/// carrier already exists (the shape a peer would lose). Unbacked squatter
/// residue in both directions must still be swept.
#[cfg(feature = "sync")]
#[test]
fn reverse_rematerialization_keeps_locally_backed_edges_into_a_dominated_key() -> Result<()> {
    let (_dir, vault) = test_vault();
    let window_key = WindowKey::new("2026-03");
    let source_learned_at = window_key.start_timestamp().unwrap() + 60;
    let authority_learned_at = source_learned_at + 60;
    let genesis = authority_genesis_fixture_for_window(0x6C);
    let id = crate::authority::authority_log_entity_id(&genesis)?;
    let source = EntityId::from_bytes([0xC4; 16])?;
    let residue_peer = EntityId::from_bytes([0xC5; 16])?;

    // The legitimate local source is learned FIRST, so `entities_in_range`
    // hands it to the walk before the authority id.
    vault.put_entity(
        &source,
        crate::registry::ENTITY_TYPE_EVENT,
        TimeRange {
            start: source_learned_at,
            end: source_learned_at,
        },
        source_learned_at,
        b"legitimate local source",
    )?;
    vault.put_authority_log_entry(
        &genesis,
        TimeRange {
            start: authority_learned_at,
            end: authority_learned_at,
        },
        authority_learned_at,
    )?;
    let local = vault.get_raw(&id)?.expect("authority row stored");
    vault.put_edge(&source, EdgeKind::Mentions, &id, 0.5)?;
    let backed = vault
        .edges_out(&source)?
        .into_iter()
        .find(|edge| edge.target == id)
        .expect("local source→authority edge stored");
    let backed_value = encode_edge_value_for_crdt(
        backed.kind,
        backed.weight,
        backed.created_at,
        backed.vad,
        backed.provenance,
    )?;

    let doc = create_window_doc("squatted-window", &window_key);
    let squatter = make_entity_blob(
        crate::registry::ENTITY_TYPE_EVENT,
        authority_learned_at,
        b"squatter",
    );
    map_insert_bytes(&doc.get_map("entities"), &id.to_hex(), &squatter)?;
    let backed_key = format_edge_key(&source, EdgeKind::Mentions, &id);
    let residue_in = format_edge_key(&residue_peer, EdgeKind::Mentions, &id);
    let residue_out = format_edge_key(&id, EdgeKind::Mentions, &residue_peer);
    let residue_value = encode_edge_value_for_crdt(EdgeKind::Mentions, 0.7, 1, None, None)?;
    map_insert_bytes(&doc.get_map("edges"), &backed_key, &backed_value)?;
    for key in [&residue_in, &residue_out] {
        map_insert_bytes(&doc.get_map("edges"), key, &residue_value)?;
    }
    doc.commit();

    reverse_rematerialize(&vault, &doc, &window_key)?;

    let edges = doc.get_map("edges");
    assert_eq!(
        map_get_bytes(&doc.get_map("entities"), &id.to_hex()),
        Some(local),
        "the validated authority row must still replace the dominated carrier"
    );
    assert_eq!(
        map_get_bytes(&edges, &backed_key),
        Some(backed_value),
        "an LMDB-backed inbound edge must survive the dominance sweep — a \
         squatter must never trigger deletion of replicated local graph state"
    );
    assert!(
        map_get_bytes(&edges, &residue_in).is_none(),
        "unbacked inbound squatter residue must still be swept"
    );
    assert!(
        map_get_bytes(&edges, &residue_out).is_none(),
        "unbacked outbound squatter residue must still be swept"
    );
    Ok(())
}

/// ONE-1604-D1 (fix-leg 4, negative half): the edge sweep is scoped to the
/// DOMINANCE verdict, never to mere presence at an authority key. A carrier
/// every peer's replay door would admit keeps presence-only semantics, and
/// its edges must survive untouched — otherwise the sweep would silently
/// erase replicated graph state on ordinary convergence.
#[cfg(feature = "sync")]
#[test]
fn reverse_rematerialization_preserves_edges_of_an_admissible_authority_carrier() -> Result<()> {
    let (_dir, vault) = test_vault();
    let window_key = WindowKey::new("2026-03");
    let learned_at = window_key.start_timestamp().unwrap() + 60;
    let genesis = authority_genesis_fixture_for_window(0x6B);
    let id = crate::authority::authority_log_entity_id(&genesis)?;
    let neighbor = EntityId::from_bytes([0xC3; 16])?;
    vault.put_authority_log_entry(
        &genesis,
        TimeRange {
            start: learned_at,
            end: learned_at,
        },
        learned_at,
    )?;
    let local = vault.get_raw(&id)?.expect("authority row stored");

    // Byte-different but fully admissible: same signed body, a different
    // (valid, non-inverted) occurred range.
    let admissible = make_entity_blob_with_range(
        ENTITY_TYPE_AUTHORITY_LOG,
        learned_at - 30,
        learned_at,
        learned_at,
        &local[crate::batch::ENTITY_METADATA_HEADER_LEN..],
    );
    let doc = create_window_doc("admissible-window", &window_key);
    map_insert_bytes(&doc.get_map("entities"), &id.to_hex(), &admissible)?;
    let in_key = format_edge_key(&neighbor, EdgeKind::Mentions, &id);
    let edge_value = encode_edge_value_for_crdt(EdgeKind::Mentions, 0.7, 1, None, None)?;
    map_insert_bytes(&doc.get_map("edges"), &in_key, &edge_value)?;
    doc.commit();

    reverse_rematerialize(&vault, &doc, &window_key)?;

    assert_eq!(
        map_get_bytes(&doc.get_map("entities"), &id.to_hex()),
        Some(admissible),
        "an admissible carrier must still be preserved"
    );
    assert_eq!(
        map_get_bytes(&doc.get_map("edges"), &in_key),
        Some(edge_value),
        "edges at a non-dominated authority key must survive untouched"
    );
    Ok(())
}

/// ONE-1604-D1 (fix-leg 3, P2 — the external probe's exact assertion pair):
/// the dominance check was TYPE-BYTE-blind. It preserved any carrier whose
/// envelope header read type-122, resting on "two authority rows at one key
/// are byte-identical by construction" — an invariant that holds only for
/// rows through the VALIDATED write path. A raw CRDT carrier bypasses
/// `apply_put`, so a hostile peer can park a POISONED type-122 row at a
/// revocation's derived key: here, the revocation's own valid body wrapped in
/// an INVERTED occurred range. Every receiving peer's replay door rejects
/// that envelope with `InvalidTimeRange` before the authority validator runs,
/// so preserving it exported the rejection and left downstream peers MISSING
/// the revocation entirely (probe: local_replaced_fake=false,
/// fake_survived=true).
#[cfg(feature = "sync")]
#[test]
fn reverse_rematerialization_replaces_poisoned_authority_carrier_with_inverted_range() -> Result<()>
{
    let (_dir, vault) = test_vault();
    let window_key = WindowKey::new("2026-03");
    let learned_at = window_key.start_timestamp().unwrap() + 60;
    let genesis = authority_genesis_fixture_for_window(0x71);
    let revoke = authority_revoke_fixture_for_window(&genesis, 0x71, 0x72, 0x73);
    let id = crate::authority::authority_log_entity_id(&revoke)?;
    vault.put_authority_log_entry(
        &revoke,
        TimeRange {
            start: learned_at,
            end: learned_at,
        },
        learned_at,
    )?;
    let local = vault.get_raw(&id)?.expect("authority row stored");

    // Same valid signed body, poisoned envelope: occurred_start > occurred_end.
    let poisoned = make_entity_blob_with_range(
        ENTITY_TYPE_AUTHORITY_LOG,
        learned_at + 1,
        learned_at,
        learned_at,
        &local[crate::batch::ENTITY_METADATA_HEADER_LEN..],
    );
    assert_ne!(
        poisoned, local,
        "the poisoned carrier must genuinely differ"
    );
    assert_eq!(
        poisoned[0], ENTITY_TYPE_AUTHORITY_LOG,
        "the carrier must read as type-122 — that is what made it type-byte-invisible"
    );
    let doc = create_window_doc("poisoned-authority-window", &window_key);
    map_insert_bytes(&doc.get_map("entities"), &id.to_hex(), &poisoned)?;
    doc.commit();

    reverse_rematerialize(&vault, &doc, &window_key)?;

    let carrier = map_get_bytes(&doc.get_map("entities"), &id.to_hex());
    assert_eq!(
        carrier.as_deref(),
        Some(local.as_slice()),
        "local_replaced_fake: the fully validated local row must replace the poisoned carrier"
    );
    assert_ne!(
        carrier.as_deref(),
        Some(poisoned.as_slice()),
        "fake_survived: the inadmissible carrier must NOT reach peers"
    );
    Ok(())
}

/// ONE-1604-D1 (fix-leg 3, P2 — regression 2): the other half of the poisoned
/// type-122 surface. A carrier with a well-formed envelope but a DIVERGENT or
/// MALFORMED body is equally unreplayable — it fails
/// `decode_authority_log_entry_body` (canonical encoding + origin signature),
/// or clears decode but hashes to a different content-derived key, so it
/// could never be admitted under this id. Both shapes are dominated.
#[cfg(feature = "sync")]
#[test]
fn reverse_rematerialization_replaces_divergent_and_malformed_authority_bodies() -> Result<()> {
    let window_key = WindowKey::new("2026-03");
    let learned_at = window_key.start_timestamp().unwrap() + 60;
    let genesis = authority_genesis_fixture_for_window(0x74);
    let revoke = authority_revoke_fixture_for_window(&genesis, 0x74, 0x75, 0x76);
    let id = crate::authority::authority_log_entity_id(&revoke)?;

    // A DIFFERENT valid, fully signed authority entry — it decodes cleanly,
    // but its content-derived key is not this one, so the key bind rejects it.
    let foreign = authority_genesis_fixture_for_window(0x77);
    let foreign_body = crate::authority::encode_authority_log_entry_body(&foreign)?;
    assert_ne!(
        crate::authority::authority_log_entity_id(&foreign)?,
        id,
        "the divergent body must derive a different store key"
    );

    for (label, body) in [
        ("divergent", foreign_body),
        ("malformed", b"not messagepack at all".to_vec()),
    ] {
        let (_dir, vault) = test_vault();
        vault.put_authority_log_entry(
            &revoke,
            TimeRange {
                start: learned_at,
                end: learned_at,
            },
            learned_at,
        )?;
        let local = vault.get_raw(&id)?.expect("authority row stored");

        let poisoned = make_entity_blob_with_range(
            ENTITY_TYPE_AUTHORITY_LOG,
            learned_at,
            learned_at,
            learned_at,
            &body,
        );
        let doc = create_window_doc("divergent-authority-window", &window_key);
        map_insert_bytes(&doc.get_map("entities"), &id.to_hex(), &poisoned)?;
        doc.commit();

        reverse_rematerialize(&vault, &doc, &window_key)?;

        assert_eq!(
            map_get_bytes(&doc.get_map("entities"), &id.to_hex()),
            Some(local),
            "a {label} type-122 body at the derived key must be dominated"
        );
    }
    Ok(())
}

/// ONE-1604-D1 (fix-leg 3, P2 — regression 3): dominance is ADMISSIBILITY-
/// based, never byte-difference-based, so presence-only survives untouched
/// for a carrier every peer's replay door would admit. Here the carrier
/// shares the local row's signed body but declares a DIFFERENT (still valid,
/// non-inverted) occurred range: byte-different, fully admissible, preserved.
#[cfg(feature = "sync")]
#[test]
fn reverse_rematerialization_preserves_admissible_authority_carrier() -> Result<()> {
    let (_dir, vault) = test_vault();
    let window_key = WindowKey::new("2026-03");
    let learned_at = window_key.start_timestamp().unwrap() + 60;
    let genesis = authority_genesis_fixture_for_window(0x79);
    let id = crate::authority::authority_log_entity_id(&genesis)?;
    vault.put_authority_log_entry(
        &genesis,
        TimeRange {
            start: learned_at,
            end: learned_at,
        },
        learned_at,
    )?;
    let local = vault.get_raw(&id)?.expect("authority row stored");

    let admissible = make_entity_blob_with_range(
        ENTITY_TYPE_AUTHORITY_LOG,
        learned_at - 30,
        learned_at,
        learned_at,
        &local[crate::batch::ENTITY_METADATA_HEADER_LEN..],
    );
    assert_ne!(
        admissible, local,
        "the carrier must be byte-different for this to test the admissibility rule"
    );
    let doc = create_window_doc("admissible-authority-window", &window_key);
    map_insert_bytes(&doc.get_map("entities"), &id.to_hex(), &admissible)?;
    doc.commit();

    reverse_rematerialize(&vault, &doc, &window_key)?;

    assert_eq!(
        map_get_bytes(&doc.get_map("entities"), &id.to_hex()),
        Some(admissible),
        "an admissible carrier must be PRESERVED — byte difference alone never dominates"
    );
    Ok(())
}

/// ONE-1645 REPLAY door for the `FacetOf` type table.
///
/// The local batch door (`batch::validate_facet_of_edge` on `BatchOp::Edge` /
/// `PublicEdgeWithCreatedAt`) aborts an off-table facet stamp atomically, but
/// the replicated arm `BatchOp::EdgeWithCreatedAt` is deliberately UNGATED —
/// a hard abort on a replay shape would wedge sync permanently (H2). Forward
/// rematerialization therefore runs the table itself at the write chokepoint
/// and QUARANTINES the off-table row.
///
/// Why it matters: a member/guest peer replaying a `PERSON -> FACET` stamp — a
/// shape no local public writer can produce — would otherwise land it in LMDB,
/// the retrieval truth every local disclosure surface reads. The federation
/// selector mirrors this same table on its read side
/// (`selector::facet_scope_by_source`) and so ignores such a source, but
/// keeping the unwritable shape out of storage is this door's job. That is an
/// authorization bypass through replay, not a mere schema violation.
///
/// Both arms of the table are pinned in ONE window: the off-table PERSON
/// stamp quarantines with the typed reason while the on-table EVENT stamp
/// (admitted since the ONE-1645 widening) writes normally, and an unrelated
/// ordinary edge in the same pass still heals — one forged row must never
/// starve the other N-1.
#[test]
fn forward_remat_quarantines_off_table_facet_of_and_admits_the_on_table_row() -> Result<()> {
    let (_dir, vault) = test_vault();
    let window_key = WindowKey::new("2026-03");
    let person = EntityId::from_bytes([0xD1; 16])?;
    let event = EntityId::from_bytes([0xD2; 16])?;
    let facet = EntityId::from_bytes([0xD3; 16])?;
    let ordinary_src = EntityId::from_bytes([0xD4; 16])?;
    for (id, entity_type) in [
        (&person, crate::registry::ENTITY_TYPE_PERSON),
        (&event, crate::registry::ENTITY_TYPE_EVENT),
        (&facet, crate::registry::ENTITY_TYPE_FACET),
        (&ordinary_src, crate::registry::ENTITY_TYPE_PERSON),
    ] {
        vault.put_entity(
            id,
            entity_type,
            TimeRange { start: 1, end: 1 },
            1,
            b"fixture",
        )?;
    }

    let doc = create_window_doc("remote", &window_key);
    let edges = doc.get_map("edges");
    // The injected off-table stamp: PERSON -> FACET. `vault.put_edge` cannot
    // write this shape at all, which is exactly why replay must not.
    let forged_key = format_edge_key(&person, EdgeKind::FacetOf, &facet);
    let forged_value = encode_edge_value_for_crdt(EdgeKind::FacetOf, 0.7, 10, None, None)?;
    map_insert_bytes(&edges, &forged_key, &forged_value)?;
    // On-table control: EVENT -> FACET is admitted by the widened table.
    let admitted_key = format_edge_key(&event, EdgeKind::FacetOf, &facet);
    map_insert_bytes(
        &edges,
        &admitted_key,
        &encode_edge_value_for_crdt(EdgeKind::FacetOf, 0.7, 11, None, None)?,
    )?;
    // Unrelated control: a plain edge that shares the window but not the kind.
    let ordinary_key = format_edge_key(&ordinary_src, EdgeKind::Mentions, &facet);
    map_insert_bytes(
        &edges,
        &ordinary_key,
        &encode_edge_value_for_crdt(EdgeKind::Mentions, 0.4, 12, None, None)?,
    )?;
    doc.commit();

    let count = forward_rematerialize(&vault, &doc, &Materializer::new(), &window_key)?;
    assert_eq!(
        count, 2,
        "the off-table stamp is skipped while the other N-1 edges still heal"
    );
    assert!(
        !vault.edge_exists(&person, EdgeKind::FacetOf, &facet)?,
        "a PERSON-sourced facet stamp must never land through replay: the \
         federation selector would treat it as a facet seed"
    );
    assert!(
        vault.edge_exists(&event, EdgeKind::FacetOf, &facet)?,
        "the on-table EVENT stamp must replicate normally"
    );
    assert!(
        vault.edge_exists(&ordinary_src, EdgeKind::Mentions, &facet)?,
        "one off-table row must not abort the rest of the rematerialization pass"
    );

    let quarantined = crate::sync::quarantine::quarantined_records(&vault)?;
    assert_eq!(
        quarantined.len(),
        1,
        "exactly the forged row is quarantined"
    );
    let record = &quarantined[0].1;
    assert_eq!(record.container, QuarantineContainer::Edges);
    assert_eq!(
        record.reason_code, "InvalidFacetOfEdge",
        "the peer's row must carry the typed table reason, not a generic one"
    );
    assert_eq!(
        (record.crdt_key_hash, record.crdt_key_len),
        crate::sync::quarantine::crdt_key_metadata(&forged_key)
    );
    assert_eq!(
        record.payload_hash,
        crate::sync::quarantine::payload_hash(&forged_value)
    );
    Ok(())
}

/// ONE-1604-D1 (fix-leg 3, P2 — regression 3, legacy-genesis leg): the
/// decode layer's dual-encoding posture must reach the dominance verdict
/// UNCHANGED. `decode_authority_log_entry_body` admits both the exact
/// canonical AND the exact legacy-genesis encoding (whose signed bytes omit
/// `pending_widen_delay_secs`), and `authority_entry_hash` keys off whichever
/// of the two actually verifies. So:
///
/// * a legacy-encoded carrier AT ITS OWN derived key is ADMISSIBLE and is
///   preserved as-is — the codebase never normalizes legacy bytes, it keys
///   off them (`authority/tests.rs::legacy_signed_genesis_derives_a_stable_
///   store_key_from_its_legacy_bytes`), so there is no re-encode posture to
///   follow here;
/// * the current re-encoding of that same legacy-signed entry carries no
///   verifying signature, so it fails the BODY check and is dominated — for
///   INADMISSIBILITY, not for differing from the local bytes.
///
/// Asserted at the admissibility helper rather than through a full
/// reverse-remat pass because no live door can put a legacy-signed row into a
/// vault: `put_authority_log_entry` re-encodes canonically, and the
/// replicated door needs a local authority root that a genesis row is itself
/// the only source of. The helper is the whole dominance predicate, so its
/// verdict IS the preserve/dominate decision.
#[cfg(feature = "sync")]
#[test]
fn legacy_genesis_carrier_is_admissible_and_its_current_reencoding_is_not() -> Result<()> {
    use ed25519_dalek::{Signer, SigningKey};

    const DOMAIN_LEN: usize = 20; // b"oneiron/authority/v1"
    let mut legacy = authority_genesis_fixture_for_window(0x7A);
    let signing = SigningKey::from_bytes(&[0x7A; 32]);

    // Re-sign over the delay-free transcript, then encode the delay-free
    // body: exactly the legacy-genesis pair the decode layer still accepts.
    let canonical_transcript = crate::authority::authority_transcript(&legacy)?;
    let mut cursor = std::io::Cursor::new(&canonical_transcript[DOMAIN_LEN..]);
    let legacy_transcript_value =
        strip_genesis_delay_field(&rmpv::decode::read_value(&mut cursor).expect("transcript"));
    let mut legacy_transcript = canonical_transcript[..DOMAIN_LEN].to_vec();
    rmpv::encode::write_value(&mut legacy_transcript, &legacy_transcript_value)
        .expect("legacy transcript");
    legacy.signer.signature = signing.sign(&legacy_transcript).to_bytes().to_vec();

    let current_body = crate::authority::encode_authority_log_entry_body(&legacy)?;
    let mut cursor = std::io::Cursor::new(current_body.as_slice());
    let legacy_value =
        strip_genesis_delay_field(&rmpv::decode::read_value(&mut cursor).expect("body"));
    let mut legacy_body = Vec::new();
    rmpv::encode::write_value(&mut legacy_body, &legacy_value).expect("legacy body");
    assert_ne!(
        legacy_body, current_body,
        "the two encodings must genuinely differ for this to test the dual-encoding path"
    );

    let id = crate::authority::authority_log_entity_id(&legacy)?;
    let envelope =
        |body: &[u8]| make_entity_blob_with_range(ENTITY_TYPE_AUTHORITY_LOG, 5, 9, 9, body);

    assert!(
        crdt_carrier_is_admissible_authority_row(&id, &envelope(&legacy_body)),
        "a legacy-encoded carrier at its own derived key must be ADMISSIBLE (preserved, not normalized)"
    );
    assert!(
        !crdt_carrier_is_admissible_authority_row(&id, &envelope(&current_body)),
        "the current re-encoding carries no verifying signature — dominated for inadmissibility"
    );
    // Same legacy bytes, inverted envelope: the envelope leg is independent
    // of the body leg, so a legacy body cannot launder a poisoned range.
    assert!(
        !crdt_carrier_is_admissible_authority_row(
            &id,
            &make_entity_blob_with_range(ENTITY_TYPE_AUTHORITY_LOG, 9, 5, 9, &legacy_body)
        ),
        "an inverted occurred range must dominate even a legacy-valid body"
    );
    Ok(())
}

/// The replay door must never turn an ORDERING accident into a permanent
/// rejection. The type table reads endpoint types from entity rows, so it is
/// deliberately placed AFTER the endpoint-existence check: a facet stamp whose
/// endpoints have not arrived yet DEFERS (stays in the CRDT, no `x:` row) and
/// materializes on the next pass once the endpoints land.
///
/// Without this ordering an out-of-order but perfectly legitimate TURN
/// stamp would be read as `src_type = None` — the fail-closed
/// "unknowable type" arm — and quarantined forever. That is the H2 wedge the
/// batch arm exists to avoid, reintroduced one layer up.
#[test]
fn forward_remat_defers_facet_of_with_absent_endpoints_instead_of_quarantining() -> Result<()> {
    let (_dir, vault) = test_vault();
    let window_key = WindowKey::new("2026-03");
    let turn_src = EntityId::from_bytes([0xE1; 16])?;
    let facet = EntityId::from_bytes([0xE2; 16])?;

    let doc = create_window_doc("remote", &window_key);
    map_insert_bytes(
        &doc.get_map("edges"),
        &format_edge_key(&turn_src, EdgeKind::FacetOf, &facet),
        &encode_edge_value_for_crdt(EdgeKind::FacetOf, 0.7, 10, None, None)?,
    )?;
    doc.commit();

    forward_rematerialize(&vault, &doc, &Materializer::new(), &window_key)?;
    assert!(
        crate::sync::quarantine::quarantined_records(&vault)?.is_empty(),
        "an edge whose endpoints have not arrived defers; it is not a table rejection"
    );
    assert!(!vault.edge_exists(&turn_src, EdgeKind::FacetOf, &facet)?);

    // The endpoints arrive in a later window pass; the same CRDT row now
    // materializes because the table can finally read real types.
    vault.put_entity(
        &turn_src,
        ENTITY_TYPE_TURN,
        TimeRange { start: 1, end: 1 },
        1,
        b"turn fixture",
    )?;
    vault.put_entity(
        &facet,
        crate::registry::ENTITY_TYPE_FACET,
        TimeRange { start: 1, end: 1 },
        1,
        b"facet fixture",
    )?;

    forward_rematerialize(&vault, &doc, &Materializer::new(), &window_key)?;
    assert!(
        vault.edge_exists(&turn_src, EdgeKind::FacetOf, &facet)?,
        "a deferred on-table stamp must heal once its endpoints exist"
    );
    assert!(
        crate::sync::quarantine::quarantined_records(&vault)?.is_empty(),
        "a legitimate deferred replay must never leave quarantine evidence"
    );
    Ok(())
}

/// ONE-1124 fail-closed split at the replay table (P3 retrofit).
///
/// `validate_facet_of_edge` surfaces TWO error classes: the remote-op
/// rejection `InvalidFacetOfEdge` (off-table stamp — quarantine and continue)
/// and LOCAL faults, notably `CorruptedIndex("entity header")` when a STORED
/// endpoint row will not parse. The pre-retrofit code quarantined every `Err`
/// alike, which is wrong twice over: it swallows the engine's own storage
/// defect behind a continue instead of aborting the drain, and the `x:` row it
/// writes is PERMANENT false evidence blaming the peer for a forgery it never
/// sent.
///
/// Fixture: an endpoint row whose stored bytes are shorter than the 25-byte
/// entity envelope. The endpoint EXISTS (so the pass clears the
/// endpoint-existence check and reaches the table), but its header cannot be
/// read — exactly the local-defect shape.
#[test]
fn forward_remat_aborts_on_corrupted_endpoint_header_instead_of_quarantining() -> Result<()> {
    let (_dir, vault) = test_vault();
    let window_key = WindowKey::new("2026-03");
    let turn_src = EntityId::from_bytes([0xF1; 16])?;
    let facet = EntityId::from_bytes([0xF2; 16])?;
    vault.put_entity(
        &turn_src,
        ENTITY_TYPE_TURN,
        TimeRange { start: 1, end: 1 },
        1,
        b"turn fixture",
    )?;
    // A row too short to carry the entity header — a LOCAL corruption, not a
    // missing endpoint (which would defer) and not a wrong type (which would
    // quarantine).
    vault.with_write_txn(|wtxn| {
        vault.store.entities.put(wtxn, facet.as_bytes(), b"trunc")?;
        Ok(())
    })?;

    let doc = create_window_doc("remote", &window_key);
    map_insert_bytes(
        &doc.get_map("edges"),
        &format_edge_key(&turn_src, EdgeKind::FacetOf, &facet),
        &encode_edge_value_for_crdt(EdgeKind::FacetOf, 0.7, 10, None, None)?,
    )?;
    doc.commit();

    let err = forward_rematerialize(&vault, &doc, &Materializer::new(), &window_key)
        .expect_err("a corrupted stored endpoint header must ABORT the drain");
    assert_eq!(
        err.kind(),
        crate::error::ErrorKind::CorruptedIndex,
        "the local defect must propagate typed, not be re-cast as a peer rejection"
    );
    assert!(
        crate::sync::quarantine::quarantined_records(&vault)?.is_empty(),
        "a LOCAL fault must never leave an x: row misattributing it to the peer"
    );
    Ok(())
}

/// The retrofit's other arm, pinned in the same neighborhood so a future
/// refactor cannot satisfy the abort test by disabling the gate entirely: an
/// off-table PERSON -> FACET stamp — both endpoints present and parseable —
/// still QUARANTINES and lets the window continue.
#[test]
fn forward_remat_still_quarantines_off_table_when_endpoint_rows_are_healthy() -> Result<()> {
    let (_dir, vault) = test_vault();
    let window_key = WindowKey::new("2026-03");
    let person = EntityId::from_bytes([0xF3; 16])?;
    let facet = EntityId::from_bytes([0xF4; 16])?;
    for (id, entity_type) in [
        (&person, crate::registry::ENTITY_TYPE_PERSON),
        (&facet, crate::registry::ENTITY_TYPE_FACET),
    ] {
        vault.put_entity(
            id,
            entity_type,
            TimeRange { start: 1, end: 1 },
            1,
            b"fixture",
        )?;
    }

    let doc = create_window_doc("remote", &window_key);
    map_insert_bytes(
        &doc.get_map("edges"),
        &format_edge_key(&person, EdgeKind::FacetOf, &facet),
        &encode_edge_value_for_crdt(EdgeKind::FacetOf, 0.7, 10, None, None)?,
    )?;
    doc.commit();

    forward_rematerialize(&vault, &doc, &Materializer::new(), &window_key)
        .expect("an off-table stamp quarantines; it must never abort (H2)");
    assert!(!vault.edge_exists(&person, EdgeKind::FacetOf, &facet)?);
    let records = crate::sync::quarantine::quarantined_records(&vault)?;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].1.reason_code, "InvalidFacetOfEdge");
    Ok(())
}

// ---------------------------------------------------------------------------
// SECRET_CUSTODY (byte 77) ONE-1865 seal — FIX1 CHOKEPOINT
// ---------------------------------------------------------------------------

/// Builds a live custody record in the vault via the door and returns its raw
/// stored bytes (header + body), mirrored exactly as `reverse_rematerialize`
/// would read them back.
fn seed_secret_custody(
    vault: &Vault,
    window_key: &WindowKey,
    name: &str,
    value: &[u8],
) -> Result<(EntityId, Vec<u8>)> {
    let learned_at = window_key.start_timestamp().unwrap() + 60;
    let rec = crate::secret_custody::SecretCustodyRecord {
        schema_version: crate::secret_custody::SECRET_CUSTODY_SCHEMA_VERSION,
        name: name.to_owned(),
        class: crate::secret_custody::CustodyClass::CustodyPortable,
        device_only: false,
        value_bytes: value.to_vec(),
        status: crate::secret_custody::SecretCustodyStatus::Active,
        registered_at: learned_at,
        rotated_at: None,
        rotation_generation: 0,
        bindings: vec![crate::secret_custody::SecretBinding {
            effector: "door:receive-pack".to_owned(),
            tier_ceiling: crate::secret_custody::CustodyTier::T0Doored,
            scopes: vec!["read".to_owned()],
        }],
        manifest_ref: "secrets.toml".to_owned(),
        declared_paths: vec![".secrets/api.key".to_owned()],
        policy_floor_snapshot: crate::secret_custody::SecretCustodyFloor::default(),
    };
    let id = vault.register_secret(rec)?;
    // The sealed public `get_raw` denies byte 77 by design; this fixture needs
    // the on-disk bytes to plant a carrier, so it reads through the same
    // crate-internal unsealed reader the scrub passes use.
    let raw = vault.get_raw_unsealed(&id)?.expect("custody row present");
    Ok((id, raw))
}

/// Reverse re-materialization must never mirror a custody record into the
/// canonical window doc, and must scrub any custody carrier (and its incident
/// edges) that landed before the pass ran.
#[test]
fn secret_custody_never_enters_doc_via_reverse_rematerialize() -> Result<()> {
    let (_dir, vault) = test_vault();
    let window_key = WindowKey::new("2026-03");
    let learned_at = window_key.start_timestamp().unwrap() + 60;
    let secret_value = b"hunter2-secret";
    let (custody, custody_raw) = seed_secret_custody(&vault, &window_key, "api-key", secret_value)?;

    // An ordinary control entity proves the pass still mirrors other rows.
    let ordinary = EntityId::from_bytes([0x47; 16])?;
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

    let doc = create_window_doc("source", &window_key);
    let entities = doc.get_map("entities");
    let edge_key = format_edge_key(&ordinary, EdgeKind::Mentions, &custody);
    let edge_val = encode_edge_value_for_crdt(EdgeKind::Mentions, 0.5, learned_at, None, None)?;

    // Pre-seed a custody carrier + incident edge as if they landed before the
    // seal: reverse remat must scrub BOTH, not merely skip the insert.
    map_insert_bytes(&entities, &custody.to_hex(), &custody_raw)?;
    map_insert_bytes(&doc.get_map("edges"), &edge_key, &edge_val)?;
    doc.commit();

    // Count = 1: only the ordinary control mirrors. The custody row is sealed.
    assert_eq!(reverse_rematerialize(&vault, &doc, &window_key)?, 1);
    assert!(
        map_get_bytes(&entities, &ordinary.to_hex()).is_some(),
        "ordinary entity still mirrors through reverse remat"
    );
    assert!(
        map_get_bytes(&entities, &custody.to_hex()).is_none(),
        "custody record body must be scrubbed from the canonical doc"
    );
    assert!(
        map_get_bytes(&doc.get_map("edges"), &edge_key).is_none(),
        "custody incident edge must be scrubbed from the canonical doc"
    );
    Ok(())
}

/// The export path runs the same seal: a custody carrier already resident in
/// the doc must be scrubbed and the window forced onto history-free snapshot
/// transport, so exported bytes never carry the secret value.
#[test]
fn secret_custody_never_leaves_doc_via_export() -> Result<()> {
    let (_dir, vault) = test_vault();
    let window_key = WindowKey::new("2026-03");
    let learned_at = window_key.start_timestamp().unwrap() + 60;
    let secret_value = b"hunter2-secret";
    let (custody, custody_raw) = seed_secret_custody(&vault, &window_key, "api-key", secret_value)?;

    let ordinary = EntityId::from_bytes([0x48; 16])?;
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

    let doc = create_window_doc("source", &window_key);
    map_insert_bytes(&doc.get_map("entities"), &custody.to_hex(), &custody_raw)?;
    map_insert_bytes(
        &doc.get_map("entities"),
        &ordinary.to_hex(),
        &make_entity_blob(ENTITY_TYPE_TURN, learned_at, b"ordinary turn"),
    )?;
    doc.commit();

    // Export to a fresh peer: the custody body must not survive, the ordinary
    // control must.
    let export = export_window_updates_since(
        &vault,
        &window_key,
        &doc,
        &VersionVector::default().encode(),
    )?;
    let peer = create_window_doc("peer", &window_key);
    import_doc(&peer, &export)?;
    assert!(
        map_get_bytes(&peer.get_map("entities"), &custody.to_hex()).is_none(),
        "exported window must not carry the custody record body"
    );
    assert!(
        map_get_bytes(&peer.get_map("entities"), &ordinary.to_hex()).is_some(),
        "ordinary entity still exports"
    );
    // The local doc was scrubbed in place too.
    assert!(
        map_get_bytes(&doc.get_map("entities"), &custody.to_hex()).is_none(),
        "local doc scrubbed before export"
    );
    // And the window is now pinned history-free, so the pre-scrub set-op bytes
    // in Loro history can never take a raw delta/snapshot path later.
    assert!(
        history_free_window_required(&vault, &window_key)?,
        "custody carrier scrub pins the window to history-free transport"
    );
    Ok(())
}

/// C2 EXPORT-SCRUB BYPASS: the map key is peer-chosen, the type byte is not.
/// Parsing the key before classifying the body let a custody carrier filed
/// under a non-canonical key skip the scrub and ship its plaintext in the
/// export.
#[test]
fn secret_custody_under_malformed_key_never_leaves_doc_via_export() -> Result<()> {
    let (_dir, vault) = test_vault();
    let window_key = WindowKey::new("2026-03");
    let learned_at = window_key.start_timestamp().unwrap() + 60;
    let secret_value = b"hunter2-malformed-key";
    let (_custody, custody_raw) =
        seed_secret_custody(&vault, &window_key, "api-key", secret_value)?;

    // A key no `EntityId::from_hex` can parse — exactly what a hostile or
    // buggy peer is free to write into the entities map.
    let malformed_key = "not-a-canonical-entity-id";
    let ordinary = EntityId::from_bytes([0x49; 16])?;
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

    let doc = create_window_doc("source", &window_key);
    map_insert_bytes(&doc.get_map("entities"), malformed_key, &custody_raw)?;
    map_insert_bytes(
        &doc.get_map("entities"),
        &ordinary.to_hex(),
        &make_entity_blob(ENTITY_TYPE_TURN, learned_at, b"ordinary turn"),
    )?;
    doc.commit();

    let export = export_window_updates_since(
        &vault,
        &window_key,
        &doc,
        &VersionVector::default().encode(),
    )?;

    // The load-bearing assertion: the secret value is not anywhere in the bytes
    // that go on the wire.
    assert!(
        !export
            .windows(secret_value.len())
            .any(|w| w == secret_value.as_slice()),
        "exported bytes must not carry the secret value"
    );

    let peer = create_window_doc("peer", &window_key);
    import_doc(&peer, &export)?;
    assert!(
        map_get_bytes(&peer.get_map("entities"), malformed_key).is_none(),
        "a malformed-key custody carrier must not reach the peer"
    );
    assert!(
        map_get_bytes(&peer.get_map("entities"), &ordinary.to_hex()).is_some(),
        "ordinary entity still exports"
    );
    assert!(
        map_get_bytes(&doc.get_map("entities"), malformed_key).is_none(),
        "local doc scrubbed before export"
    );
    assert!(
        history_free_window_required(&vault, &window_key)?,
        "the scrub pins the window to history-free transport"
    );

    let quarantined = crate::sync::quarantine::quarantined_records(&vault)?;
    assert_eq!(quarantined.len(), 1);
    assert_eq!(quarantined[0].1.container, QuarantineContainer::Entities);
    assert_eq!(quarantined[0].1.reason_code, "InvalidSecretCustodyBody");
    assert_eq!(
        (
            quarantined[0].1.crdt_key_hash,
            quarantined[0].1.crdt_key_len
        ),
        crate::sync::quarantine::crdt_key_metadata(malformed_key)
    );
    Ok(())
}
