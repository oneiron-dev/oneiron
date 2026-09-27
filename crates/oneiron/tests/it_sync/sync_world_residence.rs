//! World-month residence regressions through public engine doors.

use std::sync::Arc;

use loro::{ExportMode, VersionVector};
use oneiron::recovery::{
    CanonicalSnapshot, RecoveryBudget, capture_canonical_window,
    rebuild_vault_window_from_canonical, recover_vault_window,
};
use oneiron::sync::bridge::Materializer;
use oneiron::sync::schema::create_root_doc;
use oneiron::sync::transport::{self, TAG_SYNC_UPDATE, TAG_WINDOW_SYNC, window_sub_tags};
use oneiron::sync::window::{export_window_updates_since, load_window_from_state};
use oneiron::sync::{SyncClient, SyncClientConfig, WindowKey, WindowManager};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EdgeKind, EntityId,
    TimeRange, Vault, VaultConfig,
};

fn vault() -> (tempfile::TempDir, Arc<Vault>) {
    let dir = tempfile::tempdir().expect("create test vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open test vault"));
    (dir, vault)
}

fn manager(vault: &Arc<Vault>) -> Arc<WindowManager> {
    Arc::new(WindowManager::new(
        vault.clone(),
        Arc::new(Materializer::new()),
        "test",
    ))
}

fn window_requests(frames: &[Vec<u8>]) -> Vec<WindowKey> {
    frames
        .iter()
        .filter(|frame| frame.first() == Some(&TAG_WINDOW_SYNC))
        .map(|frame| {
            WindowKey::new(
                transport::decode_window_sync(&frame[1..])
                    .expect("decode requested window")
                    .0,
            )
        })
        .collect()
}

fn transfer(
    source: &Vault,
    manager: &Arc<WindowManager>,
    client: &mut SyncClient,
    key: &WindowKey,
) {
    let doc = manager.open_window(key).expect("open source window");
    let update =
        export_window_updates_since(source, key, &doc.doc, &VersionVector::default().encode())
            .expect("export source window");
    let frame = transport::encode_window_sync(key.as_str(), window_sub_tags::UPDATE, &update)
        .into_result()
        .expect("encode window update");
    client
        .handle_server_message(&frame)
        .unwrap_or_else(|error| panic!("{key} import: {error}"));
}

#[test]
fn fresh_follow_uses_wire_request_order_for_same_and_older_base_edges() {
    let (_source_dir, source) = vault();
    let person_old = EntityId::now();
    let person_now = EntityId::now();
    let at_old = WindowKey::new("2025-11").start_timestamp().unwrap() + 60;
    let at_world = WindowKey::new("2026-02").start_timestamp().unwrap() + 60;
    source
        .put_entity(
            &person_old,
            oneiron::registry::ENTITY_TYPE_PERSON,
            TimeRange {
                start: at_old,
                end: at_old,
            },
            at_old,
            b"old",
        )
        .unwrap();
    source
        .put_entity(
            &person_now,
            oneiron::registry::ENTITY_TYPE_PERSON,
            TimeRange {
                start: at_world,
                end: at_world,
            },
            at_world,
            b"same month",
        )
        .unwrap();
    let mut projects = Vec::new();
    for n in 0..5 {
        let world = EntityId::now();
        let claim = EntityId::now();
        source
            .put_entity(
                &world,
                oneiron::registry::ENTITY_TYPE_WORLD,
                TimeRange {
                    start: at_world,
                    end: at_world,
                },
                at_world,
                b"world",
            )
            .unwrap();
        let mut body = ClaimBody::new(
            "test.project",
            ClaimSubject::Entity(person_old),
            rmpv::Value::from(format!("fact {n}")),
            1.0,
            ClaimApprovalStatus::Proposed,
            ClaimLifecycleStatus::Active,
        );
        body.world = Some(world);
        source
            .put_claim(
                &claim,
                &body,
                TimeRange {
                    start: at_world,
                    end: at_world,
                },
                at_world,
            )
            .unwrap();
        projects.push((world, claim));
    }
    let (selected_world, selected_claim) = projects[0];
    source
        .batch()
        .edge(&selected_claim, EdgeKind::About, &person_old, 1.0)
        .edge(&selected_claim, EdgeKind::Mentions, &person_now, 1.0)
        .edge(&person_old, EdgeKind::Mentions, &selected_claim, 1.0)
        .commit()
        .unwrap();
    let source_manager = manager(&source);
    let known = oneiron::sync::discover_local_window_keys(&source).unwrap();
    let key = WindowKey::for_world(at_world, selected_world);
    assert!(known.contains(&key));
    assert!(!known.contains(&WindowKey::for_world(at_old, selected_world)));
    let root = create_root_doc("server", "vault", &known);
    let mut root_frame = vec![TAG_SYNC_UPDATE];
    root_frame.extend_from_slice(&root.export(ExportMode::snapshot()).unwrap());

    let (_peer_dir, peer) = vault();
    let (mut client, _) = SyncClient::new(
        manager(&peer),
        SyncClientConfig {
            followed_worlds: Some(vec![selected_world]),
            ..Default::default()
        },
    )
    .unwrap();
    let initial = window_requests(&client.generate_initial_sync());
    assert!(initial.iter().all(|key| key.world().is_none()));
    let mut ordered = initial;
    ordered.extend(window_requests(
        &client.handle_server_message(&root_frame).unwrap(),
    ));
    let first_world = ordered
        .iter()
        .position(|key| key.world().is_some())
        .unwrap();
    assert!(ordered[..first_world].contains(&WindowKey::from_timestamp(at_old)));
    assert!(ordered[..first_world].contains(&WindowKey::from_timestamp(at_world)));
    assert!(
        ordered[first_world..]
            .iter()
            .all(|key| key.world().is_some())
    );
    for requested in &ordered {
        transfer(&source, &source_manager, &mut client, requested);
    }
    assert_eq!(
        peer.get(&selected_claim).unwrap(),
        source.get(&selected_claim).unwrap()
    );
    for (_, foreign) in &projects[1..] {
        assert!(peer.get(foreign).unwrap().is_none());
    }
    assert!(
        peer.edges_out(&selected_claim)
            .unwrap()
            .iter()
            .any(|edge| edge.kind == EdgeKind::About && edge.target == person_old)
    );
    assert!(
        peer.edges_out(&selected_claim)
            .unwrap()
            .iter()
            .any(|edge| edge.kind == EdgeKind::Mentions && edge.target == person_now)
    );
    assert!(
        peer.edges_out(&person_old)
            .unwrap()
            .iter()
            .any(|edge| edge.kind == EdgeKind::Mentions && edge.target == selected_claim)
    );

    let (second_world, second_claim) = projects[1];
    client.follow_world(second_world);
    client.generate_initial_sync(); // next negotiation
    let backfill = window_requests(&client.handle_server_message(&root_frame).unwrap());
    let second_key = WindowKey::for_world(at_world, second_world);
    assert!(backfill.contains(&second_key));
    transfer(&source, &source_manager, &mut client, &second_key);
    assert_eq!(
        peer.get(&second_claim).unwrap(),
        source.get(&second_claim).unwrap()
    );
    for (_, still_unfollowed) in &projects[2..] {
        assert!(peer.get(still_unfollowed).unwrap().is_none());
    }
    let (home, _) = SyncClient::new(
        source_manager,
        SyncClientConfig {
            followed_worlds: None,
            ..Default::default()
        },
    )
    .unwrap();
    let mut home_keys = window_requests(&home.generate_initial_sync());
    let mut home = home;
    home_keys.extend(window_requests(
        &home.handle_server_message(&root_frame).unwrap(),
    ));
    for (world, _) in projects {
        assert!(home_keys.contains(&WindowKey::for_world(at_world, world)));
    }
}

#[test]
fn late_follow_accepts_valid_soft_and_hard_deleted_world_history() {
    for reason in [
        oneiron::deletion::TombstoneReason::UserDelete,
        oneiron::deletion::TombstoneReason::UserHardDelete,
    ] {
        let (_source_dir, source) = vault();
        let (_peer_dir, peer) = vault();
        let world = EntityId::now();
        let person = EntityId::now();
        let erased = EntityId::now();
        let alive = EntityId::now();
        let key = WindowKey::for_world(1_771_027_200, world);
        let at = key.start_timestamp().unwrap() + 60;
        let occurred = TimeRange { start: at, end: at };
        for node in [&source, &peer] {
            node.put_entity(
                &world,
                oneiron::registry::ENTITY_TYPE_WORLD,
                occurred,
                at,
                b"world",
            )
            .unwrap();
            node.put_entity(
                &person,
                oneiron::registry::ENTITY_TYPE_PERSON,
                occurred,
                at,
                b"person",
            )
            .unwrap();
        }
        for claim in [erased, alive] {
            let mut body = ClaimBody::new(
                "test.deleted_history",
                ClaimSubject::Entity(person),
                rmpv::Value::from("fact"),
                1.0,
                ClaimApprovalStatus::Proposed,
                ClaimLifecycleStatus::Active,
            );
            body.world = Some(world);
            source.put_claim(&claim, &body, occurred, at).unwrap();
        }
        source
            .batch()
            .edge(&erased, EdgeKind::About, &person, 1.0)
            .commit()
            .unwrap();
        let source_manager = manager(&source);
        let doc = source_manager.open_window(&key).unwrap();
        let deletion = match reason {
            oneiron::deletion::TombstoneReason::UserDelete => {
                oneiron::deletion::DeleteReason::UserDelete
            }
            oneiron::deletion::TombstoneReason::UserHardDelete => {
                oneiron::deletion::DeleteReason::UserHardDelete
            }
            _ => unreachable!("fixture chooses only user-delete reasons"),
        };
        source.delete_entity_with_reason(&erased, deletion).unwrap();
        let update = export_window_updates_since(
            &source,
            &key,
            &doc.doc,
            &VersionVector::default().encode(),
        )
        .unwrap();
        let (mut client, _) = SyncClient::new(
            manager(&peer),
            SyncClientConfig {
                followed_worlds: Some(vec![world]),
                ..Default::default()
            },
        )
        .unwrap();
        let frame = transport::encode_window_sync(key.as_str(), window_sub_tags::UPDATE, &update)
            .into_result()
            .unwrap();
        client.handle_server_message(&frame).unwrap();
        assert_eq!(peer.get(&alive).unwrap(), source.get(&alive).unwrap());
        assert!(
            client
                .window(key.as_str())
                .unwrap()
                .doc
                .get_map("tombstones")
                .get(&erased.to_hex())
                .is_some()
        );
    }
}

#[test]
fn canonical_soft_world_recovery_restores_shell_edge_and_address() {
    let (_source_dir, source) = vault();
    let world = EntityId::now();
    let person = EntityId::now();
    let claim = EntityId::now();
    let at = 1_771_027_200;
    let occurred = TimeRange { start: at, end: at };
    source
        .put_entity(
            &world,
            oneiron::registry::ENTITY_TYPE_WORLD,
            occurred,
            at,
            b"world",
        )
        .unwrap();
    source
        .put_entity(
            &person,
            oneiron::registry::ENTITY_TYPE_PERSON,
            occurred,
            at,
            b"person",
        )
        .unwrap();
    let mut body = ClaimBody::new(
        "test.soft_world",
        ClaimSubject::Entity(person),
        rmpv::Value::from("fact"),
        1.0,
        ClaimApprovalStatus::Proposed,
        ClaimLifecycleStatus::Active,
    );
    body.world = Some(world);
    source.put_claim(&claim, &body, occurred, at).unwrap();
    source
        .batch()
        .edge(&claim, EdgeKind::About, &person, 1.0)
        .commit()
        .unwrap();
    source
        .delete_entity_with_reason(&claim, oneiron::deletion::DeleteReason::UserDelete)
        .unwrap();
    let key = WindowKey::for_world(at, world);
    let source_doc = load_window_from_state(&source, "source", &key).unwrap();
    let snapshot = capture_canonical_window(&source, key.as_str(), &source_doc).unwrap();
    let encoded = snapshot.encode().unwrap();
    assert_eq!(CanonicalSnapshot::decode(&encoded).unwrap(), snapshot);
    let rebuilt = rebuild_vault_window_from_canonical(&snapshot).unwrap();
    assert!(rebuilt.get_map("entities").get(&claim.to_hex()).is_some());
    let (_peer_dir, peer) = vault();
    peer.put_entity(
        &world,
        oneiron::registry::ENTITY_TYPE_WORLD,
        occurred,
        at,
        b"world",
    )
    .unwrap();
    peer.put_entity(
        &person,
        oneiron::registry::ENTITY_TYPE_PERSON,
        occurred,
        at,
        b"person",
    )
    .unwrap();
    let manifest_dir = tempfile::tempdir().unwrap();
    let manifest = manifest_dir.path().join("recovery-manifest");
    std::fs::write(&manifest, b"invalid previous manifest").unwrap();
    let recovered = recover_vault_window(
        &peer,
        &Materializer::new(),
        &manifest,
        &snapshot,
        RecoveryBudget::default(),
    )
    .unwrap();
    assert_eq!(peer.get_raw(&claim).unwrap().unwrap().len(), 25);
    assert_eq!(
        peer.sync_state_get(&format!("m:dw:{}", claim.to_hex()))
            .unwrap()
            .as_deref(),
        Some(key.as_str().as_bytes())
    );
    assert!(
        peer.edges_out(&claim)
            .unwrap()
            .iter()
            .any(|edge| edge.kind == EdgeKind::About && edge.target == person)
    );
    oneiron::sync::server_state::persist_window_snapshot(&peer, &key, &recovered.window).unwrap();
    let opened = manager(&peer).open_window(&key).unwrap();
    assert!(
        opened
            .doc
            .get_map("tombstones")
            .get(&claim.to_hex())
            .is_some()
    );
}
