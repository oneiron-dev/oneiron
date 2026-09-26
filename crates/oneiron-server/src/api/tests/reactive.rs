//! Local-first reactive read sync/refresh/ignore/lag/origins plus engine-observer vault write path.

use super::*;

/// The initial path is synchronous end to end: this fixture runs with no Tokio
/// runtime at all, so an async constructor or a server round trip could not
/// even compile-and-run here, let alone a `Loading` state.
#[test]
fn local_reactive_read_is_synchronous() {
    let (_dir, server) = test_server();
    let id = seeded_test_entity_id(0x1437_0001);
    seed_reactive_turn(server.vault(), &id, 1_770_000_000);

    let (probe, reads) = reactive_probe(id, vec![ReactiveDependency::AnyPersistent]);
    let read = open_local_reactive_read(&server, probe).expect("open reactive read");

    assert_eq!(reactive_reads(&reads), 1, "open reads exactly once");
    assert!(
        read.snapshot().is_some(),
        "a cached read must be serveable immediately, with no socket and no network"
    );
    assert_eq!(read.revision(), 0);
}

/// A closed notice channel is terminal but harmless: the last snapshot stays
/// readable, which is what "keeps working offline" means for this contract.
#[tokio::test]
async fn local_reactive_read_keeps_snapshot_when_channel_closes() {
    let dir = tempfile::tempdir().expect("temp vault dir");
    let vault = Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap());
    let id = seeded_test_entity_id(0x1437_0002);
    seed_reactive_turn(&vault, &id, 1_770_000_000);

    let (tx, _rx) = tokio::sync::broadcast::channel::<crate::server::BroadcastPayload>(8);
    let (probe, reads) = reactive_probe(id, vec![ReactiveDependency::AnyPersistent]);
    let mut read = ReactiveLocalRead::open(Arc::clone(&vault), &tx, probe).expect("open");
    drop(tx);

    let err = read
        .refresh_on_change()
        .await
        .expect_err("a closed channel ends the wait");
    assert!(matches!(err, ReactiveReadError::ChannelClosed));
    assert!(
        read.snapshot().is_some(),
        "the retained snapshot survives channel closure"
    );
    assert_eq!(reactive_reads(&reads), 1, "closure triggers no re-query");
    assert_eq!(read.revision(), 0);
}

/// A matching persistent notice re-runs the query exactly once and bumps the
/// revision — once for an entity document, once for a root update.
#[tokio::test]
async fn local_reactive_read_refreshes_on_matching_sync() {
    let dir = tempfile::tempdir().expect("temp vault dir");
    let vault = Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap());
    let learned_at = 1_770_000_000;
    let document_id = seeded_test_entity_id(0x1437_0003);
    let (document_probe, document_reads) =
        reactive_probe(document_id, vec![ReactiveDependency::Doc(document_id)]);
    let root_id = seeded_test_entity_id(0x1437_0004);
    let (root_probe, root_reads) = reactive_probe(root_id, vec![ReactiveDependency::Root]);

    let (tx, _rx) = tokio::sync::broadcast::channel::<crate::server::BroadcastPayload>(8);
    let mut document_read =
        ReactiveLocalRead::open(Arc::clone(&vault), &tx, document_probe).unwrap();
    let mut root_read = ReactiveLocalRead::open(Arc::clone(&vault), &tx, root_probe).unwrap();
    assert!(document_read.snapshot().is_none());
    assert!(root_read.snapshot().is_none());

    seed_reactive_turn(&vault, &document_id, learned_at);
    seed_reactive_turn(&vault, &root_id, learned_at);
    crate::broadcast::broadcast(&tx, 0, reactive_doc_update_frame(document_id))
        .expect("broadcast document update");
    crate::broadcast::broadcast(&tx, 0, crate::protocol::encode_root_update(b"root-delta"))
        .expect("broadcast root update");

    assert!(
        document_read
            .refresh_on_change()
            .await
            .expect("document update refreshes")
            .is_some()
    );
    assert_eq!(document_read.revision(), 1);
    assert_eq!(reactive_reads(&document_reads), 2);

    assert!(
        root_read
            .refresh_on_change()
            .await
            .expect("root update refreshes")
            .is_some()
    );
    assert_eq!(root_read.revision(), 1);
    assert_eq!(reactive_reads(&root_reads), 2);
}

/// Non-persistent frames are checked against the widest dependency set there
/// is, so what rejects them is the frame class itself and not a narrow
/// dependency that happened to miss.
#[tokio::test]
async fn local_reactive_read_ignores_nonpersistent_frames() {
    let dir = tempfile::tempdir().expect("temp vault dir");
    let vault = Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap());
    let learned_at = 1_770_000_000;
    let window_key = oneiron::sync::WindowKey::from_timestamp(learned_at);
    let id = seeded_test_entity_id(0x1437_0005);

    let (tx, _rx) = tokio::sync::broadcast::channel::<crate::server::BroadcastPayload>(32);
    let (probe, reads) = reactive_probe(id, vec![ReactiveDependency::AnyPersistent]);
    let mut read = ReactiveLocalRead::open(Arc::clone(&vault), &tx, probe).unwrap();

    for frame in reactive_nonpersistent_frames(window_key.as_str()) {
        crate::broadcast::broadcast(&tx, 0, frame).expect("broadcast non-persistent frame");
    }
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(100),
            read.refresh_on_change()
        )
        .await
        .is_err(),
        "ephemeral, VV, lease, selector, malformed, and unknown frames must not wake a local read"
    );
    assert_eq!(
        reactive_reads(&reads),
        1,
        "no re-query on negotiation noise"
    );
    assert_eq!(read.revision(), 0);

    seed_reactive_turn(&vault, &id, learned_at);
    crate::broadcast::broadcast(&tx, 0, reactive_doc_update_frame(id))
        .expect("broadcast document update");
    assert!(
        read.refresh_on_change()
            .await
            .expect("a persistent frame still wakes the same read")
            .is_some()
    );
    assert_eq!(read.revision(), 1);
    assert_eq!(reactive_reads(&reads), 2);
}

#[tokio::test]
async fn local_reactive_read_ignores_unrelated_document() {
    let dir = tempfile::tempdir().expect("temp vault dir");
    let vault = Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap());
    let learned_at = 1_770_000_000;
    let id = seeded_test_entity_id(0x1437_0006);
    let other = seeded_test_entity_id(0x1437_0013);
    let (tx, _rx) = tokio::sync::broadcast::channel::<crate::server::BroadcastPayload>(8);
    let (probe, reads) = reactive_probe(id, vec![ReactiveDependency::Doc(id)]);
    let mut read = ReactiveLocalRead::open(Arc::clone(&vault), &tx, probe).unwrap();

    crate::broadcast::broadcast(&tx, 0, reactive_doc_update_frame(other))
        .expect("broadcast unrelated document update");
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(100),
            read.refresh_on_change()
        )
        .await
        .is_err()
    );
    assert_eq!(reactive_reads(&reads), 1);

    seed_reactive_turn(&vault, &id, learned_at);
    crate::broadcast::broadcast(&tx, 0, reactive_doc_update_frame(id))
        .expect("broadcast matching document update");
    assert!(read.refresh_on_change().await.expect("refresh").is_some());
    assert_eq!(read.revision(), 1);
    assert_eq!(reactive_reads(&reads), 2);
}

/// Dropped notices degrade to extra work, never to stale data: the only frames
/// on this channel name another document the query does not read, so the refresh can
/// only be explained by the lag escalation itself.
#[tokio::test]
async fn local_reactive_read_recovers_from_lag() {
    let dir = tempfile::tempdir().expect("temp vault dir");
    let vault = Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap());
    let learned_at = 1_770_000_000;
    let id = seeded_test_entity_id(0x1437_0007);
    let other = seeded_test_entity_id(0x1437_0014);

    let (tx, _rx) = tokio::sync::broadcast::channel::<crate::server::BroadcastPayload>(2);
    let (probe, reads) = reactive_probe(id, vec![ReactiveDependency::Doc(id)]);
    let mut read = ReactiveLocalRead::open(Arc::clone(&vault), &tx, probe).unwrap();
    assert!(read.snapshot().is_none());

    seed_reactive_turn(&vault, &id, learned_at);
    for _ in 0..5 {
        crate::broadcast::broadcast(&tx, 0, reactive_doc_update_frame(other))
            .expect("overflow the receiver");
    }

    assert!(
        read.refresh_on_change()
            .await
            .expect("lag escalates to a coarse re-read")
            .is_some(),
        "a lagged receiver must produce a current snapshot, not a placeholder"
    );
    assert_eq!(read.revision(), 1);
    assert_eq!(reactive_reads(&reads), 2);
}

/// Local/bridge frames (`conn_id = 0`) and frames from the consumer's own
/// connection both reach the reactive subscriber — a writer's own device still
/// has to refresh its LMDB-derived view — while `BroadcastSubscriber` keeps
/// suppressing its own echo for WebSocket forwarding on the same channel.
#[tokio::test]
async fn local_reactive_read_observes_bridge_and_own_connection_origins() {
    let dir = tempfile::tempdir().expect("temp vault dir");
    let vault = Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap());
    let learned_at = 1_770_000_000;
    let id = seeded_test_entity_id(0x1437_0008);
    seed_reactive_turn(&vault, &id, learned_at);

    let (tx, _rx) = tokio::sync::broadcast::channel::<crate::server::BroadcastPayload>(8);
    let (probe, reads) = reactive_probe(id, vec![ReactiveDependency::Doc(id)]);
    let mut read = ReactiveLocalRead::open(Arc::clone(&vault), &tx, probe).unwrap();
    let mut websocket_subscriber = crate::broadcast::BroadcastSubscriber::new(7, &tx);

    crate::broadcast::broadcast(&tx, 0, reactive_doc_update_frame(id))
        .expect("bridge-origin frame");
    read.refresh_on_change().await.expect("bridge origin wakes");
    assert_eq!(read.revision(), 1);

    crate::broadcast::broadcast(&tx, 7, reactive_doc_update_frame(id))
        .expect("own-connection frame");
    read.refresh_on_change()
        .await
        .expect("own-connection origin wakes");
    assert_eq!(read.revision(), 2);
    assert_eq!(reactive_reads(&reads), 3);

    // The WebSocket path is untouched: connection 7 sees the bridge frame and
    // skips its own echo, so it receives exactly one of the two.
    assert!(
        websocket_subscriber
            .recv()
            .await
            .expect("subscriber alive")
            .is_some()
    );
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(100),
            websocket_subscriber.recv()
        )
        .await
        .is_err(),
        "echo suppression for WebSocket forwarding must be unchanged"
    );
}

/// Entity documents share a monthly ledger window but must not share a local
/// read invalidation. A real durable text edit flows through the server's
/// document relay; the matching query re-reads and its sibling does not.
#[tokio::test]
async fn local_entity_document_edit_refreshes_only_matching_read() {
    let (_dir, server) = test_server();
    let learned_at = 1_770_000_000;
    let first = seeded_test_entity_id(0x1437_0010);
    let second = seeded_test_entity_id(0x1437_0011);
    seed_reactive_turn(server.vault(), &first, learned_at);
    seed_reactive_turn(server.vault(), &second, learned_at);
    let (first_probe, first_reads) = reactive_probe(first, vec![ReactiveDependency::Doc(first)]);
    let (second_probe, second_reads) =
        reactive_probe(second, vec![ReactiveDependency::Doc(second)]);
    let mut first_read = open_local_reactive_read(&server, first_probe).expect("first read");
    let mut second_read = open_local_reactive_read(&server, second_probe).expect("second read");
    assert_eq!(reactive_reads(&first_reads), 1);
    assert_eq!(reactive_reads(&second_reads), 1);

    let document = server
        .reassert_manager
        .documents()
        .open(first)
        .expect("open document");
    document
        .edit_text(0, 0, "one edit")
        .expect("durable document edit");
    assert_eq!(document.text().unwrap(), "one edit");
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        first_read.refresh_on_change(),
    )
    .await
    .expect("document relay reaches local query")
    .expect("matching read succeeds");
    assert_eq!(reactive_reads(&first_reads), 2);
    assert_eq!(first_read.revision(), 1);
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(100),
            second_read.refresh_on_change(),
        )
        .await
        .is_err(),
        "an entity in the same window must not re-read"
    );
    assert_eq!(reactive_reads(&second_reads), 1);
    assert_eq!(second_read.revision(), 0);
}

/// Ledger WindowSync updates are not entity-document invalidations, even
/// for a broad local read. Document edits have their own named notices.
#[tokio::test]
async fn local_read_ignores_window_update_even_with_broad_dependency() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap());
    let id = seeded_test_entity_id(0x1437_0012);
    let (tx, _rx) = tokio::sync::broadcast::channel::<crate::server::BroadcastPayload>(8);
    let (probe, reads) = reactive_probe(id, vec![ReactiveDependency::AnyPersistent]);
    let mut read = ReactiveLocalRead::open(vault, &tx, probe).unwrap();
    crate::broadcast::broadcast(&tx, 0, reactive_window_update_frame("2026-03")).unwrap();
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(100),
            read.refresh_on_change()
        )
        .await
        .is_err()
    );
    assert_eq!(reactive_reads(&reads), 1);
    assert_eq!(read.revision(), 0);
}

/// Production wiring, end to end: a real LMDB write, mirrored into the window
/// by the engine's own LMDB→CRDT path, reaches a reactive read through
/// Observer B's local tee. The other entity is in the SAME window, but its
/// query does not re-read. No encoded frame is injected in this fixture.
#[tokio::test]
async fn local_vault_write_reaches_reactive_read_through_engine_observer() {
    let (_dir, server) = test_server();
    let learned_at = 1_770_000_000;
    let window_key = oneiron::sync::WindowKey::from_timestamp(learned_at);
    let doc = server
        .get_or_create_window(&window_key)
        .await
        .expect("open window");

    let id = seeded_test_entity_id(0x1437_0009);
    let other = seeded_test_entity_id(0x1437_0015);
    seed_reactive_turn(server.vault(), &other, learned_at);
    assert_eq!(
        oneiron::sync::window::reverse_rematerialize(server.vault(), &doc, &window_key)
            .expect("mirror initial sibling"),
        1
    );
    let (probe, reads) = reactive_probe(id, vec![ReactiveDependency::Doc(id)]);
    let (other_probe, other_reads) = reactive_probe(other, vec![ReactiveDependency::Doc(other)]);
    let mut read = open_local_reactive_read(&server, probe).expect("open reactive read");
    let mut other_read = open_local_reactive_read(&server, other_probe).expect("open sibling read");
    assert!(read.snapshot().is_none());
    assert!(other_read.snapshot().is_some());

    seed_reactive_turn(server.vault(), &id, learned_at);
    assert_eq!(
        oneiron::sync::window::reverse_rematerialize(server.vault(), &doc, &window_key)
            .expect("mirror local write into the window"),
        1
    );

    let refreshed =
        tokio::time::timeout(std::time::Duration::from_secs(5), read.refresh_on_change())
            .await
            .expect("observer notice reaches the reactive read")
            .expect("refresh succeeds")
            .is_some();
    assert!(refreshed, "the reactive read serves the newly written body");
    assert_eq!(read.revision(), 1);
    assert_eq!(reactive_reads(&reads), 2);
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(100),
            other_read.refresh_on_change()
        )
        .await
        .is_err(),
        "Observer B must name only the changed entity, not its whole window"
    );
    assert_eq!(other_read.revision(), 0);
    assert_eq!(reactive_reads(&other_reads), 1);
}

/// A remote ledger commit is materialized by Observer B before its local tee
/// notifies. Only the changed entity's document dependency can re-read.
#[tokio::test]
async fn observer_b_materialization_refreshes_only_changed_entity() {
    use loro::CommitOptions;

    let (_dir, server) = test_server();
    let learned_at = 1_770_000_000u64;
    let window = oneiron::sync::WindowKey::from_timestamp(learned_at);
    let doc = server
        .get_or_create_window(&window)
        .await
        .expect("open window");
    let first = seeded_test_entity_id(0x1437_0016);
    let second = seeded_test_entity_id(0x1437_0017);
    // The second entity is already present before either local query opens.
    let mut blob = vec![1u8];
    for _ in 0..3 {
        blob.extend_from_slice(&learned_at.to_be_bytes());
    }
    blob.extend_from_slice(b"remote body");
    doc.get_map("entities")
        .insert(&second.to_hex(), blob.as_slice())
        .expect("write sibling");
    doc.commit_with(CommitOptions::new().origin("conn:7"));

    let (first_probe, first_reads) = reactive_probe(first, vec![ReactiveDependency::Doc(first)]);
    let (second_probe, second_reads) =
        reactive_probe(second, vec![ReactiveDependency::Doc(second)]);
    let mut first_read = open_local_reactive_read(&server, first_probe).expect("first read");
    let mut second_read = open_local_reactive_read(&server, second_probe).expect("second read");
    assert!(first_read.snapshot().is_none());
    assert_eq!(
        second_read.snapshot().as_deref(),
        Some(b"remote body".as_slice())
    );

    doc.get_map("entities")
        .insert(&first.to_hex(), blob.as_slice())
        .expect("write first");
    doc.commit_with(CommitOptions::new().origin("conn:7"));
    let snapshot = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        first_read.refresh_on_change(),
    )
    .await
    .expect("Observer B emits an entity notice")
    .expect("local read succeeds");
    assert_eq!(snapshot.as_deref(), Some(b"remote body".as_slice()));
    assert_eq!(reactive_reads(&first_reads), 2);
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(100),
            second_read.refresh_on_change(),
        )
        .await
        .is_err(),
        "a sibling in the same window must not re-read"
    );
    assert_eq!(reactive_reads(&second_reads), 1);
}
