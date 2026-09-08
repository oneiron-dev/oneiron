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
/// revision — once for a window update, once for a root update.
#[tokio::test]
async fn local_reactive_read_refreshes_on_matching_sync() {
    let dir = tempfile::tempdir().expect("temp vault dir");
    let vault = Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap());
    let learned_at = 1_770_000_000;
    let window_key = oneiron::sync::WindowKey::from_timestamp(learned_at);

    let window_id = seeded_test_entity_id(0x1437_0003);
    let (window_probe, window_reads) = reactive_probe(
        window_id,
        vec![ReactiveDependency::Window(window_key.as_str().to_owned())],
    );
    let root_id = seeded_test_entity_id(0x1437_0004);
    let (root_probe, root_reads) = reactive_probe(root_id, vec![ReactiveDependency::Root]);

    let (tx, _rx) = tokio::sync::broadcast::channel::<crate::server::BroadcastPayload>(8);
    let mut window_read = ReactiveLocalRead::open(Arc::clone(&vault), &tx, window_probe).unwrap();
    let mut root_read = ReactiveLocalRead::open(Arc::clone(&vault), &tx, root_probe).unwrap();
    assert!(window_read.snapshot().is_none());
    assert!(root_read.snapshot().is_none());

    seed_reactive_turn(&vault, &window_id, learned_at);
    seed_reactive_turn(&vault, &root_id, learned_at);
    crate::broadcast::broadcast(&tx, 0, reactive_window_update_frame(window_key.as_str()))
        .expect("broadcast window update");
    crate::broadcast::broadcast(&tx, 0, crate::protocol::encode_root_update(b"root-delta"))
        .expect("broadcast root update");

    assert!(
        window_read
            .refresh_on_change()
            .await
            .expect("window update refreshes")
            .is_some()
    );
    assert_eq!(window_read.revision(), 1);
    assert_eq!(reactive_reads(&window_reads), 2);

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
    crate::broadcast::broadcast(&tx, 0, reactive_window_update_frame(window_key.as_str()))
        .expect("broadcast window update");
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
async fn local_reactive_read_ignores_unrelated_window() {
    let dir = tempfile::tempdir().expect("temp vault dir");
    let vault = Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap());
    let learned_at = 1_770_000_000;
    let window_key = oneiron::sync::WindowKey::from_timestamp(learned_at);
    let other_window = "2026-03";
    assert_ne!(window_key.as_str(), other_window);
    let id = seeded_test_entity_id(0x1437_0006);

    let (tx, _rx) = tokio::sync::broadcast::channel::<crate::server::BroadcastPayload>(8);
    let (probe, reads) = reactive_probe(
        id,
        vec![ReactiveDependency::Window(window_key.as_str().to_owned())],
    );
    let mut read = ReactiveLocalRead::open(Arc::clone(&vault), &tx, probe).unwrap();

    crate::broadcast::broadcast(&tx, 0, reactive_window_update_frame(other_window))
        .expect("broadcast unrelated window update");
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(100),
            read.refresh_on_change()
        )
        .await
        .is_err(),
        "an update to a window this query does not read must not re-run it"
    );
    assert_eq!(reactive_reads(&reads), 1);

    seed_reactive_turn(&vault, &id, learned_at);
    crate::broadcast::broadcast(&tx, 0, reactive_window_update_frame(window_key.as_str()))
        .expect("broadcast matching window update");
    assert!(read.refresh_on_change().await.expect("refresh").is_some());
    assert_eq!(read.revision(), 1);
    assert_eq!(reactive_reads(&reads), 2);
}

/// Dropped notices degrade to extra work, never to stale data: the only frames
/// on this channel name a window the query does not read, so the refresh can
/// only be explained by the lag escalation itself.
#[tokio::test]
async fn local_reactive_read_recovers_from_lag() {
    let dir = tempfile::tempdir().expect("temp vault dir");
    let vault = Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap());
    let learned_at = 1_770_000_000;
    let window_key = oneiron::sync::WindowKey::from_timestamp(learned_at);
    let id = seeded_test_entity_id(0x1437_0007);

    let (tx, _rx) = tokio::sync::broadcast::channel::<crate::server::BroadcastPayload>(2);
    let (probe, reads) = reactive_probe(
        id,
        vec![ReactiveDependency::Window(window_key.as_str().to_owned())],
    );
    let mut read = ReactiveLocalRead::open(Arc::clone(&vault), &tx, probe).unwrap();
    assert!(read.snapshot().is_none());

    seed_reactive_turn(&vault, &id, learned_at);
    for _ in 0..5 {
        crate::broadcast::broadcast(&tx, 0, reactive_window_update_frame("2026-03"))
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
    let window_key = oneiron::sync::WindowKey::from_timestamp(learned_at);
    let id = seeded_test_entity_id(0x1437_0008);
    seed_reactive_turn(&vault, &id, learned_at);

    let (tx, _rx) = tokio::sync::broadcast::channel::<crate::server::BroadcastPayload>(8);
    let (probe, reads) = reactive_probe(
        id,
        vec![ReactiveDependency::Window(window_key.as_str().to_owned())],
    );
    let mut read = ReactiveLocalRead::open(Arc::clone(&vault), &tx, probe).unwrap();
    let mut websocket_subscriber = crate::broadcast::BroadcastSubscriber::new(7, &tx);

    crate::broadcast::broadcast(&tx, 0, reactive_window_update_frame(window_key.as_str()))
        .expect("bridge-origin frame");
    read.refresh_on_change().await.expect("bridge origin wakes");
    assert_eq!(read.revision(), 1);

    crate::broadcast::broadcast(&tx, 7, reactive_window_update_frame(window_key.as_str()))
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

/// Production wiring, end to end: a real LMDB write, mirrored into the window
/// by the engine's own LMDB→CRDT path, reaches a reactive read through
/// Observer A and the server's broadcast producer. No encoded frame is injected
/// anywhere in this fixture.
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
    let (probe, reads) = reactive_probe(
        id,
        vec![ReactiveDependency::Window(window_key.as_str().to_owned())],
    );
    let mut read = open_local_reactive_read(&server, probe).expect("open reactive read");
    assert!(read.snapshot().is_none());

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
}
