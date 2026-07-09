use super::*;
use crate::config::VaultConfig;
use crate::sync::bridge::Materializer;
use core::assert_matches;

fn test_manager() -> Arc<WindowManager> {
    let config = VaultConfig::device();
    let (_dir, vault) = crate::test_util::open_test_vault_with(config);
    let vault = Arc::new(vault);
    Arc::new(WindowManager::new(
        vault,
        Arc::new(Materializer::new()),
        "test-user",
    ))
}

#[test]
fn flush_to_queue_skips_invalid_window_keys() {
    let conn = SyncConnection::new(test_manager(), ConnectionConfig::default()).unwrap();
    let mut buffer = vec![
        LocalUpdate {
            window_key: "2026-13".to_string(),
            update_bytes: vec![1, 2, 3],
        },
        LocalUpdate {
            window_key: "2026-03".to_string(),
            update_bytes: vec![4, 5, 6],
        },
    ];

    flush_to_queue(conn.queue(), &mut buffer);

    let queued = conn.queue().drain_updates().unwrap();
    assert_eq!(queued.len(), 1);
    assert_eq!(queued[0].window_key, "2026-03");
    assert_eq!(queued[0].encoded, vec![4, 5, 6]);
}

#[tokio::test]
async fn queue_push_and_drain_roundtrip() {
    let conn = SyncConnection::new(
        test_manager(),
        ConnectionConfig {
            auto_reconnect: false,
            ..Default::default()
        },
    )
    .unwrap();

    // Push some updates to the queue to simulate offline state
    conn.queue().push("2026-03", &[10, 20]).unwrap();
    conn.queue().push("2026-03", &[30, 40]).unwrap();

    let updates = conn.queue().drain_updates().unwrap();
    assert_eq!(updates.len(), 2);
    assert_eq!(updates[0].encoded, vec![10, 20]);
    assert_eq!(updates[1].encoded, vec![30, 40]);
}

#[test]
fn queue_inspection_error_does_not_clear_queue() {
    let manager = test_manager();
    let conn = SyncConnection::new(Arc::clone(&manager), ConnectionConfig::default()).unwrap();
    let (mut client, _client_rx) = SyncClient::new(manager, SyncClientConfig::default()).unwrap();
    conn.queue().push("2026-03", &[1, 2, 3]).unwrap();
    client.ensure_window("2026-03").unwrap();

    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    conn.handle_queue_overflow_check(
        &mut client,
        &event_tx,
        Err(crate::error::Error::CorruptedIndex("sync queue metadata")),
    );

    assert_eq!(conn.queue().len().unwrap(), 1);
    assert!(
        client.window("2026-03").is_some(),
        "inspection error must not drop in-memory docs"
    );
    let event = event_rx.try_recv().unwrap();
    assert_matches!(event, SyncEvent::Error(msg) if msg.contains("Queue inspection failed"));
}

#[test]
fn convergence_round_propagates_invalid_window_key_without_frame() {
    let manager = test_manager();
    let (mut client, _client_rx) = SyncClient::new(manager, SyncClientConfig::default()).unwrap();
    let mut pending = BTreeSet::new();
    pending.insert("2026-003".to_string());
    let mut session = ConvergenceSession {
        pending,
        force_resync: BTreeSet::new(),
        max_seq: 0,
        rounds_started: 0,
    };

    assert_matches!(
        session.begin_round(&mut client),
        Err(TransportError::InvalidWindowKey)
    );
}

// ───────────────────────────────────────────────────────────────────────
// ONE-1128 — convergence protocol + real re-bootstrap (socket-free)
// ───────────────────────────────────────────────────────────────────────

use crate::sync::loro_support::export_updates_since;
use crate::sync::transport::{TAG_PROTOCOL_HELLO, TAG_VERSION_VECTOR, TAG_WINDOW_SYNC};
use loro::{ExportMode, LoroDoc, VersionVector};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};

const FULL_RESYNC_TEST_WINDOW: &str = "1970-01";
const DEFERRED_TOMBSTONE_KEY: &str = "0123456789abcdef0123456789abcdef";

/// Contract literal (ARCH-0023b Fig. 2): "Max 5 rounds before force
/// re-bootstrap". A drifted budget silently changes how long a GDPR
/// tombstone can sit unconfirmed before the queue is dropped.
#[test]
fn max_convergence_rounds_is_pinned_to_five() {
    assert_eq!(MAX_CONVERGENCE_ROUNDS, 5);
}

fn window_doc() -> LoroDoc {
    let doc = LoroDoc::new();
    let _ = doc.get_map("entities");
    let _ = doc.get_map("edges");
    let _ = doc.get_map("tombstones");
    doc.commit();
    doc
}

/// Server test double for socket-free convergence tests: one Loro doc
/// per window, answering SyncStep1/SyncStep2 the same way the production
/// peer does. `forget_window` simulates the lost-confirmation failure
/// mode the stub had no defense against: inbound UPDATE frames for that window
/// are silently dropped, never imported.
struct FakeServer {
    docs: HashMap<String, LoroDoc>,
    forget_window: Option<String>,
}

impl FakeServer {
    fn new() -> Self {
        Self {
            docs: HashMap::new(),
            forget_window: None,
        }
    }

    fn doc(&mut self, key: &str) -> &LoroDoc {
        self.docs.entry(key.to_string()).or_insert_with(window_doc)
    }

    fn handle(&mut self, frame: &[u8]) -> Vec<Vec<u8>> {
        match frame[0] {
            TAG_PROTOCOL_HELLO | TAG_VERSION_VECTOR => Vec::new(),
            TAG_WINDOW_SYNC => {
                let (key, sub_tag, payload) = transport::decode_window_sync(&frame[1..]).unwrap();
                let key = key.to_string();
                let forgets = self.forget_window.as_deref() == Some(key.as_str());
                let doc = self.doc(&key);
                match sub_tag {
                    window_sub_tags::UPDATE => {
                        if !forgets {
                            doc.import(payload).unwrap();
                        }
                        Vec::new()
                    }
                    window_sub_tags::VV_REQUEST => vec![
                        transport::encode_window_sync(
                            &key,
                            window_sub_tags::UPDATE,
                            &export_updates_since(doc, payload).unwrap(),
                        )
                        .into_result()
                        .unwrap(),
                        transport::encode_window_sync(
                            &key,
                            window_sub_tags::VV_RESPONSE,
                            &doc.oplog_vv().encode(),
                        )
                        .into_result()
                        .unwrap(),
                    ],
                    window_sub_tags::VV_RESPONSE => vec![
                        transport::encode_window_sync(
                            &key,
                            window_sub_tags::UPDATE,
                            &export_updates_since(doc, payload).unwrap(),
                        )
                        .into_result()
                        .unwrap(),
                    ],
                    other => panic!("unexpected sub tag {other}"),
                }
            }
            other => panic!("unexpected tag {other}"),
        }
    }
}

async fn spawn_fake_sync_server(
    mut server: FakeServer,
    close_on_forced_window: Option<&'static str>,
    forced_window_requests: Arc<AtomicUsize>,
) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        while let Some(msg) = ws.next().await {
            let Message::Binary(data) = msg.unwrap() else {
                continue;
            };
            let responses = match data[0] {
                TAG_PROTOCOL_HELLO => Vec::new(),
                transport::TAG_LEASE_REQUEST => {
                    let (client_id, _, _) = transport::decode_lease_request(&data[1..]).unwrap();
                    vec![transport::encode_lease_granted(
                        transport::LEASE_STATUS_GRANTED,
                        client_id,
                        1,
                    )]
                }
                TAG_VERSION_VECTOR => {
                    VersionVector::decode(&data[1..]).unwrap();
                    let mut response = vec![TAG_VERSION_VECTOR];
                    response.extend_from_slice(&VersionVector::new().encode());
                    vec![response]
                }
                TAG_WINDOW_SYNC => {
                    let (window_key, sub_tag, _) =
                        transport::decode_window_sync(&data[1..]).unwrap();
                    if window_key == FULL_RESYNC_TEST_WINDOW
                        && sub_tag == window_sub_tags::VV_REQUEST
                    {
                        forced_window_requests.fetch_add(1, Ordering::SeqCst);
                        if close_on_forced_window == Some(window_key) {
                            let _ = ws.close(None).await;
                            break;
                        }
                    }
                    server.handle(&data)
                }
                other => panic!("unexpected client tag {other}"),
            };
            for response in responses {
                ws.send(Message::Binary(response.into())).await.unwrap();
            }
        }
    });
    (format!("ws://{addr}"), handle)
}

/// Drives client→server frames and all transitive replies to quiescence
/// — the socket-free equivalent of one `pump_server_frames` burst.
fn exchange(server: &mut FakeServer, client: &mut SyncClient, frames: Vec<Vec<u8>>) {
    let mut to_server = frames;
    while !to_server.is_empty() {
        let mut to_client = Vec::new();
        for frame in &to_server {
            to_client.extend(server.handle(frame));
        }
        let mut next = Vec::new();
        for frame in &to_client {
            next.extend(client.handle_server_message(frame).unwrap());
        }
        to_server = next;
    }
}

/// Builds the offline-writes fixture: window A carries a DELETE-BEARING
/// update (tombstones-map insert), window B a plain entity write. Both
/// are pushed to the persistent queue, exactly like a disconnect flush.
fn seed_offline_queue(conn: &SyncConnection) -> Vec<QueuedUpdate> {
    let writer_a = window_doc();
    writer_a
        .get_map("tombstones")
        .insert("victim-entity", b"t".as_slice())
        .unwrap();
    writer_a.commit();
    let writer_b = window_doc();
    writer_b
        .get_map("entities")
        .insert("new-entity", b"payload".as_slice())
        .unwrap();
    writer_b.commit();

    conn.queue()
        .push(
            "2026-03",
            &writer_a.export(ExportMode::all_updates()).unwrap(),
        )
        .unwrap();
    conn.queue()
        .push(
            "2026-04",
            &writer_b.export(ExportMode::all_updates()).unwrap(),
        )
        .unwrap();
    conn.queue().drain_updates().unwrap()
}

/// Replays the queue the way `connect_and_sync` does: import into the
/// local doc, then ship the raw update to the (fake) server.
fn replay(queued: &[QueuedUpdate], client: &mut SyncClient, server: &mut FakeServer) {
    for update in queued {
        client
            .import_queued_update(&update.window_key, &update.encoded)
            .unwrap();
        let frame = transport::encode_window_sync(
            &update.window_key,
            window_sub_tags::UPDATE,
            &update.encoded,
        );
        assert!(server.handle(&frame).is_empty());
    }
}

/// AC1 + AC5 (ONE-1128): offline writes → reconnect replay → one
/// bidirectional VV round → ALL windows VV-confirmed → queue cleared via
/// `clear_through_confirmed`. The pre-clear assertion pins that nothing
/// is cleared before confirmation (the old stub cleared unconditionally).
#[test]
fn convergence_clears_queue_only_after_all_windows_vv_confirm() {
    let manager = test_manager();
    let conn = SyncConnection::new(Arc::clone(&manager), ConnectionConfig::default()).unwrap();
    let (mut client, _rx) =
        SyncClient::new(Arc::clone(&manager), SyncClientConfig::default()).unwrap();
    let mut server = FakeServer::new();

    let queued = seed_offline_queue(&conn);
    assert_eq!(queued.len(), 2);
    replay(&queued, &mut client, &mut server);

    let mut session = ConvergenceSession::from_queued(&queued);
    assert!(!session.all_converged());

    let frames = session
        .begin_round(&mut client)
        .unwrap()
        .expect("round 1 is within budget");
    assert_eq!(frames.len(), 2, "one SyncStep1 per replayed window");

    // Queue must remain intact until confirmation lands.
    assert_eq!(conn.queue().len().unwrap(), 2);

    exchange(&mut server, &mut client, frames);
    session.note_progress(&client);

    assert!(
        session.all_converged(),
        "honest server must confirm in round 1"
    );
    assert_eq!(session.rounds_started, 1);

    // ONLY now: the driver's clear_through_confirmed call (every window
    // is VV-confirmed, so delete-bearing rows are cleared too).
    conn.queue()
        .clear_through_confirmed(session.max_seq)
        .unwrap();
    assert_eq!(conn.queue().len().unwrap(), 0);

    // Deep convergence on both windows, including the tombstone.
    for key in ["2026-03", "2026-04"] {
        assert_eq!(
            client.window(key).unwrap().doc.get_deep_value(),
            server.doc(key).get_deep_value(),
            "window {key} must deep-converge"
        );
    }
    let server_tombstones = server.doc("2026-03").get_map("tombstones");
    assert!(
        server_tombstones.get("victim-entity").is_some(),
        "the delete-bearing update must have reached the server"
    );
}

#[test]
fn full_resync_marker_is_never_dropped_by_vv_equality() {
    let manager = test_manager();
    let (mut client, _rx) =
        SyncClient::new(Arc::clone(&manager), SyncClientConfig::default()).unwrap();
    let mut server = FakeServer::new();
    let mut force_resync = BTreeSet::new();
    force_resync.insert(FULL_RESYNC_TEST_WINDOW.to_string());

    let mut session = ConvergenceSession::from_queued_with_force(&[], &force_resync);
    for round in 1..=MAX_CONVERGENCE_ROUNDS {
        let frames = session
            .begin_round(&mut client)
            .unwrap()
            .expect("forced rounds stay within budget");
        exchange(&mut server, &mut client, frames);
        assert_eq!(
            client.window_converged(FULL_RESYNC_TEST_WINDOW),
            Some(true),
            "fixture should prove VV equality would otherwise drop the window"
        );
        session.note_progress(&client);
        assert!(
            !session.all_converged(),
            "round {round}: fr:w window must stay pending despite VV equality"
        );
    }
    assert!(
        session.begin_round(&mut client).unwrap().is_none(),
        "forced fr:w window must exhaust into re-bootstrap"
    );
}

#[tokio::test]
async fn full_resync_marker_recovers_deferred_post_delete_op() {
    let manager = test_manager();
    let vault = Arc::clone(manager.vault());
    let marker_key = format!("fr:w:{FULL_RESYNC_TEST_WINDOW}");
    vault.sync_state_put(&marker_key, &[1u8]).unwrap();

    let mut server = FakeServer::new();
    server
        .doc(FULL_RESYNC_TEST_WINDOW)
        .get_map("tombstones")
        .insert(DEFERRED_TOMBSTONE_KEY, b"t".as_slice())
        .unwrap();
    server.doc(FULL_RESYNC_TEST_WINDOW).commit();

    let forced_window_requests = Arc::new(AtomicUsize::new(0));
    let (server_url, server_task) =
        spawn_fake_sync_server(server, None, Arc::clone(&forced_window_requests)).await;
    let conn = SyncConnection::new(
        Arc::clone(&manager),
        ConnectionConfig {
            client_config: SyncClientConfig {
                server_url,
                ..Default::default()
            },
            auto_reconnect: false,
        },
    )
    .unwrap();
    let (mut client, _rx) =
        SyncClient::new(Arc::clone(&manager), SyncClientConfig::default()).unwrap();
    let (event_tx, _event_rx) = mpsc::unbounded_channel();

    let ws_stream = conn.connect_and_sync(&mut client, &event_tx).await.unwrap();
    drop(ws_stream);
    server_task.abort();

    assert!(
        forced_window_requests.load(Ordering::SeqCst) >= 1,
        "connect-time fr:w consumer must request the marked historical window"
    );
    let recovered = client
        .window(FULL_RESYNC_TEST_WINDOW)
        .expect("forced re-bootstrap must load the marked window");
    assert!(
        recovered
            .doc
            .get_map("tombstones")
            .get(DEFERRED_TOMBSTONE_KEY)
            .is_some(),
        "deferred post-delete op must be present locally after this connect"
    );
    assert!(
        vault.sync_state_get(&marker_key).unwrap().is_none(),
        "fr:w marker clears only after successful re-bootstrap"
    );
}

#[tokio::test]
async fn full_resync_marker_retained_when_rebootstrap_errors() {
    let manager = test_manager();
    let vault = Arc::clone(manager.vault());
    let marker_key = format!("fr:w:{FULL_RESYNC_TEST_WINDOW}");
    vault.sync_state_put(&marker_key, &[1u8]).unwrap();

    let forced_window_requests = Arc::new(AtomicUsize::new(0));
    let (server_url, server_task) = spawn_fake_sync_server(
        FakeServer::new(),
        Some(FULL_RESYNC_TEST_WINDOW),
        Arc::clone(&forced_window_requests),
    )
    .await;
    let conn = SyncConnection::new(
        Arc::clone(&manager),
        ConnectionConfig {
            client_config: SyncClientConfig {
                server_url,
                ..Default::default()
            },
            auto_reconnect: false,
        },
    )
    .unwrap();
    let (mut client, _rx) =
        SyncClient::new(Arc::clone(&manager), SyncClientConfig::default()).unwrap();
    let (event_tx, _event_rx) = mpsc::unbounded_channel();

    let result = conn.connect_and_sync(&mut client, &event_tx).await;
    server_task.abort();

    assert!(
        result.is_err(),
        "server close during forced re-bootstrap must fail the connect"
    );
    assert_eq!(
        forced_window_requests.load(Ordering::SeqCst),
        1,
        "failure must happen during the forced fr:w request"
    );
    assert_eq!(
        vault.sync_state_get(&marker_key).unwrap().as_deref(),
        Some([1u8].as_slice()),
        "fr:w marker must remain set so the next connect retries"
    );
}

/// AC2 + AC4 + AC5 variant (ONE-1128): the server 'forgets' the
/// delete-bearing update (lost confirmation). The tombstone window must
/// NEVER confirm, the queue must NOT be cleared, the round counter must
/// walk to 5, and round 6 must road-block into the re-bootstrap path.
/// This test FAILS against the old stub, which cleared unconditionally.
#[test]
fn forgetful_server_blocks_clear_and_round_six_forces_re_bootstrap() {
    let manager = test_manager();
    let vault = Arc::clone(manager.vault());
    let conn = SyncConnection::new(Arc::clone(&manager), ConnectionConfig::default()).unwrap();
    let (mut client, _rx) =
        SyncClient::new(Arc::clone(&manager), SyncClientConfig::default()).unwrap();
    let mut server = FakeServer::new();
    server.forget_window = Some("2026-03".to_string());

    let queued = seed_offline_queue(&conn);
    replay(&queued, &mut client, &mut server);

    let mut session = ConvergenceSession::from_queued(&queued);
    for round in 1..=MAX_CONVERGENCE_ROUNDS {
        let frames = session
            .begin_round(&mut client)
            .unwrap()
            .expect("rounds 1-5 are within budget");
        if round > 1 {
            assert_eq!(
                frames.len(),
                1,
                "round {round}: only the unconfirmed tombstone window re-requests"
            );
        }
        exchange(&mut server, &mut client, frames);
        session.note_progress(&client);
        assert!(
            !session.all_converged(),
            "round {round}: forgotten tombstone window must NOT confirm"
        );
        assert_eq!(session.rounds_started, round);
    }

    // AC4: the queued tombstone update survives until ITS window
    // converges — nothing was cleared.
    let remaining = conn.queue().drain_updates().unwrap();
    assert_eq!(remaining.len(), 2, "queue must be fully intact");
    assert!(
        remaining.iter().any(|u| u.window_key == "2026-03"),
        "the delete-bearing row must still be queued"
    );

    // Round 6: budget exhausted → re-bootstrap signal.
    assert!(
        session.begin_round(&mut client).unwrap().is_none(),
        "round 6 must refuse and signal re-bootstrap"
    );

    // Pre-seed the protected row families before the re-bootstrap clear.
    let sweep_key = b"h:synthetic-sweep".to_vec();
    let exemption_key = b"x:synthetic-exemption".to_vec();
    {
        let mut wtxn = vault.store.env.write_txn().unwrap();
        vault
            .store
            .sync_queue
            .put(&mut wtxn, &sweep_key, &[7u8])
            .unwrap();
        vault
            .store
            .sync_queue
            .put(&mut wtxn, &exemption_key, &[9u8])
            .unwrap();
        wtxn.commit().unwrap();
    }

    // The REAL re-bootstrap local half (same path the socket driver takes).
    let frames = conn
        .re_bootstrap_local_state(&mut client, &BTreeSet::new())
        .unwrap();

    // Docs dropped.
    assert!(
        client.window("2026-03").is_none(),
        "re-bootstrap must drop in-memory window docs"
    );
    assert!(client.window("2026-04").is_none());

    // q: rows cleared; h:/m:/x: families preserved.
    assert_eq!(conn.queue().len().unwrap(), 0);
    let rtxn = vault.store.env.read_txn().unwrap();
    assert_eq!(
        vault.store.sync_queue.get(&rtxn, &sweep_key).unwrap(),
        Some([7u8].as_slice()),
        "h:* sweep rows must survive re-bootstrap (ARCH-0038 Art.17 SLA)"
    );
    assert_eq!(
        vault.store.sync_queue.get(&rtxn, &exemption_key).unwrap(),
        Some([9u8].as_slice()),
        "x:* rows must survive re-bootstrap"
    );
    assert_eq!(
        vault
            .store
            .sync_queue
            .get(&rtxn, b"m:last_update_seq".as_slice())
            .unwrap(),
        Some(2u64.to_le_bytes().as_slice()),
        "m:* sequence cursor must survive re-bootstrap"
    );
    drop(rtxn);

    // Phase 1-3 frames: root VV (EMPTY — docs really dropped) + default
    // window VV requests, and NO per-connection hello.
    let protocol_hello = transport::encode_protocol_hello();
    assert!(
        frames.iter().all(|f| f != &protocol_hello),
        "re-bootstrap must not re-send the protocol hello"
    );
    assert_eq!(frames[0][0], TAG_VERSION_VECTOR);
    assert_eq!(
        VersionVector::decode(&frames[0][1..]).unwrap(),
        VersionVector::new(),
        "re-bootstrap root VV must be empty"
    );
    assert_eq!(frames.len(), 3, "root VV + 2 default-window VV requests");
    for frame in &frames[1..] {
        assert_eq!(frame[0], TAG_WINDOW_SYNC);
        let (k, sub_tag, payload) = transport::decode_window_sync(&frame[1..]).unwrap();
        assert_eq!(sub_tag, window_sub_tags::VV_REQUEST);
        assert!(parse_window_key_str(k).is_some());
        VersionVector::decode(payload).expect("window VV must be Loro binary encoding");
    }
}

/// AC3 (ONE-1128): queue overflow triggers the SAME real re-bootstrap —
/// docs dropped + queue cleared (h:/m:/x: preserved); Phase 1-3 then
/// re-runs naturally on the next connect.
#[test]
fn queue_overflow_triggers_real_re_bootstrap() {
    let manager = test_manager();
    let vault = Arc::clone(manager.vault());
    let conn = SyncConnection::new(Arc::clone(&manager), ConnectionConfig::default()).unwrap();
    let (mut client, _rx) =
        SyncClient::new(Arc::clone(&manager), SyncClientConfig::default()).unwrap();

    conn.queue().push("2026-03", &[1, 2, 3]).unwrap();
    client.ensure_window("2026-03").unwrap();
    let exemption_key = b"x:synthetic-exemption".to_vec();
    {
        let mut wtxn = vault.store.env.write_txn().unwrap();
        vault
            .store
            .sync_queue
            .put(&mut wtxn, &exemption_key, &[9u8])
            .unwrap();
        wtxn.commit().unwrap();
    }

    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    conn.handle_queue_overflow_check(&mut client, &event_tx, Ok(true));

    assert_eq!(conn.queue().len().unwrap(), 0, "q: rows must be cleared");
    assert!(
        client.window("2026-03").is_none(),
        "overflow re-bootstrap must drop in-memory docs"
    );
    let rtxn = vault.store.env.read_txn().unwrap();
    assert_eq!(
        vault.store.sync_queue.get(&rtxn, &exemption_key).unwrap(),
        Some([9u8].as_slice()),
        "x:* rows must survive the overflow re-bootstrap"
    );
    drop(rtxn);

    let event = event_rx.try_recv().unwrap();
    assert_matches!(event, SyncEvent::Error(msg) if msg.contains("re-bootstrap"));
}
