use super::*;
use crate::config::VaultConfig;
use crate::sync::bridge::Materializer;
use core::assert_matches;
use std::time::Duration;

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

use crate::sync::loro_support::{export_updates_since, replicated_deep_value};
use crate::sync::transport::{TAG_PROTOCOL_HELLO, TAG_VERSION_VECTOR, TAG_WINDOW_SYNC};
use loro::{ExportMode, LoroDoc, VersionVector};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};

// An EMPTY historical window: ONE-1890's seeded AGENT_DEF rows occupy the
// timestamp-0 window ("1970-01"), and this fixture needs one with no local
// content so VV equality holds.
const FULL_RESYNC_TEST_WINDOW: &str = "1971-01";
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

#[tokio::test]
async fn sync_socket_disconnect_and_restart_do_not_fail_over_macro_home() {
    use crate::dreamer_runner::{
        AdmitDreamerAttempt, AdmitDreamerConsolidationAttempt, DreamerAdmissionOutcome,
        DreamerClaimAuthoringAdmission, DreamerClaimAuthoringBatchTier,
        DreamerConsolidationAdmissionOutcome, DreamerConsolidationScope, DreamerHomeNodeCandidate,
        DreamerRunnerStore, EnqueueDreamerConsolidationAttempt,
    };

    let manager = test_manager();
    let runner = DreamerRunnerStore::new(manager.vault());
    let local = runner.local_home_node_candidate(true, true, false).unwrap();
    let cloud = DreamerHomeNodeCandidate::cloud(
        if local.node_id == u64::MAX {
            1
        } else {
            local.node_id + 1
        },
        true,
    );
    let admission = |now| {
        runner
            .admit_next_consolidation(AdmitDreamerConsolidationAttempt {
                scope: DreamerConsolidationScope::Macro,
                local_node_id: local.node_id,
                claim_authoring_tier: DreamerClaimAuthoringBatchTier::batch(),
                claim_authoring: DreamerClaimAuthoringAdmission::single_pass(),
                admission: AdmitDreamerAttempt {
                    lease_owner: "local".to_owned(),
                    now,
                    budget_id: "topology-test".to_owned(),
                    budget_total_units: 10,
                    reserve_units: 1,
                    started_milestone: None,
                },
            })
            .unwrap()
    };
    let queued = runner
        .enqueue_consolidation(EnqueueDreamerConsolidationAttempt {
            scope: DreamerConsolidationScope::Macro,
            input: rmpv::Value::from("topology-test"),
            parent_attempt: None,
            dedupe_key: None,
            run_id: None,
            now: 1,
        })
        .unwrap();
    let attempt_id = match queued {
        crate::dreamer_runner::EnqueueDreamerAttemptOutcome::Enqueued(status)
        | crate::dreamer_runner::EnqueueDreamerAttemptOutcome::Existing(status) => {
            status.attempt.id
        }
    };

    // The host's feed, not an election call in this test, owns membership.
    let detached = DreamerHomeNodeCandidate::cloud(cloud.node_id, false);
    let topology = HomeNodeTopology::new(vec![local, detached]);
    let mut designated = None;
    for round in 0..2 {
        let (server_url, server_task) =
            spawn_fake_sync_server(FakeServer::new(), None, Arc::new(AtomicUsize::new(0))).await;
        let conn = SyncConnection::new(
            Arc::clone(&manager),
            ConnectionConfig {
                client_config: SyncClientConfig {
                    server_url,
                    home_node_topology: Some(topology.clone()),
                    ..Default::default()
                },
                auto_reconnect: false,
            },
        )
        .unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let running = tokio::spawn(async move { conn.run(shutdown_rx).await.unwrap() });
        tokio::time::sleep(Duration::from_secs(1)).await;
        if round == 0 {
            assert_eq!(
                runner.home_node_designation().unwrap().unwrap().node_id,
                local.node_id,
                "initial detached cloud leaves always-on local home"
            );
            topology.publish(vec![local, cloud]);
            tokio::time::timeout(Duration::from_secs(15), async {
                loop {
                    if runner
                        .home_node_designation()
                        .unwrap()
                        .is_some_and(|home| home.node_id == cloud.node_id)
                    {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("host attach must elect cloud during the live connection");
            designated = runner.home_node_designation().unwrap();
            assert_eq!(
                admission(11),
                DreamerConsolidationAdmissionOutcome::NotHomeNode(designated.unwrap())
            );
            // Lose the server unexpectedly while the cloud remains home.
            server_task.abort();
        } else {
            assert_eq!(runner.home_node_designation().unwrap(), designated);
            assert_eq!(
                admission(12),
                DreamerConsolidationAdmissionOutcome::NotHomeNode(designated.unwrap())
            );
            // Only a new host-authored topology snapshot may promote local.
            topology.publish(vec![local, detached]);
            tokio::time::timeout(Duration::from_secs(15), async {
                loop {
                    if runner
                        .home_node_designation()
                        .unwrap()
                        .is_some_and(|home| home.node_id == local.node_id)
                    {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("host detach must elect local during the live connection");
            assert!(matches!(
                admission(21),
                DreamerConsolidationAdmissionOutcome::Admission(DreamerAdmissionOutcome::Admitted(
                    _
                ))
            ));
            shutdown_tx.send(()).unwrap();
        }
        let mut events = tokio::time::timeout(Duration::from_secs(15), running)
            .await
            .expect("sync connection must shut down")
            .unwrap();
        server_task.abort();
        let mut saw_synced = false;
        let mut saw_disconnected = false;
        let mut saw_socket_error = false;
        while let Ok(event) = events.try_recv() {
            match event {
                SyncEvent::StatusChanged(crate::sync::client::SyncStatus::Synced) => {
                    saw_synced = true;
                }
                SyncEvent::StatusChanged(crate::sync::client::SyncStatus::Disconnected) => {
                    saw_disconnected = true;
                }
                SyncEvent::Error(message) if message.contains("WebSocket disconnected") => {
                    saw_socket_error = true;
                }
                _ => {}
            }
        }
        assert!(
            saw_synced && saw_disconnected,
            "round {round}: real socket lifecycle"
        );
        if round == 0 {
            assert!(
                saw_socket_error,
                "network loss must reach the disconnect branch"
            );
            assert_eq!(runner.home_node_designation().unwrap(), designated);
            assert_eq!(
                admission(13),
                DreamerConsolidationAdmissionOutcome::NotHomeNode(designated.unwrap())
            );
            assert_eq!(
                runner.status(attempt_id).unwrap().unwrap().attempt.state,
                crate::attempt_queue::AttemptState::Queued
            );
        }
    }
    assert_eq!(
        runner.home_node_designation().unwrap().unwrap().node_id,
        local.node_id
    );
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
            replicated_deep_value(&client.window(key).unwrap().doc),
            replicated_deep_value(server.doc(key)),
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
        vault
            .store
            .sync_queue
            .get(&rtxn, &sweep_key)
            .unwrap()
            .as_deref(),
        Some([7u8].as_slice()),
        "h:* sweep rows must survive re-bootstrap (ARCH-0038 Art.17 SLA)"
    );
    assert_eq!(
        vault
            .store
            .sync_queue
            .get(&rtxn, &exemption_key)
            .unwrap()
            .as_deref(),
        Some([9u8].as_slice()),
        "x:* rows must survive re-bootstrap"
    );
    assert_eq!(
        vault
            .store
            .sync_queue
            .get(&rtxn, b"m:last_update_seq".as_slice())
            .unwrap()
            .as_deref(),
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
        vault
            .store
            .sync_queue
            .get(&rtxn, &exemption_key)
            .unwrap()
            .as_deref(),
        Some([9u8].as_slice()),
        "x:* rows must survive the overflow re-bootstrap"
    );
    drop(rtxn);

    let event = event_rx.try_recv().unwrap();
    assert_matches!(event, SyncEvent::Error(msg) if msg.contains("re-bootstrap"));
}

#[tokio::test]
async fn out_of_order_window_delta_disconnects_instead_of_losing_the_update() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let source = window_doc();
    source
        .get_map("entities")
        .insert("prefix", b"first".as_slice())
        .unwrap();
    source.commit();
    let prefix_vv = source.oplog_vv();
    source
        .get_map("entities")
        .insert("later", b"second".as_slice())
        .unwrap();
    source.commit();
    let missing_prefix = source.export(ExportMode::updates(&prefix_vv)).unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        let frame =
            transport::encode_window_sync("2026-03", window_sub_tags::UPDATE, &missing_prefix)
                .into_result()
                .unwrap();
        ws.send(Message::Binary(frame.into())).await.unwrap();
    });
    let (ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}"))
        .await
        .unwrap();
    let manager = test_manager();
    let conn = SyncConnection::new(
        manager.clone(),
        ConnectionConfig {
            auto_reconnect: false,
            ..Default::default()
        },
    )
    .unwrap();
    let (mut client, _) = SyncClient::new(manager.clone(), SyncClientConfig::default()).unwrap();
    let (event_tx, mut events) = mpsc::unbounded_channel();
    let (_local_tx, mut local_rx) = mpsc::unbounded_channel();
    let (_shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel();
    let outcome = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        conn.steady_state(ws, &mut client, &event_tx, &mut local_rx, &mut shutdown_rx),
    )
    .await
    .unwrap();
    assert!(matches!(outcome, LoopExit::Disconnected(_)));
    assert_matches!(events.try_recv(), Ok(SyncEvent::Error(_)));
    assert!(
        manager
            .vault()
            .sync_state_keys_with_prefix("u:w:2026-03:")
            .unwrap()
            .is_empty()
    );
    server.await.unwrap();
}
