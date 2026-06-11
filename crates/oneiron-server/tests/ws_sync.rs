//! WebSocket integration tests for the sync server (ONE-1129).
//!
//! Covers the M4 server-durability + auth acceptance criteria:
//! - `/ws` upgrade auth (Phase-1 shared secret, fail-closed when configured)
//! - update relay between two live clients + sync_state durability literals
//! - restart durability: a relayed update AND a relayed tombstone survive a
//!   server restart (the cross-device delete-propagation case)
//! - oversized updates are rejected before any state mutates
//! - the client (`SyncConnection`) sends `SyncClientConfig.auth_token` on the
//!   upgrade request
//!
//! Restart is simulated by dropping the `SyncServer` (all in-RAM Loro Docs)
//! and constructing a new one over the same vault: the durability property
//! under test is exactly "state must round-trip through sync_state".
//! Full-suite re-scope stays ONE-474.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use loro::{ExportMode, LoroDoc};
use oneiron::sync::transport::{self, TAG_SYNC_UPDATE, TAG_WINDOW_SYNC, window_sub_tags};
use oneiron::sync::{
    ConnectionConfig, SyncClient, SyncClientConfig, SyncConnection, SyncEvent, SyncStatus,
};
use oneiron_server::build_app;
use oneiron_server::config::SyncServerConfig;
use oneiron_server::server::SyncServer;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

type WsStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

fn open_vault(dir: &std::path::Path) -> Arc<oneiron::Vault> {
    Arc::new(oneiron::Vault::open(dir, oneiron::VaultConfig::device()).unwrap())
}

fn config_with_secret(secret: Option<&str>) -> SyncServerConfig {
    SyncServerConfig {
        auth_secret: secret.map(str::to_string),
        ..Default::default()
    }
}

async fn spawn_server(
    vault: Arc<oneiron::Vault>,
    config: SyncServerConfig,
) -> (SocketAddr, Arc<SyncServer>, tokio::task::JoinHandle<()>) {
    let server = Arc::new(SyncServer::new(vault, config).unwrap());
    let app = build_app(server.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (addr, server, handle)
}

async fn connect(
    addr: SocketAddr,
    secret: Option<&str>,
) -> Result<WsStream, tokio_tungstenite::tungstenite::Error> {
    let url = format!("ws://{addr}/ws");
    let mut request = url.into_client_request().unwrap();
    if let Some(secret) = secret {
        request
            .headers_mut()
            .insert("x-oneiron-secret", secret.parse().unwrap());
    }
    tokio_tungstenite::connect_async(request)
        .await
        .map(|(ws, _resp)| ws)
}

async fn next_binary(ws: &mut WsStream) -> Vec<u8> {
    loop {
        let msg = tokio::time::timeout(Duration::from_secs(10), ws.next())
            .await
            .expect("timed out waiting for a WebSocket message")
            .expect("WebSocket stream ended unexpectedly")
            .expect("WebSocket error");
        match msg {
            Message::Binary(data) => return data.to_vec(),
            Message::Ping(_) | Message::Pong(_) => continue,
            other => panic!("unexpected WebSocket message: {other:?}"),
        }
    }
}

/// Polls sync_state until `key` exists (persistence is synchronous in the
/// handler, but the client send is fire-and-forget, so the test must wait
/// for the server task to process the frame).
async fn wait_for_sync_state_key(vault: &oneiron::Vault, key: &str) {
    for _ in 0..250 {
        if vault.sync_state_get(key).unwrap().is_some() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("timed out waiting for sync_state key {key}");
}

fn assert_unauthorized(err: &tokio_tungstenite::tungstenite::Error) {
    match err {
        tokio_tungstenite::tungstenite::Error::Http(response) => {
            assert_eq!(
                response.status(),
                401,
                "expected HTTP 401 Unauthorized, got {}",
                response.status()
            );
        }
        other => panic!("expected HTTP 401 rejection, got {other:?}"),
    }
}

fn deep_map_bytes(doc: &LoroDoc, map: &str, key: &str) -> Option<Vec<u8>> {
    let deep = doc.get_deep_value();
    let root = deep.as_map()?;
    let inner = root.get(map)?.as_map()?;
    let value = inner.get(key)?.as_binary()?;
    Some(value.to_vec())
}

// ─── /ws auth ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn ws_upgrade_rejects_unauthenticated_when_secret_configured() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, _server, handle) = spawn_server(
        open_vault(dir.path()),
        config_with_secret(Some("test-secret-aaaa")),
    )
    .await;

    // Missing header → 401 before upgrade (fail-closed).
    let err = connect(addr, None).await.unwrap_err();
    assert_unauthorized(&err);

    // Wrong secret of the SAME length → 401 (exercises the constant-time
    // comparison branch, not just the length check).
    let err = connect(addr, Some("test-secret-bbbb")).await.unwrap_err();
    assert_unauthorized(&err);

    // Correct secret → upgrade succeeds and the Phase-1 root snapshot
    // (TAG_SYNC_UPDATE) arrives.
    let mut ws = connect(addr, Some("test-secret-aaaa")).await.unwrap();
    let first = next_binary(&mut ws).await;
    assert_eq!(first[0], TAG_SYNC_UPDATE);

    handle.abort();
}

#[tokio::test]
async fn ws_upgrade_allows_unauthenticated_only_in_dev_mode() {
    // No secret configured = dev mode (same semantics as api::check_auth).
    let dir = tempfile::tempdir().unwrap();
    let (addr, _server, handle) =
        spawn_server(open_vault(dir.path()), config_with_secret(None)).await;

    let mut ws = connect(addr, None).await.unwrap();
    let first = next_binary(&mut ws).await;
    assert_eq!(first[0], TAG_SYNC_UPDATE);

    handle.abort();
}

// ─── Update relay + durability ────────────────────────────────────────────────

#[tokio::test]
async fn imported_update_relays_to_second_client_and_persists_contract_keys() {
    let dir = tempfile::tempdir().unwrap();
    let vault = open_vault(dir.path());
    let (addr, server, handle) =
        spawn_server(vault.clone(), config_with_secret(Some("relay-secret"))).await;

    let mut client_a = connect(addr, Some("relay-secret")).await.unwrap();
    let mut client_b = connect(addr, Some("relay-secret")).await.unwrap();
    // Drain the Phase-1 root snapshot on both connections; once B has its
    // snapshot, B's broadcast subscription is live.
    let _ = next_binary(&mut client_a).await;
    let _ = next_binary(&mut client_b).await;

    // Author an update in a local Loro doc.
    let author = LoroDoc::new();
    author
        .get_map("entities")
        .insert("e-relay", b"relay-payload".as_slice())
        .unwrap();
    author.commit();
    let update = author.export(ExportMode::all_updates()).unwrap();

    let msg = transport::encode_window_sync("2026-02", window_sub_tags::UPDATE, &update);
    client_a.send(Message::Binary(msg.into())).await.unwrap();

    // B receives the relayed WindowSync UPDATE with the exact payload.
    let relayed = next_binary(&mut client_b).await;
    assert_eq!(relayed[0], TAG_WINDOW_SYNC);
    let (key, sub_tag, payload) = transport::decode_window_sync(&relayed[1..]).unwrap();
    assert_eq!(key, "2026-02");
    assert_eq!(sub_tag, window_sub_tags::UPDATE);
    assert_eq!(payload, update.as_slice());

    // Durability: the imported update was persisted under the ARCH-0023b
    // sync_state key layout BEFORE it was broadcast — so by the time B holds
    // the relay, the bytes are on disk.
    let vault = server.vault();
    assert!(
        vault.sync_state_get("d:w:2026-02").unwrap().is_some(),
        "window snapshot d:w:2026-02 must exist"
    );
    assert_eq!(
        vault
            .sync_state_get("u:w:2026-02:00000001")
            .unwrap()
            .unwrap(),
        update,
        "imported update bytes must be appended at u:w:2026-02:00000001"
    );
    assert_eq!(
        vault.sync_state_get("m:u_seq:w:2026-02").unwrap().unwrap(),
        1u32.to_le_bytes(),
        "m:u_seq:w:2026-02 must be a u32 LE counter at 1"
    );
    assert_eq!(
        vault.sync_state_get("svf:w:2026-02").unwrap().unwrap(),
        vec![0u8],
        "svf:w:2026-02 must be marked stale (0) after an appended update"
    );
    assert!(
        vault.sync_state_get("d:root").unwrap().is_some(),
        "root snapshot d:root must exist"
    );

    handle.abort();
}

#[tokio::test]
async fn relayed_update_and_tombstone_survive_server_restart() {
    let dir = tempfile::tempdir().unwrap();
    let vault = open_vault(dir.path());

    // ── Session 1: client A relays an entity update, then a tombstone.
    let (addr, server1, handle1) =
        spawn_server(vault.clone(), config_with_secret(Some("restart-secret"))).await;
    let mut client_a = connect(addr, Some("restart-secret")).await.unwrap();
    let _ = next_binary(&mut client_a).await; // root snapshot

    let author = LoroDoc::new();
    author
        .get_map("entities")
        .insert("e-durable", b"survives".as_slice())
        .unwrap();
    author.commit();
    let entity_update = author.export(ExportMode::all_updates()).unwrap();
    let msg = transport::encode_window_sync("2026-02", window_sub_tags::UPDATE, &entity_update);
    client_a.send(Message::Binary(msg.into())).await.unwrap();

    // The delete-propagation case: a TOMBSTONE relayed through the server
    // must survive a restart, or durable cross-device delete propagation is
    // impossible.
    let vv_before_tombstone = author.oplog_vv();
    author
        .get_map("tombstones")
        .insert("e-deleted", b"1".as_slice())
        .unwrap();
    author.commit();
    let tombstone_update = author
        .export(ExportMode::updates(&vv_before_tombstone))
        .unwrap();
    let msg = transport::encode_window_sync("2026-02", window_sub_tags::UPDATE, &tombstone_update);
    client_a.send(Message::Binary(msg.into())).await.unwrap();

    // Wait until both updates are durable, then "restart": kill the server
    // task and drop ALL in-RAM CRDT state.
    wait_for_sync_state_key(&vault, "u:w:2026-02:00000002").await;
    let _ = client_a.close(None).await;
    handle1.abort();
    drop(server1);

    // ── Session 2: a fresh SyncServer over the same vault.
    let (addr2, _server2, handle2) =
        spawn_server(vault.clone(), config_with_secret(Some("restart-secret"))).await;
    let mut client_b = connect(addr2, Some("restart-secret")).await.unwrap();

    // The reloaded root doc still announces the window — decoded through the
    // REAL client path (SyncClient::server_windows, client.rs read path).
    let root_msg = next_binary(&mut client_b).await;
    assert_eq!(root_msg[0], TAG_SYNC_UPDATE);
    let client_dir = tempfile::tempdir().unwrap();
    let client_vault = open_vault(client_dir.path());
    let (mut sync_client, _events) = SyncClient::new(client_vault, SyncClientConfig::default());
    sync_client.handle_server_message(&root_msg).unwrap();
    assert_eq!(
        sync_client.server_windows(),
        vec!["2026-02".to_string()],
        "restarted server must still announce the persisted window in meta.windows"
    );

    // Pull the window state. The server currently ignores the VV_REQUEST
    // payload and replies with all updates; send an empty Loro VV.
    let empty_vv = LoroDoc::new().oplog_vv().encode();
    let vv_req = transport::encode_window_sync("2026-02", window_sub_tags::VV_REQUEST, &empty_vv);
    client_b.send(Message::Binary(vv_req.into())).await.unwrap();

    let reply = next_binary(&mut client_b).await;
    assert_eq!(reply[0], TAG_WINDOW_SYNC);
    let (key, sub_tag, payload) = transport::decode_window_sync(&reply[1..]).unwrap();
    assert_eq!(key, "2026-02");
    assert_eq!(sub_tag, window_sub_tags::UPDATE);

    let receiver = LoroDoc::new();
    receiver.import(payload).unwrap();
    assert_eq!(
        deep_map_bytes(&receiver, "entities", "e-durable").unwrap(),
        b"survives",
        "a relayed entity update must survive the server restart"
    );
    assert_eq!(
        deep_map_bytes(&receiver, "tombstones", "e-deleted").unwrap(),
        b"1",
        "a relayed TOMBSTONE must survive the server restart (delete propagation)"
    );

    handle2.abort();
}

#[tokio::test]
async fn oversized_update_is_rejected_before_any_state_mutates() {
    let dir = tempfile::tempdir().unwrap();
    let vault = open_vault(dir.path());
    let config = SyncServerConfig {
        auth_secret: None,
        max_update_payload: 64,
        ..Default::default()
    };
    let (addr, server, handle) = spawn_server(vault, config).await;

    let mut ws = connect(addr, None).await.unwrap();
    let _ = next_binary(&mut ws).await; // root snapshot

    let oversized = vec![0u8; 65];
    let msg = transport::encode_window_sync("2026-02", window_sub_tags::UPDATE, &oversized);
    ws.send(Message::Binary(msg.into())).await.unwrap();

    // The server closes the connection (FrameTooLarge → break).
    let closed = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match ws.next().await {
                None | Some(Ok(Message::Close(_))) | Some(Err(_)) => break,
                Some(Ok(_)) => continue,
            }
        }
    })
    .await;
    assert!(closed.is_ok(), "server must close on oversized update");

    // Fail-closed and side-effect free: nothing was created or persisted —
    // the size check runs before the window doc is fetched or created.
    let vault = server.vault();
    assert!(vault.sync_state_get("d:w:2026-02").unwrap().is_none());
    assert!(
        vault
            .sync_state_get("u:w:2026-02:00000001")
            .unwrap()
            .is_none()
    );
    assert!(vault.sync_state_get("m:u_seq:w:2026-02").unwrap().is_none());

    handle.abort();
}

// ─── Client-side auth (SyncConnection sends auth_token) ──────────────────────

async fn run_sync_connection_once(server_url: String, auth_token: &str) -> Vec<SyncEvent> {
    let client_dir = tempfile::tempdir().unwrap();
    let client_vault = open_vault(client_dir.path());
    let config = ConnectionConfig {
        client_config: SyncClientConfig {
            server_url,
            auth_token: auth_token.to_string(),
            ..Default::default()
        },
        auto_reconnect: false,
    };
    let connection = SyncConnection::new(client_vault, config).unwrap();

    let (_local_tx, local_rx) = tokio::sync::mpsc::unbounded_channel();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

    let run_handle = tokio::spawn(async move { connection.run(local_rx, shutdown_rx).await });
    // Give the connection time to handshake + finish initial sync, then
    // request a clean shutdown (ignored if the run loop already exited).
    tokio::time::sleep(Duration::from_secs(2)).await;
    let _ = shutdown_tx.send(());

    let mut event_rx = tokio::time::timeout(Duration::from_secs(30), run_handle)
        .await
        .expect("SyncConnection::run did not exit")
        .expect("SyncConnection::run task panicked");

    let mut events = Vec::new();
    while let Ok(event) = event_rx.try_recv() {
        events.push(event);
    }
    events
}

#[tokio::test]
async fn sync_connection_sends_auth_token_on_upgrade() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, _server, handle) = spawn_server(
        open_vault(dir.path()),
        config_with_secret(Some("conn-secret")),
    )
    .await;

    // Correct auth_token → handshake passes and the client reaches Synced.
    let events = run_sync_connection_once(format!("ws://{addr}/ws"), "conn-secret").await;
    assert!(
        events
            .iter()
            .any(|e| matches!(e, SyncEvent::StatusChanged(SyncStatus::Synced))),
        "client with the correct auth_token must reach Synced; events: {events:?}"
    );

    // Wrong token → the server rejects the upgrade (fail-closed); the client
    // never syncs.
    let events = run_sync_connection_once(format!("ws://{addr}/ws"), "wrong-secret").await;
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, SyncEvent::StatusChanged(SyncStatus::Synced))),
        "client with a wrong auth_token must NOT reach Synced; events: {events:?}"
    );
    assert!(
        events
            .iter()
            .any(|e| matches!(e, SyncEvent::Error(msg) if msg.contains("Connection failed"))),
        "client must surface the rejected connection; events: {events:?}"
    );

    handle.abort();
}
