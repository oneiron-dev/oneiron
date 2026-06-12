//! WebSocket upgrade handler and connection lifecycle.
//!
//! Each WebSocket connection follows the protocol from ARCH-023 §3.2:
//! 1. Phase 1: Root doc sync (send snapshot to new client)
//! 2. Phase 2: Default windows (current + previous) via VV exchange + updates
//! 3. Phase 3: Historical windows via BulkTransfer (oldest first) + BulkTransferDone
//! 4. Ongoing: bidirectional incremental sync via WindowSync + Awareness

use std::io::Read;
use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::extract::ws::{CloseFrame, Message as WsMessage, Utf8Bytes, WebSocket, WebSocketUpgrade};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use futures_util::stream::SplitStream;
use futures_util::{SinkExt, StreamExt};
use loro::VersionVector;
use oneiron::sync::WindowKey;
use oneiron::sync::export_updates_since;

use crate::api::check_auth;
use crate::broadcast::BroadcastSubscriber;
use crate::protocol::{self, ProtocolError, SyncMessage, close_codes, window_sub_tags};
use crate::server::SyncServer;

/// How long the server waits for the client's protocol-version hello.
const HELLO_TIMEOUT_SECS: u64 = 10;

/// Builds the WebSocket routes for the sync server.
pub(crate) fn ws_routes(server: Arc<SyncServer>) -> Router {
    Router::new()
        .route("/ws", get(ws_upgrade_handler))
        .with_state(server)
}

/// Handles WebSocket upgrade requests.
///
/// Phase-1 auth: when a shared secret is configured, the upgrade request
/// must carry it in the `x-oneiron-secret` header (the same constant-time
/// scheme as the HTTP API). An unauthenticated upgrade is rejected with 401
/// BEFORE the socket upgrade (fail-closed) — without this gate any network
/// peer could pull the full root snapshot and window exports. When no secret
/// is configured the server runs in dev mode (allow all), matching
/// `api::check_auth`.
async fn ws_upgrade_handler(
    ws: WebSocketUpgrade,
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
) -> Result<impl IntoResponse, StatusCode> {
    check_auth(&headers, &server.config.auth_secret)?;

    let conn_id = server.alloc_conn_id();
    tracing::info!(conn_id, "new WebSocket connection");

    Ok(ws
        .max_frame_size(server.config.max_frame_size)
        .on_upgrade(move |socket| handle_connection(socket, server, conn_id)))
}

/// Main connection lifecycle.
async fn handle_connection(socket: WebSocket, server: Arc<SyncServer>, conn_id: u32) {
    let (mut ws_sink, mut ws_stream) = socket.split();

    // Phase 0: protocol-version hello (ONE-1127). The client's FIRST frame
    // must be [TAG_PROTOCOL_HELLO, PROTOCOL_VERSION]. Anything else — wrong
    // version, malformed frame, text, or timeout — closes with 4006 BEFORE
    // any sync payload flows, so the next wire break is detectable instead
    // of surfacing as garbled decode errors mid-sync.
    match await_protocol_hello(&mut ws_stream).await {
        HelloOutcome::Valid => {}
        HelloOutcome::Reject(reason) => {
            tracing::warn!(conn_id, reason, "protocol hello rejected — closing");
            let close = WsMessage::Close(Some(CloseFrame {
                code: close_codes::VERSION_MISMATCH,
                reason: Utf8Bytes::from_static(reason),
            }));
            let _ = ws_sink.send(close).await;
            return;
        }
        HelloOutcome::Disconnected => {
            tracing::info!(conn_id, "client disconnected before protocol hello");
            return;
        }
    }

    // Subscribe to broadcast channel for outbound messages
    let mut subscriber = BroadcastSubscriber::new(conn_id, &server.broadcast_tx);

    // Phase 1: Send root doc snapshot to client.
    // Root doc is server-authoritative — client only reads it.
    match server.export_root_snapshot() {
        Ok(snapshot) => {
            let msg = protocol::encode_root_update(&snapshot);
            if ws_sink.send(WsMessage::Binary(msg.into())).await.is_err() {
                tracing::warn!(conn_id, "failed to send root snapshot");
                return;
            }
        }
        Err(e) => {
            tracing::error!(conn_id, error = %e, "failed to export root snapshot");
            return;
        }
    }

    // Channel for direct responses (e.g. VV_REQUEST replies sent only to requester)
    let (direct_tx, mut direct_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();

    // Spawn outbound task: forwards broadcast + direct messages to WebSocket sink
    let outbound_handle = {
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    broadcast_result = subscriber.recv() => {
                        match broadcast_result {
                            Ok(Some(data)) => {
                                if ws_sink.send(WsMessage::Binary(data.into())).await.is_err() {
                                    tracing::debug!(conn_id, "outbound sink closed");
                                    break;
                                }
                            }
                            Ok(None) => break,
                            Err(crate::broadcast::BroadcastError::Lagged(n)) => {
                                tracing::warn!(conn_id, missed = n, "subscriber lagged — resync needed");
                            }
                            Err(crate::broadcast::BroadcastError::TooManyLags) => {
                                tracing::warn!(conn_id, "too many lags — disconnecting");
                                let _ = ws_sink.close().await;
                                break;
                            }
                        }
                    }
                    direct_msg = direct_rx.recv() => {
                        match direct_msg {
                            Some(data) => {
                                if ws_sink.send(WsMessage::Binary(data.into())).await.is_err() {
                                    tracing::debug!(conn_id, "outbound sink closed (direct)");
                                    break;
                                }
                            }
                            None => break,
                        }
                    }
                }
            }
        })
    };

    // Inbound loop: process messages from client
    loop {
        let next_message = ws_stream.next().await;
        let Some(msg_result) = next_message else {
            break;
        };
        let data = match msg_result {
            Ok(WsMessage::Binary(data)) => data.to_vec(),
            Ok(WsMessage::Close(_)) => {
                tracing::info!(conn_id, "client closed connection");
                break;
            }
            Ok(WsMessage::Ping(_)) | Ok(WsMessage::Pong(_)) => continue,
            Ok(WsMessage::Text(_)) => {
                tracing::warn!(conn_id, "received unexpected text message");
                continue;
            }
            Err(e) => {
                tracing::warn!(conn_id, error = %e, "WebSocket error");
                break;
            }
        };

        // Size check
        if data.len() > server.config.max_frame_size {
            tracing::warn!(conn_id, size = data.len(), "frame too large");
            break;
        }

        // Parse and dispatch the message
        match protocol::parse_message(&data) {
            Ok(msg) => {
                let handle_result = handle_sync_message(&server, conn_id, msg, &direct_tx).await;
                if let Err(e) = handle_result {
                    match &e {
                        ProtocolError::UnknownTag(tag) => {
                            tracing::warn!(conn_id, tag, "unknown tag — closing");
                            break;
                        }
                        ProtocolError::VvDecode(msg) => {
                            // Fail-closed: a malformed VV is a protocol
                            // violation, never answered with a full export.
                            tracing::warn!(conn_id, error = %msg, "version vector decode failure — closing");
                            break;
                        }
                        ProtocolError::FrameTooLarge { size, max } => {
                            tracing::warn!(conn_id, size, max, "frame too large — closing");
                            break;
                        }
                        ProtocolError::BulkTransferDecode => {
                            tracing::warn!(conn_id, "bulk transfer decode failure — closing");
                            break;
                        }
                        ProtocolError::LoroImport(msg) => {
                            tracing::warn!(conn_id, error = %msg, "loro import error — closing");
                            break;
                        }
                        ProtocolError::Persistence(msg) => {
                            // Fail-closed: the server could not durably
                            // persist sync state — do not keep relaying on a
                            // connection whose updates would vanish on
                            // restart.
                            tracing::error!(conn_id, error = %msg, "sync persistence failure — closing");
                            break;
                        }
                        _ => {
                            tracing::warn!(conn_id, error = %e, "message handling failed");
                        }
                    }
                }
            }
            Err(ProtocolError::UnknownTag(tag)) => {
                tracing::warn!(conn_id, tag, "unknown tag — closing");
                break;
            }
            Err(e) => {
                tracing::warn!(conn_id, error = %e, "protocol parse error");
                break;
            }
        }
    }

    // Cleanup
    {
        let mut awareness = server.awareness.write().await;
        awareness.remove(&conn_id);
    }
    outbound_handle.abort();
    tracing::info!(conn_id, "connection closed");
}

/// Outcome of the protocol-version hello phase.
enum HelloOutcome {
    /// First frame was a valid hello with a matching version.
    Valid,
    /// Hello missing/malformed/mismatched/timed out — close with
    /// `close_codes::VERSION_MISMATCH` and this reason.
    Reject(&'static str),
    /// Client went away before sending a hello — nothing to close.
    Disconnected,
}

/// Waits for the client's protocol-version hello as the FIRST frame.
///
/// Skips ping/pong keepalives; any other frame must be the hello.
async fn await_protocol_hello(ws_stream: &mut SplitStream<WebSocket>) -> HelloOutcome {
    let deadline = tokio::time::Duration::from_secs(HELLO_TIMEOUT_SECS);
    let outcome = tokio::time::timeout(deadline, async {
        loop {
            match ws_stream.next().await {
                Some(Ok(WsMessage::Binary(data))) => {
                    return match validate_protocol_hello(&data) {
                        Ok(()) => HelloOutcome::Valid,
                        Err(_) => HelloOutcome::Reject("protocol version mismatch"),
                    };
                }
                Some(Ok(WsMessage::Ping(_) | WsMessage::Pong(_))) => continue,
                Some(Ok(WsMessage::Text(_))) => {
                    return HelloOutcome::Reject("expected binary protocol hello");
                }
                Some(Ok(WsMessage::Close(_))) | Some(Err(_)) | None => {
                    return HelloOutcome::Disconnected;
                }
            }
        }
    })
    .await;

    outcome.unwrap_or(HelloOutcome::Reject("protocol hello timeout"))
}

/// Validates a hello frame against the server's wire-protocol version.
///
/// Returns the close code to send on mismatch (always
/// `close_codes::VERSION_MISMATCH`) so callers cannot accidentally
/// downgrade the failure to a softer close.
fn validate_protocol_hello(frame: &[u8]) -> Result<(), u16> {
    match protocol::decode_protocol_hello(frame) {
        Ok(version) if version == protocol::PROTOCOL_VERSION => Ok(()),
        _ => Err(close_codes::VERSION_MISMATCH),
    }
}

/// Dispatches a parsed SyncMessage to the appropriate handler.
async fn handle_sync_message(
    server: &SyncServer,
    conn_id: u32,
    msg: SyncMessage,
    direct_tx: &tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
) -> Result<(), ProtocolError> {
    match msg {
        SyncMessage::RootUpdate(_update_bytes) => {
            // Root doc is server-authoritative — reject client updates silently
            tracing::debug!(
                conn_id,
                "rejected client root update (server-authoritative)"
            );
            Ok(())
        }
        SyncMessage::Awareness(state) => {
            let mut awareness = server.awareness.write().await;
            awareness.insert(conn_id, state.clone());
            // Broadcast awareness to other connections
            let encoded = protocol::encode_awareness(&state);
            let _ = crate::broadcast::broadcast(&server.broadcast_tx, conn_id, encoded);
            Ok(())
        }
        SyncMessage::RootVersionVector(vv_bytes) => {
            // Client is requesting root doc updates since their VV (Loro
            // binary encoding). Malformed VV → typed error, fail-closed —
            // NEVER answered with a full export as if the VV were empty.
            let client_vv = VersionVector::decode(&vv_bytes)
                .map_err(|e| ProtocolError::VvDecode(e.to_string()))?;
            tracing::debug!(conn_id, "client sent root VV — sending root delta");
            match server.export_root_updates(&client_vv) {
                Ok(delta) => {
                    let msg = protocol::encode_root_update(&delta);
                    let _ = direct_tx.send(msg);
                }
                Err(e) => {
                    tracing::error!(conn_id, error = %e, "failed to export root delta for VV response");
                }
            }
            Ok(())
        }
        SyncMessage::WindowSync {
            window_key,
            sub_tag,
            payload,
        } => handle_window_sync(server, conn_id, &window_key, sub_tag, &payload, direct_tx).await,
        SyncMessage::BulkTransfer {
            window_key,
            compressed,
        } => handle_bulk_transfer(server, &window_key, &compressed).await,
        SyncMessage::BulkTransferDone {
            window_key,
            doc_state,
        } => handle_bulk_transfer_done(server, &window_key, &doc_state).await,
    }
}

/// Handles a WindowSync message: routes to the correct window LoroDoc.
async fn handle_window_sync(
    server: &SyncServer,
    conn_id: u32,
    window_key: &str,
    sub_tag: u8,
    payload: &[u8],
    direct_tx: &tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
) -> Result<(), ProtocolError> {
    // Window-key chokepoint. `decode_window_sync` already validated the key
    // at the parse boundary; re-validate here so this write path stays
    // fail-closed even if a future caller bypasses the wire decoder.
    let key = WindowKey::try_new(window_key)
        .ok_or(ProtocolError::InvalidPayload("invalid window key"))?;

    // Enforce max_update_payload BEFORE the window doc is fetched/created:
    // an oversized update must not mutate any server state.
    if sub_tag == window_sub_tags::UPDATE && payload.len() > server.config.max_update_payload {
        return Err(ProtocolError::FrameTooLarge {
            size: payload.len(),
            max: server.config.max_update_payload,
        });
    }

    // Loads persisted window state (d:w: + pending u:w:) on first touch.
    // Corrupt persisted state closes the connection rather than serving a
    // fresh empty window (fail-closed — see SyncServer::get_or_create_window).
    let doc = server
        .get_or_create_window(&key)
        .await
        .map_err(|e| ProtocolError::Persistence(format!("window load failed: {e}")))?;

    match sub_tag {
        window_sub_tags::VV_REQUEST => {
            // Client sent its binary VV (SyncStep1) — export ONLY the delta it
            // is missing (ExportMode::updates via the single delta-export entry
            // point). Malformed VV → typed error, fail-closed: never fall back
            // to a full export.
            let delta = export_updates_since(&doc, payload).map_err(map_delta_export_err)?;
            let response =
                protocol::encode_window_sync(window_key, window_sub_tags::UPDATE, &delta);
            // Send directly to the requesting client's WebSocket sink, NOT via
            // broadcast. Broadcasting with the requester's conn_id would cause
            // echo suppression to drop the response for the requester.
            let _ = direct_tx.send(response);
            // Reverse SyncStep1: send our VV so the client pushes its local
            // diff back — this is what makes the exchange bidirectional.
            let vv_response = protocol::encode_window_sync(
                window_key,
                window_sub_tags::VV_RESPONSE,
                &doc.oplog_vv().encode(),
            );
            let _ = direct_tx.send(vv_response);
        }
        window_sub_tags::UPDATE => {
            // Client sending Loro update bytes — import with origin for echo suppression
            let origin = format!("conn:{conn_id}");
            doc.import_with(payload, &origin)
                .map_err(|e| ProtocolError::LoroImport(format!("{e}")))?;

            // Durability BEFORE fan-out (ARCH-0023b Observer A duty: "MUST
            // persist synchronously"). `subscribe_local_update` does not fire
            // for imports, so the imported update bytes are appended to
            // sync_state (u:w:*) explicitly. A persistence failure closes the
            // connection without broadcasting: the server must never relay an
            // update — tombstones included — that it cannot replay after a
            // restart.
            if let Err(e) = server.persist_imported_update(&key, payload) {
                // The cached doc already imported this update (import runs
                // before the durable append), so it now holds state a restart
                // would lose. Left cached, a later VV_REQUEST would serve the
                // unpersisted update, the origin client would VV-confirm and
                // clear its local queue, and the next server restart would
                // drop the update — tombstones included — fleet-wide. Evict
                // the window so the next access reloads from durable
                // d:w:/u:w: state. Known residual: connections already
                // holding a reference-clone of the evicted doc can still
                // export it until their next fetch (generation/poison flag =
                // follow-up).
                server.evict_window(&key).await;
                return Err(ProtocolError::Persistence(format!(
                    "update persist failed: {e}"
                )));
            }

            let broadcast_msg =
                protocol::encode_window_sync(window_key, window_sub_tags::UPDATE, payload);
            let _ = crate::broadcast::broadcast(&server.broadcast_tx, conn_id, broadcast_msg);
        }
        window_sub_tags::VV_RESPONSE => {
            // Client's VV answering our VV_REQUEST — export and send only our
            // local diff. Same fail-closed VV decoding as VV_REQUEST.
            let delta = export_updates_since(&doc, payload).map_err(map_delta_export_err)?;
            let response =
                protocol::encode_window_sync(window_key, window_sub_tags::UPDATE, &delta);
            let _ = direct_tx.send(response);
        }
        _ => {
            tracing::warn!(window_key, sub_tag, "unknown WindowSync sub-tag");
        }
    }

    Ok(())
}

/// Maps a delta-export error onto the protocol taxonomy.
///
/// Malformed inbound VV bytes (`CrdtDecodeError`) get the dedicated
/// fail-closed `VvDecode` variant (the connection loop closes on it);
/// anything else is an export-side failure.
fn map_delta_export_err(e: oneiron::Error) -> ProtocolError {
    if matches!(e, oneiron::Error::CrdtDecodeError { .. }) {
        ProtocolError::VvDecode(e.to_string())
    } else {
        ProtocolError::LoroImport(e.to_string())
    }
}

/// Rejects a BulkTransfer message from client.
///
/// BulkTransfer is a server→client message only. Clients should not send it.
async fn handle_bulk_transfer(
    _server: &SyncServer,
    window_key: &str,
    _compressed: &[u8],
) -> Result<(), ProtocolError> {
    tracing::warn!(
        window_key,
        "rejected client-to-server BulkTransfer — not supported"
    );
    Err(ProtocolError::InvalidPayload(
        "client-to-server BulkTransfer is not supported",
    ))
}

/// Rejects a BulkTransferDone message from client.
///
/// BulkTransferDone is a server→client message only. Clients should not send it.
async fn handle_bulk_transfer_done(
    _server: &SyncServer,
    window_key: &str,
    _doc_state: &[u8],
) -> Result<(), ProtocolError> {
    tracing::warn!(
        window_key,
        "rejected client-to-server BulkTransferDone — not supported"
    );
    Err(ProtocolError::InvalidPayload(
        "client-to-server BulkTransferDone is not supported",
    ))
}

/// Streaming zstd decompression with a size limit.
///
/// Returns `Ok(Some(data))` on success, `Ok(None)` if decompressed size
/// exceeds `max_bytes`, or `Err` on decode failure. This prevents
/// decompression bombs by aborting before allocating unbounded memory.
#[allow(dead_code)] // Used when server sends BulkTransfer to clients (Phase 2+)
fn decompress_bounded(
    compressed: &[u8],
    max_bytes: usize,
) -> Result<Option<Vec<u8>>, std::io::Error> {
    let mut decoder = zstd::Decoder::new(compressed)?;
    let mut buf = Vec::with_capacity(std::cmp::min(compressed.len().saturating_mul(2), max_bytes));
    let mut chunk = [0u8; 8192];
    loop {
        let n = decoder.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        if buf.len() + n > max_bytes {
            return Ok(None);
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    Ok(Some(buf))
}

/// BulkTransfer payload schema (MessagePack).
#[allow(dead_code)] // Protocol schema — used for server→client BulkTransfer generation
#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub(crate) struct BulkTransferPayload {
    pub entities: Vec<BulkEntity>,
    pub edges: Vec<BulkEdge>,
    pub tombstones: Vec<BulkTombstone>,
}

#[allow(dead_code)]
#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub(crate) struct BulkEntity {
    #[serde(with = "serde_bytes")]
    pub id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub blob: Vec<u8>,
}

#[allow(dead_code)]
#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub(crate) struct BulkEdge {
    #[serde(with = "serde_bytes")]
    pub src: Vec<u8>,
    pub kind: u8,
    #[serde(with = "serde_bytes")]
    pub tgt: Vec<u8>,
    pub weight: f32,
    pub created_at: u64,
    pub vad_valence: f32,
    pub vad_arousal: f32,
    pub vad_dominance: f32,
}

#[allow(dead_code)]
#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub(crate) struct BulkTombstone {
    #[serde(with = "serde_bytes")]
    pub id: Vec<u8>,
    pub deleted_at: u64,
    /// Tombstone wire reason byte (ONE-1132 pinned table: 1=user_delete,
    /// 2=user_hard_delete, 3=gdpr_delete, 4=policy_delete; 0 is reserved
    /// and, like any unknown byte, decodes as HARD — fail-closed).
    pub reason: u8,
    /// Deletion request UUID (16 raw bytes) — receipt correlation (M4-06).
    #[serde(with = "serde_bytes")]
    pub request_id: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SyncServerConfig;
    use loro::{ExportMode, LoroDoc};
    use tokio::sync::mpsc;

    fn test_server() -> (tempfile::TempDir, SyncServer) {
        let dir = tempfile::tempdir().unwrap();
        let vault =
            Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap());
        let server = SyncServer::new(vault, SyncServerConfig::default()).unwrap();
        (dir, server)
    }

    /// Client-side stand-in window doc with the schema containers.
    fn client_window_doc() -> LoroDoc {
        let doc = LoroDoc::new();
        let _ = doc.get_map("entities");
        let _ = doc.get_map("edges");
        let _ = doc.get_map("tombstones");
        doc.commit();
        doc
    }

    fn expect_window_sync(data: &[u8]) -> (String, u8, Vec<u8>) {
        match protocol::parse_message(data).unwrap() {
            SyncMessage::WindowSync {
                window_key,
                sub_tag,
                payload,
            } => (window_key, sub_tag, payload),
            other => panic!("expected WindowSync, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn vv_request_sends_delta_and_vv_response() {
        let (_dir, server) = test_server();
        let key = "2026-03";

        // Server window doc: chunky shared base + a server-only divergence.
        let server_doc = server
            .get_or_create_window(&WindowKey::new(key))
            .await
            .unwrap();
        server_doc
            .get_map("entities")
            .insert("base", vec![7u8; 2048].as_slice())
            .unwrap();
        server_doc.commit();

        // Client doc shares the base...
        let client_doc = client_window_doc();
        client_doc
            .import(&server_doc.export(ExportMode::all_updates()).unwrap())
            .unwrap();
        // ...then the server moves ahead.
        server_doc
            .get_map("entities")
            .insert("server-only", b"s".as_slice())
            .unwrap();
        server_doc.commit();

        let (direct_tx, mut direct_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        handle_window_sync(
            &server,
            1,
            key,
            window_sub_tags::VV_REQUEST,
            &client_doc.oplog_vv().encode(),
            &direct_tx,
        )
        .await
        .unwrap();

        // Message 1: the delta — a true ExportMode::updates delta, not all_updates.
        let (k0, sub0, delta) = expect_window_sync(&direct_rx.try_recv().unwrap());
        assert_eq!(k0, key);
        assert_eq!(sub0, window_sub_tags::UPDATE);
        let server_all = server_doc.export(ExportMode::all_updates()).unwrap();
        assert!(
            delta.len() < server_all.len(),
            "delta ({}) must be smaller than all_updates ({}) for the diverged case",
            delta.len(),
            server_all.len()
        );
        client_doc.import(&delta).unwrap();
        assert_eq!(client_doc.get_deep_value(), server_doc.get_deep_value());

        // Message 2: the server's VV so the client can push its local diff.
        let (k1, sub1, vv_payload) = expect_window_sync(&direct_rx.try_recv().unwrap());
        assert_eq!(k1, key);
        assert_eq!(sub1, window_sub_tags::VV_RESPONSE);
        let server_vv =
            VersionVector::decode(&vv_payload).expect("VV_RESPONSE payload must be Loro binary VV");
        assert_eq!(server_vv, server_doc.oplog_vv());

        assert!(direct_rx.try_recv().is_err(), "exactly two messages");
    }

    #[tokio::test]
    async fn vv_request_malformed_vv_fails_closed_no_fallback() {
        let (_dir, server) = test_server();
        let key = "2026-03";
        let server_doc = server
            .get_or_create_window(&WindowKey::new(key))
            .await
            .unwrap();
        server_doc
            .get_map("entities")
            .insert("secret", b"data".as_slice())
            .unwrap();
        server_doc.commit();

        let (direct_tx, mut direct_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        // The dead JSON encoding and garbage must both be rejected.
        for payload in [&b"{}"[..], &[0xFFu8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF][..]] {
            let result = handle_window_sync(
                &server,
                1,
                key,
                window_sub_tags::VV_REQUEST,
                payload,
                &direct_tx,
            )
            .await;
            assert!(
                matches!(result, Err(ProtocolError::VvDecode(_))),
                "malformed VV must return the typed VvDecode error"
            );
            assert!(
                direct_rx.try_recv().is_err(),
                "fail-closed: no full-export fallback may be sent for a malformed VV"
            );
        }
    }

    #[tokio::test]
    async fn vv_response_sends_local_diff_only() {
        let (_dir, server) = test_server();
        let key = "2026-04";
        let server_doc = server
            .get_or_create_window(&WindowKey::new(key))
            .await
            .unwrap();
        server_doc
            .get_map("entities")
            .insert("ahead", b"x".as_slice())
            .unwrap();
        server_doc.commit();

        let client_doc = client_window_doc();
        let (direct_tx, mut direct_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        handle_window_sync(
            &server,
            1,
            key,
            window_sub_tags::VV_RESPONSE,
            &client_doc.oplog_vv().encode(),
            &direct_tx,
        )
        .await
        .unwrap();

        let (k, sub, delta) = expect_window_sync(&direct_rx.try_recv().unwrap());
        assert_eq!(k, key);
        assert_eq!(sub, window_sub_tags::UPDATE);
        client_doc.import(&delta).unwrap();
        assert_eq!(client_doc.get_deep_value(), server_doc.get_deep_value());

        assert!(
            direct_rx.try_recv().is_err(),
            "VV_RESPONSE must NOT trigger another VV message (no ping-pong loop)"
        );
    }

    #[tokio::test]
    async fn root_vv_replies_with_delta_and_rejects_malformed() {
        let (_dir, server) = test_server();

        // Client bootstrapped from the snapshot, then the server moves ahead.
        let client_root = LoroDoc::new();
        client_root
            .import(&server.export_root_snapshot().unwrap())
            .unwrap();
        server
            .root_doc
            .get_map("meta")
            .insert("windows", "2026-03".as_bytes())
            .unwrap();
        server.root_doc.commit();

        let (direct_tx, mut direct_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        handle_sync_message(
            &server,
            1,
            SyncMessage::RootVersionVector(client_root.oplog_vv().encode()),
            &direct_tx,
        )
        .await
        .unwrap();

        let msg = direct_rx.try_recv().unwrap();
        assert_eq!(msg[0], protocol::TAG_SYNC_UPDATE);
        client_root.import(&msg[1..]).unwrap();
        assert_eq!(
            client_root.get_deep_value(),
            server.root_doc.get_deep_value()
        );

        // Malformed root VV → typed error, nothing sent.
        let result = handle_sync_message(
            &server,
            1,
            SyncMessage::RootVersionVector(b"{}".to_vec()),
            &direct_tx,
        )
        .await;
        assert!(matches!(result, Err(ProtocolError::VvDecode(_))));
        assert!(direct_rx.try_recv().is_err());
    }

    #[test]
    fn protocol_hello_validation_literals() {
        // Contract literals (ONE-1127): the valid hello is EXACTLY [3, 1] and
        // every failure closes with 4006 — assert the raw values so a drifted
        // tag/version/close-code fails here.
        assert!(validate_protocol_hello(&[3, 1]).is_ok());

        let cases: &[(&str, &[u8])] = &[
            ("future_version", &[3, 2]),
            ("zero_version", &[3, 0]),
            ("wrong_tag", &[2, 1]),
            ("empty", &[]),
            ("tag_only", &[3]),
            ("trailing_bytes", &[3, 1, 0]),
        ];
        for (case_name, frame) in cases {
            assert_eq!(
                validate_protocol_hello(frame),
                Err(4006),
                "case {case_name}: must close with VERSION_MISMATCH (4006)"
            );
        }
    }
}
