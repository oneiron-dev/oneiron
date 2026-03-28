//! WebSocket upgrade handler and connection lifecycle.
//!
//! Each WebSocket connection follows the protocol from ARCH-023 §3.2:
//! 1. Phase 1: Root doc sync (send snapshot to new client)
//! 2. Phase 2: Default windows (current + previous) via VV exchange + updates
//! 3. Phase 3: Historical windows via BulkTransfer (oldest first) + BulkTransferDone
//! 4. Ongoing: bidirectional incremental sync via WindowSync + Awareness

use std::sync::Arc;

use axum::extract::ws::{Message as WsMessage, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use futures_util::{SinkExt, StreamExt};
use loro::ExportMode;

use crate::broadcast::BroadcastSubscriber;
use crate::protocol::{
    self, window_sub_tags, ProtocolError, SyncMessage,
};
use crate::server::SyncServer;

/// Builds the WebSocket routes for the sync server.
pub fn ws_routes(server: Arc<SyncServer>) -> Router {
    Router::new()
        .route("/ws", get(ws_upgrade_handler))
        .with_state(server)
}

/// Handles WebSocket upgrade requests.
async fn ws_upgrade_handler(
    ws: WebSocketUpgrade,
    State(server): State<Arc<SyncServer>>,
) -> impl IntoResponse {
    let conn_id = server.alloc_conn_id();
    tracing::info!(conn_id, "new WebSocket connection");

    ws.max_frame_size(server.config.max_frame_size)
        .on_upgrade(move |socket| handle_connection(socket, server, conn_id))
}

/// Main connection lifecycle.
async fn handle_connection(socket: WebSocket, server: Arc<SyncServer>, conn_id: u32) {
    let (mut ws_sink, mut ws_stream) = socket.split();

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

    // Spawn outbound task: forwards broadcast messages to WebSocket sink
    let outbound_handle = {
        tokio::spawn(async move {
            loop {
                match subscriber.recv().await {
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
        })
    };

    // Inbound loop: process messages from client
    while let Some(msg_result) = ws_stream.next().await {
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
                if let Err(e) = handle_sync_message(&server, conn_id, msg).await {
                    match &e {
                        ProtocolError::UnknownTag(tag) => {
                            tracing::warn!(conn_id, tag, "unknown tag — closing");
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

/// Dispatches a parsed SyncMessage to the appropriate handler.
async fn handle_sync_message(
    server: &SyncServer,
    conn_id: u32,
    msg: SyncMessage,
) -> Result<(), ProtocolError> {
    match msg {
        SyncMessage::RootUpdate(_update_bytes) => {
            // Root doc is server-authoritative — reject client updates silently
            tracing::debug!(conn_id, "rejected client root update (server-authoritative)");
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
        SyncMessage::RootVersionVector(_vv_bytes) => {
            // Client is requesting root doc updates since their VV.
            // Root doc is server-authoritative so we just send the full snapshot.
            // (In practice, clients don't need to send VV for root — they just receive.)
            tracing::debug!(conn_id, "client sent root VV — sending snapshot");
            Ok(())
        }
        SyncMessage::WindowSync {
            window_key,
            sub_tag,
            payload,
        } => handle_window_sync(server, conn_id, &window_key, sub_tag, &payload).await,
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
) -> Result<(), ProtocolError> {
    let doc = server.get_or_create_window(window_key).await;

    match sub_tag {
        window_sub_tags::VV_REQUEST => {
            // Client sent its VersionVector — send back updates it's missing
            // For now, send all updates (full export). A proper implementation
            // would decode the client's VV and use ExportMode::updates(&client_vv).
            let updates = doc
                .export(ExportMode::all_updates())
                .map_err(|e| ProtocolError::LoroImport(format!("{e}")))?;
            let response = protocol::encode_window_sync(
                window_key,
                window_sub_tags::UPDATE,
                &updates,
            );
            let _ = crate::broadcast::broadcast(&server.broadcast_tx, conn_id, response);
        }
        window_sub_tags::UPDATE => {
            // Client sending Loro update bytes — import with origin for echo suppression
            let origin = format!("conn:{conn_id}");
            doc.import_with(payload, &origin)
                .map_err(|e| ProtocolError::LoroImport(format!("{e}")))?;

            // The subscribe_local_update callback (when registered by sync-core)
            // will handle persistence + broadcast. For now, manually broadcast.
            let broadcast_msg = protocol::encode_window_sync(
                window_key,
                window_sub_tags::UPDATE,
                payload,
            );
            let _ = crate::broadcast::broadcast(&server.broadcast_tx, conn_id, broadcast_msg);
        }
        window_sub_tags::VV_RESPONSE => {
            // Server received a VV response — used during sync negotiation.
            // The server would use this to compute what updates to send.
            tracing::debug!(window_key, "received VV response from client");
        }
        _ => {
            tracing::warn!(window_key, sub_tag, "unknown WindowSync sub-tag");
        }
    }

    Ok(())
}

/// Handles a BulkTransfer message from client (rare — usually server→client).
async fn handle_bulk_transfer(
    server: &SyncServer,
    window_key: &str,
    compressed: &[u8],
) -> Result<(), ProtocolError> {
    let decompressed =
        zstd::decode_all(compressed).map_err(|_| ProtocolError::BulkTransferDecode)?;

    if decompressed.len() > server.config.max_bulk_decompressed {
        return Err(ProtocolError::FrameTooLarge {
            size: decompressed.len(),
            max: server.config.max_bulk_decompressed,
        });
    }

    let payload: BulkTransferPayload =
        rmp_serde::from_slice(&decompressed).map_err(|_| ProtocolError::BulkTransferDecode)?;

    tracing::info!(
        window_key,
        entities = payload.entities.len(),
        edges = payload.edges.len(),
        tombstones = payload.tombstones.len(),
        "received BulkTransfer"
    );

    Ok(())
}

/// Handles BulkTransferDone message.
async fn handle_bulk_transfer_done(
    _server: &SyncServer,
    window_key: &str,
    doc_state: &[u8],
) -> Result<(), ProtocolError> {
    tracing::info!(
        window_key,
        state_len = doc_state.len(),
        "received BulkTransferDone"
    );
    Ok(())
}

/// BulkTransfer payload schema (MessagePack).
#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct BulkTransferPayload {
    pub entities: Vec<BulkEntity>,
    pub edges: Vec<BulkEdge>,
    pub tombstones: Vec<BulkTombstone>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct BulkEntity {
    #[serde(with = "serde_bytes")]
    pub id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub blob: Vec<u8>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct BulkEdge {
    #[serde(with = "serde_bytes")]
    pub src: Vec<u8>,
    pub kind: u8,
    #[serde(with = "serde_bytes")]
    pub tgt: Vec<u8>,
    pub weight: f32,
    pub created_at: u64,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct BulkTombstone {
    #[serde(with = "serde_bytes")]
    pub id: Vec<u8>,
    pub deleted_at: u64,
}
