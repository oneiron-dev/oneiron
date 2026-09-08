//! Upgrade route, hello bootstrap, and the single-owner connection event loop.

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::extract::ws::{CloseFrame, Message as WsMessage, Utf8Bytes, WebSocket, WebSocketUpgrade};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use tokio::time::Duration;

use super::app_tier::{
    handle_app_message_with_connection, handle_sync_message, require_bound_app_auth,
};
use super::conn_state::ConnState;
use super::ephemeral::encode_late_join_ephemeral_snapshot;
use super::hello::{HelloOutcome, await_protocol_hello};
use super::transport::{GuardedTransport, WS_MAX_WRITE_BUFFER_SIZE, WS_WRITE_BUFFER_SIZE};
use oneiron::sync::FederationQuotaConfig;

use crate::auth::{RevokedTokenJtis, is_revoked_or_unreadable, require_owner_auth};
use crate::broadcast::BroadcastSubscriber;
use crate::protocol::{self, ProtocolError, SyncMessage, close_codes};
use crate::server::SyncServer;

/// Builds the WebSocket routes for the sync server.
pub(crate) fn ws_routes(server: Arc<SyncServer>) -> Router {
    Router::new()
        .route("/ws", get(ws_upgrade_handler))
        .with_state(server)
}

/// Handles WebSocket upgrade requests.
///
/// Auth: the upgrade request must present an owner-grade credential in the
/// `Authorization: Bearer` header — the configured trust-root secret or an
/// empty-claims v2 token. Scoped delegation tokens do not reach this surface.
/// An unauthenticated upgrade is rejected with 401 BEFORE the socket upgrade
/// (fail-closed) — without this gate any network peer could pull the full
/// root snapshot and window exports. When no secret is configured, upgrades
/// are rejected unless the explicit insecure dev escape hatch is enabled,
/// matching `auth::require_owner_auth` on the HTTP side.
///
/// The credential's revocable identity is carried into the connection rather
/// than discarded with the rest of the `CoreAuth`: the handshake proves the
/// token was live at upgrade time, and the socket outlives that instant.
async fn ws_upgrade_handler(
    ws: WebSocketUpgrade,
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
) -> Result<impl IntoResponse, StatusCode> {
    let auth = require_owner_auth(&headers, &server.config, server.vault().as_ref())
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    let session_jti = auth.jti().map(str::to_owned);

    let conn_id = server.alloc_conn_id();
    tracing::info!(conn_id, "new WebSocket connection");

    // `write_buffer_size` is a security setting here, not a tuning knob: it is
    // what keeps `start_send` from writing to the socket on its own. See
    // [`WS_WRITE_BUFFER_SIZE`]. Note that `max_frame_size` below does NOT pin
    // that — it bounds inbound reads only — so the outbound side is held by
    // [`GuardedTransport::fits_below_write_through`], which refuses per frame
    // in release builds.
    Ok(ws
        .max_frame_size(server.config.max_frame_size)
        .write_buffer_size(WS_WRITE_BUFFER_SIZE)
        .max_write_buffer_size(WS_MAX_WRITE_BUFFER_SIZE)
        .on_upgrade(move |socket| handle_connection(socket, server, conn_id, session_jti)))
}

/// Whether this socket's credential has since been revoked.
///
/// The upgrade handshake proves the credential was live THEN; the socket
/// lives arbitrarily long after it. Revocation is an explicit operator act
/// against one named token, so it must reach sessions that were ALREADY open
/// — otherwise `token revoke` only closes the front door while the peer
/// already inside keeps full vault service. Fail-closed on an unreadable
/// registry, matching the handshake: "we could not check" is not "still live".
///
/// `None` means the credential carries no revocable identity — the bare trust
/// root or the dev fallthrough — so there is nothing to consult and the
/// lookup is skipped entirely. Those are retired by rotating `auth_secret`,
/// which invalidates them without any registry read.
pub(super) fn session_credential_revoked(
    revoked: &dyn RevokedTokenJtis,
    session_jti: Option<&str>,
) -> bool {
    session_jti.is_some_and(|jti| is_revoked_or_unreadable(jti, revoked))
}

/// What woke the connection loop.
///
/// The select produces this and nothing borrowed, so every future it raced —
/// including the read — is dropped before the handler touches the transport
/// again. That is what lets one task own both halves.
enum ConnEvent {
    Inbound(Option<Result<WsMessage, axum::Error>>),
    Broadcast(Result<Option<Vec<u8>>, crate::broadcast::BroadcastError>),
    Direct(Option<Vec<u8>>),
    AppDelivery,
}

/// Main connection lifecycle.
///
/// The socket is deliberately NOT split. A split hands the two halves to two
/// tasks over one transport, and tungstenite's read path flushes the shared
/// out-buffer whenever it queues an automatic pong or close — which drains
/// application frames the write half is still holding under a revocation
/// consult. Keeping the socket whole means the borrow checker enforces what no
/// runtime check could: while a guarded frame is pending, no read exists to
/// flush it. See [`GuardedTransport`].
#[expect(clippy::cognitive_complexity)]
async fn handle_connection(
    socket: WebSocket,
    server: Arc<SyncServer>,
    conn_id: u32,
    session_jti: Option<String>,
) {
    // Every frame this connection ever writes goes through here, and each one
    // re-consults the revocation registry first. The hello close below is the
    // single deliberate exception: it carries no vault state and is the
    // refusal itself.
    let mut transport = GuardedTransport::new(
        socket,
        Arc::clone(server.vault()) as Arc<dyn RevokedTokenJtis + Send + Sync>,
        session_jti.clone(),
        conn_id,
    );

    // Phase 0: protocol-version hello (ONE-1127). The client's FIRST frame
    // must be a supported protocol hello. Malformed frames or unsupported
    // versions close with 4006 BEFORE any sync payload flows, so wire breaks
    // are detectable instead of surfacing as garbled decode errors mid-sync.
    //
    // A token can idle here — upgraded but silent — for the whole hello
    // timeout, so a revocation can land between the handshake and the first
    // frame. The sends below therefore cannot rely on the handshake's proof
    // of liveness, and do not: they consult at the chokepoint.
    let protocol_version = match await_protocol_hello(&mut transport).await {
        HelloOutcome::Valid(version) => version,
        HelloOutcome::Reject(reason) => {
            tracing::warn!(conn_id, reason, "protocol hello rejected — closing");
            let close = WsMessage::Close(Some(CloseFrame {
                code: close_codes::VERSION_MISMATCH,
                reason: Utf8Bytes::from_static(reason),
            }));
            transport.send_unguarded_close_frame(close).await;
            return;
        }
        HelloOutcome::Disconnected => {
            tracing::info!(conn_id, "client disconnected before protocol hello");
            return;
        }
    };

    // Subscribe to broadcast channel for outbound messages
    let mut subscriber = BroadcastSubscriber::new(conn_id, &server.broadcast_tx);

    // Phase 1: Send root doc snapshot to client.
    // Root doc is server-authoritative — client only reads it.
    match server.export_root_snapshot() {
        Ok(snapshot) => {
            let msg = protocol::encode_root_update(&snapshot);
            if !transport.send_binary(msg).await {
                tracing::warn!(conn_id, "failed to send root snapshot");
                return;
            }
        }
        Err(e) => {
            tracing::error!(conn_id, error = %e, "failed to export root snapshot");
            return;
        }
    }

    // Late-join/reconnect snapshot for the Loro-native ephemeral lane.
    if let Some(msg) = encode_late_join_ephemeral_snapshot(&server, conn_id)
        && !transport.send_binary(msg).await
    {
        tracing::warn!(conn_id, "failed to send ephemeral snapshot");
        return;
    }

    // Channel for direct responses (e.g. VV_REQUEST replies sent only to requester)
    let (direct_tx, mut direct_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let federation_quota = FederationQuotaConfig::new(
        server.config.max_federation_windows_per_connection,
        server.config.federation_flood_pause_secs,
    );
    let mut conn_state = ConnState::new(
        server.config.max_messages_per_sec,
        protocol_version,
        federation_quota,
    );

    let mut app_connection = crate::livequery::connection::Connection::new(
        crate::livequery::connection::Hub::for_server(&server),
        conn_id,
    );
    let mut app_tick = tokio::time::interval(Duration::from_millis(25));

    // One loop, one owner. The outbound arms used to run in a spawned task over
    // the split sink; they are folded in here because two tasks cannot share
    // this transport safely — see [`GuardedTransport`]. Reads and writes now
    // interleave only at this select, never during a guarded send.
    //
    // BOTH outbound arms still write through the guarded chokepoint, so neither
    // unsolicited fan-out nor a direct answer can outlive the credential:
    // fan-out is service the peer never asked for, and a direct response can
    // sit queued in this channel — or blocked mid-`send` — across the very
    // revocation that should have stopped it.
    loop {
        let event = tokio::select! {
            msg = transport.read_next(), if direct_rx.is_empty() => ConnEvent::Inbound(msg),
            broadcast_result = subscriber.recv() => ConnEvent::Broadcast(broadcast_result),
            direct_msg = direct_rx.recv() => ConnEvent::Direct(direct_msg),
            _ = app_tick.tick(), if app_connection.has_active_subscriptions() => ConnEvent::AppDelivery,
        };

        let next_message = match event {
            ConnEvent::Inbound(msg) => msg,
            ConnEvent::AppDelivery => {
                if conn_state.bound_auth.is_some() {
                    if require_bound_app_auth(&server, &conn_state).is_err() {
                        transport
                            .send_unguarded_close_frame(WsMessage::Close(Some(CloseFrame {
                                code: close_codes::CLOSE_RPC_NO_PRINCIPAL,
                                reason: Utf8Bytes::from_static(
                                    "bound credential is no longer live",
                                ),
                            })))
                            .await;
                        break;
                    }
                    match app_connection.broadcast_delivery() {
                        Ok(frames) => {
                            for frame in frames {
                                // Recipient/subscription routing is stripped only by the
                                // matching socket. Never fan out a bare private app frame.
                                let _ = server.broadcast_tx.send((0, frame));
                            }
                        }
                        Err(_) => break,
                    }
                }
                continue;
            }
            ConnEvent::Broadcast(broadcast_result) => {
                match broadcast_result {
                    Ok(Some(data)) => {
                        if crate::livequery::connection::Connection::is_scoped_broadcast(&data) {
                            let Some(frame) = app_connection.receive_broadcast(&data) else {
                                continue;
                            };
                            let Ok(auth) = require_bound_app_auth(&server, &conn_state) else {
                                break;
                            };
                            transport.app_jti = auth.jti().map(str::to_owned);
                            let sent = transport.send_binary(frame).await;
                            transport.app_jti = None;
                            if !sent {
                                break;
                            }
                            continue;
                        }
                        // Unrouted app payloads must never cross the shared fan-out.
                        if matches!(
                            data.first().copied(),
                            Some(protocol::TAG_RPC | protocol::TAG_SUB)
                        ) {
                            continue;
                        }
                        if should_forward_broadcast(protocol_version, &data)
                            && !transport.send_binary(data).await
                        {
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(crate::broadcast::BroadcastError::Lagged(n)) => {
                        app_connection.replay_after_lag();
                        tracing::warn!(conn_id, missed = n, "subscriber lagged — resync needed");
                    }
                    Err(crate::broadcast::BroadcastError::TooManyLags) => {
                        tracing::warn!(conn_id, "too many lags — disconnecting");
                        transport.close().await;
                        break;
                    }
                }
                continue;
            }
            ConnEvent::Direct(direct_msg) => {
                let Some(data) = direct_msg else {
                    break;
                };
                let app_frame = matches!(
                    data.first().copied(),
                    Some(protocol::TAG_RPC | protocol::TAG_SUB)
                );
                if app_frame
                    && conn_state.bound_auth.as_ref().is_none_or(|auth| {
                        session_credential_revoked(server.vault().as_ref(), auth.jti())
                    })
                {
                    transport
                        .send_unguarded_close_frame(WsMessage::Close(Some(CloseFrame {
                            code: close_codes::CLOSE_RPC_NO_PRINCIPAL,
                            reason: Utf8Bytes::from_static("bound credential is no longer live"),
                        })))
                        .await;
                    break;
                }
                transport.app_jti = if app_frame {
                    conn_state
                        .bound_auth
                        .as_ref()
                        .and_then(|auth| auth.jti().map(str::to_owned))
                } else {
                    None
                };
                let sent = transport.send_binary(data).await;
                transport.app_jti = None;
                if !sent {
                    break;
                }
                continue;
            }
        };

        let Some(msg_result) = next_message else {
            break;
        };
        let data = match msg_result {
            Ok(WsMessage::Binary(data)) => data.to_vec(),
            Ok(WsMessage::Close(_)) => {
                tracing::info!(conn_id, "client closed connection");
                break;
            }
            Ok(WsMessage::Ping(_)) | Ok(WsMessage::Pong(_)) => {
                if !conn_state.record_inbound_message() {
                    tracing::warn!(
                        conn_id,
                        max = server.config.max_messages_per_sec,
                        "message rate limit exceeded by control frame — closing"
                    );
                    break;
                }
                continue;
            }
            Ok(WsMessage::Text(_)) => {
                if !conn_state.record_inbound_message() {
                    tracing::warn!(
                        conn_id,
                        max = server.config.max_messages_per_sec,
                        "message rate limit exceeded — closing"
                    );
                    break;
                }
                tracing::warn!(conn_id, "received unexpected text message");
                continue;
            }
            Err(e) => {
                tracing::warn!(conn_id, error = %e, "WebSocket error");
                break;
            }
        };

        if !conn_state.record_inbound_message() {
            tracing::warn!(
                conn_id,
                max = server.config.max_messages_per_sec,
                "message rate limit exceeded — closing"
            );
            break;
        }

        // Size check
        if data.len() > server.config.max_frame_size {
            tracing::warn!(conn_id, size = data.len(), "frame too large");
            break;
        }

        // Parse and dispatch the message
        match protocol::parse_message(&data) {
            Ok(msg) => {
                // Live revocation consult, ahead of every privileged sync
                // message. The handshake established liveness at upgrade
                // time only; a `jti` revoked since must get no further
                // service on this socket. This is the READ-side gate the
                // outbound chokepoint cannot supply: refusing a request
                // before it runs also stops its side effects, which for a
                // write reach the hub store and every live peer rather than
                // this socket's sink.
                if privileged_sync_message(&msg)
                    && session_credential_revoked(server.vault().as_ref(), session_jti.as_deref())
                {
                    tracing::warn!(
                        conn_id,
                        "credential revoked — refusing sync message and closing"
                    );
                    break;
                }
                let handle_result = match msg {
                    SyncMessage::Rpc(payload) => handle_app_message_with_connection(
                        &server,
                        &mut conn_state,
                        protocol::TAG_RPC,
                        &payload,
                        &direct_tx,
                        Some(&mut app_connection),
                    ),
                    SyncMessage::Sub(payload) => handle_app_message_with_connection(
                        &server,
                        &mut conn_state,
                        protocol::TAG_SUB,
                        &payload,
                        &direct_tx,
                        Some(&mut app_connection),
                    ),
                    msg => {
                        handle_sync_message(&server, conn_id, msg, &direct_tx, &mut conn_state)
                            .await
                    }
                };
                if let Err(e) = handle_result {
                    match &e {
                        ProtocolError::RpcVersionMismatch | ProtocolError::RpcNoPrincipal => {
                            let code = if matches!(e, ProtocolError::RpcVersionMismatch) {
                                close_codes::CLOSE_RPC_VERSION_MISMATCH
                            } else {
                                close_codes::CLOSE_RPC_NO_PRINCIPAL
                            };
                            transport
                                .send_unguarded_close_frame(WsMessage::Close(Some(CloseFrame {
                                    code,
                                    reason: Utf8Bytes::from_static("app-tier admission refused"),
                                })))
                                .await;
                            break;
                        }
                        ProtocolError::InvalidPayload(msg) => {
                            tracing::warn!(conn_id, error = %msg, "invalid payload — closing");
                            break;
                        }
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

    tracing::info!(conn_id, "connection closed");
}

/// Whether this message class moves server state, and therefore requires a
/// live credential.
///
/// Everything that reads the vault out (root VV deltas, window VV exchange,
/// selector fetches), writes into it (window updates), registers device
/// identity (lease), or publishes to live peers (ephemeral presence/cursor
/// state) is privileged. Exactly one class is not:
///
/// - `RootUpdate` — the root doc is server-authoritative; the handler
///   discards client updates without touching any state, so a revoked peer
///   sending one already achieves nothing. Exempting it keeps an idle
///   keepalive-shaped connection off the registry.
///
/// `Ephemeral` is deliberately NOT exempt, though it carries no vault
/// content. The read-side argument for exempting it — the outbound guard
/// stops the revoked peer from receiving the fan-out — says nothing about
/// the write side: the handler applies the payload to the hub store and
/// broadcasts it, so a revoked bearer would keep PUBLISHING presence and
/// cursor state to every live peer after losing all read access. Revocation
/// means no further service in either direction.
///
/// The exemption is the reason this is an explicit allow-list rather than a
/// blanket check: a new privileged message variant must be classified here,
/// and the compiler forces that decision by exhaustive match.
fn privileged_sync_message(msg: &SyncMessage) -> bool {
    match msg {
        SyncMessage::RootUpdate(_) => false,
        SyncMessage::Ephemeral(_)
        | SyncMessage::RootVersionVector(_)
        | SyncMessage::LeaseRequest { .. }
        | SyncMessage::WindowSync { .. }
        | SyncMessage::Rpc(_)
        | SyncMessage::Sub(_) => true,
    }
}

pub(super) fn should_forward_broadcast(protocol_version: u8, data: &[u8]) -> bool {
    protocol_version == protocol::LEGACY_FULL_WINDOW_PROTOCOL_VERSION
        || data.first().copied() != Some(protocol::TAG_WINDOW_SYNC)
}
