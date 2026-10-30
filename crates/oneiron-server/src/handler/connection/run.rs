//! The single-owner connection event loop: one socket's protocol hello, its
//! root snapshot, then every frame it reads and every frame it is sent.

use std::sync::Arc;

use axum::extract::ws::{CloseFrame, Message as WsMessage, Utf8Bytes, WebSocket};
use oneiron::sync::documents::document_frame_withheld_for;
use tokio::time::Duration;

use super::super::app_tier::{
    handle_app_message_with_connection, handle_sync_message, require_bound_app_auth,
};
use super::super::conn_state::ConnState;
use super::super::ephemeral::late_join_presence;
use super::super::protocol_close::internal_fault_close;
use super::super::socket_stop::StoppingTransport;
use super::super::transport::GuardedTransport;
use super::super::window_pads::send_released;
use super::{
    ConnEvent, MAX_VERB_CALLS_IN_FLIGHT, privileged_sync_message, session_credential_revoked,
    session_gone, should_forward_broadcast, window_delivery, window_update_withheld,
};

use crate::auth::{CoreAuth, RevokedTokenJtis};
use crate::broadcast::BroadcastSubscriber;
use crate::protocol::{self, ProtocolError, SyncMessage, close_codes};
use crate::server::SyncServer;

/// Main connection lifecycle.
///
/// The socket is deliberately NOT split. A split hands the two halves to two
/// tasks over one transport, and tungstenite's read path flushes the shared
/// out-buffer whenever it queues an automatic pong or close — which drains
/// application frames the write half is still holding under a revocation
/// consult. Keeping the socket whole means the borrow checker enforces what no
/// runtime check could: while a guarded frame is pending, no read exists to
/// flush it. See [`GuardedTransport`].
///
/// `socket` comes with the engine's stop it lives under (OF-237): on it the
/// loop stops reading at its next wait, the transport closes, and the
/// connection ends once every verb RPC it admitted has.
#[expect(clippy::cognitive_complexity)]
pub(super) async fn handle_connection(
    (socket, mut stop): (WebSocket, crate::embedded::UpgradeStop),
    server: Arc<SyncServer>,
    conn_id: u32,
    (session_jti, owner): (Option<String>, Option<CoreAuth>),
    telemetry_actor: String,
    locality: oneiron::claim::CallerLocality,
    machine: oneiron::authority::PeerMachine,
) {
    // Every frame this connection ever writes goes through here, and each one
    // re-consults the revocation registry first. The hello close below is the
    // single deliberate exception: it carries no vault state and is the
    // refusal itself.
    let transport = GuardedTransport::new(
        socket,
        Arc::clone(server.vault()) as Arc<dyn RevokedTokenJtis + Send + Sync>,
        session_jti.clone(),
        conn_id,
    )
    .with_inbound_cap(server.config.max_frame_size)
    .with_live_owner(server.vault(), owner.clone());
    // Its hello and sends give way to the engine's stop.
    let mut transport = StoppingTransport::new(transport, stop.clone());

    // Phase 0: protocol-version hello (ONE-1127). The client's FIRST frame
    // must be a supported protocol hello. Malformed frames or unsupported
    // versions close with 4006 BEFORE any sync payload flows, so wire breaks
    // are detectable instead of surfacing as garbled decode errors mid-sync.
    //
    // A token can idle here — upgraded but silent — for the whole hello
    // timeout, so a revocation can land between the handshake and the first
    // frame. The sends below therefore cannot rely on the handshake's proof
    // of liveness, and do not: they consult at the chokepoint. A rejected
    // hello is its connection's receipt before its close (FIX 3303).
    let Some(protocol_version) =
        super::super::protocol_close::hello(&mut transport, &server, conn_id, None).await
    else {
        return;
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
        Err(_) => {
            tracing::error!(
                conn_id,
                reason = "root_snapshot_export_failed",
                "failed to export root snapshot"
            );
            // FIX 5849: the server's own fault: closed 1011, no receipt.
            if protocol::ROOT_EXPORT_FAULT_CLOSES {
                internal_fault_close(&mut transport, close_codes::EXPORT_FAULT_REASON).await;
            }
            return;
        }
    }

    // Late-join/reconnect snapshot for the Loro-native ephemeral lane.
    for msg in late_join_presence(&server, conn_id, locality, machine) {
        if !transport.send_binary(msg).await {
            tracing::warn!(conn_id, "failed to send ephemeral snapshot");
            return;
        }
    }

    // Channel for direct responses (e.g. VV_REQUEST replies sent only to requester)
    let (direct_tx, mut direct_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let mut conn_state = ConnState::new(protocol_version).with_peer_machine(machine);
    conn_state.locality = locality;
    conn_state.bound_auth.clone_from(&owner);
    tracing::debug!(
        conn_id,
        machine = ?conn_state.peer_machine(server.vault()),
        "socket machine"
    );

    let mut app_connection = crate::livequery::connection::Connection::new(
        crate::livequery::connection::Hub::for_server(&server),
        conn_id,
    );
    let mut app_tick = tokio::time::interval(Duration::from_millis(25));
    let mut asset_body_tick = tokio::time::interval(super::super::asset_bodies::ASSET_BODY_POLL);
    // Verb RPCs answer off this loop, which serves the socket meanwhile; their
    // answers queue on `direct_tx`. A call still running when the loop ends
    // runs to its end below.
    let mut verb_calls = tokio::task::JoinSet::new();
    // This socket's live-session consult: a privileged frame takes it before
    // dispatch, and a window frame again once its window loads (FIX 5438).
    let gone = || session_gone(server.vault(), session_jti.as_deref(), owner.as_ref());

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
            biased;
            // OF-237: the engine's stop ends the loop at its wait.
            () = stop.turned() => break,
            // A VV catch-up queues its UPDATE and VV_RESPONSE before binding
            // the subscription. Drain those direct frames before a concurrent
            // broadcast can overtake their causal prefix on this socket.
            direct_msg = direct_rx.recv() => ConnEvent::Direct(direct_msg),
            Some(answered) = verb_calls.join_next(), if !verb_calls.is_empty() => {
                ConnEvent::Answered(answered)
            }
            msg = transport.read_next(),
                if direct_rx.is_empty() && verb_calls.len() < MAX_VERB_CALLS_IN_FLIGHT =>
            {
                ConnEvent::Inbound(msg)
            }
            broadcast_result = subscriber.recv() => ConnEvent::Broadcast(broadcast_result),
            _ = app_tick.tick(), if app_connection.has_active_subscriptions() => ConnEvent::AppDelivery,
            _ = asset_body_tick.tick(), if direct_rx.is_empty() => ConnEvent::AssetBodies,
        };

        let next_message = match event {
            ConnEvent::Inbound(msg) => msg,
            ConnEvent::Answered(Ok(Ok(()))) => continue,
            ConnEvent::Answered(Ok(Err(error))) => {
                tracing::warn!(conn_id, %error, "verb RPC answer failed — closing");
                break;
            }
            ConnEvent::Answered(Err(error)) => {
                tracing::warn!(conn_id, %error, "verb RPC ended without an answer — closing");
                break;
            }
            ConnEvent::AssetBodies => {
                super::super::asset_bodies::poll(&server, &mut conn_state, &direct_tx);
                continue;
            }
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
                                let _ = crate::broadcast::broadcast(&server.broadcast_tx, 0, frame);
                            }
                        }
                        Err(_) => break,
                    }
                }
                // Delivery/revocation work is level-triggered. Its synchronous
                // authority checks may outlast a period; a backlog of timer
                // ticks must not crowd out inbound frames or queued replies.
                app_tick.reset();
                continue;
            }
            ConnEvent::Broadcast(broadcast_result) => {
                match broadcast_result {
                    Ok(Some(data)) => {
                        if crate::livequery::connection::Connection::is_scoped_broadcast(&data) {
                            let Some(frame) = app_connection.release_for(
                                conn_state.locality,
                                conn_state.peer_machine(server.vault()),
                                &data,
                            ) else {
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
                        if matches!(
                            data.first(),
                            Some(&oneiron::sync::transport::TAG_DOCUMENT)
                                | Some(&oneiron::sync::transport::TAG_BATCH)
                        ) {
                            let mut retry = Vec::new();
                            let Ok(frames) = super::super::documents::document_delivery_retrying(
                                &server,
                                &conn_state,
                                &data,
                                &mut retry,
                            ) else {
                                break;
                            };
                            for frame in frames {
                                let _ = direct_tx.send(frame);
                            }
                            super::super::documents::retry_later(&direct_tx, retry);
                            continue;
                        }
                        if protocol::is_residence_version(protocol_version)
                            && data.first() == Some(&protocol::TAG_WINDOW_SYNC)
                        {
                            let Ok((raw_key, sub_tag, _)) =
                                protocol::decode_window_sync(&data[1..])
                            else {
                                break;
                            };
                            if sub_tag == protocol::window_sub_tags::UPDATE {
                                let Some(key) = oneiron::sync::WindowKey::try_new(raw_key) else {
                                    break;
                                };
                                if let Some(selector) = conn_state.promoted_windows.get(&key) {
                                    let Ok(auth) = require_bound_app_auth(&server, &conn_state)
                                    else {
                                        break;
                                    };
                                    let Ok(window) = server.reassert_manager.open_window(&key)
                                    else {
                                        break;
                                    };
                                    if super::super::window_sync::authorize_promoted_window(
                                        &server,
                                        auth,
                                        conn_state.peer_machine(server.vault()),
                                        &key,
                                        selector,
                                        &window.doc,
                                    )
                                    .is_err()
                                    {
                                        break;
                                    }
                                    let Ok(frame) = protocol::encode_window_sync(
                                        raw_key,
                                        protocol::window_sub_tags::PROMOTED_INVALIDATE,
                                        &[],
                                    )
                                    .into_result() else {
                                        break;
                                    };
                                    transport.app_jti = auth.jti().map(str::to_owned);
                                    let sent = transport.send_binary(frame).await;
                                    transport.app_jti = None;
                                    if !sent {
                                        break;
                                    }
                                }
                            }
                            continue;
                        }
                        // New owner peers receive only subscribed keys. Legacy
                        // v6 peers cannot decode world-month keys, so they keep
                        // base-month broadcasts but never receive world frames.
                        let frame = if data.first() == Some(&protocol::TAG_WINDOW_SYNC) {
                            window_delivery(&server, protocol_version, &conn_state, data)
                        } else {
                            should_forward_broadcast(protocol_version, &data).then_some(data)
                        };
                        if let Some(frame) = frame
                            && !send_released(&server, &conn_state, &mut transport, frame).await
                        {
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(crate::broadcast::BroadcastError::Lagged(n)) => {
                        // Rule 5: lag never closes a socket. Each subscription it
                        // holds is told again, through the direct queue's doors.
                        for frame in
                            super::super::lag_resync::lag_resync_frames(&server, &conn_state)
                        {
                            let _ = direct_tx.send(frame);
                        }
                        app_connection.replay_after_lag();
                        tracing::warn!(conn_id, missed = n, "subscriber lagged — resynced");
                    }
                }
                continue;
            }
            ConnEvent::Direct(direct_msg) => {
                let Some(data) = direct_msg else {
                    break;
                };
                let mut data = data;
                // A queued app body is judged again at its last door before
                // the send, by the rows it carries (DEC-0005).
                if crate::livequery::connection::Connection::is_scoped_broadcast(&data) {
                    #[cfg(test)]
                    crate::livequery::release_hook::run(&server);
                    let Some(frame) = app_connection.release_for(
                        conn_state.locality,
                        conn_state.peer_machine(server.vault()),
                        &data,
                    ) else {
                        continue;
                    };
                    data = frame;
                }
                let app_frame = matches!(
                    data.first().copied(),
                    Some(
                        protocol::TAG_RPC
                            | protocol::TAG_SUB
                            | oneiron::sync::transport::TAG_DOCUMENT
                            | oneiron::sync::transport::TAG_BATCH
                    )
                ) || (matches!(
                    conn_state.window_sync_mode,
                    super::super::conn_state::WindowSyncMode::Selector
                        | super::super::conn_state::WindowSyncMode::Residence
                ) && data.first().copied()
                    == Some(protocol::TAG_WINDOW_SYNC));
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
                let document_frame = matches!(
                    data.first(),
                    Some(&oneiron::sync::transport::TAG_DOCUMENT)
                        | Some(&oneiron::sync::transport::TAG_BATCH)
                );
                transport.app_jti = if app_frame || document_frame {
                    conn_state
                        .bound_auth
                        .as_ref()
                        .and_then(|auth| auth.jti().map(str::to_owned))
                } else {
                    None
                };
                if matches!(
                    data.first(),
                    Some(&oneiron::sync::transport::TAG_DOCUMENT)
                        | Some(&oneiron::sync::transport::TAG_BATCH)
                ) {
                    use super::super::documents::{DirectDelivery, direct_delivery};
                    match direct_delivery(&server, &conn_state, &mut transport, &direct_tx, &data)
                        .await
                    {
                        DirectDelivery::Send(frame) => data = frame,
                        DirectDelivery::Done => continue,
                        DirectDelivery::Close => break,
                    }
                }
                let peer = conn_state.peer_machine(server.vault());
                let ledger_withheld = if conn_state.window_sync_mode
                    == super::super::conn_state::WindowSyncMode::Selector
                {
                    super::super::federation::selector_update_withheld(&server, &data, peer)
                } else {
                    window_update_withheld(&server, peer, &data)
                };
                if ledger_withheld
                    || document_frame_withheld_for(server.vault(), peer, &data)
                    || (data.first() == Some(&oneiron::sync::transport::TAG_LFS_CHUNK_SYNC)
                        && super::super::lfs_chunks::chunk_reply_withheld(&server, &mut conn_state))
                {
                    transport.app_jti = None;
                    continue;
                }
                let sent = send_released(&server, &conn_state, &mut transport, data).await;
                transport.app_jti = None;
                if !sent {
                    break;
                }
                continue;
            }
        };

        let Some(msg_result) = next_message else {
            // A frame the transport refused is receipted, then closed (FIX 3303).
            super::super::protocol_close::close_read_refusal(&server, &mut transport, None).await;
            break;
        };
        let data = match msg_result {
            Ok(WsMessage::Binary(data)) => data.to_vec(),
            Ok(WsMessage::Close(_)) => {
                tracing::info!(conn_id, "client closed connection");
                break;
            }
            Ok(WsMessage::Ping(_)) | Ok(WsMessage::Pong(_)) => {
                continue;
            }
            Ok(WsMessage::Text(_)) => {
                tracing::warn!(conn_id, "received unexpected text message");
                continue;
            }
            Err(error) => {
                tracing::warn!(conn_id, reason = "websocket_read_failed", "WebSocket error");
                // A frame the WebSocket codec refused is a refusal, not a
                // disconnect: receipted, then closed (FIX 5311).
                super::super::protocol_close::close_read_error(
                    &server,
                    &mut transport,
                    &error,
                    None,
                )
                .await;
                break;
            }
        };

        // Size check: an oversized frame is receipted, then closed (FIX 5310).
        if data.len() > server.config.max_frame_size {
            tracing::warn!(conn_id, size = data.len(), "frame too large");
            super::super::protocol_close::refuse_frame(
                &mut transport,
                &server,
                close_codes::FRAME_TOO_LARGE,
                "frame too large",
                None,
            )
            .await;
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
                if privileged_sync_message(&msg) && gone() {
                    tracing::warn!(
                        conn_id,
                        "credential revoked — refusing sync message and closing"
                    );
                    break;
                }
                if let Err(error) = server.vault().resume_from_slim_on_inbound() {
                    tracing::warn!(
                        conn_id,
                        kind = ?error.kind(),
                        "failed to resume vault for inbound frame"
                    );
                    break;
                }
                if !matches!(&msg, SyncMessage::Rpc(_) | SyncMessage::Sub(_)) {
                    let _ = server.wire_telemetry.record(
                        &format!("sync:{:02x}", data[0]),
                        &telemetry_actor,
                        oneiron_vault_contract::now_ts(),
                    );
                }
                // Rule 5: a new session or subscription waits its turn here,
                // before the synchronous app tier runs it; only a live bound
                // credential that may read joins a line. The wait gives way to
                // the engine's stop (OF-237).
                if let SyncMessage::Sub(payload) = &msg
                    && let Ok(auth) =
                        super::super::app_tier::require_bound_app_auth(&server, &conn_state)
                    && auth.require(crate::auth::CoreScope::Read).is_ok()
                {
                    let admitted = app_connection.admit(Some(auth), payload);
                    if stop.until(admitted).await.is_none() {
                        break;
                    }
                }
                let handle_result = match msg {
                    SyncMessage::Rpc(payload) => handle_app_message_with_connection(
                        &server,
                        &mut conn_state,
                        protocol::TAG_RPC,
                        &payload,
                        &direct_tx,
                        Some(&mut app_connection),
                    )
                    .map(|call| {
                        if let Some(call) = call {
                            verb_calls.spawn(call.answer(Arc::clone(&server), direct_tx.clone()));
                        }
                    }),
                    SyncMessage::Sub(payload) => handle_app_message_with_connection(
                        &server,
                        &mut conn_state,
                        protocol::TAG_SUB,
                        &payload,
                        &direct_tx,
                        Some(&mut app_connection),
                    )
                    .map(drop),
                    msg => match handle_sync_message(
                        &server,
                        conn_id,
                        msg,
                        &direct_tx,
                        &mut conn_state,
                        &gone,
                    )
                    .await
                    {
                        Ok(std::ops::ControlFlow::Break(())) => break,
                        result => result.map(drop),
                    },
                };
                if let Err(e) = handle_result {
                    super::dispatch_error::close_on(&mut transport, &server, conn_id, &e).await;
                    break;
                }
            }
            Err(ProtocolError::UnknownTag(tag)) => {
                tracing::warn!(conn_id, tag, "unknown tag — closing");
                super::super::protocol_close::refuse_frame(
                    &mut transport,
                    &server,
                    close_codes::UNKNOWN_TAG,
                    "unknown tag",
                    None,
                )
                .await;
                break;
            }
            Err(ProtocolError::InvalidPayload(reason)) => {
                tracing::warn!(conn_id, error = %reason, "invalid payload — closing");
                super::super::protocol_close::refuse_frame(
                    &mut transport,
                    &server,
                    close_codes::DECODE_ERROR,
                    "invalid payload",
                    None,
                )
                .await;
                break;
            }
            Err(ProtocolError::FrameTooLarge { size, max }) => {
                tracing::warn!(conn_id, size, max, "frame too large — closing");
                super::super::protocol_close::refuse_frame(
                    &mut transport,
                    &server,
                    close_codes::FRAME_TOO_LARGE,
                    "frame too large",
                    None,
                )
                .await;
                break;
            }
            Err(e) => {
                tracing::warn!(conn_id, kind = e.kind(), "protocol parse error");
                break;
            }
        }
    }

    // OF-237: the socket closes, then every verb RPC it admitted runs to its
    // end; none is aborted. Only after them does its place in an embedded
    // engine's drain go, so no worker stops under one.
    drop(transport);
    while verb_calls.join_next().await.is_some() {}
    conn_state.closed(server.vault());
    tracing::info!(conn_id, "connection closed");
}
