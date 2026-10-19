//! Upgrade route, hello bootstrap, and the single-owner connection event loop.

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::extract::ws::{CloseFrame, Message as WsMessage, Utf8Bytes, WebSocket, WebSocketUpgrade};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use oneiron::sync::documents::document_frame_withheld_for;
use tokio::time::Duration;

use super::app_tier::{
    handle_app_message_with_connection, handle_sync_message, require_bound_app_auth,
};
use super::conn_state::ConnState;
use super::ephemeral::late_join_presence;
use super::socket_stop::StoppingTransport;
use super::transport::{GuardedTransport, WS_MAX_WRITE_BUFFER_SIZE, WS_WRITE_BUFFER_SIZE};

use crate::auth::{CoreAuth, RevokedTokenJtis, is_revoked_or_unreadable, require_owner_auth};
use crate::broadcast::BroadcastSubscriber;
use crate::protocol::{self, ProtocolError, SyncMessage, close_codes};
use crate::server::SyncServer;

/// Builds the WebSocket routes for the sync server.
pub(crate) fn ws_routes(server: Arc<SyncServer>) -> Router {
    Router::new()
        .route("/ws", get(ws_upgrade_handler))
        .with_state(server.clone())
        .layer(axum::middleware::from_fn_with_state(
            server.clone(),
            crate::auth::admit_http_binding,
        ))
        // FIX 811: a refused upgrade is its connection's receipt.
        .layer(axum::middleware::from_fn_with_state(
            server,
            crate::api::call_receipt::connection_receipt,
        ))
}

/// Handles WebSocket upgrade requests.
///
/// Auth: the upgrade request must present an owner-grade credential in the
/// `Authorization: Bearer` header — a logged, holder-bound top-scope slip.
/// Neither the issuer secret nor a device lease grants socket access.
/// An unauthenticated upgrade is rejected with 401 BEFORE the socket upgrade
/// (fail-closed) — without this gate any network peer could pull the full
/// root snapshot and window exports. When no secret is configured, upgrades
/// are rejected unless the explicit insecure dev escape hatch is enabled,
/// matching `auth::require_owner_auth` on the HTTP side. An upgrade naming
/// the MCP subprotocol is the one exception: it opens the MCP carrier
/// ([`super::mcp_socket`]), which serves none of that state.
///
/// The credential's revocable identity is carried into the connection rather
/// than discarded with the rest of the `CoreAuth`: the handshake proves the
/// token was live at upgrade time, and the socket outlives that instant.
///
/// On a managed vault, an upgrade its supervisor attested as the owner's own
/// (managed ingress verified that over the `GET`, its path, raw query,
/// placing headers and empty body, never the frames) is the owner himself,
/// while the vault records him as its live owner (FIX 5255). No token id
/// names him, so the socket asks the vault that again before every read,
/// release and inbound effect, and its app tier is bound to him without a
/// slip. A machine stands for the socket only where one was proved.
async fn ws_upgrade_handler(
    ws: WebSocketUpgrade,
    headers: HeaderMap,
    crate::auth::Locality(locality): crate::auth::Locality,
    machine: Option<axum::Extension<oneiron::authority::PeerMachine>>,
    extensions: axum::http::Extensions,
    State(server): State<Arc<SyncServer>>,
) -> Result<Response, Response> {
    // The MCP carrier serves no sync state, so it admits any holder-bound
    // slip rather than only an owner-grade one.
    if super::mcp_socket::requested(&ws) {
        // On a managed vault its calls would ride a held socket past the
        // reap freeze, which admits each request or upgrade once: a slip
        // there is refused, named, and each call goes as one `POST /mcp`.
        if server.managed_issuer.is_some() && crate::auth::carries_caller_slip(&headers) {
            return Err(managed_mcp_carrier_refused());
        }
        return super::mcp_socket::upgrade(ws, &headers, &extensions, server)
            .map_err(IntoResponse::into_response);
    }
    let auth = match CoreAuth::for_attested_request(&headers, &extensions, "/ws", &server) {
        Some(Ok(auth)) if auth.is_owner_grade() => auth,
        Some(Ok(_)) => {
            return Err(crate::auth::caller_slip_too_narrow("full replication").into_response());
        }
        Some(Err(refused)) => return Err(refused.into_response()),
        None => require_owner_auth(&headers, &server.config, server.vault().as_ref())
            .map_err(|_| sync_upgrade_refused(&headers, &server))?,
    };
    // Full replication reads the whole vault, an owner act: a hosted
    // operator's root is refused before the upgrade (FIX 2222).
    crate::api::host_action::require_host_owner_act(&server, &auth)
        .map_err(|_| StatusCode::FORBIDDEN.into_response())?;
    let session_jti = auth.jti().map(str::to_owned);
    let owner = auth.managed_owner().is_some().then(|| auth.clone());
    // The socket's sync frames count under the actor its upgrade admitted,
    // as an HTTP request counts under its own (OF-520, FIX 1086).
    let telemetry_actor = auth.principal_ref().unwrap_or(auth.principal()).to_owned();
    // The binding door proved the machine with the upgrade's own slip proof.
    let machine = machine.map_or(oneiron::authority::PeerMachine::Unknown, |m| m.0);
    // The home answers with its own machine over that same proof, so the
    // device judges its sends for this machine (OF-534 G6/G7).
    let home_proof = home_proof_header(&headers, server.vault().as_ref());

    let conn_id = server.alloc_conn_id();
    tracing::info!(conn_id, "new WebSocket connection");

    // `write_buffer_size` is a security setting here, not a tuning knob: it is
    // what keeps `start_send` from writing to the socket on its own. See
    // [`WS_WRITE_BUFFER_SIZE`]. Note that `max_frame_size` below does NOT pin
    // that — it bounds inbound reads only — so the outbound side is held by
    // [`GuardedTransport::fits_below_write_through`], which refuses per frame
    // in release builds.
    // FIX 811: the socket's unattributed replies name the connection its
    // upgrade arrived on.
    let connection = crate::api::call_receipt::connection_id();
    // OF-237: over an embedded engine's channel or mesh the whole socket,
    // hello included, lives under the engine's stop, which it answers itself,
    // and the stop waits for it and every call it admitted from before the
    // upgrade registers.
    let hold = crate::embedded::UpgradeHold::take(&extensions);
    let mut response = ws
        .max_frame_size(server.config.max_frame_size)
        .write_buffer_size(WS_WRITE_BUFFER_SIZE)
        .max_write_buffer_size(WS_MAX_WRITE_BUFFER_SIZE)
        .on_upgrade(move |socket| {
            crate::embedded::UpgradeHold::run(hold, move |stop| {
                crate::api::call_receipt::on_connection(
                    connection,
                    handle_connection(
                        (socket, stop),
                        server,
                        conn_id,
                        (session_jti, owner),
                        telemetry_actor,
                        locality,
                        machine,
                    ),
                )
            })
        })
        .into_response();
    if let Some(value) = home_proof {
        response
            .headers_mut()
            .insert(oneiron::sync::home_proof::HOME_PROOF_HEADER, value);
    }
    Ok(response)
}

/// The refusal of a sync upgrade whose credential is not owner-grade. On a
/// managed vault a caller's own forwarded slip that verified, but is
/// narrower than full replication, is told so and never served as the host
/// (WILL-PLAN L14 row 01); every other refusal is the bare 401 it was.
fn sync_upgrade_refused(headers: &HeaderMap, server: &SyncServer) -> Response {
    if server.managed_issuer.is_some()
        && CoreAuth::from_headers(headers, &server.config, server.vault().as_ref()).is_ok()
    {
        return crate::auth::caller_slip_too_narrow("full replication").into_response();
    }
    StatusCode::UNAUTHORIZED.into_response()
}

/// The MCP carrier's refusal on a managed vault (WILL-PLAN L14 row 01). The
/// reap freeze admits a request or an upgrade once and never sees a call on
/// a socket it already let through, and the carrier holds nothing a reap
/// counts, so a reap could read quiescent over a call in flight. The bound
/// is the service's vault lifecycle allocation; the same calls run on this
/// vault as one `POST /mcp` each, and the carrier runs on a self-hosted one.
fn managed_mcp_carrier_refused() -> Response {
    let body = serde_json::json!({
        "error": "mcp_carrier_unavailable",
        "message": "This hosted vault serves MCP as one POST /mcp per call, not on a held \
            socket: a call on the socket would run past the reap pause of the service's vault \
            lifecycle allocation. The same calls work here over POST /mcp, and the socket \
            carrier works on a self-hosted vault.",
        "bound": {"kind": "capacity", "resource": "vault_lifecycle_allocation"},
        "alternative": "POST /mcp",
        "self_hosted": {"supported": true},
    });
    (StatusCode::FORBIDDEN, axum::Json(body)).into_response()
}

/// This install's machine proof answering the upgrade whose slip proof
/// `headers` carry, or `None`: no slip proof, or no machine of this vault
/// here yet. A proof that cannot be made leaves the device judging this home
/// as an unknown destination, as before.
fn home_proof_header(
    headers: &HeaderMap,
    vault: &oneiron::Vault,
) -> Option<axum::http::HeaderValue> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")?
        .trim();
    let proof = crate::auth::BindingProof::from_headers(headers).ok()?;
    let value = vault
        .home_connection_proof(token, proof.timestamp, &proof.nonce)
        .ok()??;
    axum::http::HeaderValue::from_str(&value).ok()
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
/// `None` is possible only in explicit unauthenticated development mode.
pub(super) fn session_credential_revoked(
    revoked: &dyn RevokedTokenJtis,
    session_jti: Option<&str>,
) -> bool {
    session_jti.is_some_and(|jti| is_revoked_or_unreadable(jti, revoked))
}

/// Whether this socket's caller no longer stands: its credential revoked
/// ([`session_credential_revoked`]), or, for a managed vault's attested
/// owner, whom no token id names, the vault no longer recording him as its
/// live owner (FIX 5255).
fn session_gone(
    vault: &oneiron::Vault,
    session_jti: Option<&str>,
    owner: Option<&CoreAuth>,
) -> bool {
    session_credential_revoked(vault, session_jti)
        || owner.is_some_and(|owner| !owner.credential_is_live(vault))
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
    /// A verb RPC run off the loop ended; its answer is already queued.
    Answered(Result<Result<(), ProtocolError>, tokio::task::JoinError>),
}

/// How many verb RPCs one socket runs at once, off its loop. The loop reads
/// no further frame from the socket while this many are in flight.
const MAX_VERB_CALLS_IN_FLIGHT: usize = 8;

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
async fn handle_connection(
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
        super::protocol_close::hello(&mut transport, &server, conn_id).await
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
            return;
        }
    }

    // Late-join/reconnect snapshot for the Loro-native ephemeral lane.
    for msg in late_join_presence(&server, conn_id) {
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
    // Verb RPCs answer off this loop, which serves the socket meanwhile; their
    // answers queue on `direct_tx`. A call still running when the loop ends
    // runs to its end below.
    let mut verb_calls = tokio::task::JoinSet::new();

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
                            let Ok(frames) = super::documents::document_delivery_retrying(
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
                            super::documents::retry_later(&direct_tx, retry);
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
                                    if super::window_sync::authorize_promoted_window(
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
                            && !transport.send_binary(frame).await
                        {
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(crate::broadcast::BroadcastError::Lagged(n)) => {
                        // Rule 5: lag never closes a socket. Each subscription it
                        // holds is told again, through the direct queue's doors.
                        for frame in super::lag_resync::lag_resync_frames(&server, &conn_state) {
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
                    super::conn_state::WindowSyncMode::Selector
                        | super::conn_state::WindowSyncMode::Residence
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
                    let mut retry = Vec::new();
                    let delivered = super::documents::document_delivery_retrying(
                        &server,
                        &conn_state,
                        &data,
                        &mut retry,
                    );
                    super::documents::retry_later(&direct_tx, retry);
                    match delivered {
                        Ok(mut frames) if frames.len() == 1 => data = frames.remove(0),
                        Ok(frames) if frames.is_empty() => continue,
                        _ => break,
                    }
                }
                let peer = conn_state.peer_machine(server.vault());
                let ledger_withheld =
                    if conn_state.window_sync_mode == super::conn_state::WindowSyncMode::Selector {
                        super::federation::selector_update_withheld(&server, &data, peer)
                    } else {
                        window_update_withheld(&server, peer, &data)
                    };
                if ledger_withheld
                    || document_frame_withheld_for(server.vault(), peer, &data)
                    || (data.first() == Some(&oneiron::sync::transport::TAG_LFS_CHUNK_SYNC)
                        && super::lfs_chunks::chunk_reply_withheld(&server, &mut conn_state))
                {
                    transport.app_jti = None;
                    continue;
                }
                let sent = transport.send_binary(data).await;
                transport.app_jti = None;
                if !sent {
                    break;
                }
                continue;
            }
        };

        let Some(msg_result) = next_message else {
            // A frame the transport refused is receipted, then closed (FIX 3303).
            super::protocol_close::close_read_refusal(&server, &mut transport).await;
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
                super::protocol_close::close_read_error(&server, &mut transport, &error).await;
                break;
            }
        };

        // Size check: an oversized frame is receipted, then closed (FIX 5310).
        if data.len() > server.config.max_frame_size {
            tracing::warn!(conn_id, size = data.len(), "frame too large");
            super::protocol_close::refuse_frame(
                &mut transport,
                &server,
                close_codes::FRAME_TOO_LARGE,
                "frame too large",
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
                if privileged_sync_message(&msg)
                    && session_gone(server.vault(), session_jti.as_deref(), owner.as_ref())
                {
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
                    && let Ok(auth) = super::app_tier::require_bound_app_auth(&server, &conn_state)
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
                        // FIX 5310: each refusal below is its connection's
                        // receipt, then the close it always sent, or, where
                        // it sent none, its protocol close code.
                        ProtocolError::ReplacementUnsupported => {
                            super::protocol_close::refuse_frame(
                                &mut transport,
                                &server,
                                close_codes::VERSION_MISMATCH,
                                "window behind its history-free floor: upgrade this device to hello v13+ (v14 for residence)",
                            )
                            .await;
                            break;
                        }
                        ProtocolError::WaitedOut => {
                            tracing::warn!(
                                conn_id,
                                reason = "waited_out",
                                "document waited for its turn past its deadline — closing"
                            );
                            super::protocol_close::refuse_frame(
                                &mut transport,
                                &server,
                                close_codes::TRY_AGAIN_LATER,
                                "waited for its turn past its deadline: nothing was applied",
                            )
                            .await;
                            break;
                        }
                        ProtocolError::InvalidPayload(msg) => {
                            tracing::warn!(conn_id, error = %msg, "invalid payload — closing");
                            super::protocol_close::refuse_frame(
                                &mut transport,
                                &server,
                                close_codes::DECODE_ERROR,
                                "invalid payload",
                            )
                            .await;
                            break;
                        }
                        ProtocolError::UnknownTag(tag) => {
                            tracing::warn!(conn_id, tag, "unknown tag — closing");
                            super::protocol_close::refuse_frame(
                                &mut transport,
                                &server,
                                close_codes::UNKNOWN_TAG,
                                "unknown tag",
                            )
                            .await;
                            break;
                        }
                        ProtocolError::VvDecode(_) => {
                            // Fail-closed: a malformed VV is a protocol
                            // violation, never answered with a full export.
                            tracing::warn!(
                                conn_id,
                                reason = "version_vector_decode_failed",
                                "version vector decode failure — closing"
                            );
                            break;
                        }
                        ProtocolError::FrameTooLarge { size, max } => {
                            tracing::warn!(conn_id, size, max, "frame too large — closing");
                            super::protocol_close::refuse_frame(
                                &mut transport,
                                &server,
                                close_codes::FRAME_TOO_LARGE,
                                "frame too large",
                            )
                            .await;
                            break;
                        }
                        ProtocolError::LoroImport(_) => {
                            tracing::warn!(
                                conn_id,
                                reason = "loro_import_failed",
                                "loro import error — closing"
                            );
                            break;
                        }
                        ProtocolError::Persistence(_) => {
                            // Fail-closed: the server could not durably
                            // persist sync state — do not keep relaying on a
                            // connection whose updates would vanish on
                            // restart.
                            tracing::error!(
                                conn_id,
                                reason = "sync_persistence_failed",
                                "sync persistence failure — closing"
                            );
                            break;
                        }
                    }
                }
            }
            Err(ProtocolError::UnknownTag(tag)) => {
                tracing::warn!(conn_id, tag, "unknown tag — closing");
                super::protocol_close::refuse_frame(
                    &mut transport,
                    &server,
                    close_codes::UNKNOWN_TAG,
                    "unknown tag",
                )
                .await;
                break;
            }
            Err(ProtocolError::InvalidPayload(reason)) => {
                tracing::warn!(conn_id, error = %reason, "invalid payload — closing");
                super::protocol_close::refuse_frame(
                    &mut transport,
                    &server,
                    close_codes::DECODE_ERROR,
                    "invalid payload",
                )
                .await;
                break;
            }
            Err(ProtocolError::FrameTooLarge { size, max }) => {
                tracing::warn!(conn_id, size, max, "frame too large — closing");
                super::protocol_close::refuse_frame(
                    &mut transport,
                    &server,
                    close_codes::FRAME_TOO_LARGE,
                    "frame too large",
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
        | SyncMessage::LfsChunks(_)
        | SyncMessage::RootVersionVector(_)
        | SyncMessage::LeaseRequest { .. }
        | SyncMessage::Doc { .. }
        | SyncMessage::Batch(_)
        | SyncMessage::WindowSync { .. }
        | SyncMessage::Rpc(_)
        | SyncMessage::Sub(_) => true,
    }
}

fn window_broadcast_allowed(
    protocol_version: u8,
    state: &super::conn_state::ConnState,
    frame: &[u8],
) -> bool {
    let key = frame
        .get(1..)
        .and_then(|payload| oneiron::sync::transport::decode_window_sync(payload).ok())
        .and_then(|(key, _, _)| oneiron::sync::WindowKey::try_new(key));
    match protocol_version {
        version if protocol::is_owner_window_version(version) => {
            key.is_some_and(|key| state.receives_window(&key))
        }
        _ => false,
    }
}

/// What a broadcast window frame becomes on this socket: itself where the
/// socket is pushed the window, a `WINDOW_INVALIDATE` where it forgot the
/// window's subscription past `max_windows_per_connection`, or nothing. A
/// frame this server withholds as device-only is neither.
fn window_delivery(
    server: &SyncServer,
    protocol_version: u8,
    state: &super::conn_state::ConnState,
    frame: Vec<u8>,
) -> Option<Vec<u8>> {
    if window_broadcast_allowed(protocol_version, state, &frame) {
        let peer = state.peer_machine(server.vault());
        return (!window_update_withheld(server, peer, &frame)).then_some(frame);
    }
    if !protocol::takes_window_invalidations(protocol_version) {
        return None;
    }
    let (key, _, _) = frame
        .get(1..)
        .and_then(|payload| protocol::decode_window_sync(payload).ok())?;
    let window = oneiron::sync::WindowKey::try_new(key)?;
    if !state.invalidates_window(&window)
        || window_update_withheld(server, state.peer_machine(server.vault()), &frame)
    {
        return None;
    }
    protocol::encode_window_sync(key, protocol::window_sub_tags::WINDOW_INVALIDATE, &[])
        .into_result()
        .ok()
}

/// Whether `frame` is a window UPDATE or REPLACEMENT this server now
/// withholds from the machine `peer` proved on this socket, by that
/// machine's own world read settings (OF-534 G6). Read at the socket, since
/// the flag may turn after the frame was queued for this connection.
fn window_update_withheld(
    server: &SyncServer,
    peer: oneiron::authority::PeerMachine,
    frame: &[u8],
) -> bool {
    if frame.first() != Some(&protocol::TAG_WINDOW_SYNC) {
        return false;
    }
    frame
        .get(1..)
        .and_then(|payload| protocol::decode_window_sync(payload).ok())
        .is_some_and(|(key, sub_tag, update)| {
            matches!(
                sub_tag,
                protocol::window_sub_tags::UPDATE | protocol::window_sub_tags::REPLACEMENT
            ) && oneiron::sync::window::raw_update_verdict_for(
                &server.reassert_manager,
                key,
                update,
                peer,
            ) != oneiron::sync::window::UpdateVerdict::Portable
        })
}

pub(super) fn should_forward_broadcast(protocol_version: u8, data: &[u8]) -> bool {
    if matches!(
        data.first(),
        Some(&oneiron::sync::transport::TAG_DOCUMENT) | Some(&oneiron::sync::transport::TAG_BATCH)
    ) {
        return false; // Only document_delivery may construct a recipient's export.
    }
    (protocol_version == protocol::LEGACY_FULL_WINDOW_PROTOCOL_VERSION
        || protocol::is_owner_window_version(protocol_version))
        || data.first().copied() != Some(protocol::TAG_WINDOW_SYNC)
}
