//! Booking-only app RPCs for a managed holder who is no longer an Owner.
use super::super::protocol_close;
use super::super::socket_stop::StoppingTransport;
use super::super::transport::{GuardedTransport, WS_MAX_WRITE_BUFFER_SIZE, WS_WRITE_BUFFER_SIZE};
use crate::auth::{CoreAuth, RevokedTokenJtis};
use crate::livequery::RpcReply;
use crate::managed::{ManagedCarrierContext, ManagedOwnerSession};
use crate::protocol::{self, ProtocolError, close_codes};
use crate::server::SyncServer;
use axum::extract::ConnectInfo;
use axum::extract::ws::{Message as WsMessage, WebSocket, WebSocketUpgrade};
use axum::http::{Extensions, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use std::net::SocketAddr;
use std::sync::Arc;

struct Caller {
    session: ManagedOwnerSession,
    managed: ManagedCarrierContext,
    locality: oneiron::claim::CallerLocality,
    machine: oneiron::authority::PeerMachine,
    room_turn: Option<String>,
    session_ref: Option<String>,
    signing: oneiron::memory::SigningRequestTransport,
}

pub(super) fn upgrade(
    ws: WebSocketUpgrade,
    headers: &HeaderMap,
    extensions: &Extensions,
    server: Arc<SyncServer>,
    holder: oneiron::EntityId,
    placement: (
        oneiron::claim::CallerLocality,
        oneiron::authority::PeerMachine,
    ),
) -> Result<Response, Response> {
    let managed = extensions
        .get::<ManagedCarrierContext>()
        .cloned()
        .ok_or_else(|| StatusCode::INTERNAL_SERVER_ERROR.into_response())?;
    let session = CoreAuth::for_attested_booking_holder(holder, &server)
        .ok()
        .as_ref()
        .and_then(ManagedOwnerSession::opened_by)
        .ok_or_else(|| StatusCode::UNAUTHORIZED.into_response())?;
    let header = |name: &str| {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
    };
    let caller = Caller {
        session,
        managed,
        locality: placement.0,
        machine: placement.1,
        room_turn: header("x-oneiron-room-turn"),
        session_ref: header("x-oneiron-session"),
        signing: oneiron::memory::SigningRequestTransport::new(
            extensions
                .get::<ConnectInfo<SocketAddr>>()
                .filter(|peer| peer.0.port() != 0)
                .map(|peer| peer.0.ip()),
            header("user-agent"),
        ),
    };
    let conn_id = server.alloc_conn_id();
    let connection = crate::api::call_receipt::connection_id();
    let hold = crate::embedded::UpgradeHold::take(extensions);
    Ok(ws
        .max_frame_size(server.config.max_frame_size)
        .write_buffer_size(WS_WRITE_BUFFER_SIZE)
        .max_write_buffer_size(WS_MAX_WRITE_BUFFER_SIZE)
        .on_upgrade(move |socket| {
            crate::embedded::UpgradeHold::run(hold, move |stop| {
                crate::api::call_receipt::on_connection(
                    connection,
                    serve(socket, stop, server, conn_id, caller),
                )
            })
        })
        .into_response())
}

async fn serve(
    socket: WebSocket,
    mut stop: crate::embedded::UpgradeStop,
    server: Arc<SyncServer>,
    conn_id: u32,
    caller: Caller,
) {
    let transport = GuardedTransport::new(
        socket,
        Arc::clone(server.vault()) as Arc<dyn RevokedTokenJtis + Send + Sync>,
        None,
        conn_id,
    )
    .with_inbound_cap(server.config.max_frame_size)
    .with_live_owner(server.vault(), None);
    let mut transport = StoppingTransport::new(transport, stop.clone());
    let admission = Some(&caller.managed);
    match protocol_close::hello(&mut transport, &server, conn_id, admission).await {
        Some(version) if version >= protocol::APP_TIER_PROTOCOL_VERSION_VERSION => {}
        Some(_) => {
            protocol_close::refuse_hello_version(
                &mut transport,
                &server,
                close_codes::CLOSE_RPC_VERSION_MISMATCH,
                "app tier needs protocol 8",
                admission,
            )
            .await;
            return;
        }
        None => return,
    }
    // No session is opened here: this handle only releases RPC rows.
    let mut release = crate::livequery::connection::Connection::new(
        crate::livequery::connection::Hub::for_server(&server),
        conn_id,
    );
    let mut calls: tokio::task::JoinSet<Result<RpcReply, ProtocolError>> =
        tokio::task::JoinSet::new();
    'serving: loop {
        let data = tokio::select! {
            biased;
            () = stop.turned() => break,
            Some(answered) = calls.join_next(), if !calls.is_empty() => {
                let Ok(Ok(reply)) = answered else { break };
                for frame in reply.queued(conn_id) {
                    if let Some(frame) = release.release_for(caller.locality, caller.machine, &frame)
                        && !transport.send_binary(frame).await
                    { break 'serving; }
                }
                continue;
            }
            inbound = transport.read_next(), if calls.len() < super::MAX_VERB_CALLS_IN_FLIGHT => {
                match inbound {
                    Some(Ok(WsMessage::Binary(data))) => data,
                    Some(Ok(WsMessage::Ping(_) | WsMessage::Pong(_) | WsMessage::Text(_))) => continue,
                    Some(Ok(WsMessage::Close(_))) => break,
                    Some(Err(error)) => {
                        protocol_close::close_read_error(&server, &mut transport, &error, admission).await;
                        break;
                    }
                    None => {
                        protocol_close::close_read_refusal(&server, &mut transport, admission).await;
                        break;
                    }
                }
            }
        };
        if data.len() > server.config.max_frame_size {
            protocol_close::refuse_frame(
                &mut transport,
                &server,
                close_codes::FRAME_TOO_LARGE,
                "frame too large",
                admission,
            )
            .await;
            break;
        }
        let Some((&protocol::TAG_RPC, payload)) = data.split_first() else {
            protocol_close::refuse_frame(
                &mut transport,
                &server,
                close_codes::UNKNOWN_TAG,
                "this socket carries booking RPCs only",
                admission,
            )
            .await;
            break;
        };
        let Ok((request, carried)) = crate::livequery::decode_rpc_call(payload) else {
            protocol_close::refuse_frame(
                &mut transport,
                &server,
                close_codes::DECODE_ERROR,
                "invalid app envelope",
                admission,
            )
            .await;
            break;
        };
        let request_id = request.request_id;
        if request.method == "ping" && carried.is_none() {
            let reply = || {
                let digest = oneiron::receipt::call_json_digest(&request.params);
                let stamp = crate::api::call_receipt::record_socket_reply(
                    &server,
                    request.method,
                    oneiron::receipt::CallOutcome::Ok,
                    digest.clone(),
                    Some(digest),
                );
                crate::livequery::stamped_ping_result(request_id, request.params, &stamp)
                    .map(|frame| vec![frame])
            };
            let frames = caller.managed.admit_receipt(reply).unwrap_or_else(|pause| {
                RpcReply::paused(request_id, pause.body()).map(|reply| reply.queued(conn_id))
            });
            let Ok(frames) = frames else { break };
            for frame in frames {
                if !transport.send_binary(frame).await {
                    break 'serving;
                }
            }
            continue;
        }
        if !crate::api::booking::booking_payer_verbs().any(|verb| verb == request.method) {
            protocol_close::refuse_frame(
                &mut transport,
                &server,
                close_codes::DECODE_ERROR,
                crate::error::MANAGED_OWNER_SIGN_IN_AGAIN,
                admission,
            )
            .await;
            break;
        }
        // Re-resolve this holder, not the upgrade's former Owner rights.
        // Native booking doors resolve its live grants and payer.
        let Ok(auth) = CoreAuth::for_attested_booking_holder(caller.session.holder(), &server)
        else {
            break;
        };
        let auth = auth.at(caller.locality).toward(caller.machine);
        let mut carried = carried.unwrap_or_default();
        carried.room_turn = carried.room_turn.or_else(|| caller.room_turn.clone());
        carried.session = carried.session.or_else(|| caller.session_ref.clone());
        let context =
            crate::livequery::SocketCallContext::arrived(&server, &auth, Some(carried), None)
                .with_signing_request_transport(Some(caller.signing.clone()));
        let call_server = Arc::clone(&server);
        let connection = crate::api::call_receipt::connection_id();
        let answer = caller
            .managed
            .admit_socket_call(crate::api::call_receipt::on_connection(
                connection,
                async move {
                    let _ = call_server.wire_telemetry.record(
                        &request.method,
                        auth.principal_ref().unwrap_or(auth.principal()),
                        oneiron_vault_contract::now_ts(),
                    );
                    crate::livequery::rpc_reply(&call_server, &auth, request, context).await
                },
            ));
        match answer {
            Ok(answer) => {
                calls.spawn(async move {
                    answer.await.map_err(|_| {
                        ProtocolError::InvalidPayload("booking call ended without an answer")
                    })?
                });
            }
            Err(pause) => {
                let Ok(reply) = RpcReply::paused(request_id, pause.body()) else {
                    break;
                };
                for frame in reply.queued(conn_id) {
                    if !transport.send_binary(frame).await {
                        break 'serving;
                    }
                }
            }
        }
    }
    drop(transport);
    while calls.join_next().await.is_some() {}
}
