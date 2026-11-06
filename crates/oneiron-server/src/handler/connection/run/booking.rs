//! A stale owner sign-in's app-tier socket (FIX 11712; DEC-0005 and
//! ARCH-0062 stale-owner booking parity; ARCH-0044 facade calls on the held
//! socket).
//!
//! A managed vault's attested holder the vault no longer records as its
//! live owner books at the per-request doors (FIX 5327) and on his held MCP
//! socket (FIX 5935). His app-tier socket books too, and does nothing more.
//! Its upgrade names no MCP subprotocol, and its mode is fixed there: it
//! never becomes a replication socket, and a slip that fails never falls
//! back to him.
//!
//! The socket serves no sync state. It subscribes to no broadcast, keeps no
//! replication state, and sends no root snapshot, presence or key offer. It
//! answers the protocol hello (the app tier's protocol 8 or later), `ping`,
//! and the generated booking verbs among the booking payer doors
//! (`api::booking_payer_verbs`), each as a binary `rpc.req`. Any other frame
//! closes it before anything runs: `auth.bind`, a subscription, a residence
//! call, every other facade verb, and every sync, document, window,
//! leaf-key, asset or presence frame.
//!
//! Each call is his own call where this socket sits. It builds his booking
//! caller again (`CoreAuth::for_attested_booking_holder`), takes its call
//! context on arrival, and runs through the facade's one generated dispatch
//! ([`crate::livequery::rpc_reply`]): hooks, schemas, receipts, invocation
//! replay and the booking doors' publication and payer checks all stand.
//! No credential, owner proof or live-owner guard stands behind the socket,
//! so its transport closes on the vault's deletion alone.
//!
//! Each call runs under its own reap admission
//! ([`ManagedCarrierContext::admit_call`]), kept through its reply's
//! encoding and its receipt. The send door judges each reply frame's rows
//! just before that frame is sent, under a short receipt admission of its
//! own for the delivery refusal it may write: a reply that waits behind a
//! peer that does not read holds no admission, and a row its world kept
//! from the socket meanwhile stays unsent. A ping's receipt and a protocol
//! refusal's are admitted alone. While the vault is
//! frozen, a call or a ping is answered with the served pause, as on the
//! MCP carrier. An idle socket holds no admission.

use std::sync::Arc;

use axum::extract::ws::{Message as WsMessage, WebSocket};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

use super::super::super::protocol_close;
use super::super::super::socket_stop::StoppingTransport;
use super::super::super::transport::GuardedTransport;
use super::super::{MAX_VERB_CALLS_IN_FLIGHT, vault_deleted};
use crate::auth::{CoreAuth, RevokedTokenJtis};
use crate::livequery::connection::{Connection, Hub};
use crate::livequery::{RpcRequest, SocketCallContext};
use crate::managed::ManagedCarrierContext;
use crate::protocol::{APP_TIER_PROTOCOL_VERSION_VERSION, ProtocolError, TAG_RPC, close_codes};
use crate::server::SyncServer;

/// The reason the socket's close states for a frame or a call it does not
/// serve.
const BOOKING_ONLY: &str = "this socket carries booking calls only";

/// What a stale owner sign-in's app-tier socket keeps from its upgrade:
/// whose socket it is, and the reap admission each of its calls and
/// receipts takes. Never a credential, an owner proof or a live-owner
/// guard: each call builds his booking caller again.
pub(in crate::handler::connection) struct BookingCaller {
    /// The person his supervisor attested on the upgrade.
    holder: oneiron::EntityId,
    /// The reap admission managed ingress handed the upgrade.
    managed: ManagedCarrierContext,
}

impl BookingCaller {
    /// The socket an upgrade opens for `holder`, a stale owner sign-in
    /// (`mcp_socket::stale_booking_holder`), on a managed vault whose
    /// ingress handed the upgrade the reap admission its calls take. An
    /// upgrade it handed none is refused, never served bare.
    pub(in crate::handler::connection) fn upgraded(
        holder: oneiron::EntityId,
        extensions: &axum::http::Extensions,
    ) -> Result<Self, Response> {
        let managed = extensions
            .get::<ManagedCarrierContext>()
            .cloned()
            .ok_or_else(|| StatusCode::INTERNAL_SERVER_ERROR.into_response())?;
        Ok(Self { holder, managed })
    }
}

/// What woke the booking loop.
enum Event {
    Answered(Result<Result<Answer, ProtocolError>, tokio::task::JoinError>),
    Inbound(Option<Result<WsMessage, axum::Error>>),
}

/// One call's answer, as the loop takes it back.
enum Answer {
    /// Its reply frames as the call queued them, each still naming its
    /// rows. The call's reap admission ended once they were encoded and
    /// receipted: a reply waiting on a peer that does not read holds no
    /// admission. The send door judges each frame as it is sent
    /// ([`released`]).
    Reply(Vec<Vec<u8>>),
    /// The served pause: the vault was frozen for reap, and nothing ran.
    Paused(Vec<Vec<u8>>),
}

/// The booking loop. Every frame it writes goes through the guarded
/// transport, which asks the vault first whether its Owners deleted it, and
/// every read does too. A caller at `locality`, whose upgrade proved
/// `machine` and was observed as `signing_request_transport`, makes each
/// call. On the engine's stop (OF-237) the loop stops reading at its next
/// wait and the transport closes; the socket ends once every call it
/// admitted has.
pub(super) async fn serve(
    (socket, mut stop): (WebSocket, crate::embedded::UpgradeStop),
    server: Arc<SyncServer>,
    conn_id: u32,
    caller: BookingCaller,
    locality: oneiron::claim::CallerLocality,
    machine: oneiron::authority::PeerMachine,
    signing_request_transport: Option<oneiron::memory::SigningRequestTransport>,
) {
    tracing::info!(conn_id, "app-tier socket serves booking calls only");
    // No token id names him and he is no live owner: the guard asks the
    // vault only whether its Owners deleted it.
    let transport = GuardedTransport::new(
        socket,
        Arc::clone(server.vault()) as Arc<dyn RevokedTokenJtis + Send + Sync>,
        None,
        conn_id,
    )
    .with_inbound_cap(server.config.max_frame_size)
    .with_live_owner(server.vault(), None);
    // Its hello and sends give way to the engine's stop.
    let mut transport = StoppingTransport::new(transport, stop.clone());
    let admission = Some(&caller.managed);
    // FIX 3303: each refusal below is its connection's receipt, then the
    // close, the receipt admitted under the reap freeze.
    match protocol_close::hello(&mut transport, &server, conn_id, admission).await {
        Some(version) if version >= APP_TIER_PROTOCOL_VERSION_VERSION => {}
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
    let holder = caller.holder.to_hex();
    // The connection a call's context names and the send door its reply
    // leaves by: no subscription opens here.
    let mut replies = Connection::new(Hub::for_server(&server), conn_id);
    // Calls answer off this loop, which reads no further frame while
    // `MAX_VERB_CALLS_IN_FLIGHT` of them are in flight. A call still running
    // when the loop ends runs to its end below.
    let mut calls = tokio::task::JoinSet::new();
    'serving: loop {
        let event = tokio::select! {
            biased;
            // OF-237: the engine's stop ends the loop at its wait.
            () = stop.turned() => break,
            Some(answered) = calls.join_next(), if !calls.is_empty() => Event::Answered(answered),
            inbound = transport.read_next(), if calls.len() < MAX_VERB_CALLS_IN_FLIGHT => {
                Event::Inbound(inbound)
            }
        };
        let data = match event {
            Event::Answered(Ok(Ok(Answer::Reply(frames)))) => {
                for frame in frames {
                    // Judged now, just before it is sent: a row a world
                    // kept from this socket while the frame waited stays
                    // unsent, and the refusal replaces it.
                    let Some(frame) = released(
                        &server,
                        &caller.managed,
                        &mut replies,
                        (locality, machine),
                        frame,
                    ) else {
                        // Frozen for reap: no refusal receipt can be
                        // written, so nothing more leaves and the socket
                        // closes. The call's own receipt stands.
                        tracing::info!(conn_id, "vault frozen at a booking reply's send — closing");
                        break 'serving;
                    };
                    if let Some(frame) = frame
                        && !transport.send_binary(frame).await
                    {
                        break 'serving;
                    }
                }
                continue;
            }
            Event::Answered(Ok(Ok(Answer::Paused(frames)))) => {
                for frame in frames {
                    if !transport.send_binary(frame).await {
                        break 'serving;
                    }
                }
                continue;
            }
            Event::Answered(Ok(Err(error))) => {
                tracing::warn!(conn_id, %error, "booking call answer failed — closing");
                break;
            }
            Event::Answered(Err(error)) => {
                tracing::warn!(
                    conn_id,
                    panicked = error.is_panic(),
                    "booking call ended without an answer — closing"
                );
                break;
            }
            Event::Inbound(Some(Ok(WsMessage::Binary(data)))) => data,
            Event::Inbound(Some(Ok(
                WsMessage::Ping(_) | WsMessage::Pong(_) | WsMessage::Text(_),
            ))) => {
                continue;
            }
            Event::Inbound(Some(Ok(WsMessage::Close(_)))) => break,
            // A frame the WebSocket codec refused is a refusal, not a
            // disconnect: receipted, then closed (FIX 5311).
            Event::Inbound(Some(Err(error))) => {
                protocol_close::close_read_error(&server, &mut transport, &error, admission).await;
                break;
            }
            // A frame the transport refused is a refusal, not a disconnect.
            Event::Inbound(None) => {
                protocol_close::close_read_refusal(&server, &mut transport, admission).await;
                break;
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
        // Only app RPCs: no sync, document, window, leaf-key, asset,
        // presence or subscription frame is served on this socket.
        let Some((&TAG_RPC, payload)) = data.split_first() else {
            protocol_close::refuse_frame(
                &mut transport,
                &server,
                close_codes::UNKNOWN_TAG,
                BOOKING_ONLY,
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
        // OF-520: each call counts under the person who makes it.
        let _ = server.wire_telemetry.record(
            &request.method,
            &holder,
            oneiron_vault_contract::now_ts(),
        );
        if request.method == "ping" {
            // A call context rides a facade verb RPC only (FIX 2059).
            if carried.is_some() {
                protocol_close::refuse_frame(
                    &mut transport,
                    &server,
                    close_codes::DECODE_ERROR,
                    "a call context rides only a facade verb RPC",
                    admission,
                )
                .await;
                break;
            }
            let Ok(frames) = ping(&server, &caller.managed, request) else {
                break;
            };
            for frame in frames {
                if !transport.send_binary(frame).await {
                    break 'serving;
                }
            }
            continue;
        }
        // The five booking verbs alone, as the booking payer doors name
        // them: `auth.bind`, a residence call and every other facade verb
        // are refused before anything runs.
        if !crate::api::booking_payer_verbs().any(|verb| verb == request.method.as_str()) {
            protocol_close::refuse_frame(
                &mut transport,
                &server,
                close_codes::CLOSE_RPC_NO_PRINCIPAL,
                BOOKING_ONLY,
                admission,
            )
            .await;
            break;
        }
        // FIX 1930: a vault its Owners deleted serves no further call.
        if vault_deleted(server.vault()) {
            break;
        }
        // His booking caller, built again for this call alone, where this
        // socket sits: never a credential kept from the upgrade.
        let Ok(auth) = CoreAuth::for_attested_booking_holder(caller.holder, &server) else {
            protocol_close::refuse_frame(
                &mut transport,
                &server,
                close_codes::CLOSE_RPC_NO_PRINCIPAL,
                BOOKING_ONLY,
                admission,
            )
            .await;
            break;
        };
        let auth = auth.at(locality);
        // FIX 2059: the call context is taken on arrival, before the call
        // leaves the loop. It names no subscription open here.
        let context = SocketCallContext::arrived(&server, &auth, carried, Some(&replies))
            .with_signing_request_transport(signing_request_transport.clone());
        calls.spawn(crate::api::call_receipt::on_connection(
            crate::api::call_receipt::connection_id(),
            answer(
                Arc::clone(&server),
                caller.managed.clone(),
                auth,
                request,
                context,
                conn_id,
            ),
        ));
    }
    // OF-237: the socket closes, then every call it admitted runs to its
    // end; none is aborted. Only after them does its place in an embedded
    // engine's drain go, so no worker stops under one.
    drop(transport);
    while calls.join_next().await.is_some() {}
}

/// A `ping`: the connection's reply, echoing its params (FIX 811). Its
/// receipt is admitted under the reap freeze; while the vault is frozen it
/// is answered with the served pause and records nothing.
fn ping(
    server: &SyncServer,
    managed: &ManagedCarrierContext,
    request: RpcRequest,
) -> Result<Vec<Vec<u8>>, ProtocolError> {
    let id = request.request_id;
    let reply = || {
        let digest = oneiron::receipt::call_json_digest(&request.params);
        let stamp = crate::api::call_receipt::record_socket_reply(
            server,
            request.method,
            oneiron::receipt::CallOutcome::Ok,
            digest.clone(),
            Some(digest),
        );
        crate::livequery::stamped_ping_result(id, request.params, &stamp).map(|frame| vec![frame])
    };
    managed
        .admit_receipt(reply)
        .unwrap_or_else(|paused| served_pause(id, paused.status(), &paused.body()))
}

/// One booking call, off the loop, under its own reap admission: the vault
/// woken from slim as a served request wakes it, then the verb through the
/// WS door ([`crate::livequery::rpc_reply`]), its reply encoded and queued
/// for `conn_id`. The admission ends there, before the reply goes back to
/// the loop, so no completed call holds one while the loop waits on a peer
/// that does not read; the send door judges the reply's rows at its send
/// ([`released`]). While the vault is frozen for reap nothing runs, and the
/// call is answered with the served pause.
async fn answer(
    server: Arc<SyncServer>,
    managed: ManagedCarrierContext,
    auth: CoreAuth,
    request: RpcRequest,
    context: SocketCallContext,
    conn_id: u32,
) -> Result<Answer, ProtocolError> {
    let id = request.request_id;
    let call = async move {
        if let Err(error) = server.vault().resume_from_slim_on_inbound() {
            return Err(ProtocolError::Persistence(error.to_string()));
        }
        crate::livequery::rpc_reply(&server, &auth, request, context)
            .await
            .map(|reply| reply.queued(conn_id))
    };
    match managed.admit_call(call).await {
        Ok(Some((frames, held))) => {
            // Its encoding and receipt ran under the admission, which ends
            // here: the send door judges its rows at the send.
            drop(held);
            frames.map(Answer::Reply)
        }
        Ok(None) => Err(ProtocolError::InvalidPayload(
            "the booking call ended without an answer",
        )),
        Err(paused) => served_pause(id, paused.status(), &paused.body()).map(Answer::Paused),
    }
}

/// `frame`, one frame of a call's reply, as this socket's send door
/// releases it just before it is sent: a result chunk judged again by the
/// rows it carries, for where the socket at `locality` sits and the
/// `machine` it proved, judged now (DEC-0005, OF-534 G6). A chunk that would
/// carry a row kept from it is replaced by the refusal, and the rest of its
/// result is dropped (`Some(None)`); the refusal's receipt is written under
/// a receipt admission taken for this judgment alone, never the call's.
/// A refusal the call answered with carries no rows and leaves as it is.
/// `None` while the vault is frozen for reap: no receipt can be written, so
/// the frame does not leave.
fn released(
    server: &SyncServer,
    managed: &ManagedCarrierContext,
    replies: &mut Connection,
    (locality, machine): (
        oneiron::claim::CallerLocality,
        oneiron::authority::PeerMachine,
    ),
    frame: Vec<u8>,
) -> Option<Option<Vec<u8>>> {
    if !Connection::is_scoped_broadcast(&frame) {
        return Some(Some(frame));
    }
    managed
        .admit_receipt(|| {
            let peer = server.vault().peer_machine_stands(machine);
            replies.release_for(locality, peer, &frame)
        })
        .ok()
}

/// The served pause a call or a ping is answered with while the vault is
/// frozen for reap, as the MCP carrier answers it (FIX 5128): the status and
/// body a served write gets, as the request's one result, with no receipt.
fn served_pause(
    id: u64,
    status: StatusCode,
    body: &serde_json::Value,
) -> Result<Vec<Vec<u8>>, ProtocolError> {
    crate::livequery::rpc_result(
        id,
        json!({ "status": status.as_u16(), "body": body.to_string() }),
    )
}
