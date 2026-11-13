//! A scoped caller's app-tier socket (FIX-LIST 23077; ARCH-0044 T1 and T2).
//!
//! ARCH-0044 T1 serves the held socket to any authenticated client that can
//! hold one (the code-mode inject, the native app and BYOA agents alike), and
//! T2 binds its principal to the connection. A caller whose own slip verified
//! at the upgrade but is narrower than full replication (a scoped agent, a
//! guest, an attenuated person) holds this socket. Its mode is fixed at the
//! upgrade: it never becomes a replication socket, which stays the owner's.
//!
//! The socket serves no sync state. It sends no root snapshot, presence,
//! leaf key, sealed update or window answer, and of the shared fan-out it
//! forwards only the app frames routed to it. It answers the protocol hello
//! (the app tier's protocol 8 or later), then `auth.bind`, `ping`, the facade
//! verbs and subscriptions, each through the one app tier the replication
//! socket runs ([`handle_app_message_with_connection`]): the bind, hooks,
//! schemas, receipts and each verb's own grant check stand. A residence call,
//! a machine handoff, and every sync, document, window, leaf-key, asset or
//! presence frame close it before anything runs.
//!
//! Its grant is checked live at each use. Before each frame it reads, the
//! socket asks whether the upgrade's slip still stands; each call and each
//! delivery asks again for the bound credential ([`require_bound_app_auth`]);
//! and the transport asks for both before every frame it writes. A slip
//! revoked since gets no further service here, and its next upgrade is
//! refused before a socket opens.

use std::sync::Arc;

use axum::extract::ws::{CloseFrame, Message as WsMessage, Utf8Bytes, WebSocket};
use tokio::time::Duration;

use super::super::super::app_tier::{handle_app_message_with_connection, require_bound_app_auth};
use super::super::super::conn_state::ConnState;
use super::super::super::protocol_close;
use super::super::super::socket_stop::StoppingTransport;
use super::super::super::transport::GuardedTransport;
use super::super::{MAX_VERB_CALLS_IN_FLIGHT, session_gone};
use crate::auth::{CoreAuth, RevokedTokenJtis};
use crate::broadcast::{BroadcastError, BroadcastSubscriber};
use crate::livequery::connection::{Connection, Hub};
use crate::protocol::{
    self, APP_TIER_PROTOCOL_VERSION_VERSION, ProtocolError, SyncMessage, close_codes,
};
use crate::server::SyncServer;

/// The reason the socket's close states for a frame or a call it does not
/// serve.
const FACADE_ONLY: &str = "this socket carries facade calls and subscriptions only";

/// What one step of the loop leaves the socket to do.
enum Flow {
    Continue,
    Close,
}

/// What woke the facade loop.
enum Event {
    Inbound(Option<Result<WsMessage, axum::Error>>),
    Broadcast(Result<Option<Vec<u8>>, BroadcastError>),
    Direct(Option<Vec<u8>>),
    Delivery,
    Answered(Result<Result<(), ProtocolError>, tokio::task::JoinError>),
}

/// One facade socket, which its loop alone holds.
struct FacadeSocket {
    server: Arc<SyncServer>,
    conn_id: u32,
    transport: StoppingTransport,
    stop: crate::embedded::UpgradeStop,
    /// The upgrade's slip: its revocable token id, and the credential whose
    /// liveness each frame asks again.
    session_jti: Option<String>,
    credential: CoreAuth,
    conn_state: ConnState,
    subscriber: BroadcastSubscriber,
    app_connection: Connection,
    app_tick: tokio::time::Interval,
    direct_tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    direct_rx: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    /// Verb RPCs answer off the loop; their answers queue on `direct_tx`.
    verb_calls: tokio::task::JoinSet<Result<(), ProtocolError>>,
}

/// The facade loop, for the caller whose slip `credential` (token id
/// `session_jti`) the upgrade verified, at `locality`, whose upgrade proved
/// `machine` and was observed as `signing_request_transport`. On the engine's
/// stop (OF-237) the loop stops reading at its next wait and the transport
/// closes; the socket ends once every call it admitted has.
pub(super) async fn serve(
    (socket, stop): (WebSocket, crate::embedded::UpgradeStop),
    server: Arc<SyncServer>,
    conn_id: u32,
    (session_jti, credential): (Option<String>, CoreAuth),
    locality: oneiron::claim::CallerLocality,
    machine: oneiron::authority::PeerMachine,
    signing_request_transport: Option<oneiron::memory::SigningRequestTransport>,
) {
    tracing::info!(
        conn_id,
        "app-tier socket serves facade calls and subscriptions only"
    );
    // The guard asks for the upgrade's token id and for the slip itself
    // before every frame it writes: a slip revoked or expired since gets
    // nothing more.
    let transport = GuardedTransport::new(
        socket,
        Arc::clone(server.vault()) as Arc<dyn RevokedTokenJtis + Send + Sync>,
        session_jti.clone(),
        conn_id,
    )
    .with_inbound_cap(server.config.max_frame_size)
    .with_live_owner(server.vault(), Some(credential.clone()));
    // Its hello and sends give way to the engine's stop.
    let mut transport = StoppingTransport::new(transport, stop.clone());
    // A rejected hello is its connection's receipt before its close (FIX 3303).
    let protocol_version = match protocol_close::hello(&mut transport, &server, conn_id, None).await
    {
        Some(version) if version >= APP_TIER_PROTOCOL_VERSION_VERSION => version,
        Some(_) => {
            protocol_close::refuse_hello_version(
                &mut transport,
                &server,
                close_codes::CLOSE_RPC_VERSION_MISMATCH,
                "app tier needs protocol 8",
                None,
            )
            .await;
            return;
        }
        None => return,
    };
    let mut conn_state = ConnState::new(protocol_version).with_peer_machine(machine);
    conn_state.locality = locality;
    conn_state.signing_request_transport = signing_request_transport;
    let subscriber = BroadcastSubscriber::new(conn_id, &server.broadcast_tx);
    let app_connection = Connection::new(Hub::for_server(&server), conn_id);
    let (direct_tx, direct_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let mut socket = FacadeSocket {
        server,
        conn_id,
        transport,
        stop,
        session_jti,
        credential,
        conn_state,
        subscriber,
        app_connection,
        app_tick: tokio::time::interval(Duration::from_millis(25)),
        direct_tx,
        direct_rx,
        verb_calls: tokio::task::JoinSet::new(),
    };
    while let Some(event) = socket.next_event().await {
        let flow = match event {
            Event::Inbound(inbound) => socket.inbound(inbound).await,
            Event::Direct(direct) => socket.direct(direct).await,
            Event::Broadcast(broadcast) => socket.broadcast(broadcast).await,
            Event::Delivery => socket.deliver().await,
            Event::Answered(answered) => socket.answered(answered),
        };
        if matches!(flow, Flow::Close) {
            break;
        }
    }
    socket.close().await;
}

impl FacadeSocket {
    /// What the loop answers next, or `None` on the engine's stop (OF-237).
    /// Queued replies go first, and no further frame is read while
    /// `MAX_VERB_CALLS_IN_FLIGHT` calls are in flight.
    async fn next_event(&mut self) -> Option<Event> {
        let calls = self.verb_calls.len();
        let direct_empty = self.direct_rx.is_empty();
        let subscribed = self.app_connection.has_active_subscriptions();
        let event = tokio::select! {
            biased;
            () = self.stop.turned() => return None,
            direct = self.direct_rx.recv() => Event::Direct(direct),
            Some(answered) = self.verb_calls.join_next(), if calls > 0 => Event::Answered(answered),
            inbound = self.transport.read_next(),
                if direct_empty && calls < MAX_VERB_CALLS_IN_FLIGHT =>
            {
                Event::Inbound(inbound)
            }
            broadcast = self.subscriber.recv() => Event::Broadcast(broadcast),
            _ = self.app_tick.tick(), if subscribed => Event::Delivery,
        };
        Some(event)
    }

    /// One frame the peer sent. Only app frames are served, each after the
    /// upgrade's slip is asked again.
    async fn inbound(&mut self, inbound: Option<Result<WsMessage, axum::Error>>) -> Flow {
        let Some(read) = inbound else {
            // A frame the transport refused is receipted, then closed (FIX 3303).
            protocol_close::close_read_refusal(&self.server, &mut self.transport, None).await;
            return Flow::Close;
        };
        let data = match read {
            Ok(WsMessage::Binary(data)) => data.to_vec(),
            Ok(WsMessage::Close(_)) => return Flow::Close,
            Ok(WsMessage::Ping(_) | WsMessage::Pong(_) | WsMessage::Text(_)) => {
                return Flow::Continue;
            }
            Err(error) => {
                // A frame the WebSocket codec refused is a refusal, not a
                // disconnect: receipted, then closed (FIX 5311).
                protocol_close::close_read_error(&self.server, &mut self.transport, &error, None)
                    .await;
                return Flow::Close;
            }
        };
        if data.len() > self.server.config.max_frame_size {
            self.refuse(close_codes::FRAME_TOO_LARGE, "frame too large")
                .await;
            return Flow::Close;
        }
        // Only app RPCs and subscriptions: no sync, document, window,
        // leaf-key, asset or presence frame is served on this socket.
        let (tag, payload) = match protocol::parse_message(&data) {
            Ok(SyncMessage::Rpc(payload)) => (protocol::TAG_RPC, payload),
            Ok(SyncMessage::Sub(payload)) => (protocol::TAG_SUB, payload),
            Ok(_) | Err(ProtocolError::UnknownTag(_)) => {
                self.refuse(close_codes::UNKNOWN_TAG, FACADE_ONLY).await;
                return Flow::Close;
            }
            Err(_) => {
                self.refuse(close_codes::DECODE_ERROR, "invalid payload")
                    .await;
                return Flow::Close;
            }
        };
        // The upgrade's slip, asked again before anything runs: a slip
        // revoked or expired since, or a vault its Owners deleted, gets no
        // further service.
        if session_gone(
            self.server.vault(),
            self.session_jti.as_deref(),
            Some(&self.credential),
        ) {
            tracing::warn!(
                conn_id = self.conn_id,
                "credential no longer live — refusing facade frame and closing"
            );
            self.close_unbound().await;
            return Flow::Close;
        }
        let method = (tag == protocol::TAG_RPC)
            .then(|| crate::livequery::decode_rpc_call(&payload).ok())
            .flatten()
            .map(|(request, _)| request.method);
        // A residence call or a machine handoff serves the owner's machines:
        // closed before anything runs.
        if method.as_deref().is_some_and(|method| {
            method.starts_with("residence.") || crate::livequery::machine_handoff_method(method)
        }) {
            self.refuse(close_codes::CLOSE_RPC_NO_PRINCIPAL, FACADE_ONLY)
                .await;
            return Flow::Close;
        }
        let lifecycle_observation = method
            .as_deref()
            .is_some_and(crate::api::is_slim_lifecycle_observation);
        if !lifecycle_observation
            && let Err(error) = self.server.vault().resume_from_slim_on_inbound()
        {
            tracing::warn!(
                conn_id = self.conn_id,
                kind = ?error.kind(),
                "failed to resume vault for inbound frame"
            );
            return Flow::Close;
        }
        // Rule 5: a new subscription waits its turn here, before the app tier
        // runs it; only a live bound credential that may read joins a line.
        // The wait gives way to the engine's stop (OF-237).
        if tag == protocol::TAG_SUB
            && let Ok(auth) = require_bound_app_auth(&self.server, &self.conn_state)
            && auth.require(crate::auth::CoreScope::Read).is_ok()
        {
            let admitted = self.app_connection.admit(Some(auth), &payload);
            if self.stop.until(admitted).await.is_none() {
                return Flow::Close;
            }
        }
        match handle_app_message_with_connection(
            &self.server,
            &mut self.conn_state,
            tag,
            &payload,
            &self.direct_tx,
            Some(&mut self.app_connection),
        ) {
            Ok(Some(call)) => {
                self.verb_calls
                    .spawn(call.answer(Arc::clone(&self.server), self.direct_tx.clone()));
                Flow::Continue
            }
            Ok(None) => Flow::Continue,
            Err(error) => {
                super::super::dispatch_error::close_on(
                    &mut self.transport,
                    &self.server,
                    self.conn_id,
                    &error,
                )
                .await;
                Flow::Close
            }
        }
    }

    /// A frame a call or a subscription queued for this socket: judged again
    /// at its last door by the rows it carries (DEC-0005), then sent only if
    /// it is an app frame.
    async fn direct(&mut self, direct: Option<Vec<u8>>) -> Flow {
        let Some(mut data) = direct else {
            return Flow::Close;
        };
        if Connection::is_scoped_broadcast(&data) {
            let Some(frame) = self.app_connection.release_for(
                self.conn_state.locality,
                self.conn_state.peer_machine(self.server.vault()),
                &data,
            ) else {
                return Flow::Continue;
            };
            data = frame;
        }
        if !matches!(
            data.first().copied(),
            Some(protocol::TAG_RPC | protocol::TAG_SUB)
        ) {
            tracing::warn!(
                conn_id = self.conn_id,
                "facade socket withheld a queued frame that is not an app frame"
            );
            return Flow::Continue;
        }
        self.send_bound(data).await
    }

    /// One frame of the shared fan-out. Only an app frame routed to this
    /// socket leaves; the sync fan-out never does.
    async fn broadcast(&mut self, broadcast: Result<Option<Vec<u8>>, BroadcastError>) -> Flow {
        match broadcast {
            Ok(Some(data)) => {
                if !Connection::is_scoped_broadcast(&data) {
                    return Flow::Continue;
                }
                let Some(frame) = self.app_connection.release_for(
                    self.conn_state.locality,
                    self.conn_state.peer_machine(self.server.vault()),
                    &data,
                ) else {
                    return Flow::Continue;
                };
                self.send_bound(frame).await
            }
            Ok(None) => Flow::Close,
            // Rule 5: lag never closes a socket. Each subscription it holds
            // is told again.
            Err(BroadcastError::Lagged(missed)) => {
                self.app_connection.replay_after_lag();
                tracing::warn!(
                    conn_id = self.conn_id,
                    missed,
                    "facade subscriber lagged — resynced"
                );
                Flow::Continue
            }
        }
    }

    /// A subscription delivery pass, as on the replication socket: the bound
    /// credential is asked again first, and the frames go out through the
    /// shared fan-out, routed to this socket.
    async fn deliver(&mut self) -> Flow {
        if self.conn_state.bound_auth.is_some() {
            if require_bound_app_auth(&self.server, &self.conn_state).is_err() {
                self.close_unbound().await;
                return Flow::Close;
            }
            let Ok(frames) = self.app_connection.broadcast_delivery() else {
                return Flow::Close;
            };
            for frame in frames {
                // Recipient and subscription routing is stripped only by the
                // matching socket.
                let _ = crate::broadcast::broadcast(&self.server.broadcast_tx, 0, frame);
            }
        }
        // Delivery work is level-triggered: a backlog of ticks must not crowd
        // out inbound frames or queued replies.
        self.app_tick.reset();
        Flow::Continue
    }

    /// A verb RPC run off the loop ended; its answer is already queued.
    fn answered(
        &self,
        answered: Result<Result<(), ProtocolError>, tokio::task::JoinError>,
    ) -> Flow {
        match answered {
            Ok(Ok(())) => Flow::Continue,
            Ok(Err(error)) => {
                tracing::warn!(conn_id = self.conn_id, %error, "facade call answer failed — closing");
                Flow::Close
            }
            Err(error) => {
                tracing::warn!(
                    conn_id = self.conn_id,
                    panicked = error.is_panic(),
                    "facade call ended without an answer — closing"
                );
                Flow::Close
            }
        }
    }

    /// Sends one app frame under the bound credential, asked again now. A
    /// credential no longer live closes the socket with the bound-principal
    /// refusal instead.
    async fn send_bound(&mut self, frame: Vec<u8>) -> Flow {
        let live = require_bound_app_auth(&self.server, &self.conn_state)
            .map(|auth| auth.jti().map(str::to_owned));
        let Ok(app_jti) = live else {
            self.close_unbound().await;
            return Flow::Close;
        };
        self.transport.app_jti = app_jti;
        let sent = self.transport.send_binary(frame).await;
        self.transport.app_jti = None;
        if sent { Flow::Continue } else { Flow::Close }
    }

    /// Refuses a frame read after the hello: receipted, then closed with
    /// `close_code` (FIX 3303).
    async fn refuse(&mut self, close_code: u16, reason: &'static str) {
        protocol_close::refuse_frame(&mut self.transport, &self.server, close_code, reason, None)
            .await;
    }

    /// The close a socket whose credential no longer stands is told.
    async fn close_unbound(&mut self) {
        self.transport
            .send_unguarded_close_frame(WsMessage::Close(Some(CloseFrame {
                code: close_codes::CLOSE_RPC_NO_PRINCIPAL,
                reason: Utf8Bytes::from_static("bound credential is no longer live"),
            })))
            .await;
    }

    /// OF-237: the socket closes, then every call it admitted runs to its
    /// end; none is aborted.
    async fn close(self) {
        let Self {
            server,
            conn_id,
            transport,
            conn_state,
            mut verb_calls,
            ..
        } = self;
        drop(transport);
        while verb_calls.join_next().await.is_some() {}
        conn_state.closed(server.vault());
        tracing::info!(conn_id, "facade connection closed");
    }
}
