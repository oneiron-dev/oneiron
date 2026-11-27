//! The residence RPC lane's socket: one short-lived authenticated socket to
//! the home a call reads from. Its endpoint is read once, with the carrier
//! chosen for it, and both are checked before any credential leaves (FIX
//! 8862). The ordinary lane binds the host's actor session over it; home
//! handoffs and exact pad repairs can open it as this machine alone.

use std::time::Duration;

use futures_util::{Sink, SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::error::ProtocolError;
use tokio_tungstenite::tungstenite::http::header::AUTHORIZATION;
use tokio_tungstenite::tungstenite::{Error as WsError, Message};

use super::super::endpoint::ResidenceEndpoint;
use super::super::types::SyncClientConfig;
use crate::sync::residence_operation_budgets::ResidenceOperationBudgets;
use crate::sync::transport::{self, TAG_RPC, TransportError};

/// The app-tier response encoding has a fixed 32-MiB payload ceiling.
const MAX_RPC_REPLY_BYTES: usize = 32 * 1024 * 1024;

pub(super) fn residence_budgets(
    vault: &crate::Vault,
) -> Result<ResidenceOperationBudgets, TransportError> {
    vault
        .residence_operation_budgets()
        .map_err(|error| TransportError::Storage(error.to_string()))?
        .ok_or(TransportError::InvalidPayload(
            "residence policy unavailable",
        ))
}

type Socket = crate::sync::carrier::SyncSocket;

#[derive(Serialize)]
struct RequestEnvelope {
    #[serde(rename = "type")]
    kind: &'static str,
    id: u64,
    seq: u64,
    last: bool,
    payload: Value,
}

#[derive(Deserialize)]
struct ReplyEnvelope {
    #[serde(rename = "type")]
    kind: String,
    id: u64,
    seq: u64,
    last: bool,
    payload: rmpv::Value,
}

struct RpcChunks {
    chunks: std::vec::IntoIter<Vec<u8>>,
    current: Option<std::io::Cursor<Vec<u8>>>,
}

impl RpcChunks {
    fn new(chunks: Vec<Vec<u8>>) -> Self {
        Self {
            chunks: chunks.into_iter(),
            current: None,
        }
    }
}

impl std::io::Read for RpcChunks {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if let Some(cursor) = self.current.as_mut() {
                let n = std::io::Read::read(cursor, buf)?;
                if n != 0 {
                    return Ok(n);
                }
                self.current = None;
            }
            self.current = Some(std::io::Cursor::new(match self.chunks.next() {
                Some(chunk) => chunk,
                None => return Ok(0),
            }));
        }
    }
}

/// The home answered a residence RPC and refused it (FIX 3353), apart from a
/// call that failed: a socket that broke or timed out, or a reply that did not
/// parse.
pub(super) struct HomeRefused {
    /// The code the home gave.
    pub(super) code: Option<String>,
}

impl HomeRefused {
    fn request_error(&self) -> TransportError {
        if self.code.as_deref() == Some("INDEX_REVISION_CHANGED") {
            TransportError::IndexRevisionChanged
        } else {
            TransportError::InvalidPayload("home refused residence RPC")
        }
    }
}

/// What [`ResidenceRpc::call_inner`] read back for a sent request.
enum CallReply {
    /// The home's answer or its refusal.
    Answer(Result<Value, HomeRefused>),
    /// The home's refusal after part of its answer had come: its one frame,
    /// numbered 0 and last, in place of a later chunk and the rest of the
    /// answer (the live-query lane's refusal, SELECTOR-RELEASE-POINT = B).
    Replaced(HomeRefused),
    /// The socket ended after the request was sent and before the whole
    /// answer came. A deadline that ran out is not this.
    Interrupted,
}

impl CallReply {
    /// The reply as every caller but a touch reads it: an ended socket, and
    /// an answer the home replaced part-way, are the home's fault, as before
    /// (FIX 22179).
    fn into_call(self) -> Result<Result<Value, HomeRefused>, RpcFault> {
        match self {
            Self::Answer(answer) => Ok(answer),
            Self::Replaced(_) | Self::Interrupted => Err(RpcFault::remote()),
        }
    }

    /// The reply as a touch reads it: a RESULT_CHANGED refusal, in place of
    /// the answer or of its rest, and an ended socket are an answer the home
    /// withdrew. Any other refusal of the rest fails as every caller reads it.
    fn into_touch(self) -> Result<Value, TouchFault> {
        match self {
            Self::Answer(Ok(reply)) => Ok(reply),
            Self::Answer(Err(refusal)) | Self::Replaced(refusal)
                if refusal.code.as_deref() == Some("RESULT_CHANGED") =>
            {
                Err(TouchFault::Withdrawn)
            }
            Self::Answer(Err(refusal)) => Err(TouchFault::Other(refusal.request_error())),
            Self::Replaced(_) => Err(TouchFault::Other(refused())),
            Self::Interrupted => Err(TouchFault::Withdrawn),
        }
    }
}

/// What one reply frame says of call `id`, read where its chunk `seq` is due.
enum ReplyFrame {
    /// The answer's chunk `seq`; `last` when the answer ends with it.
    Chunk { bytes: Vec<u8>, last: bool },
    /// The home's refusal in place of the answer.
    Refused(HomeRefused),
    /// The home's refusal in place of the rest of an answer it had begun
    /// ([`CallReply::Replaced`]).
    Replaced(HomeRefused),
}

/// Reads one reply frame of call `id` where its chunk `seq` is due. Every
/// frame must be chunk `seq` of call `id`, but for the home's refusal of the
/// rest of an answer: the live-query lane numbers each refusal 0 and last,
/// in place of whichever chunk was due.
fn reply_frame(frame: &[u8], id: u64, seq: u64) -> Result<ReplyFrame, RpcFault> {
    if frame.first() != Some(&TAG_RPC) {
        return Err(RpcFault::remote());
    }
    let reply: ReplyEnvelope =
        rmp_serde::from_slice(&frame[1..]).map_err(|_| RpcFault::remote())?;
    if reply.id != id {
        return Err(RpcFault::remote());
    }
    let replaced = seq > 0 && reply.seq == 0 && reply.last && reply.kind == "rpc.err";
    if reply.seq != seq && !replaced {
        return Err(RpcFault::remote());
    }
    if reply.kind == "rpc.err" {
        let code = reply.payload.as_map().and_then(|fields| {
            fields
                .iter()
                .find(|(key, _)| key.as_str() == Some("code"))
                .and_then(|(_, value)| value.as_str())
        });
        let refusal = HomeRefused {
            code: code.map(str::to_owned),
        };
        return Ok(if replaced {
            ReplyFrame::Replaced(refusal)
        } else {
            ReplyFrame::Refused(refusal)
        });
    }
    if reply.kind != "rpc.res" {
        return Err(RpcFault::remote());
    }
    let bytes = match reply.payload {
        rmpv::Value::Binary(bytes) => bytes,
        rmpv::Value::String(text) => text.into_bytes(),
        _ => return Err(RpcFault::remote()),
    };
    Ok(ReplyFrame::Chunk {
        bytes,
        last: reply.last,
    })
}

/// Why a touch read failed. [`Self::Withdrawn`]: the home withdrew its
/// answer, as a RESULT_CHANGED refusal (in place of the answer or of its
/// rest) or, judged at a later frame, by closing the socket before the answer
/// completed (SELECTOR-RELEASE-POINT = B). [`Self::Other`]: every other
/// failure, with the error [`ResidenceRpc::request`] gives for it.
pub(super) enum TouchFault {
    Withdrawn,
    Other(TransportError),
}

impl From<TransportError> for TouchFault {
    fn from(error: TransportError) -> Self {
        Self::Other(error)
    }
}

/// Why a residence RPC failed, by the side the fault is on (FIX 22179),
/// around the error the call tells.
#[derive(Debug)]
pub(super) enum RpcFault {
    /// The home's: a refused upgrade or bind, a socket to it that broke or
    /// timed out, its refusal, or a reply that breaks the RPC contract.
    Remote(TransportError),
    /// This machine's own: its actor session or selector, the endpoint it
    /// chose, its upgrade's signing or header, a carrier it cannot set up for
    /// the endpoint's URL (FIX 22217), its bind's or request's encode or
    /// size, or its request ids running out.
    Local(TransportError),
    /// The home's HTTP 401 to a member lane's residence upgrade (MEMBER-SYNC
    /// threat F5): it did not accept the credential. The session tells it
    /// once as the main upgrade's 401 and redials; every other caller sees
    /// [`refused`] through [`Self::into_error`]. Only a member lane's dial
    /// names it: owner and federation dials keep [`Self::Remote`] here, so
    /// their paths stay as they were.
    Unauthorized,
    /// The home's HTTP 403 to a member lane's residence upgrade (MEMBER-SYNC
    /// threat F5): it accepted the credential and refuses that credential
    /// this socket, with the typed reason when the home named one
    /// (MEMBER-SYNC-WORLD-PACT = C). The session tells it once and parks as
    /// the main upgrade's 403 does; every other caller sees [`refused`]
    /// through [`Self::into_error`]. Only a member lane's dial names it.
    Forbidden(Option<crate::sync::carrier::ForbiddenReason>),
}

impl RpcFault {
    /// The home's fault, told as [`refused`].
    fn remote() -> Self {
        Self::Remote(refused())
    }

    /// This machine's own fault, told with `cause`: the step of this
    /// machine's that failed (FIX 22236).
    fn local(cause: &'static str) -> Self {
        Self::Local(TransportError::InvalidPayload(cause))
    }

    /// The error the call tells, its side dropped. An upgrade refusal tells
    /// [`refused`], as its dial did before F5 named it: owner-machine callers
    /// keep a plain error.
    pub(super) fn into_error(self) -> TransportError {
        match self {
            Self::Remote(error) | Self::Local(error) => error,
            Self::Unauthorized | Self::Forbidden(_) => refused(),
        }
    }
}

pub(super) struct ResidenceRpc {
    socket: Socket,
    next_id: u64,
    pub(super) timeout: Duration,
    /// The machine the home proved on this socket's upgrade (OF-534 G7).
    pub(super) home: crate::authority::PeerMachine,
    /// BLAKE3 of the exact endpoint URL this socket dialed: a metadata-only
    /// route address that keys this install's automatic attempts (FIX 9254).
    /// Never a home identity, never proof, never persisted with secrets.
    pub(super) address: [u8; 32],
    /// Opened as this machine alone, with no actor bound (FIX 6458): its
    /// replies come after the sync frames the home opens each socket with.
    unbound: bool,
}

impl ResidenceRpc {
    /// `None` is only a transport outage, the home's: a call that needs the
    /// home fails on it as [`TransportError::home_offline`] (FIX 22190). A
    /// refused bind or malformed reply is an error, not permission to label
    /// the search local-only.
    pub(super) async fn connect(
        vault: &crate::Vault,
        config: &SyncClientConfig,
        budgets: ResidenceOperationBudgets,
    ) -> Result<Option<Self>, TransportError> {
        Self::connect_by_side(vault, config, budgets)
            .await
            .map_err(RpcFault::into_error)
    }

    /// [`Self::connect`], its fault told by the side it is on (FIX 22179): a
    /// missing actor session or selector, the endpoint, the upgrade, the
    /// carrier's setup (FIX 22217) and the bind's encode are this machine's
    /// own; the home's answer is the home's.
    pub(super) async fn connect_by_side(
        vault: &crate::Vault,
        config: &SyncClientConfig,
        budgets: ResidenceOperationBudgets,
    ) -> Result<Option<Self>, RpcFault> {
        let timeout = Duration::from_millis(budgets.rpc_timeout_ms);
        let deadline = tokio::time::Instant::now() + timeout;
        let session = config.note_session.as_ref().ok_or_else(|| {
            RpcFault::local("this machine has no actor session for the residence RPC")
        })?;
        config
            .residence_selector
            .as_ref()
            .ok_or_else(|| RpcFault::local("this machine has no selector for the residence RPC"))?;
        let Some((mut socket, home, address)) = Self::dial(vault, config, deadline).await? else {
            return Ok(None);
        };
        let bind_frame =
            super::super::note_session::bind_frame(session).map_err(RpcFault::Local)?;
        tokio::time::timeout_at(deadline, socket.send(Message::Binary(bind_frame.into())))
            .await
            .map_err(|_| RpcFault::remote())?
            .map_err(|_| RpcFault::remote())?;
        // A future server may send an ephemeral snapshot before the bind ack.
        // Only the exact fixed-ID null reply opens the RPC lane.
        let mut opening_messages = 0;
        while opening_messages < 16 {
            let msg = tokio::time::timeout_at(deadline, socket.next())
                .await
                .map_err(|_| RpcFault::remote())?
                .ok_or_else(RpcFault::remote)?
                .map_err(|_| RpcFault::remote())?;
            let Message::Binary(frame) = msg else {
                return Err(RpcFault::remote());
            };
            if frame.first() == Some(&transport::TAG_ROOT_PART) {
                let part =
                    transport::decode_root_update_part(&frame[1..]).map_err(RpcFault::Remote)?;
                if part.offset + part.bytes.len() == part.total {
                    opening_messages += 1;
                }
                continue;
            }
            opening_messages += 1;
            match frame.first() {
                Some(&TAG_RPC) => {
                    let receipt = super::super::note_session::accept_bind_reply(&frame[1..])
                        .map_err(RpcFault::Remote)?;
                    tracing::debug!(?receipt, "the home answered the residence lane's bind");
                    return Ok(Some(Self {
                        socket,
                        next_id: 1,
                        timeout,
                        home,
                        address,
                        unbound: false,
                    }));
                }
                Some(&transport::TAG_EPHEMERAL) | Some(&transport::TAG_SYNC_UPDATE) => continue,
                _ => return Err(RpcFault::remote()),
            }
        }
        Err(RpcFault::remote())
    }

    /// The lane a home handoff or exact pad repair opens with no actor session.
    /// The upgrade proves this machine's transport slip, and the home's answer
    /// names the machine it is; machine-only residence calls judge their own
    /// read authority without an actor bind. `None` is only a transport outage.
    /// A member lane never opens it (MEMBER-SYNC threat F8: the client
    /// invariant): the home serves a member lane no machine call, so this
    /// refuses at once there.
    pub(super) async fn connect_machine(
        vault: &crate::Vault,
        config: &SyncClientConfig,
        budgets: ResidenceOperationBudgets,
    ) -> Result<Option<Self>, TransportError> {
        if config.member_lane {
            return Err(refused());
        }
        let timeout = Duration::from_millis(budgets.rpc_timeout_ms);
        let deadline = tokio::time::Instant::now() + timeout;
        // A bearer token alone proves no holder, so the home could not
        // answer it with the machine it is.
        config.transport_credential.as_ref().ok_or_else(refused)?;
        Ok(Self::dial(vault, config, deadline)
            .await
            .map_err(RpcFault::into_error)?
            .map(|(socket, home, address)| Self {
                socket,
                next_id: 1,
                timeout,
                home,
                address,
                unbound: true,
            }))
    }

    /// Dials the residence endpoint and sends the residence hello; the
    /// socket, the machine the home proved on its upgrade, and the dialed
    /// endpoint's route address, or `None` on a transport outage. The
    /// endpoint, its URL and the upgrade's credential are this machine's own
    /// (FIX 22179), and so is a carrier it cannot set up for that URL
    /// ([`crate::sync::carrier::own_setup_fault`], FIX 22217); a refused
    /// upgrade and the hello's send are the home's. A member lane's dial
    /// carries the [`crate::sync::carrier::MEMBER_LANE_HEADER`] request
    /// (MEMBER-SYNC D1), and its HTTP 401/403 answer is classified with the
    /// main upgrade's shared rule and named as [`RpcFault::Unauthorized`] or
    /// [`RpcFault::Forbidden`] (MEMBER-SYNC threat F5); an owner or
    /// federation dial keeps the old [`RpcFault::Remote`] there.
    async fn dial(
        vault: &crate::Vault,
        config: &SyncClientConfig,
        deadline: tokio::time::Instant,
    ) -> Result<Option<(Socket, crate::authority::PeerMachine, [u8; 32])>, RpcFault> {
        // FIX 8862: the endpoint is read once, the carrier is chosen for
        // that endpoint, and both pass the credential check before any
        // header below is added.
        let endpoint = ResidenceEndpoint::select(config).ok_or_else(|| {
            RpcFault::local("no residence endpoint fits this machine's sync config")
        })?;
        let mut request = endpoint.url.as_str().into_client_request().map_err(|_| {
            RpcFault::local("the residence endpoint URL is not a WebSocket request")
        })?;
        // The upgrade proves the device's transport slip, as the sync
        // socket does, signed on the wall clock as it is; a bind then
        // attenuates it to the actor.
        let mut binding = None;
        if let Some(credential) = &config.transport_credential {
            binding = Some(
                credential
                    .sign_upgrade(
                        vault,
                        config.authority_checkpoint_pin.as_ref(),
                        vault.store.clock.wall_now(),
                        &mut request,
                    )
                    .map_err(|_| {
                        RpcFault::local("this machine could not sign its residence upgrade")
                    })?,
            );
        } else if !config.auth_token.is_empty() {
            let header = format!("Bearer {}", config.auth_token)
                .parse()
                .map_err(|_| {
                    RpcFault::local("this machine's bearer token is not a valid header")
                })?;
            request.headers_mut().insert(AUTHORIZATION, header);
        }
        // MEMBER-SYNC D1: a member lane asks for itself with one request
        // header, a restriction request that is never authority. Without it
        // this upgrade takes the path it took before.
        if config.member_lane {
            request.headers_mut().insert(
                crate::sync::carrier::MEMBER_LANE_HEADER,
                tokio_tungstenite::tungstenite::http::HeaderValue::from_static(
                    crate::sync::carrier::MEMBER_LANE_HEADER_VALUE,
                ),
            );
        }
        // Whether the upgrade carries a credential, as the main upgrade
        // reads it: a 403 to one that carries none refuses nothing held.
        let carried = binding.is_some() || request.headers().contains_key(AUTHORIZATION);
        let (mut socket, response) = match tokio::time::timeout_at(
            deadline,
            crate::sync::carrier::connect_sync_socket(request, endpoint.dialer),
        )
        .await
        {
            Ok(Ok(connected)) => connected,
            Ok(Err(error @ tokio_tungstenite::tungstenite::Error::Http(_))) => {
                // MEMBER-SYNC threat F5, member lanes only: the residence
                // upgrade's HTTP refusal is classified with the main
                // upgrade's shared rule, so the session tells it once and a
                // 403 parks as the main upgrade's does. Owner and federation
                // dials keep the old remote fault here.
                if config.member_lane
                    && let Some(refusal) = crate::sync::carrier::upgrade_refusal(&error, carried)
                {
                    return Err(match refusal {
                        crate::sync::carrier::UpgradeRefusal::Unauthorized => {
                            RpcFault::Unauthorized
                        }
                        crate::sync::carrier::UpgradeRefusal::Forbidden(reason) => {
                            RpcFault::Forbidden(reason)
                        }
                    });
                }
                return Err(RpcFault::remote());
            }
            Ok(Err(error)) if crate::sync::carrier::own_setup_fault(&error) => {
                return Err(RpcFault::local(
                    "this machine cannot set up a carrier for the residence endpoint",
                ));
            }
            Ok(Err(_)) | Err(_) => return Ok(None),
        };
        tokio::time::timeout_at(
            deadline,
            socket.send(Message::Binary(
                transport::encode_residence_protocol_hello().into(),
            )),
        )
        .await
        .map_err(|_| RpcFault::remote())?
        .map_err(|_| RpcFault::remote())?;
        let home = crate::sync::home_proof::home_peer(vault, &response, binding.as_ref());
        let address: [u8; 32] = blake3::hash(endpoint.url.as_bytes()).into();
        Ok(Some((socket, home, address)))
    }

    pub(super) async fn request(
        &mut self,
        method: &str,
        params: Value,
    ) -> Result<Value, TransportError> {
        self.request_by_side(method, params)
            .await
            .map_err(RpcFault::into_error)
    }

    /// [`Self::request`], its fault told by the side it is on (FIX 22179):
    /// the home's refusal is the home's, as [`Self::call_inner`] sides the
    /// rest.
    pub(super) async fn request_by_side(
        &mut self,
        method: &str,
        params: Value,
    ) -> Result<Value, RpcFault> {
        self.call_inner(method, params, None)
            .await?
            .into_call()?
            .map_err(|refusal| RpcFault::Remote(refusal.request_error()))
    }

    /// [`Self::request`], with an answer the home withdrew told apart
    /// ([`TouchFault::Withdrawn`]), so the touch can ask again.
    pub(super) async fn request_touch(
        &mut self,
        method: &str,
        params: Value,
    ) -> Result<Value, TouchFault> {
        self.call_inner(method, params, None)
            .await
            .map_err(RpcFault::into_error)?
            .into_touch()
    }

    /// [`Self::request`], with the home's refusal kept apart from a call that
    /// failed: `Ok(Err(_))` when the home answered no.
    pub(super) async fn call(
        &mut self,
        method: &str,
        params: Value,
    ) -> Result<Result<Value, HomeRefused>, TransportError> {
        self.call_inner(method, params, None)
            .await
            .and_then(CallReply::into_call)
            .map_err(RpcFault::into_error)
    }

    /// A bearer leaves only for the exact issuing machine, rejudged after
    /// the actual socket's ready and immediately before its start_send.
    pub(super) async fn request_for_machine(
        &mut self,
        vault: &crate::Vault,
        machine: crate::EntityId,
        method: &str,
        params: Value,
    ) -> Result<Value, TransportError> {
        self.call_inner(method, params, Some((vault, machine)))
            .await
            .and_then(CallReply::into_call)
            .map_err(RpcFault::into_error)?
            .map_err(|_| TransportError::InvalidPayload("admitting machine refused bearer RPC"))
    }

    /// One call on the socket, its fault told by the side it is on (FIX
    /// 22179): its id, encode and size are this machine's own; the send, the
    /// reply and the admitting machine's proof are the home's.
    async fn call_inner(
        &mut self,
        method: &str,
        params: Value,
        machine: Option<(&crate::Vault, crate::EntityId)>,
    ) -> Result<CallReply, RpcFault> {
        let id = self.next_id;
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or_else(|| RpcFault::local("this socket's residence RPC request ids ran out"))?;
        let request = RequestEnvelope {
            kind: "rpc.req",
            id,
            seq: 0,
            last: true,
            payload: json!({"method": method, "params": params}),
        };
        let bytes = rmp_serde::to_vec_named(&request)
            .map_err(|_| RpcFault::local("the residence RPC request did not encode"))?;
        if bytes.len() > transport::MAX_DECODED_PAYLOAD_BYTES {
            return Err(RpcFault::local(
                "the residence RPC request is over the frame limit",
            ));
        }
        let mut frame = vec![TAG_RPC];
        frame.extend(bytes);
        let deadline = tokio::time::Instant::now() + self.timeout;
        if let Some((vault, machine)) = machine {
            tokio::time::timeout_at(
                deadline,
                futures_util::future::poll_fn(|cx| {
                    std::pin::Pin::new(&mut self.socket).poll_ready(cx)
                }),
            )
            .await
            .map_err(|_| RpcFault::remote())?
            .map_err(|_| RpcFault::remote())?;
            if !matches!(
                vault.peer_machine_stands(self.home),
                crate::authority::PeerMachine::Proven { machine: proven, .. } if proven == machine
            ) {
                return Err(RpcFault::Remote(TransportError::InvalidPayload(
                    "the option link's admitting machine did not prove this socket",
                )));
            }
            std::pin::Pin::new(&mut self.socket)
                .start_send(Message::Binary(frame.into()))
                .map_err(|_| RpcFault::remote())?;
            tokio::time::timeout_at(deadline, self.socket.flush())
                .await
                .map_err(|_| RpcFault::remote())?
                .map_err(|_| RpcFault::remote())?;
        } else {
            tokio::time::timeout_at(deadline, self.socket.send(Message::Binary(frame.into())))
                .await
                .map_err(|_| RpcFault::remote())?
                .map_err(|_| RpcFault::remote())?;
        }
        let mut chunks = Vec::new();
        let mut received = 0usize;
        for seq in 0..512u64 {
            let frame = loop {
                // A ready stream of opening frames must not outrun the same
                // deadline by completing each individual next() immediately.
                if tokio::time::Instant::now() >= deadline {
                    return Err(RpcFault::remote());
                }
                let frame = match tokio::time::timeout_at(deadline, self.socket.next())
                    .await
                    .map_err(|_| RpcFault::remote())?
                {
                    Some(Ok(Message::Binary(frame))) => frame,
                    None | Some(Ok(Message::Close(_))) => return Ok(CallReply::Interrupted),
                    Some(Err(error)) if socket_ended(&error) => {
                        return Ok(CallReply::Interrupted);
                    }
                    Some(Ok(_) | Err(_)) => return Err(RpcFault::remote()),
                };
                // FIX 6458: an unbound lane passes over the sync frames the
                // home opens each socket with; a bound lane takes none.
                let opening = matches!(
                    frame.first(),
                    Some(&transport::TAG_EPHEMERAL)
                        | Some(&transport::TAG_SYNC_UPDATE)
                        | Some(&transport::TAG_ROOT_PART)
                );
                if !(self.unbound && opening) {
                    break frame;
                }
            };
            let (chunk, last) = match reply_frame(&frame, id, seq)? {
                ReplyFrame::Chunk { bytes, last } => (bytes, last),
                ReplyFrame::Refused(refusal) => return Ok(CallReply::Answer(Err(refusal))),
                ReplyFrame::Replaced(refusal) => return Ok(CallReply::Replaced(refusal)),
            };
            if received.saturating_add(chunk.len()) > MAX_RPC_REPLY_BYTES {
                return Err(RpcFault::remote());
            }
            received += chunk.len();
            chunks.push(chunk);
            if last {
                return rmp_serde::from_read(RpcChunks::new(chunks))
                    .map(|reply| CallReply::Answer(Ok(reply)))
                    .map_err(|_| RpcFault::remote());
            }
        }
        Err(RpcFault::remote())
    }
}

pub(super) fn refused() -> TransportError {
    TransportError::InvalidPayload("opened-item RPC unavailable")
}

/// Whether a read error is the socket ending: a closed connection, a reset
/// without the closing handshake, or a cut stream. A frame the home sent
/// that does not decode (a codec frame comes back as `Io(InvalidData)`, one
/// over the cap as `Capacity`), a protocol fault and a read that timed out
/// are not, so they are never read as a withdrawn answer.
fn socket_ended(error: &WsError) -> bool {
    match error {
        WsError::ConnectionClosed
        | WsError::AlreadyClosed
        | WsError::Protocol(ProtocolError::ResetWithoutClosingHandshake) => true,
        WsError::Io(error) => matches!(
            error.kind(),
            std::io::ErrorKind::UnexpectedEof
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::NotConnected
        ),
        _ => false,
    }
}

#[cfg(test)]
mod reply_frame_tests;

#[cfg(test)]
mod socket_end_tests {
    use futures_util::{FutureExt, StreamExt};
    use tokio_tungstenite::tungstenite::error::{CapacityError, ProtocolError};
    use tokio_tungstenite::tungstenite::{Error as WsError, Message};

    use super::socket_ended;
    use crate::sync::transport::{TAG_CODEC, WireSocket};

    /// A codec frame under an id this side does not know fails the read while
    /// the socket stays open: the home's malformed reply, not an ended socket.
    #[test]
    fn an_undecodable_codec_frame_is_not_a_socket_end() {
        let frame = Message::Binary(vec![TAG_CODEC, 0xEE, 1, 2, 3].into());
        let mut socket =
            WireSocket::to_our_server(futures_util::stream::iter([Ok::<_, WsError>(frame)]), 1024);
        let error = socket
            .next()
            .now_or_never()
            .flatten()
            .expect("the frame is read at once")
            .expect_err("an unknown codec fails the read");
        assert!(
            matches!(&error, WsError::Io(io) if io.kind() == std::io::ErrorKind::InvalidData),
            "{error:?}"
        );
        assert!(!socket_ended(&error), "{error:?}");
    }

    #[test]
    fn only_a_closed_or_cut_connection_is_a_socket_end() {
        for ended in [
            WsError::ConnectionClosed,
            WsError::AlreadyClosed,
            WsError::Protocol(ProtocolError::ResetWithoutClosingHandshake),
            WsError::Io(std::io::ErrorKind::ConnectionReset.into()),
            WsError::Io(std::io::ErrorKind::UnexpectedEof.into()),
        ] {
            assert!(socket_ended(&ended), "{ended:?}");
        }
        for open in [
            WsError::Io(std::io::ErrorKind::InvalidData.into()),
            WsError::Io(std::io::ErrorKind::TimedOut.into()),
            WsError::Capacity(CapacityError::MessageTooLong {
                size: 2,
                max_size: 1,
            }),
            WsError::Protocol(ProtocolError::NonZeroReservedBits),
            WsError::Utf8,
        ] {
            assert!(!socket_ended(&open), "{open:?}");
        }
    }
}
