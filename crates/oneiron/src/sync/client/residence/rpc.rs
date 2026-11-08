//! The residence RPC lane's socket: one short-lived authenticated socket to
//! the home a call reads from. Its endpoint is read once, with the carrier
//! chosen for it, and both are checked before any credential leaves (FIX
//! 8862). The ordinary lane binds the host's actor session over it; home
//! handoffs and exact pad repairs can open it as this machine alone.

use std::time::Duration;

use futures_util::{Sink, SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header::AUTHORIZATION;

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

    /// The error the call tells, its side dropped.
    pub(super) fn into_error(self) -> TransportError {
        match self {
            Self::Remote(error) | Self::Local(error) => error,
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
                    super::super::note_session::accept_bind_reply(&frame[1..])
                        .map_err(RpcFault::Remote)?;
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
    pub(super) async fn connect_machine(
        vault: &crate::Vault,
        config: &SyncClientConfig,
        budgets: ResidenceOperationBudgets,
    ) -> Result<Option<Self>, TransportError> {
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
    /// upgrade and the hello's send are the home's.
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
                    .sign_upgrade(vault, vault.store.clock.wall_now(), &mut request)
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
        let (mut socket, response) = match tokio::time::timeout_at(
            deadline,
            crate::sync::carrier::connect_sync_socket(request, endpoint.dialer),
        )
        .await
        {
            Ok(Ok(connected)) => connected,
            Ok(Err(tokio_tungstenite::tungstenite::Error::Http(_))) => {
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
            .map_err(|refusal| {
                RpcFault::Remote(
                    if refusal.code.as_deref() == Some("INDEX_REVISION_CHANGED") {
                        TransportError::IndexRevisionChanged
                    } else {
                        TransportError::InvalidPayload("home refused residence RPC")
                    },
                )
            })
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
    ) -> Result<Result<Value, HomeRefused>, RpcFault> {
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
                let msg = tokio::time::timeout_at(deadline, self.socket.next())
                    .await
                    .map_err(|_| RpcFault::remote())?
                    .ok_or_else(RpcFault::remote)?
                    .map_err(|_| RpcFault::remote())?;
                let Message::Binary(frame) = msg else {
                    return Err(RpcFault::remote());
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
            if frame.first() != Some(&TAG_RPC) {
                return Err(RpcFault::remote());
            }
            let reply: ReplyEnvelope =
                rmp_serde::from_slice(&frame[1..]).map_err(|_| RpcFault::remote())?;
            if reply.id != id || reply.seq != seq {
                return Err(RpcFault::remote());
            }
            if reply.kind == "rpc.err" {
                let code = reply.payload.as_map().and_then(|fields| {
                    fields
                        .iter()
                        .find(|(key, _)| key.as_str() == Some("code"))
                        .and_then(|(_, value)| value.as_str())
                });
                return Ok(Err(HomeRefused {
                    code: code.map(str::to_owned),
                }));
            }
            if reply.kind != "rpc.res" {
                return Err(RpcFault::remote());
            }
            let chunk = match reply.payload {
                rmpv::Value::Binary(bytes) => bytes,
                rmpv::Value::String(text) => text.into_bytes(),
                _ => return Err(RpcFault::remote()),
            };
            if received.saturating_add(chunk.len()) > MAX_RPC_REPLY_BYTES {
                return Err(RpcFault::remote());
            }
            received += chunk.len();
            chunks.push(chunk);
            if reply.last {
                return rmp_serde::from_read(RpcChunks::new(chunks))
                    .map(Ok)
                    .map_err(|_| RpcFault::remote());
            }
        }
        Err(RpcFault::remote())
    }
}

pub(super) fn refused() -> TransportError {
    TransportError::InvalidPayload("opened-item RPC unavailable")
}
