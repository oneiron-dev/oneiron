//! The residence RPC lane's socket: one short-lived authenticated socket to
//! the home a call reads from. Its endpoint is read once, with the carrier
//! chosen for it, and both are checked before any credential leaves (FIX
//! 8862). The ordinary lane binds the host's actor session over it; a home
//! handoff with none opens it as this machine alone (FIX 6458).

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
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

/// The home answered a residence RPC and refused it (FIX 3353), apart from a
/// call that failed: a socket that broke or timed out, or a reply that did not
/// parse.
pub(super) struct HomeRefused {
    /// The code the home gave.
    pub(super) code: Option<String>,
}

pub(super) struct ResidenceRpc {
    socket: Socket,
    next_id: u64,
    pub(super) timeout: Duration,
    /// The machine the home proved on this socket's upgrade (OF-534 G7).
    pub(super) home: crate::authority::PeerMachine,
    /// Opened as this machine alone, with no actor bound (FIX 6458): its
    /// replies come after the sync frames the home opens each socket with.
    unbound: bool,
}

impl ResidenceRpc {
    /// `None` is only a transport outage. A refused bind or malformed reply
    /// is an error, not permission to label the search local-only.
    pub(super) async fn connect(
        vault: &crate::Vault,
        config: &SyncClientConfig,
        budgets: ResidenceOperationBudgets,
    ) -> Result<Option<Self>, TransportError> {
        let timeout = Duration::from_millis(budgets.rpc_timeout_ms);
        let deadline = tokio::time::Instant::now() + timeout;
        let session = config.note_session.as_ref().ok_or_else(refused)?;
        config.residence_selector.as_ref().ok_or_else(refused)?;
        let Some((mut socket, home)) = Self::dial(vault, config, deadline).await? else {
            return Ok(None);
        };
        tokio::time::timeout_at(
            deadline,
            socket.send(Message::Binary(
                super::super::note_session::bind_frame(session)?.into(),
            )),
        )
        .await
        .map_err(|_| refused())?
        .map_err(|_| refused())?;
        // A future server may send an ephemeral snapshot before the bind ack.
        // Only the exact fixed-ID null reply opens the RPC lane.
        for _ in 0..16 {
            let msg = tokio::time::timeout_at(deadline, socket.next())
                .await
                .map_err(|_| refused())?
                .ok_or_else(refused)?
                .map_err(|_| refused())?;
            let Message::Binary(frame) = msg else {
                return Err(refused());
            };
            match frame.first() {
                Some(&TAG_RPC) => {
                    super::super::note_session::accept_bind_reply(&frame[1..])?;
                    return Ok(Some(Self {
                        socket,
                        next_id: 1,
                        timeout,
                        home,
                        unbound: false,
                    }));
                }
                Some(&transport::TAG_EPHEMERAL) | Some(&transport::TAG_SYNC_UPDATE) => continue,
                _ => return Err(refused()),
            }
        }
        Err(refused())
    }

    /// FIX 6458: the lane a home handoff opens with no actor session. The
    /// upgrade proves this machine's transport slip, and the home's answer
    /// names the machine it is; no actor binds, so only the home's handoff
    /// calls answer on it. `None` is only a transport outage.
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
            .await?
            .map(|(socket, home)| Self {
                socket,
                next_id: 1,
                timeout,
                home,
                unbound: true,
            }))
    }

    /// Dials the residence endpoint and sends the residence hello; the
    /// socket and the machine the home proved on its upgrade, or `None` on
    /// a transport outage.
    async fn dial(
        vault: &crate::Vault,
        config: &SyncClientConfig,
        deadline: tokio::time::Instant,
    ) -> Result<Option<(Socket, crate::authority::PeerMachine)>, TransportError> {
        // FIX 8862: the endpoint is read once, the carrier is chosen for
        // that endpoint, and both pass the credential check before any
        // header below is added.
        let endpoint = ResidenceEndpoint::select(config).ok_or_else(refused)?;
        let mut request = endpoint
            .url
            .as_str()
            .into_client_request()
            .map_err(|_| refused())?;
        // The upgrade proves the device's transport slip, as the sync
        // socket does, signed on the wall clock as it is; a bind then
        // attenuates it to the actor.
        let mut binding = None;
        if let Some(credential) = &config.transport_credential {
            binding = Some(
                credential
                    .sign_upgrade(vault, vault.store.clock.wall_now(), &mut request)
                    .map_err(|_| refused())?,
            );
        } else if !config.auth_token.is_empty() {
            let header = format!("Bearer {}", config.auth_token)
                .parse()
                .map_err(|_| refused())?;
            request.headers_mut().insert(AUTHORIZATION, header);
        }
        let (mut socket, response) = match tokio::time::timeout_at(
            deadline,
            crate::sync::carrier::connect_sync_socket(request, endpoint.dialer),
        )
        .await
        {
            Ok(Ok(connected)) => connected,
            Ok(Err(tokio_tungstenite::tungstenite::Error::Http(_))) => return Err(refused()),
            Ok(Err(_)) | Err(_) => return Ok(None),
        };
        tokio::time::timeout_at(
            deadline,
            socket.send(Message::Binary(
                transport::encode_residence_protocol_hello().into(),
            )),
        )
        .await
        .map_err(|_| refused())?
        .map_err(|_| refused())?;
        let home = crate::sync::home_proof::home_peer(vault, &response, binding.as_ref());
        Ok(Some((socket, home)))
    }

    pub(super) async fn request(
        &mut self,
        method: &str,
        params: Value,
    ) -> Result<Value, TransportError> {
        self.call(method, params).await?.map_err(|refusal| {
            if refusal.code.as_deref() == Some("INDEX_REVISION_CHANGED") {
                TransportError::IndexRevisionChanged
            } else {
                TransportError::InvalidPayload("home refused residence RPC")
            }
        })
    }

    /// [`Self::request`], with the home's refusal kept apart from a call that
    /// failed: `Ok(Err(_))` when the home answered no.
    pub(super) async fn call(
        &mut self,
        method: &str,
        params: Value,
    ) -> Result<Result<Value, HomeRefused>, TransportError> {
        let id = self.next_id;
        self.next_id = self.next_id.checked_add(1).ok_or_else(refused)?;
        let request = RequestEnvelope {
            kind: "rpc.req",
            id,
            seq: 0,
            last: true,
            payload: json!({"method": method, "params": params}),
        };
        let bytes = rmp_serde::to_vec_named(&request).map_err(|_| refused())?;
        if bytes.len() > transport::MAX_DECODED_PAYLOAD_BYTES {
            return Err(refused());
        }
        let mut frame = vec![TAG_RPC];
        frame.extend(bytes);
        let deadline = tokio::time::Instant::now() + self.timeout;
        tokio::time::timeout_at(deadline, self.socket.send(Message::Binary(frame.into())))
            .await
            .map_err(|_| refused())?
            .map_err(|_| refused())?;
        let mut assembled = Vec::new();
        for seq in 0..512u64 {
            let frame = loop {
                let msg = tokio::time::timeout_at(deadline, self.socket.next())
                    .await
                    .map_err(|_| refused())?
                    .ok_or_else(refused)?
                    .map_err(|_| refused())?;
                let Message::Binary(frame) = msg else {
                    return Err(refused());
                };
                // FIX 6458: an unbound lane passes over the sync frames the
                // home opens each socket with; a bound lane takes none.
                let opening = matches!(
                    frame.first(),
                    Some(&transport::TAG_EPHEMERAL) | Some(&transport::TAG_SYNC_UPDATE)
                );
                if !(self.unbound && opening) {
                    break frame;
                }
            };
            if frame.first() != Some(&TAG_RPC) {
                return Err(refused());
            }
            let reply: ReplyEnvelope = rmp_serde::from_slice(&frame[1..]).map_err(|_| refused())?;
            if reply.id != id || reply.seq != seq {
                return Err(refused());
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
                return Err(refused());
            }
            let chunk = reply.payload.as_slice().ok_or_else(refused)?;
            if assembled.len().saturating_add(chunk.len()) > MAX_RPC_REPLY_BYTES {
                return Err(refused());
            }
            assembled.extend_from_slice(chunk);
            if reply.last {
                return rmp_serde::from_slice(&assembled)
                    .map(Ok)
                    .map_err(|_| refused());
            }
        }
        Err(refused())
    }
}

pub(super) fn refused() -> TransportError {
    TransportError::InvalidPayload("opened-item RPC unavailable")
}
