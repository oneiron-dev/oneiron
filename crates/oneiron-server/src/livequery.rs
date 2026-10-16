//! App-tier framing and coarse live-query state, separate from WindowSync.
//!
//! Facade construction uses only verified CoreAuth claims. No payload actor,
//! token re-parser, or default class can cross this boundary. Reads run in the
//! deferred owner loop, never in Observer B or through a second materializer.

#[cfg(test)]
use oneiron::memory::Effort;
use oneiron::memory::{Memory, RecallScope, ScopedView};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::auth::{CoreAuth, CoreScope};
use crate::protocol::{ProtocolError, TAG_RPC, TAG_SUB};

mod budget;
mod error;
mod history;
mod reads;
mod residence;
pub(crate) use residence::ResidenceIndexCache;
mod routing;
mod wire;
use error::AppError;
use reads::{Read, read_method};

/// RPC ids never index the subscription table.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RpcRequest {
    pub request_id: u64,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

pub(crate) fn decode_rpc(payload: &[u8]) -> Result<RpcRequest, ProtocolError> {
    wire::rpc(payload)
}

pub(crate) fn decode_sub(payload: &[u8]) -> Result<SubRequest, ProtocolError> {
    wire::sub(payload)
}

pub(crate) fn ping_result(id: u64, payload: Value) -> Result<Vec<u8>, ProtocolError> {
    wire::frame(TAG_RPC, "ping", id, 0, true, payload)
}

pub(crate) fn bind_token(params: &Value) -> Result<String, ProtocolError> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Bind {
        token: String,
        binding: crate::auth::BindingProof,
    }
    serde_json::from_value::<Bind>(params.clone())
        .map(|bind| {
            let _ = bind.binding;
            bind.token
        })
        .map_err(|_| ProtocolError::RpcNoPrincipal)
}

/// Results are a bounded, sequenced MessagePack byte stream, including empty values.
pub(crate) fn rpc_result(request_id: u64, result: Value) -> Result<Vec<Vec<u8>>, ProtocolError> {
    wire::result(request_id, &result)
}

fn rpc_error(request_id: u64, error: AppError) -> Result<Vec<Vec<u8>>, ProtocolError> {
    Ok(vec![wire::frame(
        TAG_RPC, "rpc.err", request_id, 0, true, error,
    )?])
}

/// A read RPC's reply frames, and the rows its result carries as its
/// producer named them: `None` when it could not.
pub(crate) struct RpcReply {
    request_id: u64,
    frames: Vec<Vec<u8>>,
    /// `None` for a refusal, which carries no rows.
    rows: Option<Option<Vec<oneiron::EntityId>>>,
}

impl RpcReply {
    fn answer(
        request_id: u64,
        result: Result<(Value, Option<Vec<oneiron::EntityId>>), AppError>,
    ) -> Result<Self, ProtocolError> {
        let (frames, rows) = match result {
            Ok((value, rows)) => match rpc_result(request_id, value) {
                Ok(frames) => (frames, Some(rows)),
                Err(_) => (
                    rpc_error(
                        request_id,
                        AppError::bad_request("RPC result byte limit exceeded", None),
                    )?,
                    None,
                ),
            },
            Err(error) => (rpc_error(request_id, error)?, None),
        };
        Ok(Self {
            request_id,
            frames,
            rows,
        })
    }

    /// The frames as `conn`'s send door takes them: each chunk of a result
    /// carries the rows the release judges again (DEC-0005).
    pub(crate) fn queued(self, conn: u32) -> Vec<Vec<u8>> {
        let Some(rows) = self.rows else {
            return self.frames;
        };
        self.frames
            .into_iter()
            .map(|frame| routing::wrap(conn, self.request_id, 0, rows.as_deref(), frame))
            .collect()
    }
}

/// Both identity claims come from the credential, exactly as on the HTTP facade.
fn bound_memory<'a>(vault: &'a oneiron::Vault, auth: &CoreAuth) -> Result<Memory<'a>, AppError> {
    let (actor, class) = bound_reader(auth)?;
    let memory = vault.memory(actor, class).at(auth.locality());
    // Reads run under the credential this principal presented (ONE-1187-D6).
    Ok(match auth.verified_slip() {
        Some(proof) => memory.with_read_proof(proof),
        None => memory,
    })
}

/// The principal a bound credential reads as, and its actor class.
fn bound_reader(auth: &CoreAuth) -> Result<(oneiron::EntityId, oneiron::EdgeActorClass), AppError> {
    auth.require(CoreScope::Read)?;
    auth.require_unrestricted_record_scope()?;
    let principal = auth.principal_ref().ok_or_else(|| {
        AppError::forbidden(
            "facade routes bind writes to an authenticated principal",
            [
                "Present a slip minted with --principal-ref <32-hex person id>.",
                "An owner-grade credential names no principal and cannot write here.",
            ],
        )
    })?;
    let actor = oneiron::EntityId::from_hex(principal).map_err(|_| {
        AppError::forbidden(
            "principal_ref is not a 32-hex entity id",
            ["Re-mint the slip with a 32-character lowercase hex principal ref."],
        )
    })?;
    Ok((actor, bound_actor_class(auth)?))
}

fn bound_actor_class(auth: &CoreAuth) -> Result<oneiron::EdgeActorClass, AppError> {
    match auth.actor_class() {
        Some("human") => Ok(oneiron::EdgeActorClass::Human),
        Some("agent") => Ok(oneiron::EdgeActorClass::Agent),
        Some("system") => Ok(oneiron::EdgeActorClass::System),
        None | Some(_) => Err(AppError::forbidden(
            "facade routes bind writes to a declared actor class",
            [
                "Present a slip minted with --actor-class <human|agent|system>.",
                "Reconnect with a differently scoped slip to act as another actor.",
            ],
        )),
    }
}

pub(crate) fn residence_rpc(
    server: &crate::server::SyncServer,
    auth: &CoreAuth,
    peer: oneiron::authority::PeerMachine,
    request: RpcRequest,
    index_cache: &mut Option<ResidenceIndexCache>,
) -> Result<RpcReply, ProtocolError> {
    residence::run(server, auth, peer, request, index_cache)
}

#[cfg(test)]
pub(crate) fn bound_rpc(
    server: &crate::server::SyncServer,
    auth: &CoreAuth,
    request: RpcRequest,
) -> Result<Vec<Vec<u8>>, ProtocolError> {
    bound_rpc_reply(server, auth, request).map(|reply| reply.frames)
}

pub(crate) fn bound_rpc_reply(
    server: &crate::server::SyncServer,
    auth: &CoreAuth,
    request: RpcRequest,
) -> Result<RpcReply, ProtocolError> {
    let result = (|| {
        if !read_method(&request.method) {
            // A canonical verb under the wrong root is refused with its
            // correction, before scope, identity or any engine call.
            if let Some(refusal) = oneiron::task_verb::sdk::wrong_root(&request.method) {
                return Err(refusal.into());
            }
            return Err(AppError::bad_request("unknown read RPC", Some("method")));
        }
        // HTTP order: scope, request/limit validation, identity, engine call.
        auth.require(CoreScope::Read)?;
        auth.require_unrestricted_record_scope()?;
        let read = Read::parse(&request.method, request.params)?;
        let memory = bound_memory(server.vault(), auth)?;
        read.run(server, auth, &memory)
    })();
    RpcReply::answer(request.request_id, result)
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Channel {
    #[default]
    View,
    Receipts,
    PendingConsent,
    /// Human owner feed of durable per-entry SAVED_QUERY watches.
    OwnerFeed,
    // Reserved, explicitly rejected rather than aliasing a different stream.
    MemoryBoard,
    Gap,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "method", deny_unknown_fields)]
pub(crate) enum SubRequest {
    #[serde(rename = "sub.open")]
    Open {
        #[serde(rename = "subscriptionId")]
        subscription_id: u64,
        #[serde(rename = "scopedView")]
        scoped_view: ScopedView,
        #[serde(default)]
        channel: Channel,
        #[serde(default)]
        cursor: Option<Cursor>,
        #[serde(default)]
        origin: Option<String>,
    },
    #[serde(rename = "sub.ack")]
    Ack {
        #[serde(rename = "subscriptionId")]
        subscription_id: u64,
        cursor: Cursor,
    },
    #[serde(rename = "sub.close")]
    Close {
        #[serde(rename = "subscriptionId")]
        subscription_id: u64,
    },
}

pub(crate) fn sub_error(id: u64, error: AppError) -> Result<Vec<u8>, ProtocolError> {
    wire::frame(TAG_SUB, "sub.err", id, 0, true, error)
}

impl SubRequest {
    pub(crate) fn id(&self) -> u64 {
        match self {
            Self::Open {
                subscription_id, ..
            }
            | Self::Ack {
                subscription_id, ..
            }
            | Self::Close { subscription_id } => *subscription_id,
        }
    }
}

pub(crate) mod connection;
mod membership;
mod publication;
mod source;

/// Opaque Loro cursor plus a container-batch ordinal. A single Loro commit
/// can materialize several containers; VV alone cannot acknowledge those
/// different snapshots without accidentally acknowledging an unseen batch.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Cursor {
    pub document: String,
    #[serde(with = "serde_bytes")]
    pub version_vector: Vec<u8>,
    pub batch: u64,
}

pub(crate) mod subscriptions;

#[cfg(test)]
pub(crate) mod test_wire;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod remediation_tests;

#[cfg(test)]
mod socket_tests;

#[cfg(test)]
mod production_tests;

#[cfg(test)]
mod device_local_tests;

#[cfg(test)]
pub(crate) mod rule5_tests;

/// A device-only flag committed while a reply sits in a socket's queue,
/// before its send door releases it.
#[cfg(test)]
pub(crate) mod release_hook {
    use std::cell::Cell;

    thread_local! {
        // Per thread: the socket runs on the test's own current-thread
        // runtime.
        static FLAG: Cell<Option<oneiron::EntityId>> = const { Cell::new(None) };
    }

    pub(crate) fn arm(world: oneiron::EntityId) {
        FLAG.set(Some(world));
    }

    pub(crate) fn run(server: &crate::server::SyncServer) {
        if let Some(world) = FLAG.take() {
            server
                .vault()
                .keep_world_on_this_machine_under_for_test(
                    &crate::test_credentials::host_issuer(server),
                    world,
                    true,
                )
                .expect("device-only flag");
        }
    }
}

#[cfg(test)]
mod production_socket_tests;
