//! App-tier framing and coarse live-query state, separate from WindowSync.
//!
//! Facade construction uses only verified CoreAuth claims. No payload actor,
//! token re-parser, or default class can cross this boundary. Reads run in the
//! deferred owner loop, never in Observer B or through a second materializer.

#[cfg(test)]
use oneiron::memory::Effort;
use oneiron::memory::{Memory, RecallScope};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::auth::{CoreAuth, CoreScope};
use crate::protocol::{ProtocolError, TAG_RPC, TAG_SUB};

mod budget;
mod error;
mod history;
mod reads;
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
    }
    serde_json::from_value::<Bind>(params.clone())
        .map(|bind| bind.token)
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

/// Both identity claims come from the credential, exactly as on the HTTP facade.
fn bound_memory<'a>(vault: &'a oneiron::Vault, auth: &CoreAuth) -> Result<Memory<'a>, AppError> {
    auth.require(CoreScope::Read)?;
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
    Ok(vault.memory(actor, bound_actor_class(auth)?))
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

pub(crate) fn bound_rpc(
    vault: &oneiron::Vault,
    auth: &CoreAuth,
    request: RpcRequest,
) -> Result<Vec<Vec<u8>>, ProtocolError> {
    let result = (|| {
        if !read_method(&request.method) {
            return Err(AppError::bad_request("unknown read RPC", Some("method")));
        }
        // HTTP order: scope, request/limit validation, identity, engine call.
        auth.require(CoreScope::Read)?;
        let read = Read::parse(&request.method, request.params)?;
        let memory = bound_memory(vault, auth)?;
        read.run(&memory)
    })();
    match result {
        Ok(value) => rpc_result(request.request_id, value).or_else(|_| {
            rpc_error(
                request.request_id,
                AppError::bad_request("RPC result byte limit exceeded", None),
            )
        }),
        Err(error) => rpc_error(request.request_id, error),
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ScopedView {
    pub world_ref: Option<String>,
    pub facet: Option<String>,
    pub filter: Option<Value>,
    pub query: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Channel {
    #[default]
    View,
    Receipts,
    PendingConsent,
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
mod production_socket_tests;
