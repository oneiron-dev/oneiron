//! App-tier framing and coarse live-query state, separate from WindowSync.
//!
//! Facade construction uses only verified CoreAuth claims. No payload actor,
//! token re-parser, or default class can cross this boundary. An `rpc.req`
//! names any facade verb, and it runs through the facade's one generated
//! dispatch under the connection's bound credential (OF-489), from the
//! deferred owner loop, never in Observer B or through a second materializer.

#[cfg(test)]
use oneiron::memory::Effort;
use oneiron::memory::{Memory, RecallScope, ScopedView};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::api::call_receipt::{self, CallStamp};
use crate::auth::{CoreAuth, CoreScope};
use crate::protocol::{ProtocolError, TAG_RPC, TAG_SUB};

mod budget;
mod error;
mod history;
mod residence;
pub(crate) use residence::ResidenceIndexCache;
mod routing;
mod rpc;
mod wire;
use error::AppError;

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

fn rpc_error(
    request_id: u64,
    error: AppError,
    stamp: &CallStamp,
) -> Result<Vec<Vec<u8>>, ProtocolError> {
    Ok(vec![wire::stamped_frame(
        TAG_RPC, "rpc.err", request_id, 0, true, error, stamp,
    )?])
}

/// What a WS RPC's receipt states of its request (OF-538), taken before the
/// call consumes its params.
pub(crate) struct RpcCall {
    method: String,
    request_digest: String,
    /// The input versions the call reads (OF-568); `None` when uncaptured.
    inputs: Option<oneiron::receipt::ActionInputs>,
}

impl RpcCall {
    pub(crate) fn of(request: &RpcRequest) -> Self {
        Self {
            method: request.method.clone(),
            request_digest: oneiron::receipt::call_json_digest(&request.params),
            inputs: None,
        }
    }

    /// [`Self::of`], with the input versions the call reads captured before
    /// it runs (OF-568).
    pub(crate) fn captured(server: &crate::server::SyncServer, request: &RpcRequest) -> Self {
        Self {
            inputs: call_receipt::action_inputs(server, &request.method, Some(&request.params)),
            ..Self::of(request)
        }
    }
}

/// An RPC's reply frames, and the rows its result carries as its producer
/// named them: `None` when it could not.
pub(crate) struct RpcReply {
    request_id: u64,
    frames: Vec<Vec<u8>>,
    /// `None` for a refusal, which carries no rows.
    rows: Option<Option<Vec<oneiron::EntityId>>>,
}

impl RpcReply {
    /// OF-538's one WS door: records the call once it has answered, in its
    /// own write transaction, and states the receipt on every `rpc.res`
    /// chunk and on `rpc.err` alike. The result is packed first, so one past
    /// the byte limit is recorded as the refusal the caller receives.
    ///
    /// A WS RPC runs on the vault the bound credential reads, never inside
    /// an off-record session, so the anonymous no-record exception never
    /// arises here.
    fn answer(
        server: &crate::server::SyncServer,
        auth: &CoreAuth,
        call: RpcCall,
        request_id: u64,
        result: Result<(Value, Option<Vec<oneiron::EntityId>>), AppError>,
    ) -> Result<Self, ProtocolError> {
        let too_large = || AppError::bad_request("RPC result byte limit exceeded", None);
        // A `reveal.wait` reply is digested with its value masked (OF-560).
        let mut masked = None;
        let packed = result.and_then(|(value, rows)| {
            masked = oneiron::task_verb::sdk::masked_reveal_reply(&call.method, &value);
            wire::packed(&value)
                .map(|bytes| (bytes, rows))
                .map_err(|_| too_large())
        });
        let (outcome, result_digest, served) = match &packed {
            Ok((bytes, rows)) => (
                oneiron::receipt::CallOutcome::Ok,
                Some(masked.as_ref().map_or_else(
                    || oneiron::receipt::call_bytes_digest(bytes),
                    oneiron::receipt::call_json_digest,
                )),
                rows.iter()
                    .flatten()
                    .take(oneiron::receipt::MAX_CALL_RECEIPT_SERVED)
                    .map(oneiron::EntityId::to_hex)
                    .collect(),
            ),
            Err(error) => (
                oneiron::receipt::CallOutcome::Refused {
                    code: error.code().to_owned(),
                },
                Some(oneiron::receipt::call_refusal_digest(
                    error.code(),
                    error.message(),
                )),
                Vec::new(),
            ),
        };
        let (actor_ref, actor_class) = call_receipt::call_actor(auth);
        let stamp = call_receipt::record(
            server,
            false,
            oneiron::receipt::CallReceiptInput {
                transport: oneiron::receipt::CallTransport::Ws,
                verb: call.method,
                actor_ref,
                actor_class,
                credential_ref: call_receipt::credential_ref(auth),
                outcome,
                request_digest: call.request_digest,
                result_digest,
                inputs: call.inputs,
                served,
            },
        );
        let (frames, rows) = match packed {
            Ok((bytes, rows)) => match wire::result_chunks(request_id, &bytes, &stamp) {
                Ok(frames) => (frames, Some(rows)),
                Err(_) => (rpc_error(request_id, too_large(), &stamp)?, None),
            },
            Err(error) => (rpc_error(request_id, error, &stamp)?, None),
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

/// [`rpc_reply`] from a synchronous test door, through the blocking bridge
/// ([`rpc::blocking`]); a socket's owner loop awaits [`rpc_reply`] off the
/// loop. The facade's server and host doors take the served handle, which
/// this door finds through the socket's hub.
#[cfg(test)]
pub(crate) fn bound_rpc_reply(
    server: &crate::server::SyncServer,
    auth: &CoreAuth,
    request: RpcRequest,
) -> Result<RpcReply, ProtocolError> {
    let Some(served) = connection::Hub::served(server) else {
        let call = RpcCall::of(&request);
        let unserved = AppError::internal_server_error("no live-query hub serves this server");
        return RpcReply::answer(server, auth, call, request.request_id, Err(unserved));
    };
    rpc::blocking(rpc_reply(&served, auth, request))
}

/// One verb RPC on a held socket, answered through OF-538's WS door: the
/// facade verb it names runs through the facade's generated dispatch under
/// the connection's bound credential, with the admission its HTTP route
/// applies, and its answer carries the rows it was derived from to the send
/// door. A name that is no facade verb is refused before any check, with its
/// correction when it is a canonical verb under the wrong root.
pub(crate) async fn rpc_reply(
    server: &std::sync::Arc<crate::server::SyncServer>,
    auth: &CoreAuth,
    request: RpcRequest,
) -> Result<RpcReply, ProtocolError> {
    let call = RpcCall::captured(server, &request);
    let result = rpc::run(server, auth, &request.method, request.params).await;
    RpcReply::answer(server, auth, call, request.request_id, result)
}

/// A page size a scoped view asks for, or `default`, within the facade's
/// list ceiling.
fn facade_limit(requested: Option<usize>, default: usize) -> Result<usize, AppError> {
    let limit = requested.unwrap_or(default);
    if limit == 0 || limit > crate::api::CORE_MAX_LIST_LIMIT {
        return Err(AppError::new(
            oneiron::memory::MEMORY_CODE_BAD_REQUEST,
            format!(
                "limit must be between 1 and {}",
                crate::api::CORE_MAX_LIST_LIMIT
            ),
            ["Request a smaller page and paginate."],
        ));
    }
    Ok(limit)
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
