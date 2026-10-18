//! The held socket's verb RPC (OF-489 socket-first): an `rpc.req` names any
//! facade row, and it runs through the facade's one generated dispatch under
//! the credential the connection bound, meeting the admission its HTTP route
//! applies. A Write row is a write here as there. Board, browser and run rows
//! stay off the socket: the dispatch refuses each by the context it needs.
//!
//! The call context an `rpc.req` carries beside its params (FIX 2059) is
//! what the HTTP facade reads from its headers: the session the call is made
//! in, the room whose turn it runs in and its logical invocation, read the
//! same way, plus a subscription open on the same connection, which the
//! socket resolves to its open instance (FIX 2612 (b)).
use std::sync::Arc;

use oneiron::EntityId;
use oneiron::runtime_hooks::InvocationId;
use oneiron::runtime_hooks::verb::InvocationOutcome;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{AppError, RpcCallContext};
use crate::api::DoorClaim;
use crate::api::call_receipt;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// A verb RPC's answer: its result and the rows it carries, or its refusal.
type Answer = Result<(Value, Option<Vec<EntityId>>), AppError>;

/// What a held socket took of one verb RPC's call context before the call
/// left its owner loop (FIX 2059): the context as its `rpc.req` carried it,
/// whether the session it names was anonymous for the bound principal on
/// arrival, and the open instance of the subscription it names. The session
/// binds this request only: the socket's bound credential and every other
/// call on it keep their own.
#[derive(Default)]
pub(crate) struct SocketCallContext {
    carried: RpcCallContext,
    /// Judged on arrival; judged again before the receipt is written.
    arrived_anonymous: bool,
    /// `None` when the context names no subscription; `Some(None)` when the
    /// one it names is not open on this socket.
    subscription: Option<Option<String>>,
}

impl SocketCallContext {
    /// The context `carried` as the socket that bound `auth` takes it on
    /// arrival: its session judged for the credential's principal now, and
    /// the subscription it names as `connection` holds it open now
    /// ([`super::connection::Connection::subscription_instance`]). A call
    /// with no socket behind it holds no subscription open.
    pub(crate) fn arrived(
        server: &SyncServer,
        auth: &CoreAuth,
        carried: Option<RpcCallContext>,
        connection: Option<&super::connection::Connection>,
    ) -> Self {
        let carried = carried.unwrap_or_default();
        let subscription = carried
            .subscription
            .map(|id| connection.and_then(|connection| connection.subscription_instance(auth, id)));
        let mut context = Self {
            carried,
            arrived_anonymous: false,
            subscription,
        };
        context.arrived_anonymous = context.anonymous(server, auth);
        context
    }

    /// The session the context names, as the off-record surface reads it.
    fn session_ref(&self) -> Option<&str> {
        self.carried
            .session
            .as_deref()
            .map(call_receipt::spelled_session_ref)
    }

    /// Whether the call runs inside an anonymous off-record session `auth`'s
    /// principal is verified in, on arrival or now (OF-063): the check the
    /// HTTP facade makes of its session header
    /// ([`call_receipt::session_is_anonymous_for`]).
    pub(super) fn anonymous(&self, server: &SyncServer, auth: &CoreAuth) -> bool {
        self.arrived_anonymous
            || call_receipt::session_is_anonymous_for(
                server,
                self.session_ref(),
                call_receipt::request_principal(auth),
            )
    }

    /// The facade call this context carries for `auth`'s credential. Its
    /// lens card is held for the subscription instance the socket resolved,
    /// and for no creating run: no run attaches on the socket, so a render
    /// keeps `LensFrameStore::record` until one does (FIX 2612 (b)).
    fn facade_call<'a>(&'a self, auth: &'a CoreAuth) -> crate::api::FacadeCall<'a> {
        crate::api::FacadeCall::bound(
            auth,
            self.carried.room_turn.as_deref(),
            self.carried.invocation.as_deref(),
            self.carried.session.as_deref(),
        )
        .lens_held(None, self.subscription.clone().flatten())
    }
}

/// [`run`], once per invocation the call context names (OF-580), as the
/// HTTP facade's invocation claim runs a route: a second call naming it for
/// the same call waits for this one's answer and gets it again, without
/// running, under its own request id and receipt; one naming it for another
/// call is refused at once. The call is the bound credential's, where it
/// sits, its verb, the room turn, session and subscription instance its
/// context names, and its params; never its request id. An invocation that
/// is no id is left to the row's own refusal. A context naming a
/// subscription not open on this socket is refused before anything runs,
/// as `NOT_FOUND`, the same as a `sub.ack` for it.
pub(super) async fn claimed(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    context: &SocketCallContext,
    method: &str,
    params: Value,
) -> Answer {
    let subscription = match &context.subscription {
        Some(None) => return Err(AppError::not_found("subscription", None)),
        Some(Some(instance)) => instance.as_str(),
        None => "",
    };
    let Some(invocation) = context
        .carried
        .invocation
        .as_deref()
        .and_then(InvocationId::parse_hex)
    else {
        return run(server, auth, context, method, params).await;
    };
    let room_turn = context.carried.room_turn.as_deref().unwrap_or_default();
    let session = context.carried.session.as_deref().unwrap_or_default();
    let digest = oneiron::receipt::call_json_digest(&params);
    let body = crate::api::invocation_body(
        Some(auth),
        auth.locality(),
        &[
            b"ws-facade".as_slice(),
            method.as_bytes(),
            room_turn.as_bytes(),
            session.as_bytes(),
            subscription.as_bytes(),
            digest.as_bytes(),
        ],
    );
    match crate::api::claim_door_invocation(server, invocation, body).await {
        DoorClaim::Run(claim) => {
            let answer = run(server, auth, context, method, params).await;
            if let Some(outcome) = saved(&answer) {
                claim.finish(outcome);
            }
            answer
        }
        DoorClaim::Answered(outcome) => replayed(outcome),
        DoorClaim::InFlight => Err(AppError::invocation_in_flight()),
        DoorClaim::Conflict => Err(AppError::invocation_conflict()),
    }
}

/// A claimed call's answer as the calls waiting on it take it again: its
/// result and the rows it carries, each by its hex id, or its whole refusal.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
enum Saving<'a> {
    Answered {
        value: &'a Value,
        rows: Option<Vec<String>>,
    },
    Refused(&'a AppError),
}

/// [`Saving`], read back.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
enum Saved {
    Answered {
        value: Value,
        rows: Option<Vec<String>>,
    },
    Refused(AppError),
}

/// `answer` as the claim saves it for the calls waiting on it; `None`, so
/// each is told to retry, when it cannot be saved.
fn saved(answer: &Answer) -> Option<InvocationOutcome> {
    let saving = match answer {
        Ok((value, rows)) => Saving::Answered {
            value,
            rows: rows
                .as_ref()
                .map(|rows| rows.iter().map(EntityId::to_hex).collect()),
        },
        Err(refusal) => Saving::Refused(refusal),
    };
    let body = serde_json::to_value(saving).ok()?;
    Some(InvocationOutcome { status: 200, body })
}

/// The first call's answer, taken again by a call that waited on it. Its
/// rows are judged again at this call's send door; a row that does not read
/// back leaves the rows unknown, so the result stays on this device.
fn replayed(outcome: InvocationOutcome) -> Answer {
    match serde_json::from_value(outcome.body) {
        Ok(Saved::Answered { value, rows }) => {
            let rows = rows.and_then(|rows| {
                rows.iter()
                    .map(|row| EntityId::from_hex(row).ok())
                    .collect::<Option<Vec<_>>>()
            });
            Ok((value, rows))
        }
        Ok(Saved::Refused(refusal)) => Err(refusal),
        Err(_) => Err(AppError::invocation_in_flight()),
    }
}

/// Runs facade verb `method` over `params` as `auth`'s call, in the call
/// context the socket took. Beside the result come the rows it carries, for
/// the send door to judge again (DEC-0005): those its reads listed, and
/// those its input and its result name by ref. `None` when one of them is
/// unknown, so the result does not leave this device.
async fn run(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    context: &SocketCallContext,
    method: &str,
    params: Value,
) -> Answer {
    let mut input_rows = Vec::new();
    let input_named = named_rows(server.vault(), &params, &mut input_rows);
    let call = context.facade_call(auth);
    let output = crate::api::facade_call_verb(server, &call, method, Ok(params)).await?;
    let rows = output.rows.and_then(|mut rows| {
        input_named?;
        named_rows(server.vault(), &output.value, &mut rows)?;
        rows.append(&mut input_rows);
        Some(rows)
    });
    Ok((output.value, rows))
}

/// Lists in `rows` each row `value` names by ref: a whole id, or a short
/// ref, keys included. `None` when a short ref names no row.
fn named_rows(vault: &oneiron::Vault, value: &Value, rows: &mut Vec<EntityId>) -> Option<()> {
    rows.extend(crate::device_local::short_refs_named(vault, value)?);
    let mut pending = vec![value];
    while let Some(value) = pending.pop() {
        match value {
            Value::String(text) => rows.extend(EntityId::from_hex(text).ok()),
            Value::Array(items) => pending.extend(items),
            Value::Object(map) => {
                for (key, item) in map {
                    rows.extend(EntityId::from_hex(key).ok());
                    pending.push(item);
                }
            }
            _ => {}
        }
    }
    Some(())
}

/// Runs `call` to its answer from a synchronous test door (a socket's owner
/// loop awaits its calls off the loop): [`crate::server::blocking`] leaves
/// this worker first, so every other task keeps a worker while the caller
/// waits, and the call runs on the server's own runtime. Outside any runtime,
/// a runtime of its own runs it.
#[cfg(test)]
pub(super) fn blocking<T: Send>(
    call: impl std::future::Future<Output = Result<T, crate::protocol::ProtocolError>> + Send,
) -> Result<T, crate::protocol::ProtocolError> {
    let runtime = tokio::runtime::Handle::try_current().ok();
    crate::server::blocking(move || match runtime {
        Some(runtime) => runtime.block_on(call),
        None => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| {
                crate::protocol::ProtocolError::InvalidPayload("no runtime answers this RPC")
            })?
            .block_on(call),
    })
}
