//! OF-538: the lasting receipt every wire reply carries, reads included.
//!
//! One central door per transport records each call after its own work is
//! done (`facade::facade_call_receipt` for the HTTP facade, the `tools/call`
//! arm of the MCP gateway, `livequery::RpcReply::answer` for WS RPC) and
//! states the ref on the reply, success and refusal alike. This module is
//! what the three share: the stamp, its header, the caller's attribution and
//! the anonymous no-record exception.
//!
//! The exception (ARCH-0052): a call inside an `OffRecordMode::Anonymous`
//! session writes no row, and every off-record route says so on its reply
//! (`x-oneiron-receipt-ref: none; no-record`), since no wire receipt may
//! record that a session ran.
//!
//! A reply no credential attributed (FIX 811, Engine ruling 10-18): a
//! pre-auth refusal (the binding door's, a credential that does not
//! authenticate, an unbound socket's) or a protocol-only reply (MCP
//! `initialize`, `tools/list`, parse errors; WS `auth.bind` and `ping`) is
//! recorded for the connection it arrived on ([`connection_call`]): the
//! connection's id, no person, no credential, and the normal row life. A
//! door records its own; [`connection_receipt`], outside the binding door,
//! records what reached no door.

use std::future::Future;
use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue};
use axum::middleware::Next;
use axum::response::Response;
use oneiron::receipt::{ActionInputs, CallOutcome, CallReceiptInput, CallTransport};
use serde_json::{Map, Value};

use crate::auth::CoreAuth;
use crate::server::SyncServer;

tokio::task_local! {
    /// The id of the connection the call in flight arrived on: one per
    /// accepted socket, never derived from the peer's address.
    static CONNECTION_ID: u128;
}

/// Runs `call` as one connection's: every reply inside it that no credential
/// attributed names `id` ([`request_connection`]).
pub(crate) fn on_connection<F: Future>(id: u128, call: F) -> impl Future<Output = F::Output> {
    CONNECTION_ID.scope(id, call)
}

/// A fresh connection id, for one accepted socket.
pub(crate) fn mint_connection_id() -> u128 {
    let mut id = [0_u8; 16];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut id);
    u128::from_be_bytes(id)
}

/// The id of the connection the call in flight arrived on, minted on the
/// spot for a call outside any (an in-process or managed-listener request),
/// which is then its own connection.
pub(crate) fn connection_id() -> u128 {
    CONNECTION_ID
        .try_with(|id| *id)
        .unwrap_or_else(|_| mint_connection_id())
}

/// [`connection_id`] as the 32 hex a receipt's `actor_ref` states.
pub(crate) fn request_connection() -> String {
    format!("{:032x}", connection_id())
}

/// The receipt input of a reply no credential attributed (FIX 811): the
/// connection is its actor, of class `connection`, with no credential and
/// no captured inputs.
pub(crate) fn connection_call(
    transport: CallTransport,
    verb: String,
    outcome: CallOutcome,
    request_digest: String,
    result_digest: Option<String>,
) -> CallReceiptInput {
    CallReceiptInput {
        transport,
        verb,
        actor_ref: request_connection(),
        actor_class: oneiron::receipt::CONNECTION_CALL_ACTOR_CLASS.to_owned(),
        credential_ref: None,
        outcome,
        request_digest,
        result_digest,
        inputs: None,
        served: Vec::new(),
    }
}

/// Records a socket's reply no credential attributed (FIX 811): a WS
/// `auth.bind` or `ping`, or a frame the socket refused. A socket never runs
/// inside an off-record session.
pub(crate) fn record_socket_reply(
    server: &SyncServer,
    verb: String,
    outcome: CallOutcome,
    request_digest: String,
    result_digest: Option<String>,
) -> CallStamp {
    record(
        server,
        false,
        connection_call(
            CallTransport::Ws,
            verb,
            outcome,
            request_digest,
            result_digest,
        ),
    )
}

/// Says a door answered this reply's receipt, recorded or not, so
/// [`connection_receipt`] leaves it alone.
#[derive(Clone, Copy, Debug)]
pub(crate) struct DoorAnswered;

/// The header every facade reply states its call receipt in.
pub(crate) const RECEIPT_REF_HEADER: &str = "x-oneiron-receipt-ref";

/// The header value of a reply that by design has no receipt.
const NO_RECORD_HEADER_VALUE: &str = "none; no-record";

/// What one reply says of its call's receipt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CallStamp {
    /// The call's lasting receipt, `call:<32hex>`.
    Recorded(String),
    /// A call inside an anonymous off-record session: no row exists, and the
    /// reply says so explicitly.
    NoRecord,
    /// The call has no receipt: no credential attributed it, or its row could
    /// not be written (logged). The reply states nothing.
    Unrecorded,
}

impl CallStamp {
    /// The ref, for a recorded call.
    pub(crate) fn receipt_ref(&self) -> Option<&str> {
        match self {
            Self::Recorded(receipt_ref) => Some(receipt_ref),
            Self::NoRecord | Self::Unrecorded => None,
        }
    }

    /// Whether the call is the anonymous no-record exception.
    pub(crate) const fn no_record(&self) -> bool {
        matches!(self, Self::NoRecord)
    }

    /// The `x-oneiron-receipt-ref` value: the ref, or `none; no-record`.
    pub(crate) fn header_value(&self) -> Option<HeaderValue> {
        match self {
            Self::Recorded(receipt_ref) => HeaderValue::from_str(receipt_ref).ok(),
            Self::NoRecord => Some(HeaderValue::from_static(NO_RECORD_HEADER_VALUE)),
            Self::Unrecorded => None,
        }
    }

    /// Stamps `x-oneiron-receipt-ref` on a reply, and marks it answered by
    /// its door ([`DoorAnswered`]).
    pub(crate) fn stamp_header(&self, response: &mut Response) {
        if let Some(value) = self.header_value() {
            response.headers_mut().insert(RECEIPT_REF_HEADER, value);
        }
        response.extensions_mut().insert(DoorAnswered);
    }

    /// States the receipt in a JSON object: `receipt_ref`, which is `null`
    /// with `no_record: true` for the anonymous exception. An unrecorded call
    /// adds nothing.
    pub(crate) fn stamp_json(&self, object: &mut Map<String, Value>) {
        match self {
            Self::Recorded(receipt_ref) => {
                object.insert("receipt_ref".to_owned(), Value::String(receipt_ref.clone()));
            }
            Self::NoRecord => {
                object.insert("receipt_ref".to_owned(), Value::Null);
                object.insert("no_record".to_owned(), Value::Bool(true));
            }
            Self::Unrecorded => {}
        }
    }
}

/// Every off-record route's reply: it writes no receipt and says so
/// (ARCH-0052: "no wire receipt records that a session ran").
pub(crate) async fn no_record_reply(mut response: Response) -> Response {
    CallStamp::NoRecord.stamp_header(&mut response);
    response
}

/// Whether a request made for `principal` runs inside an anonymous
/// off-record session that principal is verified in: the session its
/// `x-oneiron-session` header names is one the live registry holds in
/// `OffRecordMode::Anonymous`, and the principal the request's credential
/// names (its holder, whichever class acts under it) is on its room's
/// roster or is the actor who entered it alone
/// (`Vault::off_record_session_is_anonymous_for`, OF-063). Every other
/// request records as anywhere else, and so does one with no principal
/// (the host root, an OAuth relay, the legacy shared secret): it binds no
/// session (Engine ruling 2137/2271). Each transport asks when the call
/// arrives and again when its receipt would be written: a caller verified
/// at either time writes none, so a session closed mid-call keeps its
/// call's exception.
pub(crate) fn in_anonymous_session(
    server: &SyncServer,
    headers: &HeaderMap,
    principal: Option<oneiron::EntityId>,
) -> bool {
    request_session_ref(headers).is_some_and(|session_ref| {
        server
            .vault()
            .off_record_session_is_anonymous_for(session_ref, principal)
    })
}

/// The principal a request's credential names, as an entity: its holder
/// (`principal_ref`). `None` for a credential that names none.
pub(crate) fn request_principal(auth: &CoreAuth) -> Option<oneiron::EntityId> {
    auth.principal_ref()
        .and_then(|principal| oneiron::EntityId::from_hex(principal).ok())
}

/// The principal an MCP call binds its session for (OF-063, FIX 2271): the
/// one its credential names, or, for the configured root, whose credential
/// verifies no slip and names no principal, the host-registered actor it
/// acts through, the actor its rows' surfaces bind
/// (`Memory::keeps_no_record` reads the same). A slip that names no
/// principal maps to none, so it binds no session.
pub(crate) fn mcp_session_principal(
    auth: Option<&CoreAuth>,
    actor: oneiron::EntityId,
) -> Option<oneiron::EntityId> {
    match auth {
        Some(auth) if auth.principal_ref().is_some() || auth.verified_slip().is_some() => {
            request_principal(auth)
        }
        _ => Some(actor),
    }
}

/// The session ref a request's `x-oneiron-session` header names, as text;
/// `None` when it names none or is no text. The engine binds it to the
/// request's memory surface (`Memory::in_off_record_session`), so a
/// reference refusal reads the same anonymous signal this receipt does.
pub(crate) fn request_session_ref(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(super::write_facet::SESSION_HEADER)?
        .to_str()
        .ok()
        .map(str::trim)
}

/// Who a credential's call is attributed to: its bound principal and actor
/// class, else the credential's own principal, `unbound`.
pub(crate) fn call_actor(auth: &CoreAuth) -> (String, String) {
    (
        auth.principal_ref()
            .unwrap_or_else(|| auth.principal())
            .to_owned(),
        auth.actor_class().unwrap_or("unbound").to_owned(),
    )
}

/// The presented credential's revocable id: a slip's id, when it has one.
pub(crate) fn credential_ref(auth: &CoreAuth) -> Option<String> {
    auth.jti().map(str::to_owned)
}

/// The input versions a call of `verb` on `request` reads, captured before
/// it runs (OF-568): the vault's state and each entity the request names.
/// `None` for a call that reads the world, or when the capture failed.
pub(crate) fn action_inputs(
    server: &SyncServer,
    verb: &str,
    request: Option<&Value>,
) -> Option<ActionInputs> {
    if oneiron::receipt::call_reads_world(verb) {
        return None;
    }
    let named = request
        .map(oneiron::receipt::json_entity_refs)
        .unwrap_or_default();
    server.vault().action_inputs(&named).ok().flatten()
}

/// Writes one call's receipt, or states the anonymous exception without
/// writing. Best effort (FIX 813, Engine ruling 10-18): the call's own work
/// has already committed or rolled back, so a row that cannot be written
/// blocks nothing and changes nothing in the reply but its missing ref. It
/// is logged as one warn line naming the row (transport, verb, actor class,
/// outcome) and the error.
pub(crate) fn record(server: &SyncServer, anonymous: bool, input: CallReceiptInput) -> CallStamp {
    if anonymous {
        return CallStamp::NoRecord;
    }
    let transport = input.transport;
    let verb = input.verb.clone();
    let actor_class = input.actor_class.clone();
    let outcome = input.outcome.clone();
    match server.vault().record_call_receipt(input) {
        Ok(receipt_ref) => CallStamp::Recorded(receipt_ref),
        Err(error) => {
            tracing::warn!(
                ?transport,
                %verb,
                %actor_class,
                ?outcome,
                %error,
                "call answered without its receipt"
            );
            CallStamp::Unrecorded
        }
    }
}

/// The door a path's replies are recorded by, and the verb an unattributed
/// reply there states: the facade's verb, the MCP endpoint, a refused WS
/// upgrade. `None` for routes that keep no wire receipt.
fn receipted_door(path: &str) -> Option<(CallTransport, String)> {
    if let Some(verb) = path.strip_prefix("/v1/core/facade/") {
        return Some((CallTransport::HttpFacade, verb.to_owned()));
    }
    match path {
        "/mcp" | "/mcp/tool-first" => {
            Some((CallTransport::Mcp, path.trim_start_matches('/').to_owned()))
        }
        "/ws" => Some((CallTransport::Ws, "ws.upgrade".to_owned())),
        _ => None,
    }
}

/// FIX 811's outer door, outside the binding door: a facade, MCP or WS
/// upgrade reply that reached no door's receipt (the binding door's or the
/// deleted vault's refusal, a request no credential authenticates) is
/// recorded for its connection and states the ref in
/// `x-oneiron-receipt-ref`. The server read none of its body, so its request
/// digest is of no bytes. An accepted WS upgrade is no call and records
/// nothing; neither does a request in an anonymous off-record session.
pub(crate) async fn connection_receipt(
    State(server): State<Arc<SyncServer>>,
    request: Request,
    next: Next,
) -> Response {
    let Some((transport, verb)) = receipted_door(request.uri().path()) else {
        return next.run(request).await;
    };
    let session = request_session_ref(request.headers()).map(str::to_owned);
    let mut response = next.run(request).await;
    let status = response.status();
    if response.extensions().get::<DoorAnswered>().is_some()
        || response.headers().contains_key(RECEIPT_REF_HEADER)
        || (transport == CallTransport::Ws && status == axum::http::StatusCode::SWITCHING_PROTOCOLS)
    {
        return response;
    }
    let anonymous = session.is_some_and(|session_ref| {
        server
            .vault()
            .off_record_session_is_anonymous_for(&session_ref, None)
    });
    let outcome = if status.is_success() {
        CallOutcome::Ok
    } else {
        CallOutcome::Refused {
            code: format!("HTTP_{}", status.as_u16()),
        }
    };
    let stamp = record(
        &server,
        anonymous,
        connection_call(
            transport,
            verb,
            outcome,
            oneiron::receipt::call_bytes_digest(&[]),
            None,
        ),
    );
    stamp.stamp_header(&mut response);
    response
}
