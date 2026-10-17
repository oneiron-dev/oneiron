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

use axum::http::{HeaderMap, HeaderValue};
use axum::response::Response;
use oneiron::receipt::CallReceiptInput;
use serde_json::{Map, Value};

use crate::auth::CoreAuth;
use crate::server::SyncServer;

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

    /// Stamps `x-oneiron-receipt-ref` on a reply.
    pub(crate) fn stamp_header(&self, response: &mut Response) {
        if let Some(value) = self.header_value() {
            response.headers_mut().insert(RECEIPT_REF_HEADER, value);
        }
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

/// Whether `actor`'s request runs inside an anonymous off-record session it
/// is verified in: the session its `x-oneiron-session` header names is one
/// the live registry holds in `OffRecordMode::Anonymous`, and `actor` (the
/// request's own, the credential's bound principal) is on its room's roster
/// or is the actor who entered it alone
/// (`Vault::off_record_session_is_anonymous_for`, OF-063). A request bound
/// to no actor proves no one, so it records as anywhere else, but in a
/// stretch whose entering door named no actor. A session the registry
/// cannot be asked about counts as anonymous, so a call that might be one
/// records nothing. Each transport asks when the call arrives and again
/// when its receipt would be written: a caller verified at either time
/// writes none, so a session closed mid-call keeps its call's exception.
pub(crate) fn in_anonymous_session(
    server: &SyncServer,
    headers: &HeaderMap,
    actor: Option<oneiron::EntityId>,
) -> bool {
    request_session_ref(headers).is_some_and(|session_ref| {
        server
            .vault()
            .off_record_session_is_anonymous_for(session_ref, actor)
    })
}

/// The actor a facade request is attributed to, as an entity: the
/// credential's bound principal. `None` for a credential bound to none.
pub(crate) fn request_actor(auth: &CoreAuth) -> Option<oneiron::EntityId> {
    auth.principal_ref()
        .and_then(|principal| oneiron::EntityId::from_hex(principal).ok())
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

/// Writes one call's receipt, or states the anonymous exception without
/// writing. A row that cannot be written is logged and the reply carries no
/// ref: the call itself already happened.
pub(crate) fn record(server: &SyncServer, anonymous: bool, input: CallReceiptInput) -> CallStamp {
    if anonymous {
        return CallStamp::NoRecord;
    }
    match server.vault().record_call_receipt(input) {
        Ok(receipt_ref) => CallStamp::Recorded(receipt_ref),
        Err(error) => {
            tracing::warn!(%error, "call answered without its receipt");
            CallStamp::Unrecorded
        }
    }
}
