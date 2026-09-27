//! Host-side Linear GraphQL adapter for the engine's TASK ↔ issue mirror.
//!
//! Reads use a cursor-paged GraphQL query. Writes can ONLY run through an
//! injected outbound door. The door is responsible for authorization and a
//! durable, payload-bound operation-id receipt before it calls the HTTP client;
//! this crate never puts credentials in the engine or claims that a header alone
//! makes Linear mutations idempotent.

mod dispatch;
mod egress;
mod http;
mod journal;
mod source;

pub use dispatch::VaultLinearOutboundDoor;
pub use egress::{LinearHostEgress, LinearOutboundDoor};
pub use http::{GraphQlCall, GraphQlExecutor, GraphQlTransportError, HttpLinearClient};
pub use source::{LinearHostChangeSource, LinearTrackerConfig};

use oneiron::LinearSyncError;
use serde_json::Value;

fn invalid(message: &str) -> LinearSyncError {
    LinearSyncError::Transport(message.to_owned())
}

fn data<'a>(body: &'a Value, key: &str) -> Result<&'a Value, LinearSyncError> {
    if body
        .get("errors")
        .is_some_and(|errors| errors.as_array().is_none_or(|e| !e.is_empty()))
    {
        // Never echo provider bodies: they can contain foreign content or secrets.
        return Err(invalid("Linear GraphQL returned errors"));
    }
    body.get("data")
        .and_then(|data| data.get(key))
        .ok_or_else(|| invalid("Linear GraphQL response is missing data"))
}

fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str, LinearSyncError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("Linear GraphQL response has a missing field"))
}

#[cfg(test)]
mod tests;
