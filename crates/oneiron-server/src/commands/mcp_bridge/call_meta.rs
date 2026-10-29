//! What the bridge adds to a relayed `tools/call`'s `_meta`: the invocation
//! it runs under (ARCH-0080 §3), and the MCP client capabilities this stdio
//! session negotiated at its `initialize` (FIX 7969).
//!
//! The server's MCP endpoint keeps no session, so it reads a caller's
//! generated-UI surface profile from each call's `_meta.clientCapabilities`
//! (ARCH-0048 G3). The bridge is the session: it keeps the `capabilities` of
//! its client's last successful `initialize`, and names them on every call
//! that names none (CALLS "FIX 7969 re-initialize"). A successful
//! re-initialize replaces that selection, and a failed one keeps the last
//! good one. The bridge's own endpoint probe is no client handshake and
//! selects nothing. The capabilities select a rendering; they authenticate
//! no one.

use std::sync::{Mutex, PoisonError};

use serde_json::Value;

use super::INVOCATION_META;

/// The `_meta` key the server reads a call's client capabilities from.
const CLIENT_CAPABILITIES_META: &str = "clientCapabilities";

/// The body for a `tools/call` whose `_meta` names no invocation: the same
/// message with `invocation()` added there (a pending call's id, or a fresh
/// one). `None` sends the client's line as it wrote it: any other message, a
/// call that names its own, and a malformed one, which is the server's to
/// refuse.
pub(super) fn with_invocation(
    message: &mut Value,
    invocation: impl FnOnce() -> String,
) -> Option<Vec<u8>> {
    if message.get("method").and_then(Value::as_str) != Some("tools/call") {
        return None;
    }
    let meta = message
        .get_mut("params")?
        .as_object_mut()?
        .entry("_meta")
        .or_insert_with(|| Value::Object(serde_json::Map::new()))
        .as_object_mut()?;
    if meta.contains_key(INVOCATION_META) {
        return None;
    }
    meta.insert(INVOCATION_META.to_owned(), Value::String(invocation()));
    serde_json::to_vec(message).ok()
}

/// The client capabilities this stdio session negotiated.
#[derive(Default)]
pub(super) struct ClientSession {
    capabilities: Mutex<Option<Value>>,
}

impl ClientSession {
    /// For an `initialize` from the client, the `capabilities` it offers
    /// (`Some(None)` when it offers none); `None` for any other message.
    pub(super) fn offered(message: &Value) -> Option<Option<Value>> {
        (message.get("method").and_then(Value::as_str) == Some("initialize"))
            .then(|| message.pointer("/params/capabilities").cloned())
    }

    /// The server's answer to an `initialize` that offered `offered`: a
    /// result makes it this session's selection; an error keeps the last.
    pub(super) fn note_initialize(&self, offered: Option<Value>, answer: &Value) {
        if answer.get("result").is_some() {
            *self
                .capabilities
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = offered;
        }
    }

    /// Names this session's capabilities on a `tools/call` whose `_meta`
    /// names none. Returns whether `message` changed.
    pub(super) fn name_on_call(&self, message: &mut Value) -> bool {
        if message.get("method").and_then(Value::as_str) != Some("tools/call") {
            return false;
        }
        let Some(capabilities) = self
            .capabilities
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
        else {
            return false;
        };
        let Some(meta) = message
            .get_mut("params")
            .and_then(Value::as_object_mut)
            .map(|params| {
                params
                    .entry("_meta")
                    .or_insert_with(|| Value::Object(serde_json::Map::new()))
            })
            .and_then(Value::as_object_mut)
        else {
            return false;
        };
        if meta.contains_key(CLIENT_CAPABILITIES_META) {
            return false;
        }
        meta.insert(CLIENT_CAPABILITIES_META.to_owned(), capabilities);
        true
    }
}
