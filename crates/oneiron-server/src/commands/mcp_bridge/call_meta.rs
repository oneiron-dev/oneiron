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

/// The `_meta` key the server reads a call's session folder from (RECALL-SESSION-PROJECT).
pub(super) const WORKSPACE_META: &str = "oneiron/workspace";

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

/// The invocation `message`'s `_meta` names, if any.
pub(super) fn named_invocation(message: &Value) -> Option<String> {
    message
        .pointer("/params/_meta")
        .and_then(|meta| meta.get(INVOCATION_META))
        .and_then(Value::as_str)
        .map(str::to_owned)
}

/// The client capabilities this stdio session negotiated, and the folder it was started for.
#[derive(Default)]
pub(super) struct ClientSession {
    capabilities: Mutex<Option<Value>>,
    /// The session's folder (`--workspace`), as `{"digests": [...]}`: its folder digests, its
    /// own first, never its path (RECALL-SESSION-PROJECT). Named on every call, over any the
    /// client named, so the folder this bridge runs for is the one its reads default to, and on
    /// every `initialize`.
    workspace: Option<Value>,
}

impl ClientSession {
    /// A session started for the folder `workspace` names, or for none.
    pub(super) fn attached_to(
        workspace: Option<crate::workspace_identity::WorkspaceIdentity>,
    ) -> Self {
        Self {
            capabilities: Mutex::default(),
            workspace: workspace.map(|identity| serde_json::json!({ "digests": identity.digests })),
        }
    }

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

    /// Names this session's folder on an `initialize`, so the server's answer says whether a
    /// project is bound to it (RECALL-SESSION-PROJECT): the start hook's vault line gives the
    /// bind command when none is. Returns whether `message` changed.
    pub(super) fn name_on_initialize(&self, message: &mut Value) -> bool {
        if message.get("method").and_then(Value::as_str) != Some("initialize") {
            return false;
        }
        let Some(workspace) = &self.workspace else {
            return false;
        };
        let Some(meta) = meta_object(message) else {
            return false;
        };
        meta.insert(WORKSPACE_META.to_owned(), workspace.clone());
        true
    }

    /// Names this session's capabilities on a `tools/call` whose `_meta`
    /// names none, and its folder on every `tools/call`. Returns whether
    /// `message` changed.
    pub(super) fn name_on_call(&self, message: &mut Value) -> bool {
        if message.get("method").and_then(Value::as_str) != Some("tools/call") {
            return false;
        }
        let capabilities = self
            .capabilities
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if capabilities.is_none() && self.workspace.is_none() {
            return false;
        }
        let Some(meta) = meta_object(message) else {
            return false;
        };
        let mut changed = false;
        if let Some(workspace) = &self.workspace {
            meta.insert(WORKSPACE_META.to_owned(), workspace.clone());
            changed = true;
        }
        if let Some(capabilities) = capabilities
            && !meta.contains_key(CLIENT_CAPABILITIES_META)
        {
            meta.insert(CLIENT_CAPABILITIES_META.to_owned(), capabilities);
            changed = true;
        }
        changed
    }
}

/// The `_meta` object of `message`'s params, made when the params name none or name it `null`,
/// which the server reads as none, so what the bridge names always reaches the server. `None`
/// for params that are not an object, or a `_meta` that is neither an object nor `null`: that
/// call goes as the client wrote it, for the server to refuse.
fn meta_object(message: &mut Value) -> Option<&mut serde_json::Map<String, Value>> {
    let meta = message
        .get_mut("params")?
        .as_object_mut()?
        .entry("_meta")
        .or_insert(Value::Null);
    if meta.is_null() {
        *meta = Value::Object(serde_json::Map::new());
    }
    meta.as_object_mut()
}
