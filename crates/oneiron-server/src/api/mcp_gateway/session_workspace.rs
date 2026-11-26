//! The folder an attached agent session runs in, as each MCP call names it
//! (RECALL-SESSION-PROJECT; Engine ANSWER RECALL-SESSION-PROJECT-INTENT, 26 Nov: Q1 = A, the
//! session's project is the default of a read that names none, never a wall; Q2 = A).
//!
//! The `oneiron mcp` bridge started with `--workspace <DIR>` names the folder's digests (its
//! own, then its main checkout's; never its path) in every `tools/call`'s
//! `_meta["oneiron/workspace"]`. The vault keys each digest with its store id before it looks
//! the binding up. A binding is a choice about the install that holds it: another machine of the
//! vault never receives it, and a restore drops it, so on a replica, and after a restore, the
//! folder reads as unbound, and the start hook's vault line gives the bind command (Q2 = A).
//!
//! This endpoint keeps no session, so it reads them on every call, as it reads
//! `clientCapabilities`. The bridge names them on `initialize` too, and the answer says under
//! the same `_meta` key whether a project is bound to the folder (`project_bound`), so the
//! start hook's vault line gives the bind command when none is, with no recall (Q2 = A). The client names them, so they select a default and grant nothing: a
//! caller that names another folder, or forges a digest, only moves which project its own reads
//! default to, inside its credential's own ceiling, never past it (Q1 = A, selection never
//! grants). A read that names its projects (`project_refs`) reads those. A write never takes the
//! read default: a claim it writes that names no project is placed in the folder's project
//! instead, and one that names its project lands there.

use serde_json::{Map, Value, json};

use super::{McpCallContext, McpToolCallParams};
use crate::auth::SessionWorkspace;
use crate::server::SyncServer;

/// The `_meta` key a `tools/call` names its session's folder under.
pub(crate) const MCP_WORKSPACE_META: &str = "oneiron/workspace";

/// The most folder digests a call names: the folder's own and its main checkout's.
const MAX_FOLDER_DIGESTS: usize = 2;

impl McpToolCallParams {
    /// The folder digests the call's `_meta["oneiron/workspace"].digests` names
    /// ([`folder_digests`]); `None` when it names none, so the call reads with no session
    /// default.
    pub(super) fn session_workspace(&self) -> Option<Vec<String>> {
        folder_digests(self.meta.as_ref()?)
    }
}

/// The folder digests a request's `_meta["oneiron/workspace"].digests` names, each `blake3:`
/// and 64 lower-case hex, in order; `None` when it names none.
fn folder_digests(meta: &Map<String, Value>) -> Option<Vec<String>> {
    let digests: Vec<String> = meta
        .get(MCP_WORKSPACE_META)?
        .get("digests")?
        .as_array()?
        .iter()
        .filter_map(Value::as_str)
        .filter(|digest| oneiron::session_project::is_digest_text(digest))
        .take(MAX_FOLDER_DIGESTS)
        .map(str::to_owned)
        .collect();
    (!digests.is_empty()).then_some(digests)
}

/// What `initialize` answers in its result's `_meta` about the folder its own
/// `_meta["oneiron/workspace"]` names: `{"oneiron/workspace": {"project_bound": true}}` when a
/// live PROJECT is bound to it, else `project_bound` false with the reason code
/// `no_project_bound`, so the start hook's vault line gives the bind command (Q2 = A). It names
/// no project: a session learns the project it reads from its reads' receipts. `None` when the
/// request names no folder, or when the binding does not read: the handshake never fails for it.
pub(super) fn initialize_meta(server: &SyncServer, params: Option<&Value>) -> Option<Value> {
    let digests = folder_digests(params?.get("_meta")?.as_object()?)?;
    let folder = match server.vault().workspace_project(&digests).ok()? {
        Some(_) => json!({ "project_bound": true }),
        None => json!({
            "project_bound": false,
            "reason": oneiron::session_project::NO_PROJECT_BOUND_AXIS,
        }),
    };
    Some(json!({ MCP_WORKSPACE_META: folder }))
}

impl McpCallContext {
    /// This call's context for one verb row: a row that writes places a claim that names no
    /// project in the session folder's project; a row that writes nothing, and whose arguments
    /// name no `project_refs`, reads the session folder's project by default; a read that names
    /// its projects reads as its arguments say, with no session default.
    #[must_use]
    pub(crate) fn for_verb_row(mut self, writes: bool, arguments: &Value) -> Self {
        let default = self.session_workspace.clone().and_then(|folder_digests| {
            if writes {
                Some(SessionWorkspace::Writes(folder_digests))
            } else if names_project_refs(arguments) {
                None
            } else {
                Some(SessionWorkspace::Reads(folder_digests))
            }
        });
        self.actor.auth = self
            .actor
            .auth
            .take()
            .map(|auth| auth.in_session_workspace(default));
        self
    }
}

impl McpCallContext {
    /// This call's context for a row that is not a verb row (setup, `execute_code`, a run's
    /// result, an app action): no session default on the call itself. `execute_code` binds
    /// each guest verb as its own row.
    #[must_use]
    pub(crate) fn for_non_verb_row(mut self) -> Self {
        self.actor.auth = self
            .actor
            .auth
            .take()
            .map(|auth| auth.in_session_workspace(None));
        self
    }
}

/// Whether `arguments` name a project anywhere: a non-empty `project_refs` list at any depth
/// (`vault.recall`'s `spec.scope.project_refs`, the filtered claim reads' `project_refs`).
fn names_project_refs(arguments: &Value) -> bool {
    match arguments {
        Value::Object(fields) => fields.iter().any(|(key, value)| {
            (key == "project_refs" && value.as_array().is_some_and(|refs| !refs.is_empty()))
                || names_project_refs(value)
        }),
        Value::Array(items) => items.iter().any(names_project_refs),
        _ => false,
    }
}
