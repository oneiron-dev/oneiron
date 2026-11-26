//! The folder an attached agent session runs in, as each MCP call names it
//! (RECALL-SESSION-PROJECT; Engine ANSWER RECALL-SESSION-PROJECT-INTENT, 26 Nov: Q1 = A, the
//! session's project is the default of a read that names none, never a wall; Q2 = A).
//!
//! The `oneiron mcp` bridge started with `--workspace <DIR>` names the folder's digests (its
//! own, then its main checkout's; never its path) in every `tools/call`'s
//! `_meta["oneiron/workspace"]`.
//! This endpoint keeps no session, so it reads them on every call, as it reads
//! `clientCapabilities`. The client names them, so they select a default and grant nothing: a
//! caller that names another folder, or forges a digest, only moves which project its own reads
//! default to, inside its credential's own ceiling, never past it (Q1 = A, selection never
//! grants). A read that names its projects (`project_refs`) reads those. A write never takes the
//! read default.

use serde_json::Value;

use super::{McpCallContext, McpToolCallParams};

/// The `_meta` key a `tools/call` names its session's folder under.
pub(crate) const MCP_WORKSPACE_META: &str = "oneiron/workspace";

/// The most folder digests a call names: the folder's own and its main checkout's.
const MAX_FOLDER_DIGESTS: usize = 2;

impl McpToolCallParams {
    /// The folder digests the call's `_meta["oneiron/workspace"].digests` names, each `blake3:`
    /// and 64 lower-case hex, in order; `None` when it names none, so the call reads with no
    /// session default.
    pub(super) fn session_workspace(&self) -> Option<Vec<String>> {
        let digests: Vec<String> = self
            .meta
            .as_ref()?
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
}

impl McpCallContext {
    /// This call's context for one verb row: a row that writes nothing, and whose arguments
    /// name no `project_refs`, reads the session folder's project by default; every other row
    /// reads as its arguments say, with no session default.
    #[must_use]
    pub(crate) fn for_verb_row(mut self, writes: bool, arguments: &Value) -> Self {
        let default = self
            .session_workspace
            .clone()
            .filter(|_| !writes && !names_project_refs(arguments));
        self.actor.auth = self
            .actor
            .auth
            .take()
            .map(|auth| auth.in_session_workspace(default));
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
