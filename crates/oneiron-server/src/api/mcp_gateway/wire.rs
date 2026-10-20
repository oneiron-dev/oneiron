//! What an MCP request counts as on the wire (FIX 1085). A `tools/call` of a
//! registered tool counts once, under the caller the gateway resolved and the
//! tool's registered name; a reply refused with no tool call's receipt over
//! it counts under a fixed category and no caller. Observation only: nothing
//! here admits, refuses or changes a call, and a count that is not kept is
//! telemetry lost, never the call's.

use crate::mcp::{McpResolvedActor, McpSurfaceMode};
use crate::server::SyncServer;

/// The logical key a `tools/call` counts under, before the tool's registered
/// name: one key on either endpoint.
const TOOL_CALL: &str = "mcp:tools/call";

/// A body that is not JSON.
const PARSE_ERROR: &str = "parse_error";
/// A request object that does not decode, or names another JSON-RPC version.
const INVALID_REQUEST: &str = "invalid_request";
/// A method this endpoint does not serve.
const METHOD_NOT_FOUND: &str = "method_not_found";
/// A `tools/call` whose named invocation another request is running, or
/// which names another call.
const INVOCATION_REFUSED: &str = "invocation_refused";
/// A `tools/call` refused before a caller resolved for it.
const CALLER_REFUSED: &str = "caller_refused";
/// A handshake, listing, wake poll or notification refused.
const METHOD_REFUSED: &str = "method_refused";
/// A resolved caller's `tools/call` that names no tool this endpoint
/// registered, or no name at all.
const UNKNOWN_TOOL: &str = "unknown_tool";

/// Counts one `tools/call` under the caller resolved for it and the tool it
/// names, resolved against the registration validation reads, which admits
/// nothing here. An anonymous off-record session's call counts under its
/// caller and names no tool (OF-063); a name no tool is registered under
/// counts as an envelope error, under no caller.
pub(super) fn observe_tool_call(
    server: &SyncServer,
    mode: McpSurfaceMode,
    actor: &McpResolvedActor,
    name: &str,
    anonymous: bool,
) {
    let telemetry = &server.wire_telemetry;
    let now = oneiron_vault_contract::now_ts();
    let caller = actor.actor_ref.to_hex();
    let resolved = server
        .mcp_surface(mode)
        .ok()
        .and_then(|surface| surface.resolve(name));
    let _ = match resolved {
        None => telemetry.record_mcp_error(UNKNOWN_TOOL, now),
        Some(_) if anonymous => telemetry.record(TOOL_CALL, &caller, now),
        Some(tool) => {
            telemetry.record_mcp_call(&format!("{TOOL_CALL}:{}", tool.name()), &caller, now)
        }
    };
}

/// Counts one reply refused with no tool call's receipt over it, under the
/// fixed category its refusal and method fall in: never a method or tool
/// name a request sent, nor the refusal's message.
pub(super) fn observe_envelope_error(server: &SyncServer, method: &str, kind: &str) {
    let category = match kind {
        "parse_error" => PARSE_ERROR,
        "invalid_request" => INVALID_REQUEST,
        "method_not_found" => METHOD_NOT_FOUND,
        crate::api::facade::INVOCATION_IN_FLIGHT | crate::api::facade::INVOCATION_CONFLICT => {
            INVOCATION_REFUSED
        }
        _ if method == "tools/call" => CALLER_REFUSED,
        _ => METHOD_REFUSED,
    };
    let _ = server
        .wire_telemetry
        .record_mcp_error(category, oneiron_vault_contract::now_ts());
}
