//! The serve gate of a stale owner sign-in's held booking socket (FIX 5935).
//!
//! A managed vault's attested holder the vault no longer records as its live
//! owner books at the per-request doors (FIX 5327) and on `/mcp` (FIX 5934).
//! His held MCP socket carries the same calls and nothing more: the MCP
//! handshake, a `ping` and notifications, and a `tools/call` of one of the
//! generated booking verbs among the booking payer doors, resolved on the
//! endpoint the call names, never by an argument. Each call it admits is
//! judged again on its own by `/mcp`'s booking admission; any other message
//! ends the socket.

use serde_json::Value;

use crate::mcp::{McpEndpointTool, McpSurfaceMode};

/// The MCP handshake methods `/mcp` serves a stale owner sign-in's booking
/// caller (FIX 5934).
const BOOKING_SOCKET_HANDSHAKE: [&str; 4] = [
    "initialize",
    "notifications/initialized",
    "tools/list",
    "oneiron/wakes",
];

/// Whether a stale owner sign-in's booking socket carries `body`, one
/// JSON-RPC message for the MCP endpoint at `surface`: a handshake method,
/// a `ping` or a notification, which run no verb, or a `tools/call` of a
/// booking verb that endpoint registered. A batch, a message that is no
/// JSON object, an unknown endpoint and every other method or tool are
/// refused.
pub(crate) fn booking_socket_admits(surface: &str, body: &str) -> bool {
    let Ok(Value::Object(message)) = serde_json::from_str::<Value>(body) else {
        return false;
    };
    let Some(method) = message.get("method").and_then(Value::as_str) else {
        return false;
    };
    if method == "tools/call" {
        return booking_tool_call(surface, message.get("params"));
    }
    BOOKING_SOCKET_HANDSHAKE.contains(&method)
        || method == "ping"
        || method.starts_with("notifications/")
}

/// Whether `params` name a booking verb the endpoint at `surface`
/// registered as a tool.
fn booking_tool_call(surface: &str, params: Option<&Value>) -> bool {
    let mode = if surface == crate::cli::McpSurface::Primary.path() {
        McpSurfaceMode::Primary
    } else if surface == crate::cli::McpSurface::ToolFirst.path() {
        McpSurfaceMode::ToolFirst
    } else {
        return false;
    };
    let Some(name) = params
        .and_then(|params| params.get("name"))
        .and_then(Value::as_str)
    else {
        return false;
    };
    let Ok(registered) = crate::mcp::try_registered_surface(mode) else {
        return false;
    };
    let Some(McpEndpointTool::Verb(tool)) = registered.resolve(name) else {
        return false;
    };
    super::booking_payer_verbs().any(|verb| verb == tool.name)
}
