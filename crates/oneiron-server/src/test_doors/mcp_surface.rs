//! Door for `tests/mcp_surface_registration_latency.rs`: the MCP surface a
//! server serves, read through the accessor every request path uses.

use serde_json::Value;

use crate::mcp::{McpSurfaceConstructionError, McpSurfaceMode};
use crate::server::SyncServer;

/// The tool names `mode` serves on `server`, in listing order.
///
/// # Errors
///
/// The verb row that keeps `mode` from registering.
pub fn served_tool_names(
    server: &SyncServer,
    mode: McpSurfaceMode,
) -> Result<Vec<&'static str>, McpSurfaceConstructionError> {
    let surface = server.mcp_surface(mode)?;
    Ok(surface.tool_names())
}

/// The `tools/list` array `mode` serves on `server`.
///
/// # Errors
///
/// The verb row that keeps `mode` from registering.
pub fn served_listing(
    server: &SyncServer,
    mode: McpSurfaceMode,
) -> Result<Value, McpSurfaceConstructionError> {
    let surface = server.mcp_surface(mode)?;
    Ok(surface.listing().clone())
}
