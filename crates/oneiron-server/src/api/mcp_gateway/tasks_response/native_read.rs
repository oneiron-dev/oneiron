//! The native memory read arm of one generated verb tool call.
//! `execute_mcp_native_read` is its call surface.

use super::{McpCallContext, McpCarrierPolicy, McpGatewayError, McpServed};
use crate::mcp::McpVerbToolArgs;
use crate::server::SyncServer;
use serde_json::Value;
use std::sync::Arc;

/// One native memory read tool call: one atomic native response, the rows
/// it served listed in `served`.
pub(super) async fn execute_mcp_native_read(
    server: &Arc<SyncServer>,
    args: &McpVerbToolArgs,
    actor: &McpCallContext,
    served: &mut McpServed,
) -> Result<
    (
        Value,
        crate::mcp::McpPageSource,
        McpCarrierPolicy,
        Option<u64>,
    ),
    McpGatewayError,
> {
    // The native read fan-out, on the heap (FIX 12072).
    let (output, capabilities, producers) =
        Box::pin(super::memory_response::execute(server, args, actor)).await?;
    served.extend(producers);
    // One native response, with its own bounded query/batch
    // semantics. Do not invent an MCP cursor over nested DTOs.
    Ok((
        output,
        crate::mcp::McpPageSource::complete(1),
        McpCarrierPolicy::DrainWithCapabilities(capabilities),
        None,
    ))
}
