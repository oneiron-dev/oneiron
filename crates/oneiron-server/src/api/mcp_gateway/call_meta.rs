//! What a `tools/call` names in its `_meta` beside its arguments: the
//! logical verb it runs (ARCH-0080 §3), and the hook pause it resumes (L13
//! PR-D, FIX 4283).

use oneiron::EntityId;
use oneiron::runtime_hooks::InvocationId;

use super::{McpGatewayError, McpToolCallParams};

/// The `_meta` key a `tools/call` names its invocation under: 32 hex digits.
pub(crate) const MCP_INVOCATION_META: &str = "oneiron/invocation";

/// The `_meta` key a `tools/call` names the hook pause it resumes under, by
/// the ask handle its Pending gave: 32 hex digits. A session-only call's
/// pause its session no longer holds then refuses, never running as a new
/// call; a call that names none is a new call.
pub(crate) const MCP_HOOK_ASK_META: &str = "hook_ask";

impl McpToolCallParams {
    /// The invocation the call names in `_meta`, if any.
    pub(super) fn invocation(&self) -> Result<Option<InvocationId>, McpGatewayError> {
        let Some(named) = self.named(MCP_INVOCATION_META) else {
            return Ok(None);
        };
        named
            .as_str()
            .and_then(InvocationId::parse_hex)
            .map(Some)
            .ok_or_else(|| {
                McpGatewayError::new(
                    -32602,
                    "tool_args_invalid",
                    "_meta.oneiron/invocation is 32 lowercase hex digits",
                )
                .with_field("_meta")
            })
    }

    /// The hook pause the call names in `_meta` as the one it resumes, if
    /// any.
    pub(super) fn hook_ask(&self) -> Result<Option<EntityId>, McpGatewayError> {
        let Some(named) = self.named(MCP_HOOK_ASK_META) else {
            return Ok(None);
        };
        named
            .as_str()
            .and_then(|ask| EntityId::from_hex(ask).ok())
            .map(Some)
            .ok_or_else(|| {
                McpGatewayError::new(
                    -32602,
                    "tool_args_invalid",
                    "_meta.hook_ask is the 32-hex ask handle a hook's Pending gave",
                )
                .with_field("_meta")
            })
    }

    fn named(&self, key: &str) -> Option<&serde_json::Value> {
        self.meta.as_ref().and_then(|meta| meta.get(key))
    }
}
