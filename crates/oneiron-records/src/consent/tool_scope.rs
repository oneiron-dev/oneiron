//! Moved from `crates/oneiron/src/consent/tool_scope.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_consent_state::consent::tool_scope::DataClass;
use serde::Deserialize;
use serde::Serialize;

/// One outbound tool call as the automated consent check sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScopedMcpCall<'a> {
    pub server: &'a str,
    pub tool: &'a str,
    pub payload_data_class: DataClass,
    pub resolved_endpoint: &'a str,
}

/// Owned call axes threaded through the Gate before any transport is chosen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedMcpCallContext {
    pub server: String,
    pub tool: String,
    pub payload_data_class: DataClass,
    pub resolved_endpoint: String,
}

impl ScopedMcpCallContext {
    #[must_use]
    pub fn as_call(&self) -> ScopedMcpCall<'_> {
        ScopedMcpCall {
            server: &self.server,
            tool: &self.tool,
            payload_data_class: self.payload_data_class,
            resolved_endpoint: &self.resolved_endpoint,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolGrantDataClass {
    Arguments,
    XMcpHeader,
}

impl ToolGrantDataClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Arguments => "arguments",
            Self::XMcpHeader => "x_mcp_header",
        }
    }

    pub fn valid_grant_set(classes: &[Self]) -> bool {
        matches!(
            classes,
            [Self::Arguments] | [Self::XMcpHeader] | [Self::Arguments, Self::XMcpHeader]
        )
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "arguments" => Some(Self::Arguments),
            "x_mcp_header" => Some(Self::XMcpHeader),
            _ => None,
        }
    }
}
