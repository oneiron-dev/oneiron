//! MCP tool-argument constants and the validated arguments the endpoint
//! decoder produces.

use super::endpoint_args::{McpExecuteCodeToolArgs, McpSetupToolArgs, McpVerbToolArgs};
use serde::Serialize;

pub const MCP_TOOL_ARGS_SCHEMA_VERSION: &str = "mcp_tool_args.v1";

pub(super) const MCP_SCHEMA_DRAFT: &str = "https://json-schema.org/draft/2020-12/schema";

pub(super) const ENTITY_ID_PATTERN: &str = "^[0-9a-f]{32}$";

/// Closed operation set of the booking agent API (BK-08), in the instructions
/// block's canonical order, so discovery and the OpenAPI operation index
/// advertise the four ops identically.
pub const MCP_BOOK_OPERATIONS: &[&str] = &["availability", "book", "reschedule", "cancel"];

/// The MCP server name this daemon announces.
///
/// One constant so the `initialize` handshake and the server axis a
/// scoped-MCP grant is checked against cannot drift apart.
pub const MCP_SERVER_NAME: &str = "oneiron";

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "tool", content = "args", rename_all = "snake_case")]
pub enum McpValidatedToolArgs {
    /// ONE-1704 primary endpoint: the one setup call.
    Setup(Box<McpSetupToolArgs>),
    /// ONE-1704 primary endpoint: the REPL against the same gated vault API.
    ExecuteCode(Box<McpExecuteCodeToolArgs>),
    /// ONE-1704 tool-first endpoint: one GENERATED tool per exported verb row.
    Verb(Box<McpVerbToolArgs>),
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum McpToolValidationError {
    #[error("{tool} args are not valid for the tool schema: {message}")]
    Decode { tool: &'static str, message: String },
    #[error("{tool}.{field}: {message}")]
    Field {
        tool: &'static str,
        field: &'static str,
        message: String,
    },
}

impl McpToolValidationError {
    pub(super) fn field(
        tool: &'static str,
        field: &'static str,
        message: impl Into<String>,
    ) -> Self {
        Self::Field {
            tool,
            field,
            message: message.into(),
        }
    }
}
