//! Shared names for caller credential headers on vault HTTP doors.

/// The header a slip's holder proof rides in.
pub const BINDING_HEADER: &str = "x-oneiron-binding";

/// The header an MCP connector names its credential in.
pub const MCP_CREDENTIAL_HEADER: &str = "x-oneiron-mcp-credential";
