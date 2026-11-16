//! MCP protocol reference to a context pack, plus its validation.
//!
//! Protocol boundary only: consumed by `oneiron-server`'s MCP surface, not by
//! pack assembly. Assembly lives in [`super::builder`].

#[doc(hidden)]
pub use oneiron_records::context_pack::mcp_ref::{
    MCP_CONTEXT_PACK_REF_SCHEMA_VERSION, McpContextPackRef, McpContextPackRefError,
};
