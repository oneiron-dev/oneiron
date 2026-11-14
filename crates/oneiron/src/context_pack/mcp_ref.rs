//! MCP protocol reference to a context pack, plus its validation.
//!
//! Protocol boundary only: consumed by `oneiron-server`'s MCP surface, not by
//! pack assembly. Assembly lives in [`super::builder`].

use serde::{Deserialize, Serialize};

use crate::entity_id::EntityId;

#[doc(hidden)]
pub use oneiron_records::context_pack::mcp_ref::{
    MCP_CONTEXT_PACK_REF_SCHEMA_VERSION, McpContextPackRef, McpContextPackRefError,
};
#[doc(hidden)]
use oneiron_records::context_pack::mcp_ref::{
    validate_context_pack_result_id, validate_optional_context_pack_ref_field,
};
