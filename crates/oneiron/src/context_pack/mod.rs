//! Context-pack assembly: retrieval results in, a hydrated, validated,
//! budget-clamped pack out.
//!
//! Directory module. This file carries declarations and re-exports only; each
//! sibling file owns one concern. `builder` is the hub that composes them.

mod builder;
mod edge_walk;
mod eiri_memory_board;
mod empty_pack;
mod hydration;
mod mcp_ref;
mod psych_mirror;
mod quarantine;
mod telemetry;
mod types;
mod validation;
mod world_partition;

#[cfg(test)]
mod tests;

pub use builder::{ContextPackBuilder, SerializedContextPack, UnfinalizedContextPack};
pub use eiri_memory_board::assemble_eiri_memory_board;
pub use empty_pack::{EmptyContext, EmptyReason, refresh_projected_empty_context};
pub use mcp_ref::{MCP_CONTEXT_PACK_REF_SCHEMA_VERSION, McpContextPackRef, McpContextPackRefError};
pub use psych_mirror::{
    PsychProfilePackSection, PsychProfilePackStaleReason, psych_mirror_source_candidate_from_claim,
    psych_mirror_source_candidate_from_context_entity, psych_profile_pack_section,
};
pub use types::{
    ContextEntity, ContextPack, ContextPackRetrievalBudget, DEFAULT_MAX_FIELD_CHARS,
    DEFAULT_MAX_NEIGHBORS, FieldProfile, MAX_CONTEXT_NEIGHBORS, MAX_EDGE_HOP, PackFormat,
    PackItemAccounting, PackItemAccountingReason, PackItemTokenStats, PackSectionTokenStats,
    PackStats, PackTokenStats, TokenAllocation,
};
pub use world_partition::WORLD_STALE_FIELD;
