//! AGENT_DEF (`AgentDefinition`) entity — AGENT-1 (ONE-1443, OF-334).
//!
//! A saved, host-agnostic composition record: a set of skills, connectors,
//! code-mode MCPs, an optional model tier, a run scope, and an optional custom
//! prompt, carried alongside the shared `SkillRecord` lifecycle block. The body
//! is a hand-written pinned-key MessagePack map following the SKILL codec
//! discipline (strict: trailing bytes, non-string keys, unknown keys, and
//! duplicate keys are all rejected), so a host can never smuggle presentation
//! fields into the record. A stored definition is inert at rest: it references
//! skills/connectors/MCPs by id and grants nothing until a later dispatch layer
//! (AGENT-3) resolves and authorizes them.

mod codec;
mod decode;
mod doors;
mod manifest;
mod types;
pub mod workflow;

pub use self::codec::{decode_agent_definition, encode_agent_definition};
pub(crate) use self::doors::AgentAuthorLease;
pub use self::doors::AgentDefinitionPutDisposition;
pub use self::types::{
    AGENT_DEF_BODY_KEYS, AGENT_DESC_MAX_BYTES, AGENT_ID_MAX_BYTES, AGENT_INSTRUCTIONS_MAX_BYTES,
    AGENT_MAX_LIST_ENTRIES, AGENT_MODEL_TIER_MAX_BYTES, AGENT_REF_KEY_MAX_BYTES,
    AGENT_VERSION_MAX_BYTES, AgentCeiling, AgentDefinition, AgentScope, AgentWakeCadence,
    CONTEXT_BUDGET_SPLIT_KEYS, CompactionOwnership, ContextBudgetSplit, DreamingMode, MCP_REF_KEYS,
    MEMORY_PROFILE_KEYS, McpRef, MemoryProfile,
};

pub(crate) use self::codec::{
    legacy_logical_id_row, validate_agent_definition_bytes, validate_agent_definition_update,
};
pub(crate) use self::manifest::{
    seed_system_agent_definitions, system_export_identity, validate_reserved_logical_id,
};
pub(crate) use self::types::forked_from_row_ref;

// The flat agent_def.rs module used to provide these names to the sibling test
// module through `use super::*`: every agent_def-internal item the tests name
// bare, plus its own private crate/std import header. After the directory split
// the seam re-imports both so `tests.rs` resolves exactly as it did before.
#[cfg(test)]
use self::{manifest::*, types::*};
#[cfg(test)]
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::error::{Error, Result};
#[cfg(test)]
use crate::llm::ModelTierRef;
#[cfg(test)]
use crate::pipeline::WorldScope;
#[cfg(test)]
use crate::registry::ENTITY_TYPE_AGENT_DEF;
#[cfg(test)]
use crate::skill::SkillDependency;
#[cfg(test)]
use crate::temporal::TimeRange;
#[cfg(test)]
use rmpv::Value;

#[cfg(test)]
mod tests;

mod portable;
mod portable_binding;
pub(crate) use portable::{
    AgentSkillReference, agent_pack_files, resolve_agent_skill_refs, select_agent_knowledge,
};
pub(crate) use portable_binding::{
    agent_fork_hash_in_txn, bind_agent_birth_in_txn, import_agent_fork_hash_in_txn,
};

mod portable_source;
pub(crate) use portable_source::{
    birth_source_exportable, read_birth_source, validate_birth_source_put,
};

mod birth_custody;
mod birth_dependencies;
pub(crate) use birth_custody::{
    birth_custody_exists_in_txn, remove_birth_custody_in_txn, stage_birth_custody_put,
};
pub(crate) use birth_dependencies::{
    birth_carriers_for_erased_entity_in_txn, retire_birth_sources_for_entity_in_txn,
};
#[cfg(feature = "sync")]
pub(crate) use portable_source::{birth_source_holder, birth_source_matches_id};

pub(crate) use portable_source::{archived_birth_source_matches, birth_source_id};
