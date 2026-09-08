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

pub use self::codec::{decode_agent_definition, encode_agent_definition};
pub use self::types::{
    AGENT_DEF_BODY_KEYS, AGENT_DESC_MAX_BYTES, AGENT_ID_MAX_BYTES, AGENT_INSTRUCTIONS_MAX_BYTES,
    AGENT_MAX_LIST_ENTRIES, AGENT_MODEL_TIER_MAX_BYTES, AGENT_REF_KEY_MAX_BYTES,
    AGENT_VERSION_MAX_BYTES, AgentCeiling, AgentDefinition, AgentScope, CONTEXT_BUDGET_SPLIT_KEYS,
    CompactionOwnership, ContextBudgetSplit, MCP_REF_KEYS, MEMORY_PROFILE_KEYS, McpRef,
    MemoryProfile,
};

pub(crate) use self::codec::{
    legacy_logical_id_row, validate_agent_definition_bytes, validate_agent_definition_update,
};
pub(crate) use self::manifest::{seed_system_agent_definitions, validate_reserved_logical_id};
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

#[cfg(test)]
mod one_1698_tests {
    use crate::edge::EdgeActorClass;
    use crate::gate::PolicyApprovalCeiling;
    use crate::{VaultConfig, WriteActor};

    /// The `sys.default` row id, pinned by the canonical manifest. Constructed
    /// explicitly (with intent) because `test_util::entity` refuses
    /// production-pinned seed bytes.
    fn default_base_row_id() -> crate::EntityId {
        crate::EntityId::from_bytes([0xA6; 16]).expect("pinned seeded row id is non-reserved")
    }

    #[test]
    fn seeded_default_base_row_carries_its_own_ceiling() -> crate::Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::device());
        let (id, definition) = vault
            .get_seeded_agent_definition_by_logical_id("sys.default")?
            .expect("default base row is seeded");
        assert_eq!(id, default_base_row_id());
        assert_eq!(definition.agent_id, "sys.default");

        let rtxn = vault.store.env.read_txn()?;
        let ceiling = crate::gate::agent_definition_ceiling_for_actor(
            &vault.store,
            &rtxn,
            WriteActor::new(id, EdgeActorClass::Agent),
        );
        assert_eq!(ceiling, Some(PolicyApprovalCeiling::Auto));
        Ok(())
    }

    #[test]
    fn deleted_seeded_row_resolves_proposed() -> crate::Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::device());
        let id = default_base_row_id();
        vault.with_write_txn(|wtxn| {
            vault.store.entities.delete(wtxn, id.as_bytes())?;
            Ok(())
        })?;

        let rtxn = vault.store.env.read_txn()?;
        let ceiling = crate::gate::agent_definition_ceiling_for_actor(
            &vault.store,
            &rtxn,
            WriteActor::new(id, EdgeActorClass::Agent),
        );
        assert_eq!(ceiling, Some(PolicyApprovalCeiling::Proposed));
        Ok(())
    }
}
