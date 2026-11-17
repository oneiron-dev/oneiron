//! Native actor setup uses the same declared definition as the owner's door.

use crate::EntityId;
use crate::agent_def::{AgentCeiling, AgentDefinition, AgentScope};
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};

pub(super) fn shape_agent_definition(
    agent_id: &str,
    ceiling: AgentCeiling,
    enabled: bool,
    author: &EntityId,
) -> AgentDefinition {
    AgentDefinition::new(
        agent_id.to_owned(),
        "Declared by the vault's shape.",
        "1",
        None,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        AgentScope::All,
        ceiling,
        None,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        rmpv::Value::Map(vec![
            (
                rmpv::Value::from("author"),
                rmpv::Value::from(author.to_hex()),
            ),
            (
                rmpv::Value::from("definedVia"),
                rmpv::Value::from("vault_shape"),
            ),
        ]),
        None,
        enabled,
        None,
    )
}
