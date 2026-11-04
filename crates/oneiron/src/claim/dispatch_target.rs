use crate::entity_id::EntityId;

/// What a dispatch names: a stored AGENT_DEF row. Labels carry no authority —
/// actor identity at the gate is keyed on the entity id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentDispatchTarget {
    Custom(EntityId),
    /// Saved inert ordered composition; never an agent actor.
    Workflow(EntityId),
}

impl AgentDispatchTarget {
    /// Returns an agent identity only for an actual AGENT_DEF target.
    pub fn agent_definition_ref(&self) -> crate::error::Result<EntityId> {
        match self {
            Self::Custom(id) => Ok(*id),
            Self::Workflow(_) => Err(super::widen_record::invalid(
                "workflow is not an agent actor",
            )),
        }
    }
}
