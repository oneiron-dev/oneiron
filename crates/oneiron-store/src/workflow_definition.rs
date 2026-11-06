//! A saved ordered agent composition (`WORKFLOW` entities): its value, wire
//! codec and put admission. The agent definition layer (`agent_def`) saves,
//! updates and forks compositions; the store's batch put admission,
//! projections and document import validate, measure and decode them.
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_base::registry::ENTITY_TYPE_AGENT_DEF;
use oneiron_base::registry::ENTITY_TYPE_WORKFLOW;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::limit_ask::EngineLimit;
use oneiron_contracts::limit_ask::LimitWatch;
use oneiron_contracts::record_layout::ENTITY_METADATA_HEADER_LEN;
use oneiron_contracts::record_layout::EntityMetadataHeader;
use serde::{Deserialize, Serialize};

/// An ordered list of agent definitions. Execution semantics remain code-mode composition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkflowDefinition {
    pub name: String,
    pub steps: Vec<EntityId>,
    pub revision: u64,
    pub forked_from: Option<EntityId>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireWorkflow {
    pub name: String,
    steps: Vec<String>,
    pub revision: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    forked_from: Option<String>,
}
pub fn invalid() -> Error {
    Error::InvalidConfig("invalid workflow definition".into())
}

impl WorkflowDefinition {
    pub fn new(name: impl Into<String>, steps: Vec<EntityId>) -> Result<Self> {
        let definition = Self {
            name: name.into(),
            steps,
            revision: 1,
            forked_from: None,
        };
        definition.validate()?;
        Ok(definition)
    }
    pub fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() || self.revision == 0 || self.steps.is_empty() {
            return Err(invalid());
        }
        Ok(())
    }
}

pub fn encode_workflow(definition: &WorkflowDefinition) -> Result<Vec<u8>> {
    definition.validate()?;
    rmp_serde::to_vec_named(&WireWorkflow {
        name: definition.name.clone(),
        steps: definition.steps.iter().map(EntityId::to_hex).collect(),
        revision: definition.revision,
        forked_from: definition.forked_from.map(|id| id.to_hex()),
    })
    .map_err(|_| invalid())
}
pub fn decode_workflow(bytes: &[u8]) -> Result<WorkflowDefinition> {
    let mut cursor = std::io::Cursor::new(bytes);
    let wire = WireWorkflow::deserialize(&mut rmp_serde::Deserializer::new(&mut cursor))
        .map_err(|_| invalid())?;
    if cursor.position() != bytes.len() as u64 {
        return Err(invalid());
    }
    let definition = WorkflowDefinition {
        name: wire.name,
        steps: wire
            .steps
            .iter()
            .map(|id| EntityId::from_hex(id))
            .collect::<Result<_>>()?,
        revision: wire.revision,
        forked_from: wire
            .forked_from
            .as_deref()
            .map(EntityId::from_hex)
            .transpose()?,
    };
    definition.validate()?;
    Ok(definition)
}

/// An accepted composition is kept whole: past the `[limits]` `workflow_steps`
/// or `workflow_name_bytes` row it asks whether everything is okay (Rule 5).
/// Every workflow put measures here, local or replicated.
pub fn measure_workflow_limits(watch: &LimitWatch, definition: &WorkflowDefinition) {
    watch.measure(EngineLimit::WorkflowSteps, definition.steps.len() as u64);
    watch.measure(EngineLimit::WorkflowNameBytes, definition.name.len() as u64);
}
