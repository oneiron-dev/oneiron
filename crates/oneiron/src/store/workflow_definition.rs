//! A saved ordered agent composition (`WORKFLOW` entities): its value, wire
//! codec and put admission. The agent definition layer (`agent_def`) saves,
//! updates and forks compositions; the store's batch put admission,
//! projections and document import validate, measure and decode them.
use crate::EntityId;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::error::{Error, Result};
use crate::limit_ask::{EngineLimit, LimitWatch};
use crate::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_WORKFLOW};
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
    name: String,
    steps: Vec<String>,
    revision: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    forked_from: Option<String>,
}
pub(crate) fn invalid() -> Error {
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
    fn validate(&self) -> Result<()> {
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

/// Shared by local puts, batch writes and replay. Replay permits late-arriving references;
/// dispatch always resolves the live definitions before enqueuing anything. Returns the
/// decoded definition the put measures.
pub(crate) fn validate_workflow_put(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    bytes: &[u8],
    replicated: bool,
) -> Result<WorkflowDefinition> {
    let definition = decode_workflow(bytes)?;
    if definition.forked_from == Some(*id) {
        return Err(invalid());
    }
    if !replicated {
        for step in &definition.steps {
            require_kind(store, txn, step, ENTITY_TYPE_AGENT_DEF)?;
        }
        if let Some(parent) = definition.forked_from {
            require_kind(store, txn, &parent, ENTITY_TYPE_WORKFLOW)?;
        }
        if let Some(prior) = crate::ports::EntityStoreRead::port_entity_raw(store, txn, id)? {
            let header = EntityMetadataHeader::parse(&prior).ok_or_else(invalid)?;
            if header.entity_type != ENTITY_TYPE_WORKFLOW {
                return Err(invalid());
            }
            let prior = decode_workflow(&prior[ENTITY_METADATA_HEADER_LEN..])?;
            if prior != definition
                && (definition.revision <= prior.revision
                    || definition.forked_from != prior.forked_from)
            {
                return Err(invalid());
            }
        }
    }
    Ok(definition)
}
/// An accepted composition is kept whole: past the `[limits]` `workflow_steps`
/// or `workflow_name_bytes` row it asks whether everything is okay (Rule 5).
/// Every workflow put measures here, local or replicated.
pub(crate) fn measure_workflow_limits(watch: &LimitWatch, definition: &WorkflowDefinition) {
    watch.measure(EngineLimit::WorkflowSteps, definition.steps.len() as u64);
    watch.measure(EngineLimit::WorkflowNameBytes, definition.name.len() as u64);
}
pub(crate) fn require_kind(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    kind: u8,
) -> Result<()> {
    match crate::vault::live_entity_row_in_txn(store, txn, id)? {
        crate::vault::LiveEntityRow::Live { entity_type, .. } if entity_type == kind => Ok(()),
        _ => Err(Error::EntityNotFound),
    }
}
