//! Saved ordered agent compositions. Records are inert data, not a workflow language.
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::limit_ask::{EngineLimit, LimitWatch};
use crate::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_WORKFLOW};
use crate::{EntityId, TimeRange, Vault};
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
fn invalid() -> Error {
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
fn require_kind(
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

impl Vault {
    /// Save a composition through the same type-checked door as raw entity writes.
    pub fn save_workflow(
        &self,
        id: &EntityId,
        definition: &WorkflowDefinition,
        at: u64,
    ) -> Result<()> {
        self.put_entity(
            id,
            ENTITY_TYPE_WORKFLOW,
            TimeRange { start: at, end: at },
            at,
            &encode_workflow(definition)?,
        )
    }
    pub fn get_workflow(&self, id: &EntityId) -> Result<Option<WorkflowDefinition>> {
        let Some(raw) = self.get_raw(id)? else {
            return Ok(None);
        };
        if EntityMetadataHeader::parse(&raw)
            .is_none_or(|header| header.entity_type != ENTITY_TYPE_WORKFLOW)
        {
            return Err(invalid());
        }
        decode_workflow(&raw[ENTITY_METADATA_HEADER_LEN..]).map(Some)
    }
    /// Compare-and-swap protects concurrent editors. Fork identity is immutable.
    pub fn update_workflow(
        &self,
        id: &EntityId,
        expected_revision: u64,
        definition: &WorkflowDefinition,
        at: u64,
    ) -> Result<()> {
        let encoded = encode_workflow(definition)?;
        self.with_write_txn_grouped(|txn| {
            require_kind(&self.store, txn, id, ENTITY_TYPE_WORKFLOW)?;
            let prior = crate::ports::EntityStoreRead::port_entity_raw(&self.store, txn, id)?
                .ok_or(Error::EntityNotFound)?;
            let prior = decode_workflow(&prior[ENTITY_METADATA_HEADER_LEN..])?;
            if prior.revision != expected_revision || definition.revision <= expected_revision {
                return Err(invalid());
            }
            self.batch_in()
                .put(
                    id,
                    ENTITY_TYPE_WORKFLOW,
                    TimeRange { start: at, end: at },
                    at,
                    &encoded,
                )
                .apply(txn)
        })
    }
    /// Creates a composition as the authenticated owner. An occupied id is
    /// never an implicit edit, including another entity kind.
    pub fn create_workflow_as(
        &self,
        owner: &AuthenticatedOwner,
        id: &EntityId,
        definition: &WorkflowDefinition,
        at: u64,
    ) -> Result<()> {
        let encoded = encode_workflow(definition)?;
        self.with_write_txn_grouped(|txn| {
            owner.revalidate_as_vault_owner_in_txn(self, txn)?;
            if crate::ports::EntityStoreRead::port_entity_present(&self.store, txn, id)? {
                return Err(Error::ConcurrentWrite("workflow id is already occupied"));
            }
            self.batch_in()
                .put(
                    id,
                    ENTITY_TYPE_WORKFLOW,
                    TimeRange { start: at, end: at },
                    at,
                    &encoded,
                )
                .apply(txn)
        })
    }
    /// The owner's edit of exactly the revision they read. The next revision
    /// is assigned here; fork lineage stays the saved one.
    pub fn update_workflow_as(
        &self,
        owner: &AuthenticatedOwner,
        id: &EntityId,
        expected_revision: u64,
        name: &str,
        steps: Vec<EntityId>,
        at: u64,
    ) -> Result<WorkflowDefinition> {
        self.with_write_txn_grouped(|txn| {
            owner.revalidate_as_vault_owner_in_txn(self, txn)?;
            require_kind(&self.store, txn, id, ENTITY_TYPE_WORKFLOW)?;
            let prior = crate::ports::EntityStoreRead::port_entity_raw(&self.store, txn, id)?
                .ok_or(Error::EntityNotFound)?;
            let prior = decode_workflow(&prior[ENTITY_METADATA_HEADER_LEN..])?;
            if prior.revision != expected_revision {
                return Err(Error::ConcurrentWrite("workflow revision changed"));
            }
            let definition = WorkflowDefinition {
                name: name.to_owned(),
                steps,
                revision: expected_revision.checked_add(1).ok_or_else(invalid)?,
                forked_from: prior.forked_from,
            };
            self.batch_in()
                .put(
                    id,
                    ENTITY_TYPE_WORKFLOW,
                    TimeRange { start: at, end: at },
                    at,
                    &encode_workflow(&definition)?,
                )
                .apply(txn)?;
            Ok(definition)
        })
    }
    /// A fork is a new entity and keeps the source reference as lineage.
    pub fn fork_workflow(
        &self,
        parent: &EntityId,
        fork: &EntityId,
        at: u64,
    ) -> Result<WorkflowDefinition> {
        self.with_write_txn_grouped(|txn| {
            require_kind(&self.store, txn, parent, ENTITY_TYPE_WORKFLOW)?;
            if crate::ports::EntityStoreRead::port_entity_present(&self.store, txn, fork)? {
                return Err(invalid());
            }
            let raw = crate::ports::EntityStoreRead::port_entity_raw(&self.store, txn, parent)?
                .ok_or(Error::EntityNotFound)?;
            let mut definition = decode_workflow(&raw[ENTITY_METADATA_HEADER_LEN..])?;
            definition.revision = 1;
            definition.forked_from = Some(*parent);
            self.batch_in()
                .put(
                    fork,
                    ENTITY_TYPE_WORKFLOW,
                    TimeRange { start: at, end: at },
                    at,
                    &encode_workflow(&definition)?,
                )
                .apply(txn)?;
            Ok(definition)
        })
    }
    /// Every step of an accepted composition is kept; past the `[limits]`
    /// `workflow_steps` row it asks whether everything is okay (Rule 5).
    pub(crate) fn measure_workflow_steps(&self, definition: &WorkflowDefinition) {
        self.limit_watch()
            .measure(EngineLimit::WorkflowSteps, definition.steps.len() as u64);
    }
}

#[cfg(test)]
mod tests;
