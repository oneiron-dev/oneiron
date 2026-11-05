//! Saved ordered agent compositions. Records are inert data, not a workflow language.
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::limit_ask::EngineLimit;
use crate::registry::ENTITY_TYPE_WORKFLOW;
pub use crate::store::workflow_definition::{WorkflowDefinition, decode_workflow, encode_workflow};
use crate::store::workflow_definition::{invalid, require_kind};
use crate::{EntityId, TimeRange, Vault};

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
