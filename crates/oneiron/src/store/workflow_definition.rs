//! Core half of `store::workflow_definition`: its store-layer items live in `oneiron_store::workflow_definition` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::workflow_definition::*;

use crate::EntityId;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::error::{Error, Result};
use crate::limit_ask::{EngineLimit, LimitWatch};
use crate::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_WORKFLOW};
use serde::{Deserialize, Serialize};

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
