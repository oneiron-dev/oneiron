//! Store-level (pre-vault) readers for the type-76 entity kind: the helpers the
//! batch write/materialize path and the fold projection share.

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::{ENTITY_TYPE_FACET, ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT, is_structural_kind};
use crate::store::Store;

use super::decode_identity_topology_event_body;
use super::ledger_fold::{IdentityTopologyEvent, IdentityTopologyFold};
use super::lifecycle_state::EntityLifecycleState;
use super::op_apply::IdentityTopologyParticipantValidation;
use super::op_vocabulary::IdentityTopologyOp;
use super::stored_event::{StoredIdentityOpAction, StoredIdentityOpEvent};
use super::transition_table::IdentityTopologyRejection;

pub(super) fn topology_edge_weight(kind: EdgeKind) -> Result<f32> {
    kind.default_weight().ok_or(Error::InvariantViolation(
        "identity topology edge missing default weight",
    ))
}

pub(super) fn identity_topology_entity_type_for_store_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<u8>> {
    let Some(raw) = store.entities.get(rtxn, id.as_bytes())? else {
        return Ok(None);
    };
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
    Ok(Some(header.entity_type))
}

pub(super) fn identity_topology_event_for_store_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<StoredIdentityOpEvent>> {
    let Some(raw) = store.entities.get(rtxn, id.as_bytes())? else {
        return Ok(None);
    };
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if header.entity_type != ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT {
        return Err(Error::InvalidEntityType(header.entity_type));
    }
    decode_identity_topology_event_body(&raw[ENTITY_METADATA_HEADER_LEN..])
        .map(Some)
        .map_err(|_| Error::CorruptedIndex("identity topology event body"))
}

pub(super) fn identity_topology_events_for_store_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
) -> Result<Vec<IdentityTopologyEvent>> {
    let mut events = Vec::new();
    for entry in store
        .type_index
        .prefix_iter(rtxn, &[ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT])?
    {
        let (key, _) = entry?;
        let event_id = crate::vault::entity_id_from_type_index_key(&key)?;
        let record = identity_topology_event_for_store_in_txn(store, rtxn, &event_id)?
            .ok_or(Error::CorruptedIndex("identity topology event index"))?;
        events.push(IdentityTopologyEvent {
            event_id,
            seq: record.seq,
            approval: record.approval,
            action: record.action.to_fold_action(),
        });
    }
    Ok(events)
}

pub(super) fn validate_identity_op_participants_for_store_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    op: &IdentityTopologyOp,
) -> Result<IdentityTopologyParticipantValidation> {
    let is_merge = matches!(op, IdentityTopologyOp::Merge(_));
    let mut validation = IdentityTopologyParticipantValidation::Complete;
    for participant in op.participants() {
        let Some(entity_type) =
            identity_topology_entity_type_for_store_in_txn(store, rtxn, &participant)?
        else {
            validation = IdentityTopologyParticipantValidation::Deferred;
            continue;
        };
        if !is_structural_kind(entity_type) {
            return Ok(IdentityTopologyParticipantValidation::Invalid(
                IdentityTopologyRejection::NotStructural {
                    entity: participant,
                },
            ));
        }
        if is_merge && entity_type == ENTITY_TYPE_FACET {
            return Ok(IdentityTopologyParticipantValidation::Invalid(
                IdentityTopologyRejection::FacetMerge {
                    entity: participant,
                },
            ));
        }
    }
    Ok(validation)
}

pub(super) fn identity_topology_actor_complete_for_store_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    record: &StoredIdentityOpEvent,
) -> Result<bool> {
    let Some(actor) = record.actor else {
        return Ok(true);
    };
    let Some(actor_type) =
        identity_topology_entity_type_for_store_in_txn(store, rtxn, &actor.entity_ref())?
    else {
        return Ok(false);
    };
    crate::provenance::validate_actor_class(actor_type, actor.actor_class())?;
    Ok(true)
}

pub(super) fn desired_shell_edges_for_store_entity_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    fold: &IdentityTopologyFold,
    entity: &EntityId,
) -> Result<Vec<(EdgeKind, EntityId, u64)>> {
    let state = fold
        .states
        .get(entity)
        .copied()
        .unwrap_or(EntityLifecycleState::Active);
    if state == EntityLifecycleState::Active {
        return Ok(Vec::new());
    }
    let event_id = fold
        .current_event
        .get(entity)
        .ok_or(Error::CorruptedIndex("identity topology fold"))?;
    let record = identity_topology_event_for_store_in_txn(store, rtxn, event_id)?
        .ok_or(Error::CorruptedIndex("identity topology event index"))?;
    Ok(match (&record.action, state) {
        (StoredIdentityOpAction::Merge { survivor, .. }, EntityLifecycleState::Merged) => {
            vec![(EdgeKind::MergedInto, *survivor, record.at)]
        }
        (StoredIdentityOpAction::Split { heads, .. }, EntityLifecycleState::Split) => heads
            .iter()
            .map(|head| (EdgeKind::SplitInto, *head, record.at))
            .collect(),
        _ => return Err(Error::CorruptedIndex("identity topology fold")),
    })
}
