//! Store-level (pre-vault) readers for the type-76 entity kind: the helpers the
//! batch write/materialize path and the fold projection share.

use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::registry::{ENTITY_TYPE_FACET, ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT, is_structural_kind};
use crate::store::Store;

use super::decode_identity_topology_event_body;
use super::ledger_fold::{IdentityTopologyEvent, IdentityTopologyFold};
use super::lifecycle_state::EntityLifecycleState;
use super::op_apply::IdentityTopologyParticipantValidation;
use super::op_vocabulary::IdentityTopologyOp;
use super::stored_event::{StoredIdentityOpAction, StoredIdentityOpEvent};
use super::transition_table::IdentityTopologyRejection;

const VALIDATED_EVENT_PREFIX: &[u8] = b"it:validated:";
const INVALID_ACTOR_EVENT_PREFIX: &[u8] = b"it:invalid_actor:";

fn validated_event_key(id: &EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(VALIDATED_EVENT_PREFIX.len() + 16);
    key.extend_from_slice(VALIDATED_EVENT_PREFIX);
    key.extend_from_slice(id.as_bytes());
    key
}

fn invalid_actor_event_key(id: &EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(INVALID_ACTOR_EVENT_PREFIX.len() + 16);
    key.extend_from_slice(INVALID_ACTOR_EVENT_PREFIX);
    key.extend_from_slice(id.as_bytes());
    key
}

pub(super) fn identity_event_actor_invalid_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    Ok(store
        .vault_meta
        .get(rtxn, &invalid_actor_event_key(id))?
        .is_some())
}

/// Record the local refusal separately from erasable personal attribution.
/// A valid author scrub cannot turn an event already invalid here into an
/// unattributed effective op after its actor row disappears.
pub(crate) fn mark_identity_event_actor_invalid_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    store
        .vault_meta
        .put(wtxn, &invalid_actor_event_key(id), &[])?;
    Ok(())
}

/// Decide BEFORE scrubbing whether the actor had actually passed validation
/// here. A producer stamp plus a *missing* author hard-delete marker may
/// retain already-authored history; a PRESENT wrong class cannot be excused
/// by that marker. The caller owns the write transaction and stamps a local
/// veto if this returns false.
pub(crate) fn actor_valid_before_author_scrub_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    event_id: &EntityId,
    record: &StoredIdentityOpEvent,
) -> Result<bool> {
    if record.invalidated {
        return Ok(false);
    }
    if identity_event_validated_in_txn(store, rtxn, event_id)? {
        return Ok(true);
    }
    let Some(actor) = record.actor else {
        return Ok(true);
    };
    if let Some(kind) =
        identity_topology_entity_type_for_store_in_txn(store, rtxn, &actor.entity_ref())?
    {
        return Ok(crate::provenance::validate_actor_class(kind, actor.actor_class()).is_ok());
    }
    Ok(record.validated_at_write
        && store
            .sync_state
            .get(
                rtxn,
                &crate::deletion::local_hard_delete_key(&actor.entity_ref()),
            )?
            .is_some())
}

pub(super) fn identity_event_validated_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    Ok(store
        .vault_meta
        .get(rtxn, &validated_event_key(id))?
        .is_some())
}

pub(super) fn mark_identity_event_validated_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    store.vault_meta.put(wtxn, &validated_event_key(id), &[])?;
    Ok(())
}

pub(crate) fn forget_identity_event_validation_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    store.vault_meta.delete(wtxn, &validated_event_key(id))?;
    store
        .vault_meta
        .delete(wtxn, &invalid_actor_event_key(id))?;
    Ok(())
}

/// Seal a replicated event only after all available references have passed
/// the same validation as admission. A missing actor/participant never earns
/// this witness merely because it later got a deletion marker.
pub(super) fn mark_complete_identity_events_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
) -> Result<()> {
    for event in identity_topology_events_for_store_in_txn(store, &*wtxn)? {
        if identity_event_validated_in_txn(store, wtxn, &event.event_id)?
            || identity_event_actor_invalid_in_txn(store, wtxn, &event.event_id)?
        {
            continue;
        }
        if let super::ledger_fold::IdentityTopologyAction::Apply(op) = &event.action
            && !matches!(
                validate_identity_op_participants_for_store_in_txn(store, wtxn, op)?,
                IdentityTopologyParticipantValidation::Complete
            )
        {
            continue;
        }
        let record = identity_topology_event_for_store_in_txn(store, wtxn, &event.event_id)?
            .ok_or(Error::CorruptedIndex("identity topology event index"))?;
        if record.invalidated {
            continue;
        }
        if let Some(actor) = record.actor {
            let Some(kind) =
                identity_topology_entity_type_for_store_in_txn(store, wtxn, &actor.entity_ref())?
            else {
                continue;
            };
            if crate::provenance::validate_actor_class(kind, actor.actor_class()).is_err() {
                continue;
            }
        }
        mark_identity_event_validated_in_txn(store, wtxn, &event.event_id)?;
    }
    Ok(())
}

/// A known-invalid applied event must never become valid merely because its
/// wrong-kind participant was erased. Record the non-personal refusal on the
/// canonical type-76 body BEFORE deindex removes the class witness. An
/// already-sealed, once-valid decision remains historical authority.
pub(crate) fn invalidate_identity_events_for_participant_delete_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let mut invalid = Vec::new();
    for event in identity_topology_events_for_store_in_txn(store, wtxn)? {
        if !matches!(
            event.approval,
            crate::claim::ClaimApprovalStatus::Auto | crate::claim::ClaimApprovalStatus::Approved
        ) || identity_event_validated_in_txn(store, wtxn, &event.event_id)?
        {
            continue;
        }
        let super::ledger_fold::IdentityTopologyAction::Apply(op) = event.action else {
            continue;
        };
        if !op.participants().contains(id)
            || !matches!(
                validate_identity_op_participants_for_store_in_txn(store, wtxn, &op)?,
                IdentityTopologyParticipantValidation::Invalid(_)
            )
        {
            continue;
        }
        let Some(raw) = store.entities.get(wtxn, event.event_id.as_bytes())? else {
            return Err(Error::CorruptedIndex("identity topology event index"));
        };
        if raw.len() < crate::batch::ENTITY_METADATA_HEADER_LEN {
            return Err(Error::CorruptedIndex("entity metadata"));
        }
        let mut record =
            decode_identity_topology_event_body(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..])
                .map_err(|_| Error::CorruptedIndex("identity topology event body"))?;
        if record.invalidated {
            continue;
        }
        record.invalidated = true;
        let mut bytes = raw[..crate::batch::ENTITY_METADATA_HEADER_LEN].to_vec();
        bytes.extend_from_slice(&super::encode_identity_topology_event_body(&record)?);
        invalid.push((event.event_id, bytes));
    }
    for (event_id, bytes) in invalid {
        crate::vault::entity_revision::remove_entity_revisions(store, wtxn, &event_id)?;
        store.entities.put(wtxn, event_id.as_bytes(), &bytes)?;
    }
    Ok(())
}

/// Generic batch deletion has no reason/tombstone/receipt transaction. Refuse
/// every active merge participant or author and every open proposal participant
/// before `deindex_entity` can remove a shell edge or silently strand a park.
pub(crate) fn guard_batch_identity_delete_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let effective =
        super::ledger_fold::fold_effective_identity_topology_events_for_store_in_txn(store, rtxn)?;
    let fold = super::ledger_fold::fold_identity_topology_log(&effective);
    // A deferred proposal is still an open proposal. It cannot appear in
    // the effective projection until its missing peer arrives, so read raw
    // records as well when deciding whether a generic delete may tear one.
    for event in identity_topology_events_for_store_in_txn(store, rtxn)? {
        let Some(record) = identity_topology_event_for_store_in_txn(store, rtxn, &event.event_id)?
        else {
            return Err(Error::CorruptedIndex("identity topology event index"));
        };
        if let StoredIdentityOpAction::Merge { sources, survivor } = &record.action
            && sources
                .iter()
                .any(|source| fold.current_event.get(source) == Some(&event.event_id))
            && (*id == *survivor
                || sources.contains(id)
                || record.actor.is_some_and(|actor| actor.entity_ref() == *id))
        {
            return Err(Error::Sync(
                crate::error::SyncError::IdentityTopologyRejected(
                    IdentityTopologyRejection::ActiveMergeParticipantDeletion { entity: *id },
                ),
            ));
        }
        if record.approval == crate::claim::ClaimApprovalStatus::Proposed
            && !fold.resolved_proposals.contains_key(&event.event_id)
            && !fold.moot_proposals.contains(&event.event_id)
            && let super::ledger_fold::IdentityTopologyAction::Apply(op) = event.action
            && matches!(
                op,
                IdentityTopologyOp::Merge(_) | IdentityTopologyOp::Split(_)
            )
            && op.participants().contains(id)
        {
            return Err(Error::Sync(
                crate::error::SyncError::IdentityTopologyRejected(
                    IdentityTopologyRejection::ActiveMergeParticipantDeletion { entity: *id },
                ),
            ));
        }
    }
    Ok(())
}

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
    let Some(raw) = store.port_entity_record(rtxn, id)? else {
        return Ok(None);
    };

    Ok(Some(raw.entity_type))
}

pub(super) fn identity_topology_event_for_store_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<StoredIdentityOpEvent>> {
    let Some(raw) = store.port_entity_record(rtxn, id)? else {
        return Ok(None);
    };

    if raw.entity_type != ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT {
        return Err(Error::InvalidEntityType(raw.entity_type));
    }
    decode_identity_topology_event_body(&raw.body)
        .map(Some)
        .map_err(|_| Error::CorruptedIndex("identity topology event body"))
}

pub(super) fn identity_topology_events_for_store_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
) -> Result<Vec<IdentityTopologyEvent>> {
    let mut events = Vec::new();
    for entry in store.port_entity_ids_by_type(rtxn, ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT, None)? {
        let event_id = entry?;
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
    if state == EntityLifecycleState::Active
        || store
            .sync_state
            .get(rtxn, &crate::deletion::local_hard_delete_key(entity))?
            .is_some()
    {
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
            if store
                .sync_state
                .get(rtxn, &crate::deletion::local_hard_delete_key(survivor))?
                .is_some()
            {
                Vec::new()
            } else {
                vec![(EdgeKind::MergedInto, *survivor, record.at)]
            }
        }
        (StoredIdentityOpAction::Split { heads, .. }, EntityLifecycleState::Split) => heads
            .iter()
            .map(|head| (EdgeKind::SplitInto, *head, record.at))
            .collect(),
        _ => return Err(Error::CorruptedIndex("identity topology fold")),
    })
}
