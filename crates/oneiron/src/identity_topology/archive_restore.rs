//! The owner's restore of a whole-vault archive into a fresh vault decides
//! each merge and split the source held current again here
//! (RESTORE-KEEPS-MERGES-AND-SPLITS, Engine ANSWER 08:00 17 Nov = B).
//!
//! The export names those decisions in its manifest, read off the source's
//! effective fold ([`current_merge_and_split_events_in_txn`]): the archive's
//! raw type-76 rows alone cannot show which seal counted there, since an
//! engine seal counts by a local mark that never travels. The import reads
//! each named decision whole from the archive's rows
//! ([`archived_topology_decision`]) and applies it again through this
//! vault's own topology door ([`restored_merge_or_split`]), so it becomes a
//! new event of this vault, sealed by this install. The archived rows stay
//! archive data, and no archived seal or mark is trusted here.

use std::collections::BTreeSet;

use crate::claim::ClaimApprovalStatus;
use crate::entity_id::EntityId;
use crate::error::{Error, Result, SyncError};
use crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT;
use crate::vault::Vault;

use super::event_body_codec::decode_identity_topology_event_body;
use super::ledger_fold::{IdentityTopologyAction, fold_identity_topology_log};
use super::op_apply::IdentityOpWrite;
use super::op_vocabulary::IdentityTopologyOp;
use super::operation_parts::logical_identity_topology_event_with;
use super::stored_event::StoredIdentityOpEvent;
use super::wire_keys::{BODY_KEY_AMENDED, BODY_KEY_OPERATION_PAYLOAD};

/// The merge and split decisions this vault's effective ledger holds
/// current, sorted: each names a row still in its Merged or Split shell.
/// Undone, superseded, parked and refused decisions are not current, and a
/// facet moves no lifecycle state, so none of those is named.
pub(crate) fn current_merge_and_split_events_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
) -> Result<Vec<EntityId>> {
    let effective = vault.fold_effective_identity_topology_events_in_txn(rtxn)?;
    let current: BTreeSet<EntityId> = fold_identity_topology_log(&effective)
        .current_event
        .into_values()
        .collect();
    Ok(effective
        .into_iter()
        .filter(|event| {
            current.contains(&event.event_id)
                && matches!(
                    event.action,
                    IdentityTopologyAction::Apply(
                        IdentityTopologyOp::Merge(_) | IdentityTopologyOp::Split(_)
                    )
                )
        })
        .map(|event| event.event_id)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect())
}

/// The decision `id`, read whole from the rows `row` reads by id as (entity
/// type, body): its inline record, or its manifest assembled from every
/// part. `None` when a row is missing, of another type, or does not decode,
/// or a part does not add up to its manifest, as a store reader reads it.
pub(crate) fn archived_topology_decision(
    id: &EntityId,
    mut row: impl FnMut(&EntityId) -> Result<Option<(u8, Vec<u8>)>>,
) -> Result<Option<StoredIdentityOpEvent>> {
    let Some((entity_type, body)) = row(id)? else {
        return Ok(None);
    };
    if entity_type != ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT {
        return Ok(None);
    }
    let Ok(raw) = decode_identity_topology_event_body(&body) else {
        return Ok(None);
    };
    logical_identity_topology_event_with(id, raw, row)
}

/// The op and write that decide `decision` again here: an applied merge or
/// split with its own evidence and its read-through plan, under its
/// archived source, approval and confidence, with no bound actor (the
/// archived author stays archive data). `None` for any other decision.
#[must_use]
pub(crate) fn restored_merge_or_split(
    decision: &StoredIdentityOpEvent,
) -> Option<(IdentityTopologyOp, IdentityOpWrite)> {
    if !matches!(
        decision.approval,
        ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
    ) {
        return None;
    }
    let IdentityTopologyAction::Apply(mut op) = decision.action.to_fold_action() else {
        return None;
    };
    let evidence = decision.evidence.clone().unwrap_or_default();
    match &mut op {
        IdentityTopologyOp::Merge(merge) => merge.evidence = evidence,
        IdentityTopologyOp::Split(split) => split.evidence = evidence,
        _ => return None,
    }
    Some((
        op,
        IdentityOpWrite {
            source: decision.source,
            approval: decision.approval,
            confidence: decision.confidence,
            actor: None,
        },
    ))
}

/// Whether a byte slot named `key` in a type-76 body holds free bytes (an
/// operation part's slice of a larger record, an amended body) rather than a
/// typed id, reassignment item or digest. An export without secrets keeps
/// only the typed slots of a body the codec decodes whole.
#[must_use]
pub(crate) fn is_free_byte_slot(key: &str) -> bool {
    key == BODY_KEY_OPERATION_PAYLOAD || key == BODY_KEY_AMENDED
}

/// Whether `error` is the topology door refusing a decision here (a
/// participant missing, reserved for deletion or in a state the op cannot
/// move, the embedded owner retired) rather than a fault of this vault.
#[must_use]
pub(crate) fn is_topology_refusal(error: &Error) -> bool {
    matches!(
        error,
        Error::EntityNotFound
            | Error::Sync(
                SyncError::IdentityTopologyRejected(_)
                    | SyncError::InvalidIdentityTopologyEventBody(_)
            )
    )
}
