//! The authorized binding's transactional operations: the hard-erase scrub
//! and the served-dispatch writer check.

use super::*;

/// Drops authorization bindings that positively name the hard-erased id.
/// A malformed row names nothing and is left for the damage report.
///
/// # Errors
/// A storage failure.
pub(crate) fn erase_effect_authorized_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> crate::error::Result<()> {
    let mut dropped = Vec::<[u8; 32]>::new();
    for row in EFFECT_AUTHORIZED.iter_raw_from(&vault.store, wtxn, &[])? {
        let (key, value) = row?;
        let Ok(binding) = EFFECT_AUTHORIZED.decode_value(&value) else {
            continue;
        };
        if (binding.writer == *actor || binding.scheduler == *actor || binding.task == *actor)
            && let Ok(operation_id) = <[u8; 32]>::try_from(&key[..])
        {
            dropped.push(operation_id);
        }
    }
    for operation_id in dropped {
        EFFECT_AUTHORIZED.delete(&vault.store, wtxn, &operation_id)?;
    }
    Ok(())
}

/// The co-actor binding a served Linear dispatch is admitted with (OF-427),
/// read under the outbound admission writer: `request` must still be the
/// exact mirror operation of the TASK's current dirty revision, under the
/// same frozen operation binding [`Vault::authorize_linear_effect`] keeps,
/// and the revision must have a verified writer. Returns that writer's gate
/// input; the scheduler is the dispatch's own actor.
pub(crate) fn linear_effect_writer_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    request: &LinearEffectRequest,
) -> Result<ExternalEffectGateInput, crate::outbound_intent_ledger::IntentLedgerError> {
    use crate::outbound_intent_ledger::IntentLedgerError;
    let refused =
        || IntentLedgerError::InvalidInput("linear effect is not the current mirror operation");
    let linear = |error: LinearSyncError| match error {
        LinearSyncError::Store(error) => IntentLedgerError::from(error),
        _ => refused(),
    };
    let issue_id = request.issue.as_ref().map(|issue| issue.issue_id.as_str());
    if request.operation_id == [0; 32]
        || (request.kind == LinearEffectKind::Create) != request.issue.is_none()
        || issue_id.is_some_and(|id| id.trim().is_empty())
    {
        return Err(refused());
    }
    let state = linear_effect_state_in_txn(vault, txn, request.task_ref).map_err(linear)?;
    let expected = linear_operation_id(
        LinearSyncDirection::TaskToIssue,
        request.task_ref,
        state.revision,
        issue_id,
        None,
        None,
    );
    let link_matches = match (&state.link, &request.issue) {
        (None, None) => true,
        (Some(link), Some(issue)) => {
            link.issue.issue_id == issue.issue_id && link.issue.team_id == issue.team_id
        }
        _ => false,
    };
    if !link_matches
        || state.dirty_revision != Some(state.revision)
        || state.snapshot.revision != state.revision
        || state.snapshot.fields != request.fields
        || expected != request.operation_id
    {
        return Err(refused());
    }
    let writer = state.writer.ok_or_else(refused)?;
    let class = EdgeActorClass::try_from_u8(writer.actor_class).ok_or_else(refused)?;
    for (id, actor_class) in [
        (request.scheduler_actor, EdgeActorClass::System),
        (writer.actor_ref, class),
    ] {
        let entity_type = vault
            .get_entity_type_in_txn(txn, &id)?
            .ok_or(IntentLedgerError::InvalidBoundActor)?;
        crate::provenance::validate_actor_class(entity_type, actor_class)?;
    }
    let digest = binding(request, writer.actor_ref).map_err(linear)?;
    let bound = EFFECT_AUTHORIZED
        .get(&vault.store, txn, &request.operation_id)?
        .map(|kept| kept.digest == digest);
    match bound {
        Some(false) => return Err(refused()),
        Some(true) => {}
        None => EFFECT_AUTHORIZED.put(
            &vault.store,
            txn,
            &request.operation_id,
            &EffectBinding {
                digest,
                writer: writer.actor_ref,
                scheduler: request.scheduler_actor,
                task: request.task_ref,
            },
        )?,
    }
    Ok(effect(writer.actor_ref, class, request))
}
