//! Same-operation TASK writer validation and its bound, read-only preview.

use super::{EFFECT_AUTHORIZED, EffectBinding, LinearEffectRequest, binding, effect};
use crate::Vault;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::gate::ExternalEffectGateInput;
use crate::linear_sync::{
    LinearEffectKind, LinearSyncDirection, LinearSyncError, linear_operation_id,
};
use crate::task_verb::linear_effect_state_in_txn;

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
    let (effect, digest, writer) = linear_effect_writer_view_in_txn(vault, txn, request)?;
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
                writer,
                scheduler: request.scheduler_actor,
                task: request.task_ref,
            },
        )?,
    }
    Ok(effect)
}

/// The read-only part of the native co-actor binding. The request is the
/// original operation; current TASK state only verifies it.
fn linear_effect_writer_view_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    request: &LinearEffectRequest,
) -> Result<
    (ExternalEffectGateInput, [u8; 32], EntityId),
    crate::outbound_intent_ledger::IntentLedgerError,
> {
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
    Ok((
        effect(writer.actor_ref, class, request),
        digest,
        writer.actor_ref,
    ))
}

/// Previews only an already bound native mirror operation for a question.
/// It validates the same current operation and writer as admission, without
/// creating a binding or spending or keeping a press.
pub(crate) fn linear_effect_writer_preview_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    request: &LinearEffectRequest,
) -> Result<Option<ExternalEffectGateInput>, crate::outbound_intent_ledger::IntentLedgerError> {
    use crate::outbound_intent_ledger::IntentLedgerError;
    let Some(kept) = EFFECT_AUTHORIZED.get(&vault.store, txn, &request.operation_id)? else {
        return Ok(None);
    };
    let (effect, digest, _) = linear_effect_writer_view_in_txn(vault, txn, request)?;
    if kept.digest != digest {
        return Err(IntentLedgerError::InvalidInput(
            "linear effect is not the current mirror operation",
        ));
    }
    Ok(Some(effect))
}
