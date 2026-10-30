//! FIX 6823 (Engine 09:39 ruling A): the recorded outbound door's live
//! recheck of a retried Linear send reads the press the door's own admission
//! kept, so the person is never asked twice.
//!
//! The door asks its scheduler over its own `LinearDispatch` effect (its
//! dispatch request, the door verb, the frozen payload) and keeps that
//! press beside its ledger row. The recheck asked the scheduler again over
//! the direct admission's `LinearMirror` effect, a second digest for the same
//! send. It now evaluates the scheduler over the door's own effect, with the
//! press that row kept, or the person's unspent press on that same digest,
//! read and never spent here: the door's own admission spends it. The
//! writer's ask is one effect on both paths and keeps its kept press as
//! before.

use crate::Vault;
use crate::gate::ExternalEffectGateInput;
use crate::linear_sync::{
    LinearEffectHold, LinearEffectRequest, LinearSyncError, LinearSyncResult,
};
use crate::outbound::{OutboundDispatchError, OutboundDispatchRequest};
use crate::outbound_intent_ledger::{AdmittedApproval, IntentId};

/// The door's scheduler ask on a send it already admitted: its own gate
/// input and its ledger row.
pub(super) struct DoorScheduler {
    pub(super) effect: ExternalEffectGateInput,
    intent_id: IntentId,
}

/// The door's scheduler ask on `effect` as `door_request` dispatches it, when
/// the door's ledger already holds a row for that send; `None` when it holds
/// none: the send's first admission runs inside the door, which asks and
/// binds both actors itself.
///
/// # Errors
/// The request's own refusal at preparation (an engine failure as
/// [`LinearSyncError::Store`], any other as [`LinearSyncError::Transport`]),
/// or a ledger row that does not read.
pub(super) fn door_scheduler(
    vault: &Vault,
    effect: &LinearEffectRequest,
    door_request: &OutboundDispatchRequest,
) -> LinearSyncResult<Option<DoorScheduler>> {
    let mut request = door_request.clone();
    request.linear_mirror = Some(effect.clone());
    let attempt_id = crate::outbound::outbound_dispatch_attempt_id(
        request
            .ledger_identity_ref
            .as_deref()
            .unwrap_or(&request.intent_ref),
    )
    .map_err(door_error)?;
    let record = {
        let txn = vault.store.custody_snapshot()?;
        crate::outbound_intent_ledger::read_intent_for_attempt_in_txn(vault, &txn, attempt_id, 0)
            .map_err(|error| door_error(error.into()))?
    };
    let Some(record) = record else {
        return Ok(None);
    };
    Ok(Some(DoorScheduler {
        effect: crate::outbound::outbound_gate_effect(vault, &request).map_err(door_error)?,
        intent_id: record.id,
    }))
}

/// The scheduler's press the recheck reads for `door`: the one the door's
/// admission kept beside its row, else the person's still unspent press on
/// the door's own digest, as a proof that spends nothing. `None` leaves the
/// scheduler's live grants to decide.
pub(super) fn kept_door_press_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    door: &DoorScheduler,
) -> Option<AdmittedApproval> {
    crate::outbound_intent_ledger::pinned_retry_approval(vault, txn, door.intent_id, &door.effect)
        .or_else(|| {
            let digest = crate::gate::external_effect_approval_digest(&door.effect)?;
            crate::consent::approve_once_authorization_in_txn(&vault.store, txn, &digest)
                .ok()
                .flatten()
                .map(|_| AdmittedApproval::from_gate(door.intent_id, digest))
        })
}

/// A recheck's hold as the door returns it (FIX 6824): typed with its digest
/// while the Gate holds it for a press, else refused as before.
pub(super) fn hold_error(hold: LinearEffectHold) -> LinearSyncError {
    match hold.approval_digest {
        Some(approval_digest) => LinearSyncError::Held {
            role: hold.role,
            actor: hold.actor,
            gate_decision_ref: hold.gate_decision_ref,
            approval_digest,
        },
        None => LinearSyncError::AuthorizationDenied,
    }
}

fn door_error(error: OutboundDispatchError) -> LinearSyncError {
    match error {
        OutboundDispatchError::Engine(error) => LinearSyncError::Store(error),
        other => LinearSyncError::Transport(other.to_string()),
    }
}
