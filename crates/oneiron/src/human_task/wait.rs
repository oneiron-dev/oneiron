//! C9 wait binding, identity-checked response signalling and release.

use rmpv::Value;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::llm::{DREAMER_TRAP_PREDICATE, DreamerTrapKind, TrapRef, send_trap_signal};

use super::model::{HumanResponseSignal, HumanTaskError, HumanTaskResult, HumanTaskWaitBinding};
use super::storage::{
    WAIT_BINDINGS, WAIT_SIGNALS, put_wait_binding_in_txn, put_wait_signal_marker_in_txn,
    wait_signal_marker,
};

// ── C9 wait binding + identity-bound response signal ────────────────────────

/// Binds one parked step to the person expected to answer it.
///
/// The binding lands BEFORE the trap is registered as waiting, deliberately: a
/// crash in between leaves a locatable binding on a `created` trap, which the
/// signal path still accepts (signal-before-wait), whereas the reverse order
/// would leave a waiting trap nothing could find.
pub fn bind_human_wait(
    vault: &Vault,
    task_ref: EntityId,
    responder_ref: EntityId,
    trap: &TrapRef,
) -> HumanTaskResult<HumanTaskWaitBinding> {
    if trap.kind != DreamerTrapKind::HumanResponse {
        return Err(HumanTaskError::UnboundResponse);
    }
    let binding = HumanTaskWaitBinding {
        task_ref,
        responder_ref,
        trap_claim_id: trap.trap_claim_id,
        step_hash: trap.step_hash,
        is_active: true,
    };
    vault.with_write_txn_grouped(|wtxn| put_wait_binding_in_txn(vault, wtxn, &binding))?;
    Ok(binding)
}

/// An active wait binding for one TASK, if a step on this device is parked on
/// it: the first by trap when several workflows wait on the same TASK, each
/// of which [`human_wait_bindings`] lists.
pub fn human_wait_binding(
    vault: &Vault,
    task_ref: EntityId,
) -> Result<Option<HumanTaskWaitBinding>> {
    Ok(human_wait_bindings(vault, task_ref)?.into_iter().next())
}

/// Every active wait binding for one TASK, one per parked trap (FIX 9867): a
/// second trap bound to the same TASK keeps the first one's binding.
pub fn human_wait_bindings(vault: &Vault, task_ref: EntityId) -> Result<Vec<HumanTaskWaitBinding>> {
    Ok(stored_wait_bindings(vault, task_ref)?
        .into_iter()
        .filter(|binding| binding.is_active)
        .collect())
}

/// The first stored binding for one TASK, active or retired.
pub(super) fn stored_human_wait_binding(
    vault: &Vault,
    task_ref: EntityId,
) -> Result<Option<HumanTaskWaitBinding>> {
    Ok(stored_wait_bindings(vault, task_ref)?.into_iter().next())
}

/// Every stored binding for one TASK, in trap order.
fn stored_wait_bindings(vault: &Vault, task_ref: EntityId) -> Result<Vec<HumanTaskWaitBinding>> {
    let rtxn = vault.store.env.read_txn()?;
    WAIT_BINDINGS
        .iter_from(&vault.store, &rtxn, task_ref.as_bytes())?
        .map(|row| row.map(|(_, binding)| binding))
        .collect()
}

/// The stored binding of one trap on one TASK, active or retired.
fn stored_wait_binding_for(
    vault: &Vault,
    task_ref: EntityId,
    trap_claim_id: EntityId,
) -> Result<Option<HumanTaskWaitBinding>> {
    let rtxn = vault.store.env.read_txn()?;
    WAIT_BINDINGS.get(&vault.store, &rtxn, &(task_ref, trap_claim_id))
}

/// Sends the resume signal for one identity-stamped human response.
///
/// Every mismatch is refused without touching the trap: a response from the
/// wrong actor, for a different task, or against a stale step hash signals
/// nothing. Re-delivery of the SAME response returns the first signal instead
/// of re-driving the state machine; `consume_trap_signal` remains the atomic
/// consume/resume door, so the parked attempt resumes exactly once.
pub fn signal_human_response(
    vault: &Vault,
    binding: &HumanTaskWaitBinding,
    caller_identity: EntityId,
    signal: &HumanResponseSignal,
) -> HumanTaskResult<EntityId> {
    // The caller-supplied binding is a convenience handle; the DEVICE-LOCAL row
    // is the authority, so a forged, inactive, or stale binding cannot signal.
    let stored = stored_wait_binding_for(vault, binding.task_ref, binding.trap_claim_id)?
        .ok_or(HumanTaskError::UnboundResponse)?;
    if !stored.is_active || !binding.is_active || stored != *binding {
        return Err(HumanTaskError::UnboundResponse);
    }
    // `signal.responder_ref` is payload. Only the independently authenticated
    // caller identity is an authority, and both must name the persisted responder.
    if caller_identity != stored.responder_ref
        || signal.responder_ref != caller_identity
        || signal.task_ref != stored.task_ref
    {
        return Err(HumanTaskError::UnboundResponse);
    }
    require_persisted_human_response_trap(vault, &stored)?;
    if let Some((signal_ref, surface_event_ref)) = wait_signal_marker(vault, stored.trap_claim_id)?
    {
        if surface_event_ref == signal.surface_event_ref {
            return Ok(signal_ref);
        }
        // A DIFFERENT event arriving after the trap already signalled has
        // nothing left to wake.
        return Err(HumanTaskError::UnboundResponse);
    }
    let signal_ref = send_trap_signal(
        vault,
        &stored.trap_claim_id,
        stored.step_hash,
        signal.occurred_at,
    )?;
    vault.with_write_txn_grouped(|wtxn| {
        put_wait_signal_marker_in_txn(
            vault,
            wtxn,
            stored.trap_claim_id,
            signal_ref,
            signal.surface_event_ref,
        )
    })?;
    Ok(signal_ref)
}

fn require_persisted_human_response_trap(
    vault: &Vault,
    binding: &HumanTaskWaitBinding,
) -> HumanTaskResult<()> {
    let body = vault
        .get_claim(&binding.trap_claim_id)?
        .ok_or(HumanTaskError::UnboundResponse)?;
    if body.predicate != DREAMER_TRAP_PREDICATE {
        return Err(HumanTaskError::UnboundResponse);
    }
    let Value::Map(entries) = &body.value else {
        return Err(HumanTaskError::UnboundResponse);
    };
    let mut persisted_kind = None;
    for (key, value) in entries {
        if key.as_str() != Some("trap_kind") {
            continue;
        }
        if persisted_kind.replace(value.as_str()).is_some() {
            return Err(HumanTaskError::UnboundResponse);
        }
    }
    if persisted_kind.flatten() != Some(DreamerTrapKind::HumanResponse.as_str()) {
        return Err(HumanTaskError::UnboundResponse);
    }
    Ok(())
}

/// Retires the TASK's wait binding once its trap has been consumed: the one
/// active binding it holds. A TASK several traps wait on retires none here,
/// as this form cannot tell which was consumed; [`release_human_wait_trap`]
/// names it.
pub fn release_human_wait(vault: &Vault, task_ref: EntityId) -> Result<bool> {
    let active = human_wait_bindings(vault, task_ref)?;
    let [binding] = active.as_slice() else {
        return Ok(false);
    };
    release_human_wait_trap(vault, task_ref, binding.trap_claim_id)
}

/// Retires the wait binding of one consumed trap on one TASK, leaving every
/// other trap's binding on that TASK as it stands (FIX 9867).
pub fn release_human_wait_trap(
    vault: &Vault,
    task_ref: EntityId,
    trap_claim_id: EntityId,
) -> Result<bool> {
    let Some(binding) = stored_wait_binding_for(vault, task_ref, trap_claim_id)? else {
        return Ok(false);
    };
    if !binding.is_active {
        return Ok(false);
    }
    let retired = HumanTaskWaitBinding {
        is_active: false,
        ..binding
    };
    vault.with_write_txn_grouped(|wtxn| {
        put_wait_binding_in_txn(vault, wtxn, &retired)?;
        WAIT_SIGNALS.delete(&vault.store, wtxn, &binding.trap_claim_id)?;
        Ok(())
    })?;
    Ok(true)
}
