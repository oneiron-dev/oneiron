//! C9 wait binding, identity-checked response signalling and release.

use rmpv::Value;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::llm::{DREAMER_TRAP_PREDICATE, DreamerTrapKind, TrapRef, send_trap_signal};

use super::model::{HumanResponseSignal, HumanTaskError, HumanTaskResult, HumanTaskWaitBinding};
use super::storage::{
    decode_wait_binding, put_wait_binding_in_txn, put_wait_signal_marker_in_txn, wait_binding_key,
    wait_signal_key, wait_signal_marker,
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
    vault.with_write_txn(|wtxn| put_wait_binding_in_txn(vault, wtxn, &binding))?;
    Ok(binding)
}

/// The active wait binding for one TASK, if a step on this device is parked on it.
pub fn human_wait_binding(
    vault: &Vault,
    task_ref: EntityId,
) -> Result<Option<HumanTaskWaitBinding>> {
    Ok(stored_human_wait_binding(vault, task_ref)?.filter(|binding| binding.is_active))
}

pub(super) fn stored_human_wait_binding(
    vault: &Vault,
    task_ref: EntityId,
) -> Result<Option<HumanTaskWaitBinding>> {
    let rtxn = vault.store.env.read_txn()?;
    let Some(raw) = vault
        .store
        .vault_meta
        .get(&rtxn, wait_binding_key(task_ref).as_slice())?
    else {
        return Ok(None);
    };
    decode_wait_binding(raw.as_ref()).map(Some)
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
    let stored = stored_human_wait_binding(vault, binding.task_ref)?
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
    vault.with_write_txn(|wtxn| {
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

/// Retires the wait binding once its trap has been consumed.
pub fn release_human_wait(vault: &Vault, task_ref: EntityId) -> Result<bool> {
    let Some(binding) = stored_human_wait_binding(vault, task_ref)? else {
        return Ok(false);
    };
    if !binding.is_active {
        return Ok(false);
    }
    let retired = HumanTaskWaitBinding {
        is_active: false,
        ..binding
    };
    vault.with_write_txn(|wtxn| {
        put_wait_binding_in_txn(vault, wtxn, &retired)?;
        vault
            .store
            .vault_meta
            .delete(wtxn, wait_signal_key(binding.trap_claim_id).as_slice())?;
        Ok(())
    })?;
    Ok(true)
}
