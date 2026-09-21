//! Transaction-composable C9 waits that suspend one step, never its attempt.

use super::codec::invalid_trap;
use super::trap::{
    DecodedTrapClaim, append_trap_transition_in_txn, decode_trap_claim_value,
    envelope_from_claim_body, open_trap_in_txn, supersedes_neighbor_in_txn,
};
use super::trap_binding::{TrapBindingScope, trap_binding_read_in_txn};
use super::types::{
    DREAMER_TRAP_PREDICATE, DreamerTrapKind, DreamerTrapState, DurableStepContext,
    TRAP_CHAIN_WALK_CAP, TrapRef,
};
use crate::Vault;
use crate::attempt_queue::AttemptQueue;
use crate::claim::{ClaimLifecycleStatus, ClaimSubject};
use crate::entity_id::EntityId;
use crate::error::Result;

/// Creates the C9 anchor, private binding, and `Waiting` transition atomically
/// with the caller's TASK binding. The caller owns commit/rollback. No runner,
/// attempt, lease, or run-tree state changes here or in signal/consume.
pub(crate) fn open_step_wait_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    ctx: &DurableStepContext<'_>,
    step_hash: [u8; 32],
) -> Result<TrapRef> {
    if AttemptQueue::new(vault)
        .get_in_write_txn(wtxn, ctx.attempt_id)?
        .is_none()
        && !detached_step_matches(vault, wtxn, ctx, step_hash)?
    {
        return Err(invalid_trap("step-only wait attempt missing"));
    }
    let trap = open_trap_in_txn(
        vault,
        wtxn,
        ctx,
        DreamerTrapKind::HumanResponse,
        step_hash,
        "",
        TrapBindingScope::StepOnly,
    )?;
    let (head_id, head) = step_wait_head_in_txn(vault, wtxn, &trap)?;
    append_trap_transition_in_txn(
        vault,
        wtxn,
        &head_id,
        &head,
        DreamerTrapState::Waiting,
        ctx.now_ms,
        None,
    )?;
    Ok(trap)
}

/// Signals only this step in the caller's first-answer transaction. Repeated
/// signals on `Sent` or `Consumed` are authenticated, side-effect-free no-ops.
pub(crate) fn signal_step_wait_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    trap: &TrapRef,
    now: u64,
) -> Result<()> {
    let (head_id, head) = step_wait_head_in_txn(vault, wtxn, trap)?;
    match head.state {
        DreamerTrapState::Created | DreamerTrapState::Waiting => {
            append_trap_transition_in_txn(
                vault,
                wtxn,
                &head_id,
                &head,
                DreamerTrapState::Sent,
                now.max(head.at),
                None,
            )?;
        }
        DreamerTrapState::Sent | DreamerTrapState::Consumed => {}
    }
    Ok(())
}

/// Returns true only for the transaction that changes `Sent` to `Consumed`.
/// Unsignalled and already consumed waits return false. The private binding
/// remains as an authenticated idempotency receipt; without it a synced claim
/// could impersonate a locally consumed wait. Never resumes an attempt.
pub(crate) fn consume_step_wait_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    trap: &TrapRef,
    now: u64,
) -> Result<bool> {
    let (head_id, head) = step_wait_head_in_txn(vault, wtxn, trap)?;
    if head.state != DreamerTrapState::Sent {
        return Ok(false);
    }
    append_trap_transition_in_txn(
        vault,
        wtxn,
        &head_id,
        &head,
        DreamerTrapState::Consumed,
        now.max(head.at),
        None,
    )?;
    Ok(true)
}

/// Validates every node, both edge directions, and the private local identity
/// under the caller's transaction. A writer cannot consume a stale snapshot;
/// LMDB serializes this read/transition pair with every competing writer.
fn step_wait_head_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    trap: &TrapRef,
) -> Result<(EntityId, DecodedTrapClaim)> {
    let binding = trap_binding_read_in_txn(vault, rtxn, &trap.trap_claim_id)?
        .ok_or(invalid_trap("step-only trap binding missing"))?;
    if binding.park_owner != TrapBindingScope::StepOnly.owner(&trap.trap_claim_id)
        || trap.kind != DreamerTrapKind::HumanResponse
        || trap.step_hash != binding.step_hash
    {
        return Err(invalid_trap("step-only trap binding mismatch"));
    }
    let anchor = vault
        .get_claim_in_txn(rtxn, &trap.trap_claim_id)?
        .ok_or(invalid_trap("step-only trap anchor missing"))?;
    if !matches!(anchor.subject, ClaimSubject::Entity(_)) {
        return Err(invalid_trap("step-only trap subject must be an entity"));
    }
    let anchor_envelope = envelope_from_claim_body(&anchor)?;
    let mut current = trap.trap_claim_id;
    let mut previous = None;
    for _ in 0..TRAP_CHAIN_WALK_CAP {
        let body = vault
            .get_claim_in_txn(rtxn, &current)?
            .ok_or(invalid_trap("step-only trap chain record missing"))?;
        let decoded = decode_trap_claim_value(&body.value)?;
        if body.predicate != DREAMER_TRAP_PREDICATE
            || body.subject != anchor.subject
            || envelope_from_claim_body(&body)? != anchor_envelope
            || decoded.kind != trap.kind
            || decoded.attempt_id != binding.attempt_id
            || decoded.step_hash != binding.step_hash
        {
            return Err(invalid_trap("step-only trap chain identity mismatch"));
        }
        let predecessor = supersedes_neighbor_in_txn(vault, rtxn, &current, false)?;
        match previous {
            None if decoded.state == DreamerTrapState::Created && predecessor.is_none() => {}
            Some((id, state)) if predecessor == Some(id) => {
                if !DreamerTrapState::may_transition_to(state, decoded.state) {
                    return Err(invalid_trap("illegal step-only trap lineage transition"));
                }
            }
            _ => return Err(invalid_trap("step-only trap lineage mismatch")),
        }
        match supersedes_neighbor_in_txn(vault, rtxn, &current, true)? {
            Some(next) => {
                if body.lifecycle != ClaimLifecycleStatus::Superseded {
                    return Err(invalid_trap("step-only trap predecessor is not superseded"));
                }
                previous = Some((current, decoded.state));
                current = next;
            }
            None => {
                if body.lifecycle != ClaimLifecycleStatus::Active {
                    return Err(invalid_trap("step-only trap head is not active"));
                }
                return Ok((current, decoded));
            }
        }
    }
    Err(invalid_trap("step-only trap supersession chain too deep"))
}

const DETACHED_STEP: &[u8] = b"dreamer.detached_step.v1/";
fn detached_key(ctx: &DurableStepContext<'_>) -> Vec<u8> {
    [DETACHED_STEP, ctx.attempt_id.as_bytes()].concat()
}
fn detached_value(ctx: &DurableStepContext<'_>, step_hash: [u8; 32]) -> Vec<u8> {
    [
        ctx.envelope_actor.entity_ref().as_bytes().as_slice(),
        ctx.subject.as_bytes().as_slice(),
        step_hash.as_slice(),
    ]
    .concat()
}
fn detached_step_matches(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    ctx: &DurableStepContext<'_>,
    step_hash: [u8; 32],
) -> Result<bool> {
    Ok(ctx.run_id.is_none()
        && vault
            .store
            .vault_meta
            .get(txn, &detached_key(ctx))?
            .is_some_and(|v| v.as_ref() == detached_value(ctx, step_hash)))
}
/// An external SDK call has a durable step but no engine-owned run. Only the
/// authenticated facade can mint its private context proof; claims cannot.
pub(crate) fn register_detached_step_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    ctx: &DurableStepContext<'_>,
    step_hash: [u8; 32],
) -> Result<()> {
    if ctx.run_id.is_some() {
        return Err(invalid_trap("detached step names a run"));
    }
    let key = detached_key(ctx);
    let value = detached_value(ctx, step_hash);
    if let Some(prior) = vault.store.vault_meta.get(txn, &key)? {
        if prior.as_ref() != value {
            return Err(invalid_trap("detached step binding changed"));
        }
    } else {
        vault.store.vault_meta.put(txn, &key, &value)?;
    }
    Ok(())
}
