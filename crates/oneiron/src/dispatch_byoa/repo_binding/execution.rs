//! A CLI attempt's execution custody, judged in one short writer before its
//! job is staged or its sandbox spawned (FIX 6867, 9792).
//!
//! Both paths go through [`start_execution`]: an attempt dispatched against
//! a live checkout carries its binding from dispatch; one enqueued while its
//! checkout was not live yet (FIX 7197) binds here, in the same writer that
//! starts it, so its capture compares a saved epoch and generation like any
//! other. The current row and payload are read in that writer, never an
//! earlier snapshot.

use super::{
    ByoaRepoBinding, ERR_EXECUTION_CHECKOUT, checkout_error, invalid, pin_checkout_in_txn,
    reserve_epoch_in_txn,
};
use crate::Vault;
use crate::attempt_queue::{AttemptQueue, AttemptRecord};
use crate::checkout::CheckoutLeaseAct;
use crate::checkout::lease::attempt_binding::start_attempt_in_txn;
use crate::dispatch_byoa::connector::{
    ByoaAttemptPayload, ByoaConnectorSpec, CliSandboxSpec, encode_byoa_attempt_payload,
};
use crate::dispatch_byoa::dispatcher::ByoaExecutionFence;
use crate::dispatch_byoa::error::{ByoaResult, ERR_CAPTURE_CONFLICT, ERR_EXECUTION_SHAPE};
use crate::dispatch_byoa::exhaust::decode_byoa_record;
use crate::entity_id::EntityId;

/// A CLI attempt admitted to run: the spec its row carries now and the
/// checkout lease it runs against, its generation saved.
pub(in crate::dispatch_byoa) struct StartedCliExecution {
    /// The connector spec from the attempt's current payload.
    pub(in crate::dispatch_byoa) spec: CliSandboxSpec,
    /// The live checkout lease, bound to this attempt at this generation.
    pub(in crate::dispatch_byoa) checkout: CheckoutLeaseAct,
}

/// The checkout a CLI attempt executes against, judged in one short writer
/// before its job is staged or its sandbox spawned. The attempt must still
/// hold `fence`'s lease and carry no result; its current payload is read
/// there. A payload with no binding binds now: the checkout its connector
/// names, live at the vault's time for the row's TASK, is pinned, its epoch
/// reserved for this attempt, and the binding saved in the payload (and in
/// its bound work's, when that holds none yet) through the queue's
/// leased-payload door. A stored binding is never rebound. Then the binding
/// must name the spec's checkout, its TASK must still stand, and the
/// running generation is saved on the lease.
///
/// # Errors
/// [`ERR_EXECUTION_CHECKOUT`] when no live matching checkout stands or the
/// TASK is gone or cancelled; the shared-epoch refusal when another attempt
/// holds a late-pinned epoch;
/// [`ERR_EXECUTION_SHAPE`] for a row that is not a CLI attempt;
/// [`ERR_CAPTURE_CONFLICT`] for a row that already has a result; the
/// attempt queue's lease refusal; a store failure.
pub(in crate::dispatch_byoa) fn start_execution(
    vault: &Vault,
    fence: &ByoaExecutionFence,
) -> ByoaResult<StartedCliExecution> {
    vault.try_with_write_txn_grouped(|txn| {
        let current = AttemptQueue::new(vault)
            .get_in_write_txn(txn, fence.attempt_id)?
            .ok_or_else(|| invalid(ERR_EXECUTION_CHECKOUT))?;
        AttemptQueue::check_result_lease(
            &current,
            &fence.lease_owner,
            fence.attempt_count,
            "execute_byoa",
        )?;
        if current.result_ref.is_some() {
            return Err(invalid(ERR_CAPTURE_CONFLICT));
        }
        let mut payload = decode_byoa_record(&current)?;
        let ByoaConnectorSpec::CliSandbox(spec) = &payload.connector else {
            return Err(invalid(ERR_EXECUTION_SHAPE));
        };
        let spec = spec.clone();
        let (binding, late) = match payload.repo_binding.clone() {
            Some(binding) => (binding, false),
            None => {
                let binding =
                    pin_checkout_in_txn(vault, txn, &payload.connector, &current.task_ref)?
                        .ok_or_else(|| invalid(ERR_EXECUTION_CHECKOUT))?;
                (binding, true)
            }
        };
        let checkout = binding.checkout_id()?;
        if checkout != spec.checkout_id {
            return Err(invalid(ERR_EXECUTION_CHECKOUT));
        }
        let task = EntityId::from_bytes(binding.task)?;
        if !crate::vault::live_entity_row_in_txn(&vault.store, txn, &task)?.is_live()
            || vault
                .task_standing_in(txn, task)?
                .is_none_or(|standing| standing.cancelled)
        {
            return Err(invalid(ERR_EXECUTION_CHECKOUT));
        }
        if late {
            bind_late_in_txn(vault, txn, &current, fence, &mut payload, &binding)?;
        }
        let lease = start_attempt_in_txn(
            vault,
            txn,
            checkout,
            binding.epoch,
            &binding.holder,
            fence.attempt_id,
            fence.attempt_count,
        )
        .map_err(checkout_error)?
        .map_err(|_| invalid(ERR_EXECUTION_CHECKOUT))?;
        if lease.task_ref != task || lease.repo_ref.canonical() != binding.repo_ref {
            return Err(invalid(ERR_EXECUTION_CHECKOUT));
        }
        Ok(StartedCliExecution {
            spec,
            checkout: lease,
        })
    })
}

/// Binds an attempt enqueued unbound to the checkout pinned for it now, in
/// the execution writer `txn` (FIX 9792): its epoch is reserved for the
/// attempt, and the binding is saved in its payload, and in its bound
/// work's as the work's first custody when that holds none, through the
/// queue's fenced leased-payload door.
///
/// # Errors
/// The epoch's reservation refusal; the payload's encode refusal; the
/// queue's refusal of a changed or resulted row; a store failure.
fn bind_late_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    current: &AttemptRecord,
    fence: &ByoaExecutionFence,
    payload: &mut ByoaAttemptPayload,
    binding: &ByoaRepoBinding,
) -> ByoaResult<()> {
    reserve_epoch_in_txn(vault, txn, binding, fence.attempt_id)?;
    payload.repo_binding = Some(binding.clone());
    if let Some(work) = payload.work.as_mut()
        && work.repo_binding.is_none()
    {
        work.repo_binding = Some(binding.clone());
    }
    let bytes = encode_byoa_attempt_payload(payload)?;
    AttemptQueue::new(vault).replace_leased_payload_in_txn(
        txn,
        current,
        &fence.lease_owner,
        fence.attempt_count,
        bytes,
    )?;
    Ok(())
}
