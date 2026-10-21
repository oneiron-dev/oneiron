//! A BYOA CLI attempt's checkout custody (FIX 6867, G1 PR3b; ASK 2
//! approved; CALL "FIX 6867 stale capture").
//!
//! - **Dispatch** pins, in the dispatch writer and before the payload is
//!   encoded, the stored checkout the connector names: its id, epoch and
//!   holder, its repo with the pin, and its TASK ([`ByoaRepoBinding`]). The
//!   lease must be live at the vault's time, and for the TASK the dispatch
//!   names. The same writer reserves that epoch for the attempt the queue
//!   returns, so two live tries never share one writable checkout epoch,
//!   the same agent's included. A dedupe hit compares the stored binding
//!   and never rebinds it.
//! - **Execute** checks, in a short writer before staging or spawning,
//!   the acquired attempt, the stored binding, the TASK's standing and the
//!   lease at the vault's time, and saves the generation that runs. No
//!   writer spans the child.
//! - **Capture** compares the same binding and generation in its result
//!   writer. A canonical terminal retry still returns its receipt first. A
//!   fresh Completed capture whose checkout went stale while the attempt
//!   still held its own lease keeps its exhaust, taint and result ref but
//!   lands Abandoned with `repo_stale_lease`: never Completed, publishable
//!   or settleable. A lost attempt lease is refused as before.
//! - **Next seat** claims a fresh checkout of the same repo, TASK and
//!   holder through the shipped claim path, under an id derived from the
//!   spent attempt and the seat; the successor's own dispatch pins and
//!   reserves it. The old captured work stays linked through the
//!   successor's `parent_attempt`, whose payload names the old checkout and
//!   whose result names its exhaust. What dirty work the successor starts
//!   from is the host's policy: the fresh checkout materializes at the
//!   repo's pin, and nothing is published for it.
//!
//! A row dispatched before this binding (`repo_binding: None`) keeps the
//! execute check it had. Endpoint and MCP attempts have no checkout.

use serde::{Deserialize, Serialize};

use super::connector::{ByoaAttemptPayload, ByoaConnectorSpec, CliSandboxSpec};
use super::dispatcher::ByoaExecutionFence;
use super::error::{ByoaResult, ERR_EXECUTION_CHECKOUT, invalid};
use super::exhaust::{ByoaExhaustEnvelope, ByoaTerminalDisposition, decode_byoa_record};
use crate::Vault;
use crate::attempt_queue::{AttemptQueue, AttemptRecord, AttemptState, EnqueueOutcome};
use crate::checkout::lease::attempt_binding::{
    CHECKOUT_BINDING_SHARED, attempt_holds_in_txn, reserve_attempt_in_txn, start_attempt_in_txn,
};
use crate::checkout::lease::transactions::claim_in_txn;
use crate::checkout::lease::{
    CheckoutClaimRequest, CheckoutError, CheckoutFactSink, CheckoutId, CheckoutLeaseAct,
    CheckoutLeaseService, CheckoutLeaseState, CheckoutLiveness, CheckoutTaskClass, load_act_in_txn,
};
use crate::codebase::RepoRef;
use crate::entity_id::EntityId;
use crate::federation::RepoAccessRefusal;

/// The checkout epoch is already held by another attempt.
const ERR_CHECKOUT_SHARED: &str = "the byoa checkout epoch is held by another attempt";
/// A dedupe hit would retarget the stored checkout binding.
const ERR_CHECKOUT_RETARGET: &str = "the byoa attempt is bound to another checkout epoch";
/// The domain a next seat's fresh checkout id is derived under.
const SUCCESSOR_CHECKOUT_DOMAIN: &str = "oneiron.byoa.successor-checkout.v1";

/// The reason a stale capture lands with: the run repo doors' stale-lease
/// code, one source for both.
#[must_use]
pub(crate) const fn repo_stale_lease_reason() -> &'static str {
    RepoAccessRefusal::StaleLease.public_code()
}

/// The checkout one CLI attempt was dispatched against, pinned before its
/// payload was encoded. Host-built in the dispatch writer; never a request
/// field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ByoaRepoBinding {
    /// The checkout id.
    pub checkout: [u8; 16],
    /// The lease epoch reserved for this attempt.
    pub epoch: u64,
    /// The lease holder.
    pub holder: String,
    /// The lease's stored repo, with its pinned commit (canonical form).
    pub repo_ref: String,
    /// The TASK the lease was claimed for.
    pub task: [u8; 16],
}

impl ByoaRepoBinding {
    fn checkout_id(&self) -> ByoaResult<CheckoutId> {
        CheckoutId::from_bytes(self.checkout).map_err(|_| invalid(ERR_EXECUTION_CHECKOUT))
    }
}

/// Whether `lease` is live at `now` on the vault's clock.
fn live(lease: &CheckoutLeaseAct, now: u64) -> bool {
    lease.state == CheckoutLeaseState::Active
        && now >= lease.claimed_at
        && now >= lease.updated_at
        && lease.lease_expires_at.is_none_or(|expiry| now < expiry)
}

fn checkout_error(error: CheckoutError) -> super::error::ByoaError {
    match error {
        CheckoutError::Store(error) => super::error::ByoaError::Store(error),
        _ => invalid(ERR_EXECUTION_CHECKOUT),
    }
}

/// Pins the stored checkout a CLI `connector` names, in the dispatch writer
/// `txn`, for the TASK `task_ref` names when it names one. `None` for an
/// endpoint or MCP connector.
///
/// # Errors
/// [`ERR_EXECUTION_CHECKOUT`] for a checkout that is missing, not live at
/// the vault's time, or claimed for another TASK; a store failure.
pub(super) fn pin_checkout_in_txn(
    vault: &Vault,
    txn: &heed::RwTxn<'_>,
    connector: &ByoaConnectorSpec,
    task_ref: &Option<String>,
) -> ByoaResult<Option<ByoaRepoBinding>> {
    let ByoaConnectorSpec::CliSandbox(spec) = connector else {
        return Ok(None);
    };
    let now = vault.instant_in_txn(txn)?.secs();
    let lease = load_act_in_txn(vault, txn, spec.checkout_id)
        .map_err(checkout_error)?
        .filter(|lease| live(lease, now))
        .filter(|lease| {
            task_ref
                .as_deref()
                .is_none_or(|task| task == lease.task_ref.to_hex())
        })
        .ok_or_else(|| invalid(ERR_EXECUTION_CHECKOUT))?;
    Ok(Some(ByoaRepoBinding {
        checkout: *lease.checkout_id.as_bytes(),
        epoch: lease.epoch,
        holder: lease.holder_ref.clone(),
        repo_ref: lease.repo_ref.canonical(),
        task: *lease.task_ref.as_bytes(),
    }))
}

/// Reserves the pinned epoch for the attempt the queue returned, in the
/// same dispatch writer. A dedupe hit compares the binding its stored
/// payload carries with `pinned` and never rebinds: a row stored with none
/// (dispatched before this binding) stays as it is.
///
/// # Errors
/// [`ERR_CHECKOUT_SHARED`] when another attempt holds the epoch,
/// [`ERR_CHECKOUT_RETARGET`] when a dedupe hit names another binding,
/// [`ERR_EXECUTION_CHECKOUT`] for a lease no longer live; a store failure.
pub(super) fn reserve_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    pinned: Option<&ByoaRepoBinding>,
    outcome: &EnqueueOutcome,
) -> ByoaResult<()> {
    let Some(pinned) = pinned else {
        return Ok(());
    };
    let attempt = match outcome {
        EnqueueOutcome::Enqueued(attempt) => attempt,
        EnqueueOutcome::Existing(attempt) => {
            return match decode_byoa_record(attempt)?.repo_binding {
                Some(stored) if &stored != pinned => Err(invalid(ERR_CHECKOUT_RETARGET)),
                _ => Ok(()),
            };
        }
    };
    match reserve_attempt_in_txn(
        vault,
        txn,
        pinned.checkout_id()?,
        pinned.epoch,
        &pinned.holder,
        attempt.id,
    )
    .map_err(checkout_error)?
    {
        Ok(_) => Ok(()),
        Err(reason) if reason == CHECKOUT_BINDING_SHARED => Err(invalid(ERR_CHECKOUT_SHARED)),
        Err(_) => Err(invalid(ERR_EXECUTION_CHECKOUT)),
    }
}

/// The checkout a CLI attempt executes against, judged in a short writer
/// before its job is staged or its sandbox spawned: the attempt still holds
/// `fence`'s lease, its stored binding names `spec`'s checkout at a live
/// epoch for the same holder and TASK, the TASK still stands, and the
/// running generation is saved on the lease. A row stored with no binding
/// keeps today's check through `checkouts`.
///
/// # Errors
/// [`ERR_EXECUTION_CHECKOUT`] when any of those fails; the attempt queue's
/// lease refusal; a store failure.
pub(super) fn start_execution<F: CheckoutFactSink, L: CheckoutLiveness>(
    vault: &Vault,
    fence: &ByoaExecutionFence,
    record: &AttemptRecord,
    payload: &ByoaAttemptPayload,
    spec: &CliSandboxSpec,
    checkouts: &CheckoutLeaseService<'_, F, L>,
    now: u64,
) -> ByoaResult<CheckoutLeaseAct> {
    let Some(binding) = payload.repo_binding.as_ref() else {
        let checkout = checkouts
            .get(spec.checkout_id)
            .map_err(|_| invalid(ERR_EXECUTION_CHECKOUT))?
            .ok_or_else(|| invalid(ERR_EXECUTION_CHECKOUT))?;
        if checkout.state != CheckoutLeaseState::Active
            || now < checkout.updated_at
            || checkout
                .lease_expires_at
                .is_some_and(|expiry| now >= expiry)
            || record
                .task_ref
                .as_ref()
                .is_some_and(|task| *task != checkout.task_ref.to_hex())
        {
            return Err(invalid(ERR_EXECUTION_CHECKOUT));
        }
        return Ok(checkout);
    };
    let checkout = binding.checkout_id()?;
    if checkout != spec.checkout_id {
        return Err(invalid(ERR_EXECUTION_CHECKOUT));
    }
    let task = EntityId::from_bytes(binding.task)?;
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
        if !crate::vault::live_entity_row_in_txn(&vault.store, txn, &task)?.is_live()
            || vault
                .task_standing_in(txn, task)?
                .is_none_or(|standing| standing.cancelled)
        {
            return Err(invalid(ERR_EXECUTION_CHECKOUT));
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
        Ok(lease)
    })
}

/// Marks a stale capture of `record` (CALL "FIX 6867 stale capture"),
/// read in the capture's result writer `txn`: a fresh Completed capture of
/// a running bound attempt whose checkout no longer stands for it at its
/// generation, or the retry of one already landed so (Abandoned with
/// `repo_stale_lease`), becomes Abandoned with `repo_stale_lease`; its
/// exhaust, taint and result ref are kept. Any other capture is untouched.
///
/// # Errors
/// A payload that does not decode; a store failure.
pub(super) fn mark_stale_capture_in_txn<E>(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    record: &AttemptRecord,
    envelope: &mut ByoaExhaustEnvelope<E>,
    reason: &mut String,
) -> ByoaResult<()> {
    let payload = decode_byoa_record(record)?;
    let Some(binding) = payload.repo_binding.as_ref() else {
        return Ok(());
    };
    if envelope.disposition != ByoaTerminalDisposition::Completed {
        return Ok(());
    }
    let stale = if record.state.is_running() {
        !attempt_holds_in_txn(
            vault,
            txn,
            binding.checkout_id()?,
            binding.epoch,
            &binding.holder,
            record.id,
            record.attempt_count,
        )
        .map_err(checkout_error)?
    } else {
        record.state == AttemptState::Abandoned
            && record.last_error.as_deref() == Some(repo_stale_lease_reason())
    };
    if stale {
        envelope.disposition = ByoaTerminalDisposition::Abandoned;
        repo_stale_lease_reason().clone_into(reason);
    }
    Ok(())
}

/// The checkout a next seat's successor of `spent` at seat `seat` runs
/// against: a fresh id derived from the spent attempt and the seat when
/// the spent attempt was bound, else the checkout it ran on, as before.
///
/// # Errors
/// A payload that does not decode.
pub(super) fn successor_checkout(
    spent: &AttemptRecord,
    ran: &CliSandboxSpec,
    seat: usize,
) -> ByoaResult<CheckoutId> {
    if decode_byoa_record(spent)?.repo_binding.is_none() {
        return Ok(ran.checkout_id);
    }
    let mut hasher = blake3::Hasher::new_derive_key(SUCCESSOR_CHECKOUT_DOMAIN);
    hasher.update(spent.id.as_bytes());
    hasher.update(&(seat as u64).to_le_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    if bytes == [0; 16] {
        bytes[0] = 1;
    }
    CheckoutId::from_bytes(bytes).map_err(|_| invalid(ERR_EXECUTION_CHECKOUT))
}

/// Claims the fresh checkout `checkout` for the successor of `spent`,
/// through the shipped claim path in the routing writer: the spent
/// attempt's repo, TASK and holder, its lease's class and lifetime (none
/// stays none). A replay finds it claimed and claims nothing; an unbound
/// spent attempt runs its successor on its own checkout, as before.
///
/// # Errors
/// [`ERR_EXECUTION_CHECKOUT`] for a derived id holding another lease; a
/// store failure.
pub(super) fn claim_successor_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    spent: &AttemptRecord,
    checkout: CheckoutId,
    now: u64,
) -> ByoaResult<()> {
    let Some(binding) = decode_byoa_record(spent)?.repo_binding else {
        return Ok(());
    };
    let task = EntityId::from_bytes(binding.task)?;
    let repo_ref = RepoRef::parse(&binding.repo_ref)?;
    if let Some(existing) = load_act_in_txn(vault, txn, checkout).map_err(checkout_error)? {
        return if existing.task_ref == task
            && existing.holder_ref == binding.holder
            && existing.repo_ref.canonical() == repo_ref.canonical()
        {
            Ok(())
        } else {
            Err(invalid(ERR_EXECUTION_CHECKOUT))
        };
    }
    let old = load_act_in_txn(vault, txn, binding.checkout_id()?).map_err(checkout_error)?;
    let (task_class, ttl_secs) = old.as_ref().map_or((CheckoutTaskClass::Edit, None), |old| {
        (
            old.task_class,
            old.lease_expires_at
                .and_then(|expiry| expiry.checked_sub(old.updated_at)),
        )
    });
    claim_in_txn(
        vault,
        txn,
        CheckoutClaimRequest {
            checkout_id: checkout,
            task_ref: task,
            repo_ref,
            holder_ref: binding.holder,
            task_class,
            ttl_secs,
            now,
        },
    )
    .map_err(checkout_error)?;
    Ok(())
}
