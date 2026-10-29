//! A BYOA CLI attempt's checkout custody (FIX 6867, G1 PR3b; ASK 2
//! approved; CALL "FIX 6867 stale capture").
//!
//! - **Dispatch** pins, in the dispatch writer and before the payload is
//!   encoded, the stored checkout the connector names: its id, epoch and
//!   holder, its repo with the pin, and its TASK ([`ByoaRepoBinding`]), when
//!   the lease is live at the vault's time and for the TASK the dispatch
//!   names; otherwise the attempt enqueues unbound (FIX 7197) and its first
//!   execution binds it. The same writer reserves a pinned epoch
//!   for the attempt the queue returns, so two live tries never share one
//!   writable checkout epoch, the same agent's included. A dedupe hit
//!   compares the stored binding and never rebinds it.
//! - **Execute** checks, in one short writer before staging or spawning
//!   ([`start_execution`]), the acquired attempt and its current payload.
//!   An attempt enqueued unbound binds there (FIX 9792): the checkout its
//!   connector names, now live at the vault's time for its TASK, is pinned,
//!   its epoch reserved for the attempt and the binding saved in the
//!   attempt's payload, and in its bound work's when that holds none yet,
//!   through the queue's leased-payload door. A stored binding is never
//!   rebound. Then, for either path, the binding, the TASK's standing and
//!   the lease at the vault's time are checked and the generation that
//!   runs is saved. No writer spans the child.
//! - **Capture** compares the same binding and generation in its result
//!   writer. A canonical terminal retry still returns its receipt first. A
//!   fresh Completed capture whose checkout went stale while the attempt
//!   still held its own lease keeps its exhaust, taint and result ref but
//!   lands Abandoned with `repo_stale_lease`: never Completed, publishable
//!   or settleable. So does a fresh Completed capture of a running CLI
//!   attempt that holds no custody, which never started on a checkout
//!   (FIX 9792). A lost attempt lease is refused as before.
//! - **Next seat** claims a fresh checkout of the same repo, TASK and
//!   holder through the shipped claim path, under an id derived from the
//!   spent attempt and the seat; the successor's own dispatch pins and
//!   reserves it. The old captured work stays linked through the
//!   successor's `parent_attempt`, whose payload names the old checkout and
//!   whose result names its exhaust. What dirty work the successor starts
//!   from is the host's policy: the fresh checkout materializes at the
//!   repo's pin, and nothing is published for it.
//!
//! A CLI row stored with no binding (`repo_binding: None`) binds at its
//! execution like any unbound dispatch. Endpoint and MCP attempts have no
//! checkout.

mod execution;

use serde::{Deserialize, Serialize};

use super::connector::ByoaConnectorSpec;
use super::error::{ByoaResult, ERR_EXECUTION_CHECKOUT, invalid};
use super::exhaust::{ByoaExhaustEnvelope, ByoaTerminalDisposition, decode_byoa_record};
use crate::Vault;
use crate::attempt_queue::{AttemptId, AttemptRecord, AttemptState, EnqueueOutcome};
use crate::checkout::lease::attempt_binding::{
    CHECKOUT_BINDING_SHARED, attempt_holds_in_txn, reserve_attempt_in_txn,
};
use crate::checkout::lease::transactions::claim_in_txn;
use crate::checkout::lease::{
    CheckoutClaimRequest, CheckoutError, CheckoutId, CheckoutLeaseAct, CheckoutLeaseState,
    CheckoutTaskClass, load_act_in_txn,
};
use crate::codebase::RepoRef;
use crate::entity_id::EntityId;
use crate::federation::RepoAccessRefusal;

pub(super) use self::execution::{StartedCliExecution, start_execution};

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
/// endpoint or MCP connector, and for a checkout that is missing, not live
/// at the vault's time, or claimed for another TASK: that attempt enqueues
/// unbound, so a checkout made live between enqueue and execute still runs
/// (FIX 7197), and its execution pins it here then ([`start_execution`]).
/// A successor claims its fresh checkout only for a CLI connector, as here.
///
/// # Errors
/// A store failure; [`ERR_EXECUTION_CHECKOUT`] for a checkout row that does
/// not read.
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
    let Some(lease) = load_act_in_txn(vault, txn, spec.checkout_id)
        .map_err(checkout_error)?
        .filter(|lease| live(lease, now))
        .filter(|lease| {
            task_ref
                .as_deref()
                .is_none_or(|task| task == lease.task_ref.to_hex())
        })
    else {
        return Ok(None);
    };
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
    reserve_epoch_in_txn(vault, txn, pinned, attempt.id)
}

/// Reserves `binding`'s epoch for `attempt` in the writer `txn`: the same
/// attempt again is the same reservation, another attempt is refused.
///
/// # Errors
/// [`ERR_CHECKOUT_SHARED`] when another attempt holds the epoch,
/// [`ERR_EXECUTION_CHECKOUT`] for a lease no longer live; a store failure.
fn reserve_epoch_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    binding: &ByoaRepoBinding,
    attempt: AttemptId,
) -> ByoaResult<()> {
    match reserve_attempt_in_txn(
        vault,
        txn,
        binding.checkout_id()?,
        binding.epoch,
        &binding.holder,
        attempt,
    )
    .map_err(checkout_error)?
    {
        Ok(_) => Ok(()),
        Err(reason) if reason == CHECKOUT_BINDING_SHARED => Err(invalid(ERR_CHECKOUT_SHARED)),
        Err(_) => Err(invalid(ERR_EXECUTION_CHECKOUT)),
    }
}

/// Marks a stale capture of `record` (CALL "FIX 6867 stale capture"),
/// read in the capture's result writer `txn`: a fresh Completed capture of
/// a running bound attempt whose checkout no longer stands for it at its
/// saved epoch and generation, of a running CLI attempt that holds no
/// custody at all (FIX 9792), or the retry of one already landed so
/// (Abandoned with `repo_stale_lease`), becomes Abandoned with
/// `repo_stale_lease`; its exhaust, taint and result ref are kept. Any
/// other capture, an endpoint's or MCP's among them, is untouched.
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
    let cli = matches!(payload.connector, ByoaConnectorSpec::CliSandbox(_));
    if envelope.disposition != ByoaTerminalDisposition::Completed
        || (!cli && payload.repo_binding.is_none())
    {
        return Ok(());
    }
    let stale = if !record.state.is_running() {
        record.state == AttemptState::Abandoned
            && record.last_error.as_deref() == Some(repo_stale_lease_reason())
    } else if let Some(binding) = payload.repo_binding.as_ref() {
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
        // A running CLI attempt with no custody never started on a
        // checkout: its completion cannot certify success.
        true
    };
    if stale {
        envelope.disposition = ByoaTerminalDisposition::Abandoned;
        repo_stale_lease_reason().clone_into(reason);
    }
    Ok(())
}

/// The checkout a next seat's CLI successor of `spent` at seat `seat` runs
/// against: a fresh id derived from the spent attempt and the seat when the
/// work is bound to a checkout (`source`: the spent attempt's own custody,
/// else the custody its bound work kept), else `base`, the checkout the
/// work ran on or names, as before. An endpoint or MCP successor neither
/// uses nor claims it.
///
/// # Errors
/// A derived id the checkout door refuses.
pub(super) fn successor_checkout(
    spent: AttemptId,
    base: CheckoutId,
    source: Option<&ByoaRepoBinding>,
    seat: usize,
) -> ByoaResult<CheckoutId> {
    if source.is_none() {
        return Ok(base);
    }
    let mut hasher = blake3::Hasher::new_derive_key(SUCCESSOR_CHECKOUT_DOMAIN);
    hasher.update(spent.as_bytes());
    hasher.update(&(seat as u64).to_le_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    if bytes == [0; 16] {
        bytes[0] = 1;
    }
    CheckoutId::from_bytes(bytes).map_err(|_| invalid(ERR_EXECUTION_CHECKOUT))
}

/// Claims the fresh checkout `checkout` for a next seat's CLI successor,
/// through the shipped claim path in the routing writer: the repo, TASK and
/// holder of `source` (the custody [`successor_checkout`] derived it from),
/// its lease's class and lifetime (none stays none). The caller claims only
/// for a CLI successor; an endpoint or MCP successor claims nothing. A
/// replay finds it claimed and claims nothing; unbound work runs its
/// successor on its own checkout, as before.
///
/// # Errors
/// [`ERR_EXECUTION_CHECKOUT`] for a derived id holding another lease; a
/// store failure.
pub(super) fn claim_successor_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    source: Option<&ByoaRepoBinding>,
    checkout: CheckoutId,
    now: u64,
) -> ByoaResult<()> {
    let Some(binding) = source else {
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
            holder_ref: binding.holder.clone(),
            task_class,
            ttl_secs,
            now,
        },
    )
    .map_err(checkout_error)?;
    Ok(())
}
