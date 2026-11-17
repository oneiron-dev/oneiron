//! A runner attempt's checkout at its Completed capture (FIX row
//! RUNNER-WORK-CHECKOUT-STAYS-ACTIVE; Engine RULING
//! EXPORTPROOF-RUNNER-CHECKOUT-END = A, 16 Nov 08:20).
//!
//! A bound runner work's CLI attempt reserves its checkout's epoch for
//! itself, and that epoch serves no other attempt. Once the attempt's
//! capture lands Completed and its work did not move on (no spend noted, no
//! park, no next seat), the host that ran it ends the epoch through the
//! shipped fail-closed teardown (ARCH-0068 RC2):
//! [`ByoaDispatcher::end_runner_checkout`]. Its standing is the attempt's
//! own reservation at its generation, read again in each teardown writer;
//! the host never acts as the lease's holder.
//!
//! - The tree is collected only with a pushed-head receipt (a Published
//!   origin row of the checkout's local repository, pushed by its holder at
//!   or after the claim, at the head the tree carries), a clean tree and no
//!   live occupant: the shipped holder door's receipt rule.
//! - Every other lease is Retained with its tree, and its holder settles,
//!   renews or tears it down through the shipped doors as before.
//! - A Failed, Abandoned or Cancelled capture, a Completed one whose work
//!   was parked or handed on, and a CLI attempt with no bound work keep the
//!   lease as it is.
//!
//! No TASK fact is written: the capture records the run's end, and the
//! TASK stays its holder's. Stored change: keep (the shipped lease states
//! and rows only).

use std::path::Path;

use super::{ByoaRepoBinding, ERR_EXECUTION_CHECKOUT, checkout_error, invalid};
use crate::Vault;
use crate::attempt_queue::{AttemptQueue, AttemptState};
use crate::checkout::lease::attempt_binding::{attempt_holds_in_txn, attempt_reserves_in_txn};
use crate::checkout::lease::teardown::{TeardownStep, prepare_teardown_in_txn, teardown_through};
use crate::checkout::lease::transactions::{fenced_in_txn, finish_teardown_in_txn};
use crate::checkout::lease::{
    CheckoutError, CheckoutLeaseAct, CheckoutLeaseFence, CheckoutLiveness, CheckoutRepoOps,
    CheckoutTeardownOutcome, PushedHeadReceipt, load_act_in_txn,
};
use crate::codebase::RepoRef;
use crate::dispatch_byoa::connector::ByoaConnectorSpec;
use crate::dispatch_byoa::dispatcher::{
    ByoEndpointBackendFactory, ByoaDispatcher, ByoaExecutionFence,
};
use crate::dispatch_byoa::error::{ByoaError, ByoaResult};
use crate::dispatch_byoa::exhaust::{ByoaEgressPort, decode_byoa_record};
use crate::dispatch_byoa::work_binding::{RunnerWorkBindingId, head_hop};
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::git_wire::GitWire;
use crate::origin::lfs::lfs_repo_id;
use crate::origin::publication::{OriginPublicationRecord, OriginPublicationStatus};

impl<B, E> ByoaDispatcher<'_, B, E>
where
    B: ByoEndpointBackendFactory,
    E: ByoaEgressPort,
{
    /// Ends the checkout epoch `fence`'s attempt reserved, when that
    /// attempt's capture landed Completed at `fence`'s generation and its
    /// bound runner work did not move on: the shipped fail-closed teardown
    /// runs under the attempt's own reservation, judged again in each of its
    /// writers, with `liveness` the host's checkout presence. The tree is
    /// collected only with a matching pushed-head receipt, a clean tree and
    /// no live occupant; otherwise the lease is Retained with its tree.
    ///
    /// `None` when no teardown ran: the capture is not Completed at that
    /// generation, the attempt carries no bound work or no custody, its
    /// work was parked or handed on, or its checkout no longer stands for
    /// it at the vault's time.
    ///
    /// # Errors
    /// A payload or binding that does not decode; a repository or liveness
    /// port failure; a store failure. A failure after the lease turned
    /// Settling leaves it so, and its holder's teardown resumes it.
    pub fn end_runner_checkout<L: CheckoutLiveness>(
        &self,
        fence: &ByoaExecutionFence,
        liveness: &mut L,
    ) -> ByoaResult<Option<CheckoutTeardownOutcome>> {
        end_checkout(self.vault(), fence, liveness)
    }
}

/// Why a teardown writer stopped: the attempt no longer stands on its epoch
/// at the first writer (nothing is written), or a refusal.
enum EndStop {
    Unreserved,
    Refused(ByoaError),
}

impl From<CheckoutError> for EndStop {
    fn from(error: CheckoutError) -> Self {
        Self::Refused(checkout_error(error))
    }
}

impl From<Error> for EndStop {
    fn from(error: Error) -> Self {
        Self::Refused(ByoaError::Store(error))
    }
}

impl From<ByoaError> for EndStop {
    fn from(error: ByoaError) -> Self {
        Self::Refused(error)
    }
}

fn end_checkout<L: CheckoutLiveness>(
    vault: &Vault,
    fence: &ByoaExecutionFence,
    liveness: &mut L,
) -> ByoaResult<Option<CheckoutTeardownOutcome>> {
    let (binding, lease) = {
        let rtxn = vault.store.env.read_txn().map_err(Error::from)?;
        let Some(binding) = ended_custody_in(vault, &rtxn, fence)? else {
            return Ok(None);
        };
        let Some(lease) =
            load_act_in_txn(vault, &rtxn, binding.checkout_id()?).map_err(checkout_error)?
        else {
            return Ok(None);
        };
        (binding, lease)
    };
    let wire = GitWire::new(vault)?;
    let proof = pushed_head_proof(vault, &wire, &lease)?;
    let lease_fence = CheckoutLeaseFence {
        checkout_id: lease.checkout_id,
        epoch: binding.epoch,
        holder_ref: binding.holder.clone(),
    };
    let ended = teardown_through(&lease_fence, &wire, liveness, |step, live| {
        vault.try_with_write_txn_grouped(|txn| -> Result<_, EndStop> {
            match step {
                TeardownStep::Prepare => {
                    if ended_custody_in(vault, txn, fence)?.as_ref() != Some(&binding) {
                        return Err(EndStop::Unreserved);
                    }
                    let act = fenced_in_txn(vault, txn, &lease_fence)?;
                    let receipt = match &proof {
                        Some(proof) => proof.receipt_in(vault, txn, &act)?,
                        None => None,
                    };
                    let now = vault.instant_in_write_txn(txn)?.secs();
                    Ok(prepare_teardown_in_txn(
                        vault,
                        txn,
                        &lease_fence,
                        receipt.as_ref(),
                        &wire,
                        live,
                        now,
                    )?)
                }
                TeardownStep::Finish => {
                    let reserved = attempt_reserves_in_txn(
                        vault,
                        txn,
                        binding.checkout_id()?,
                        binding.epoch,
                        &binding.holder,
                        fence.attempt_id,
                        fence.attempt_count,
                    )?;
                    if !reserved {
                        return Err(EndStop::Refused(invalid(ERR_EXECUTION_CHECKOUT)));
                    }
                    let now = vault.instant_in_write_txn(txn)?.secs();
                    Ok((finish_teardown_in_txn(vault, txn, &lease_fence, now)?, None))
                }
            }
        })
    });
    match ended {
        Ok(outcome) => Ok(Some(outcome)),
        Err(EndStop::Unreserved) => Ok(None),
        Err(EndStop::Refused(error)) => Err(error),
    }
}

/// The custody `fence`'s attempt ended on, read in `txn`: the attempt
/// landed Completed at `fence`'s generation, it is a CLI attempt of a bound
/// runner work whose newest hop is this attempt with no spend noted, and
/// its checkout still stands for it (live at its epoch for its holder,
/// reserved to this attempt at this generation). `None` otherwise.
fn ended_custody_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    fence: &ByoaExecutionFence,
) -> ByoaResult<Option<ByoaRepoBinding>> {
    let Some(record) = AttemptQueue::new(vault).get_in_txn(txn, fence.attempt_id)? else {
        return Ok(None);
    };
    if record.state != AttemptState::Completed || record.attempt_count != fence.attempt_count {
        return Ok(None);
    }
    let payload = decode_byoa_record(&record)?;
    if !matches!(payload.connector, ByoaConnectorSpec::CliSandbox(_)) {
        return Ok(None);
    }
    let (Some(work), Some(binding)) = (payload.work, payload.repo_binding) else {
        return Ok(None);
    };
    let settled_here = head_hop(vault, txn, RunnerWorkBindingId::from_bytes(work.binding)?)?
        .is_some_and(|hop| hop.attempt == *record.id.as_bytes() && hop.spent.is_none());
    if !settled_here {
        return Ok(None);
    }
    let holds = attempt_holds_in_txn(
        vault,
        txn,
        binding.checkout_id()?,
        binding.epoch,
        &binding.holder,
        record.id,
        record.attempt_count,
    )
    .map_err(checkout_error)?;
    Ok(holds.then_some(binding))
}

/// The origin publication that proves a lease's tree head was pushed.
struct PushedHeadProof {
    repo_id: EntityId,
    publication: EntityId,
    holder: EntityId,
}

impl PushedHeadProof {
    /// The receipt this proof gives `act`, read again in the teardown's
    /// writer `txn`; `None` once the row no longer proves it.
    fn receipt_in(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        act: &CheckoutLeaseAct,
    ) -> ByoaResult<Option<PushedHeadReceipt>> {
        let Some(row) = vault.origin_publication_in_txn(txn, self.publication)? else {
            return Ok(None);
        };
        if row.repo_id != self.repo_id || !proves(&row, act, self.holder) {
            return Ok(None);
        }
        Ok(Some(PushedHeadReceipt {
            receipt_ref: self.publication.to_hex(),
            observed_ref: row.ref_name.as_str().to_owned(),
            pushed_head: row.new_oid.as_str().to_owned(),
            checkout_id: act.checkout_id,
            epoch: act.epoch,
        }))
    }
}

/// The pushed-head proof for `lease`'s tree: a Published origin row of its
/// local repository, pushed by its holder at or after its claim, whose new
/// head is the head the tree carries now. `None` for a repository that is
/// not a local folder, a holder that is not an actor id, a tree that reads
/// no head, or no such row: the teardown then retains the tree.
fn pushed_head_proof(
    vault: &Vault,
    wire: &GitWire<'_>,
    lease: &CheckoutLeaseAct,
) -> ByoaResult<Option<PushedHeadProof>> {
    let RepoRef::LocalFolder { path, .. } = &lease.repo_ref else {
        return Ok(None);
    };
    let Ok(holder) = EntityId::from_hex(&lease.holder_ref) else {
        return Ok(None);
    };
    // The tree's head, observed with an empty probe: the inspection only
    // reads, and the teardown inspects again against the real receipt.
    let probe = PushedHeadReceipt {
        receipt_ref: String::new(),
        observed_ref: String::new(),
        pushed_head: String::new(),
        checkout_id: lease.checkout_id,
        epoch: lease.epoch,
    };
    let inspected = wire
        .inspect_teardown(lease, &probe)
        .map_err(checkout_error)?;
    let Some(head) = inspected.observed_head.map(|head| head.to_string()) else {
        return Ok(None);
    };
    let identity = wire.repository_identity(Path::new(path))?;
    let repo_id = lfs_repo_id(&identity.as_hex())?;
    let found = vault.find_origin_publication(repo_id, |row| {
        proves(row, lease, holder) && row.new_oid.as_str() == head
    })?;
    Ok(found.map(|row| PushedHeadProof {
        repo_id,
        publication: row.publication_id,
        holder,
    }))
}

/// Whether `row` is a push `holder` published for `lease`: Published, by
/// that holder, finished at or after the claim (the shipped holder door's
/// receipt rule).
fn proves(row: &OriginPublicationRecord, lease: &CheckoutLeaseAct, holder: EntityId) -> bool {
    row.status == OriginPublicationStatus::Published
        && row.actor_id.id() == Some(holder)
        && row.finished_at.is_some_and(|at| at >= lease.claimed_at)
}
