//! The recipient a run's checkout of a masked copy was bound for (FIX 7608
//! pre-flip, FIX 10271 and 9328).
//!
//! A run binds its checkout lease through its own admission, which proves
//! its agent, the CODE anchor it reads, the PROJECT that anchor belongs to
//! and the run itself. Beside the lease's checkout binding, one immutable
//! companion keeps exactly that, keyed by the lease's checkout and epoch:
//! the Git exchanges its lease ticket admits later carry no project or
//! run, so a granted read or a held push's clearance finds them here, and
//! only when the exchange's own proven agent is the one bound. The
//! companion admits nothing and changes nothing about the checkout: a
//! lease with no copy, or a companion that cannot be written, leaves the
//! checkout as it is, and only a granted read stays unavailable.

use super::claims::{RepoProjectionCheckoutRecipient, RepoProjectionClaim, RepoProjectionRecord};
use super::recipient::RepoProjectionRevealBinding;
use crate::Vault;
use crate::checkout::lease::CheckoutLeaseAct;
use crate::entity_id::EntityId;
use crate::error::Result;

/// Records that `lease`, bound to a masked copy, was bound for `reveal`;
/// says whether it wrote the companion. A lease bound to no copy writes
/// nothing.
///
/// # Errors
/// A store failure, or another companion under the lease's id.
pub(crate) fn record_projected_checkout_recipient(
    vault: &Vault,
    lease: &CheckoutLeaseAct,
    reveal: RepoProjectionRevealBinding,
) -> Result<bool> {
    let checkout = lease.checkout_id.to_string();
    vault.with_write_txn(|wtxn| {
        let Some((graph, bound)) =
            RepoProjectionClaim::load_checkout_in_txn(vault, wtxn, &checkout, lease.epoch)?
        else {
            return Ok(false);
        };
        if bound.holder != lease.holder_ref {
            return Ok(false);
        }
        let record = RepoProjectionClaim::of(
            graph,
            RepoProjectionRecord::CheckoutRecipient(RepoProjectionCheckoutRecipient {
                checkout: checkout.clone(),
                epoch: lease.epoch,
                reveal,
            }),
        );
        let at = crate::ports::recorded_at_in_txn(&vault.store, wtxn)?;
        record.put_in_txn(vault, wtxn, at)
    })
}

/// Records that the run's `lease` on the CODE anchor `repo` was bound for
/// its proven `recipient`, logging (never raising) a failure: the
/// checkout stands either way, and only a granted read of it waits.
pub(crate) fn record_run_checkout_recipient(
    vault: &Vault,
    lease: &CheckoutLeaseAct,
    repo: EntityId,
    recipient: &super::RepoRevealRecipient,
) {
    let reveal = RepoProjectionRevealBinding::of(repo, recipient);
    if let Err(error) = record_projected_checkout_recipient(vault, lease, reveal) {
        tracing::warn!(
            kind = ?error.kind(),
            epoch = lease.epoch,
            "a checkout's recipient was not recorded; its granted reads stay masked"
        );
    }
}

/// The recipient `lease`'s run bound it for, when its companion stands
/// for the copy `graph` and names `agent`, the agent the exchange's host
/// proved; `None` otherwise.
///
/// # Errors
/// A store failure, or a record that does not decode.
pub(crate) fn projected_checkout_recipient(
    vault: &Vault,
    lease: &CheckoutLeaseAct,
    graph: &EntityId,
    agent: &EntityId,
) -> Result<Option<RepoProjectionRevealBinding>> {
    let txn = vault.store.env.read_txn()?;
    let bound = RepoProjectionClaim::load_checkout_recipient_in_txn(
        vault,
        &txn,
        &lease.checkout_id.to_string(),
        lease.epoch,
    )?;
    Ok(bound
        .filter(|(bound, reveal)| bound == graph && reveal.agent == *agent)
        .map(|(_, reveal)| reveal))
}
