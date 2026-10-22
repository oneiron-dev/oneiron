//! A checkout lease's masked copy (FIX 7608 slice 2b-ii-B2).
//!
//! A masked recipient's lease on a store that holds readable marks checks
//! out the masked copy of its pinned ORIGINAL: the copy made for the
//! store's Published roots with the lease's pin as its private root. Which
//! copy is decided once, when the lease is first materialized, and kept as
//! a value-free `repo.secret_projection` record about that copy, found
//! from the lease's checkout and epoch alone: every later bind, path
//! lookup, inspection, collection, export and Git exchange of the lease
//! reads the same copy, never a fresh one. A lease with no record checks
//! out the canonical store exactly as before. A record that names another
//! holder or another pin is an error, never a fallback to the original.

use std::path::PathBuf;

use super::claims::{RepoProjectionCheckout, RepoProjectionClaim, RepoProjectionRecord};
use super::git::{
    RepoGitProjectionRoots, materialize_masked_git_graph, projection_graph_dir,
};
use crate::Vault;
use crate::checkout::lease::CheckoutLeaseAct;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::git_wire::{GitOid, GitWire, GitWireRepo};
use crate::origin::lfs::lfs_repo_id;
use crate::origin::smart_http::store_holds_readable_marks_in_txn;

/// The bare store's directory inside a copy's own directory.
const PROJECTION_STORE_REPO: &str = "repo.git";

/// The masked copy one lease checks out: its graph, the copy store's
/// root, and the ORIGINAL and copy commits it binds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RepoProjectedCheckout {
    pub(crate) graph: EntityId,
    pub(crate) copy_root: PathBuf,
    pub(crate) original: GitOid,
    pub(crate) copy: GitOid,
}

/// The lease's pinned ORIGINAL, as its repo ref names it.
fn lease_pin(lease: &CheckoutLeaseAct) -> Result<GitOid> {
    let crate::codebase::RepoRef::LocalFolder { commit, .. } = &lease.repo_ref else {
        return Err(Error::InvariantViolation(
            "a checkout lease's repo must be a local folder",
        ));
    };
    GitOid::parse_hex(commit.clone())
}

/// The copy `lease` of the canonical store `store` was bound to, read from
/// its record alone (no mark is read, so an owned copy's checkout is found
/// again after its sources moved); `None` when the lease checks out the
/// canonical store.
///
/// # Errors
/// A store failure, or a record that names another holder or pin.
pub(crate) fn retained_projected_checkout(
    vault: &Vault,
    store: EntityId,
    lease: &CheckoutLeaseAct,
) -> Result<Option<RepoProjectedCheckout>> {
    let bound = {
        let txn = vault.store.env.read_txn()?;
        RepoProjectionClaim::load_checkout_in_txn(
            vault,
            &txn,
            &lease.checkout_id.to_string(),
            lease.epoch,
        )?
    };
    let Some((graph, record)) = bound else {
        return Ok(None);
    };
    if record.holder != lease.holder_ref || record.original != lease_pin(lease)? {
        return Err(Error::InvariantViolation(
            "a masked copy's checkout binding names another holder or pin",
        ));
    }
    Ok(Some(RepoProjectedCheckout {
        graph,
        copy_root: projection_graph_dir(vault, store, graph)?.join(PROJECTION_STORE_REPO),
        original: record.original,
        copy: record.copy,
    }))
}

/// The copy a masked recipient's `lease` of `canonical` checks out, bound
/// once: the standing binding when there is one, else the copy made now
/// for the store's Published roots and the lease's pin, recorded before
/// any byte of it is checked out. `None` when the store holds no readable
/// mark or no mark touches the closure: the canonical checkout stands.
///
/// # Errors
/// A store or git failure, or another binding for the lease.
pub(crate) fn bind_projected_checkout(
    vault: &Vault,
    wire: &GitWire<'_>,
    canonical: &GitWireRepo,
    lease: &CheckoutLeaseAct,
) -> Result<Option<RepoProjectedCheckout>> {
    let store = lfs_repo_id(&canonical.identity().as_hex())?;
    if let Some(bound) = retained_projected_checkout(vault, store, lease)? {
        return Ok(Some(bound));
    }
    {
        let txn = vault.store.env.read_txn()?;
        if !store_holds_readable_marks_in_txn(vault, &txn, &store)? {
            return Ok(None);
        }
    }
    let pin = lease_pin(lease)?;
    let published = vault.published_origin_refs(wire, store, canonical)?;
    let roots = RepoGitProjectionRoots::new(published, Some(pin))?;
    let now = vault.now_recorded_at();
    let Some(projection) = materialize_masked_git_graph(vault, wire, canonical, &roots, now)?
    else {
        return Ok(None);
    };
    let (original, copy) = projection
        .private_root()
        .cloned()
        .ok_or(Error::InvariantViolation(
            "a lease's masked copy lost its private root",
        ))?;
    let record = RepoProjectionClaim::of(
        projection.graph_id(),
        RepoProjectionRecord::Checkout(RepoProjectionCheckout {
            checkout: lease.checkout_id.to_string(),
            epoch: lease.epoch,
            holder: lease.holder_ref.clone(),
            original: original.clone(),
            copy: copy.clone(),
        }),
    );
    vault.with_write_txn(|wtxn| {
        let at = crate::ports::recorded_at_in_txn(&vault.store, wtxn)?;
        record.put_in_txn(vault, wtxn, at).map(drop)
    })?;
    Ok(Some(RepoProjectedCheckout {
        graph: projection.graph_id(),
        copy_root: projection.store_root().clone(),
        original,
        copy,
    }))
}
