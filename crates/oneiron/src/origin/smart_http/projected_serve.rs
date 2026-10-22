//! The masked selection of one Git exchange (FIX 7608 slice 2b-ii-B2, ASK
//! 1, ASK S): after the SAME push decision, a masked recipient's exchange
//! on a store that holds readable marks is served from its masked copy
//! (upload-pack advertisement and RPC) or received into the copy's private
//! ingress (receive-pack advertisement and RPC).
//!
//! An exact recipient, an unmarked store, an empty origin and a closure no
//! mark touches return `None` before any copy or ingress is made: the
//! exchange is today's, byte for byte. A lease's exchange reads the copy
//! its checkout was bound to; a lease with no binding and a raw Git
//! exchange read the copy of the store's Published roots (with the lease's
//! pin as a private root). A copy that moved between its selection and
//! its backend is retried, never answered from the canonical bytes. The
//! canonical store keys the push decision, the coordinator, the CODE
//! anchor, the Grant, the lease and the host epoch; the ingress is only
//! where the pushed objects and refs land.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::door::DoorAdmissionStamp;
use super::paths::serve_failed;
use super::push_projection::{bind_projection_ingress_in_txn, prepare_projection_ingress};
use super::read_projection::{RepoGitBackend, prepare_recipient_read_backend};
use super::recipient_serve::{RepoGitReadContext, store_holds_readable_marks_in_txn};
use super::serve::unpinned_repo_ref;
use super::serve_cmd::{ServeCommand, ServeRequest};
use crate::Vault;
use crate::checkout::lease::CheckoutLeaseAct;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::git_wire::{GitOid, GitRefName, GitWire, GitWireRepo};
use crate::origin::lfs::lfs_repo_id;
use crate::origin::secret_projection::checkout::retained_projected_checkout;
use crate::origin::secret_projection::claims::{
    RepoProjectionClaim, RepoProjectionIngressStore, RepoProjectionRecord,
};
use crate::origin::secret_projection::git::{
    RepoGitProjection, RepoGitProjectionRoots, materialize_masked_git_graph,
    projection_ingress_dir, reopen_repo_git_projection,
};

/// What a masked recipient's exchange on a marked store runs against.
pub(super) enum ProjectedExchange {
    /// The masked copy's frozen read-only backend.
    Read(RepoGitBackend),
    /// The masked copy's private ingress.
    Ingress(ProjectedIngress),
}

/// The private ingress a projection-bound push is received into.
pub(super) struct ProjectedIngress {
    projection: RepoGitProjection,
    canonical_store: EntityId,
    root: PathBuf,
    identity: String,
}

impl ProjectedExchange {
    /// The physical store a receive runs in: the ingress; `None` for a read,
    /// whose backend serves the copy store itself.
    pub(super) fn ingress_root(&self) -> Option<&Path> {
        match self {
            Self::Ingress(ingress) => Some(&ingress.root),
            Self::Read(_) => None,
        }
    }

    /// The copy's frozen read backend, for a read.
    pub(super) const fn backend(&self) -> Option<&RepoGitBackend> {
        match self {
            Self::Read(backend) => Some(backend),
            Self::Ingress(_) => None,
        }
    }

    /// The invocation the exchange spawns: the copy's read-only backend, or
    /// the canonical door's own command pointed at the ingress.
    ///
    /// # Errors
    /// As [`ServeCommand::http_backend`].
    pub(super) fn command(&self, project_root: &Path, hooks_dir: &Path) -> Result<ServeCommand> {
        match self {
            Self::Read(backend) => Ok(backend.command().clone()),
            Self::Ingress(ingress) => {
                ServeCommand::http_backend_ingress(&ingress.root, project_root, hooks_dir)
            }
        }
    }

    /// Writes the ingress proof `stamp`'s push is received under, before any
    /// admission evidence, and binds its id to the stamp. A read binds
    /// nothing.
    ///
    /// # Errors
    /// A stamp that admitted no push, or a store failure.
    pub(super) fn bind(&self, vault: &Vault, stamp: &mut DoorAdmissionStamp) -> Result<()> {
        let Self::Ingress(ingress) = self else {
            return Ok(());
        };
        let proof = prepare_projection_ingress(
            &ingress.projection,
            stamp,
            ingress.canonical_store,
            &ingress.identity,
            &ingress.root,
        )?;
        let at = stamp.admitted_at();
        let id = vault
            .with_write_txn_grouped(|wtxn| bind_projection_ingress_in_txn(vault, wtxn, &proof, at))?;
        stamp.ingress_proof = Some(id);
        Ok(())
    }
}

/// The masked selection for `request` on the served store at `repo_dir`,
/// under the host's read context `read`; `None` keeps today's exchange.
///
/// # Errors
/// A store or git failure, a lease ticket the door refuses, or a copy that
/// moved while it was selected.
pub(super) fn select_projected_exchange(
    vault: &Arc<Vault>,
    request: &ServeRequest,
    repo_dir: &Path,
    project_root: &Path,
    read: Option<&RepoGitReadContext>,
) -> Result<Option<ProjectedExchange>> {
    let Some(read) = read.filter(|read| read.reads_masked()) else {
        return Ok(None);
    };
    let wire = GitWire::new(vault)?;
    let store = lfs_repo_id(&wire.repository_identity(repo_dir)?.as_hex())?;
    {
        let txn = vault.store.env.read_txn()?;
        if !store_holds_readable_marks_in_txn(vault, &txn, &store)? {
            return Ok(None);
        }
    }
    let canonical = wire.open_repo(unpinned_repo_ref(repo_dir), repo_dir)?;
    let lease = admitted_lease(vault, request, repo_dir)?;
    let projection = match &lease {
        Some(lease) => match retained_projected_checkout(vault, store, lease)? {
            Some(bound) => Some(reopen_repo_git_projection(vault, &wire, &bound.graph)?.ok_or_else(
                || serve_failed("the checkout's masked copy no longer stands; bind it again"),
            )?),
            None => current_projection(vault, &wire, &canonical, store, Some(lease_pin(lease)?))?,
        },
        None => current_projection(vault, &wire, &canonical, store, None)?,
    };
    let Some(projection) = projection else {
        return Ok(None);
    };
    if request.is_push() {
        return receive_into_ingress(vault, &wire, projection, store).map(Some);
    }
    match prepare_recipient_read_backend(vault, &wire, &canonical, &projection, project_root, read)?
    {
        Some(backend) => Ok(Some(ProjectedExchange::Read(backend))),
        None => Err(serve_failed(
            "the masked copy moved while it was selected; retry",
        )),
    }
}

/// The lease the request's checkout ticket names, as the credential door
/// admits it for the request's principal; `None` with no ticket.
fn admitted_lease(
    vault: &Vault,
    request: &ServeRequest,
    repo_dir: &Path,
) -> Result<Option<CheckoutLeaseAct>> {
    let Some(ticket) = request
        .query_string
        .split('&')
        .find_map(|pair| pair.strip_prefix("checkout-lease="))
    else {
        return Ok(None);
    };
    let principal = request
        .remote_user
        .as_deref()
        .ok_or_else(|| serve_failed("checkout lease requires a registered principal"))?;
    crate::credential_door::require_checkout_lease(
        vault,
        ticket,
        principal,
        &unpinned_repo_ref(repo_dir),
    )
    .map(Some)
    .map_err(|error| super::paths::door_refused(&error))
}

fn lease_pin(lease: &CheckoutLeaseAct) -> Result<GitOid> {
    let crate::codebase::RepoRef::LocalFolder { commit, .. } = &lease.repo_ref else {
        return Err(serve_failed("a checkout lease's repo must be a local folder"));
    };
    GitOid::parse_hex(commit.clone())
}

/// The copy of the store's Published roots now, with `pin` as a private
/// root; `None` for an empty origin with no pin, or a closure no mark
/// touches.
fn current_projection(
    vault: &Vault,
    wire: &GitWire<'_>,
    canonical: &GitWireRepo,
    store: EntityId,
    pin: Option<GitOid>,
) -> Result<Option<RepoGitProjection>> {
    let published = vault.published_origin_refs(wire, store, canonical)?;
    if published.is_empty() && pin.is_none() {
        return Ok(None);
    }
    let roots = RepoGitProjectionRoots::new(published, pin)?;
    materialize_masked_git_graph(vault, wire, canonical, &roots, vault.now_recorded_at())
}

/// The copy's private ingress, seeded and recorded once.
fn receive_into_ingress(
    vault: &Vault,
    wire: &GitWire<'_>,
    projection: RepoGitProjection,
    store: EntityId,
) -> Result<ProjectedExchange> {
    let dir = projection_ingress_dir(vault, store, projection.graph_id())?;
    let refs: Vec<(GitRefName, GitOid)> = projection
        .refs()
        .iter()
        .map(|(name, _, copy)| (name.clone(), copy.clone()))
        .collect();
    let ingress = wire.projection_ingress(
        &dir,
        projection.store_root(),
        &refs,
        vault.now_recorded_at(),
    )?;
    let identity = ingress.identity().as_hex();
    let record = RepoProjectionClaim::of(
        projection.graph_id(),
        RepoProjectionRecord::IngressStore(RepoProjectionIngressStore {
            ingress_store: identity.clone(),
            canonical_store: store,
        }),
    );
    vault.with_write_txn(|wtxn| {
        let at = crate::ports::recorded_at_in_txn(&vault.store, wtxn)?;
        record.put_in_txn(vault, wtxn, at).map(drop)
    })?;
    Ok(ProjectedExchange::Ingress(ProjectedIngress {
        projection,
        canonical_store: store,
        root: ingress.repo_root().to_path_buf(),
        identity,
    }))
}
