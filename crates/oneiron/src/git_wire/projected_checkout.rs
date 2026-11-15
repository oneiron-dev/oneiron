//! A lease's checkout of a masked copy (FIX 7608 slice 2b-i): the
//! constructors a later slice selects, with no caller, dispatch or SDK
//! selection here.
//!
//! The canonical lease stays what it is: its `repo_ref` pins the ORIGINAL
//! commit in the canonical store, and it is proved live and pinned at that
//! original before anything is made. The checkout itself is a worktree of
//! its OWN store at the copy commit the original maps to: a bare store made
//! in its own owned handle directory (scoped by the copy store's identity,
//! so it never meets the canonical store's handles) with the copy commit's
//! whole closure exported into it from the copy store. Git run in the tree
//! so reads nothing under the vault, whose whole data tree the runner
//! fence removes, the copy store in it included
//! ([RUNNER-FENCE-MASKED-CHECKOUT]); there is no hole in the fence for the
//! copy store, through which a runner could write what the host's git
//! later reads. Its door remote names the canonical store's served name,
//! so a push from it reaches the canonical door, and collection goes
//! through that door as before. A checkout made before its store moved
//! into the handle is a linked worktree of the copy store; it is found
//! again, inspected and collected through the copy store until it is
//! collected. The ordinary checkout's materialize, inspect and collect
//! stay as they are.

#![allow(
    dead_code,
    reason = "FIX 7608: the initial-head check is kept for a later caller"
)]

use std::collections::HashSet;
use std::fs;
use std::path::Path;

use super::argv::FrozenGitArgv;
use super::checkout::{checkout_handle_dir_for, uncertain_inspection, verify_checkout_head};
use super::checkout_remote::served_repo_name;
use super::projected_object::PROJECTION_STORE_REPO;
use super::{
    GitObjectEdge, GitOid, GitWire, GitWireRepo, GitWireResult, git_object_edges, lock_repository,
};
use crate::origin::lfs::lfs_repo_id;
use crate::origin::secret_projection::checkout::{
    bind_projected_checkout, retained_projected_checkout,
};
use crate::store::code_snapshot::RepoRef;
use crate::{
    store::checkout_lease::CheckoutError,
    store::checkout_lease::CheckoutLeaseAct,
    store::checkout_lease::{
        CheckoutResult, CheckoutTeardownInspection, GitOid as LeaseGitOid, PushedHeadReceipt,
        TeardownReceiptMatch,
    },
};

/// One masked copy a lease checks out: the copy store pinned at the copy
/// commit (proved present), and the canonical original it stands in for.
#[derive(Debug, Clone)]
pub(crate) struct RepoProjectedCheckoutBinding {
    copy_store: GitWireRepo,
    original: GitOid,
    copy: GitOid,
}

impl RepoProjectedCheckoutBinding {
    /// Binds the copy store at `copy_root`, pinned at `copy`, to the
    /// canonical `original`.
    ///
    /// # Errors
    /// A copy store that does not hold `copy` as a commit.
    pub(crate) fn bind(
        wire: &GitWire<'_>,
        copy_root: &Path,
        original: GitOid,
        copy: GitOid,
    ) -> GitWireResult<Self> {
        let copy_store = wire.open_repo(
            RepoRef::LocalFolder {
                path: copy_root.to_string_lossy().into_owned(),
                commit: copy.as_str().to_owned(),
            },
            copy_root,
        )?;
        Ok(Self {
            copy_store,
            original,
            copy,
        })
    }

    /// The canonical commit this copy stands in for.
    pub(crate) const fn original(&self) -> &GitOid {
        &self.original
    }

    /// The copy commit the checkout carries.
    pub(crate) const fn copy_head(&self) -> &GitOid {
        &self.copy
    }
}

/// One pending level of an export walk: an object, what it names, and how
/// many of those are already exported.
struct ExportFrame {
    oid: GitOid,
    edges: Vec<GitObjectEdge>,
    next: usize,
}

impl GitWire<'_> {
    /// The binding of `lease`'s retained masked copy (FIX 7608 2b-ii-B2),
    /// `None` for a lease that checks out the canonical store. No mark is
    /// read: an owned copy's checkout is found again to inspect and collect
    /// it after its sources moved.
    ///
    /// # Errors
    /// A store failure, a binding naming another holder or pin, or a copy
    /// store that does not hold the bound commit.
    pub(crate) fn projected_checkout_binding(
        &self,
        lease: &CheckoutLeaseAct,
    ) -> CheckoutResult<Option<RepoProjectedCheckoutBinding>> {
        let canonical = self.checkout_repo(lease)?;
        let store = lfs_repo_id(&canonical.identity().as_hex())?;
        let Some(bound) = retained_projected_checkout(self.vault, store, lease)? else {
            return Ok(None);
        };
        Ok(Some(RepoProjectedCheckoutBinding::bind(
            self,
            &bound.copy_root,
            bound.original,
            bound.copy,
        )?))
    }

    /// The masked copy `lease` checks out, selected once (FIX 7608
    /// 2b-ii-B2): its retained binding when it has one, else, for a masked
    /// recipient (`masked`) on a store holding readable marks, the copy
    /// bound now. `None` checks out the canonical store as before.
    ///
    /// # Errors
    /// A store or git failure.
    pub(crate) fn select_projected_checkout(
        &self,
        lease: &CheckoutLeaseAct,
        masked: bool,
    ) -> CheckoutResult<Option<RepoProjectedCheckoutBinding>> {
        if let Some(binding) = self.projected_checkout_binding(lease)? {
            return Ok(Some(binding));
        }
        if !masked {
            return Ok(None);
        }
        let canonical = self.checkout_repo(lease)?;
        let Some(bound) = bind_projected_checkout(self.vault, self, &canonical, lease)? else {
            return Ok(None);
        };
        Ok(Some(RepoProjectedCheckoutBinding::bind(
            self,
            &bound.copy_root,
            bound.original,
            bound.copy,
        )?))
    }

    /// Whether `lease`'s holder reads masked (ASK 1): anyone but a live
    /// owner of the vault.
    ///
    /// # Errors
    /// A store failure.
    pub(crate) fn checkout_holder_reads_masked(
        &self,
        lease: &CheckoutLeaseAct,
    ) -> CheckoutResult<bool> {
        let Ok(holder) = crate::EntityId::from_hex(&lease.holder_ref) else {
            return Ok(true);
        };
        Ok(!self.vault.is_live_owner_person(&holder)?)
    }

    /// The owned handle directory of a masked copy's checkout: the
    /// ordinary name, under the copy store's scope.
    pub(crate) fn projected_checkout_handle_dir(
        &self,
        lease: &CheckoutLeaseAct,
        binding: &RepoProjectedCheckoutBinding,
    ) -> std::path::PathBuf {
        checkout_handle_dir_for(&self.process_env, &binding.copy_store, lease)
    }

    /// The lease's canonical store, proved live and pinned at the binding's
    /// original: a lease that pins another commit checks out no copy.
    fn projected_canonical(
        &self,
        lease: &CheckoutLeaseAct,
        binding: &RepoProjectedCheckoutBinding,
    ) -> CheckoutResult<GitWireRepo> {
        let canonical = self.checkout_repo(lease)?;
        if canonical.pinned_commit()? != binding.original {
            return Err(CheckoutError::Invalid(
                "a masked copy's checkout lease pins another original",
            ));
        }
        Ok(canonical)
    }

    /// Materializes exactly the copy commit into the lease's owned handle,
    /// as the ordinary checkout does the original: the handle is claimed
    /// exclusively, a failed export withdraws it, the head is proved, and
    /// the door remote names the canonical store. The checkout carries
    /// its own store in the handle (module docs), so nothing in the tree
    /// names the copy store in the vault.
    ///
    /// # Errors
    /// A lease not pinned at the original, a handle that is not ours, or a
    /// failed git effect.
    pub(crate) fn materialize_projected_checkout(
        &self,
        lease: &CheckoutLeaseAct,
        binding: &RepoProjectedCheckoutBinding,
    ) -> CheckoutResult<()> {
        let canonical = self.projected_canonical(lease, binding)?;
        self.preflight_checkout_remote(&canonical)?;
        let handle = checkout_handle_dir_for(&self.process_env, &binding.copy_store, lease);
        let tree = handle.join("tree");
        if !claim_projected_handle(&handle)? {
            self.verify_projected_checkout_head(lease, binding, &tree)?;
            return self.configure_projected_remote(&canonical, binding, &tree, lease);
        }
        // The handle was created exclusively by this call, so it is ours
        // to withdraw if the checkout itself fails; leaving a
        // half-exported store behind would turn a transient failure into
        // a permanently poisoned path.
        if let Err(error) = self.export_self_contained_checkout(binding, &handle, &tree, lease) {
            let _ = fs::remove_dir_all(&handle);
            return Err(error);
        }
        self.verify_projected_checkout_head(lease, binding, &tree)?;
        self.configure_projected_remote(&canonical, binding, &tree, lease)
    }

    /// Makes the checkout's own store in its freshly claimed handle,
    /// exports the copy commit's whole closure into it, proves the
    /// closure is whole there, and adds `tree` as a worktree of it.
    fn export_self_contained_checkout(
        &self,
        binding: &RepoProjectedCheckoutBinding,
        handle: &Path,
        tree: &Path,
        lease: &CheckoutLeaseAct,
    ) -> CheckoutResult<()> {
        let store = self.init_projection_store(handle)?;
        self.export_copy_closure(binding, &store)?;
        let local = self.open_repo(
            RepoRef::LocalFolder {
                path: store.repo_root().to_string_lossy().into_owned(),
                commit: binding.copy.as_str().to_owned(),
            },
            store.repo_root(),
        )?;
        if !self.reachable_objects_present(&local, &binding.copy, &[])? {
            return Err(CheckoutError::RepoOps(
                "a masked copy's exported checkout does not hold the copy's whole history"
                    .to_owned(),
            ));
        }
        self.add_worktree(&local, tree, &binding.copy, lease.updated_at)
            .map_err(CheckoutError::from)?;
        Ok(())
    }

    /// Writes every object the copy commit reaches from the copy store
    /// into `store`, each at its own id, children first, as a masked copy
    /// is written into its store: one retained object at a time, streamed
    /// from its spool, with the walk's pending levels on a heap stack,
    /// never in call frames, so a history of any depth or width is
    /// exported with no object, history, byte, count or time bound. A
    /// submodule's commit lives in another repository and is not
    /// followed (`git_object_edges`). An object the copy store lacks
    /// ends the export with an error: the checkout never stands on part
    /// of the graph.
    fn export_copy_closure(
        &self,
        binding: &RepoProjectedCheckoutBinding,
        store: &GitWireRepo,
    ) -> CheckoutResult<()> {
        let mut copied: HashSet<GitOid> = HashSet::new();
        let mut walking: HashSet<GitOid> = HashSet::from([binding.copy.clone()]);
        let mut frames = vec![self.export_frame(binding, &binding.copy)?];
        while let Some(top) = frames.last_mut() {
            if let Some(edge) = top.edges.get(top.next) {
                let child = edge.target().clone();
                top.next += 1;
                if copied.contains(&child) {
                    continue;
                }
                if !walking.insert(child.clone()) {
                    return Err(CheckoutError::RepoOps(
                        "a masked copy's object graph loops".to_owned(),
                    ));
                }
                frames.push(self.export_frame(binding, &child)?);
                continue;
            }
            let Some(done) = frames.pop() else {
                break;
            };
            walking.remove(&done.oid);
            let object = self.read_object_to_spool(&binding.copy_store, &done.oid)?;
            self.write_projection_object(store, &object)?;
            copied.insert(done.oid);
        }
        Ok(())
    }

    /// A walk level for `oid` of the copy store: what it names, its bytes
    /// dropped.
    fn export_frame(
        &self,
        binding: &RepoProjectedCheckoutBinding,
        oid: &GitOid,
    ) -> CheckoutResult<ExportFrame> {
        let object = self.read_object_to_spool(&binding.copy_store, oid)?;
        Ok(ExportFrame {
            oid: oid.clone(),
            edges: git_object_edges(&object)?,
            next: 0,
        })
    }

    /// The checkout's own store in its handle, pinned at the copy commit,
    /// or `None` for a checkout made before a masked copy's checkout
    /// carried its own store: that linked worktree's store is the copy
    /// store in the vault, and it is proved, inspected and collected
    /// through the copy store until it is collected.
    ///
    /// # Errors
    /// A store in the handle that is not its own common directory,
    /// shares objects, or does not hold the copy commit.
    fn local_checkout_store(
        &self,
        lease: &CheckoutLeaseAct,
        binding: &RepoProjectedCheckoutBinding,
    ) -> CheckoutResult<Option<GitWireRepo>> {
        let handle = checkout_handle_dir_for(&self.process_env, &binding.copy_store, lease);
        let Some(store) = self.existing_projection_store(&handle)? else {
            return Ok(None);
        };
        Ok(Some(self.open_repo(
            RepoRef::LocalFolder {
                path: store.repo_root().to_string_lossy().into_owned(),
                commit: binding.copy.as_str().to_owned(),
            },
            store.repo_root(),
        )?))
    }

    /// Proves the copy worktree at `tree` is registered with its store —
    /// its own, in the handle, or the copy store for a linked worktree
    /// made before it carried one — and carries the copy commit.
    ///
    /// # Errors
    /// An unregistered worktree or another head.
    pub(crate) fn verify_projected_checkout_head(
        &self,
        lease: &CheckoutLeaseAct,
        binding: &RepoProjectedCheckoutBinding,
        tree: &Path,
    ) -> CheckoutResult<()> {
        if let Some(local) = self.local_checkout_store(lease, binding)? {
            return verify_checkout_head(self, &local, tree, &binding.copy);
        }
        verify_checkout_head(self, &binding.copy_store, tree, &binding.copy)
    }

    /// Observes the copy checkout without mutating it, as the ordinary
    /// teardown inspection does: the receipt is matched against the head
    /// the copy worktree actually carries, and dirty or uncertain work is
    /// reported, never discarded.
    ///
    /// # Errors
    /// A failed read.
    pub(crate) fn inspect_projected_checkout_teardown(
        &self,
        lease: &CheckoutLeaseAct,
        binding: &RepoProjectedCheckoutBinding,
        receipt: &PushedHeadReceipt,
    ) -> CheckoutResult<CheckoutTeardownInspection> {
        let tree =
            checkout_handle_dir_for(&self.process_env, &binding.copy_store, lease).join("tree");
        if !tree.exists() {
            return Ok(uncertain_inspection());
        }
        // The store the tree is registered with: its own, in the handle,
        // or the copy store, for a linked worktree made before it carried
        // one. A store in the handle that no longer opens is uncertain,
        // never a reason to discard work.
        let repo = match self.local_checkout_store(lease, binding) {
            Ok(Some(local)) => local,
            Ok(None) => binding.copy_store.clone(),
            Err(_) => return Ok(uncertain_inspection()),
        };
        if !self.worktree_registered(&repo, &tree)? {
            return Ok(uncertain_inspection());
        }
        let worktree = self.open_repo(repo.repo_ref().clone(), &tree)?;
        let Ok(observed) = self.resolve_commit(&worktree, "HEAD") else {
            return Ok(uncertain_inspection());
        };
        let head = LeaseGitOid::parse(observed.as_str())?;
        let status = self.run_read(&worktree, &FrozenGitArgv::status_porcelain())?;
        let receipt_match = if observed.as_str() == receipt.pushed_head {
            TeardownReceiptMatch::Match
        } else {
            TeardownReceiptMatch::Mismatch
        };
        Ok(CheckoutTeardownInspection {
            observed_head: Some(head),
            dirty: !status.stdout.is_empty(),
            receipt_match,
            occupant: None,
        })
    }

    /// Collects only the proven owned copy handle. A checkout that
    /// carries its own store is collected whole: its store, its worktree
    /// registration and its tree all live in the handle, and the copy
    /// store registered nothing for it. A linked worktree made before
    /// that is removed from the copy store, whose registration is
    /// reconciled afterwards, as it always was.
    ///
    /// # Errors
    /// A failed git effect, or a handle that survived.
    pub(crate) fn collect_projected_checkout(
        &self,
        lease: &CheckoutLeaseAct,
        binding: &RepoProjectedCheckoutBinding,
    ) -> CheckoutResult<()> {
        let handle = checkout_handle_dir_for(&self.process_env, &binding.copy_store, lease);
        let tree = handle.join("tree");
        if !handle.exists() {
            self.prune_worktrees(&binding.copy_store)?;
            return Ok(());
        }
        if handle.join(PROJECTION_STORE_REPO).exists() {
            fs::remove_dir_all(&handle).map_err(crate::error::Error::from)?;
            if handle.exists() {
                return Err(CheckoutError::RepoOps(
                    "masked copy checkout handle survived collection".to_owned(),
                ));
            }
            return Ok(());
        }
        let _journal = self.remove_worktree(&binding.copy_store, &tree, lease.updated_at)?;
        if handle.exists() {
            fs::remove_dir_all(&handle).map_err(crate::error::Error::from)?;
        }
        self.prune_worktrees(&binding.copy_store)?;
        if handle.exists() {
            return Err(CheckoutError::RepoOps(
                "masked copy checkout handle survived collection".to_owned(),
            ));
        }
        Ok(())
    }

    /// The copy worktree's door remote, at the canonical store's served
    /// name, under the coordinator of the store the tree is registered
    /// with: its own, in the handle, or the copy store for a linked
    /// worktree made before it carried one.
    fn configure_projected_remote(
        &self,
        canonical: &GitWireRepo,
        binding: &RepoProjectedCheckoutBinding,
        tree: &Path,
        lease: &CheckoutLeaseAct,
    ) -> CheckoutResult<()> {
        if self.checkout_door.is_none() {
            return Ok(());
        }
        let repo = self
            .local_checkout_store(lease, binding)?
            .unwrap_or_else(|| binding.copy_store.clone());
        let _guard = lock_repository(repo.common_dir())?;
        let name = served_repo_name(canonical)?;
        self.configure_checkout_remote_named(&repo, tree, lease, name)
            .map_err(CheckoutError::from)
    }
}

/// Claims a masked copy's checkout handle exclusively, as the ordinary
/// checkout's claim does its own: `true` when this call made the handle,
/// `false` when it already stood, for the caller to prove the worktree
/// it holds. Nothing outside the handle's parent is ever created.
///
/// # Errors
/// A handle that cannot be made for a reason other than standing already.
fn claim_projected_handle(handle: &Path) -> CheckoutResult<bool> {
    if let Some(parent) = handle.parent() {
        fs::create_dir_all(parent).map_err(crate::error::Error::from)?;
    }
    match fs::create_dir(handle) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(error) => Err(CheckoutError::Store(crate::error::Error::from(error))),
    }
}
