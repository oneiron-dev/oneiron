//! A lease's checkout of a masked copy (FIX 7608 slice 2b-i): the
//! constructors a later slice selects, with no caller, dispatch or SDK
//! selection here.
//!
//! The canonical lease stays what it is: its `repo_ref` pins the ORIGINAL
//! commit in the canonical store, and it is proved live and pinned at that
//! original before anything is made. The checkout itself is a worktree of
//! the COPY store at the copy commit the original maps to, in its own owned
//! handle directory (scoped by the copy store's identity, so it never meets
//! the canonical store's handles), and its door remote names the canonical
//! store's served name, so a push from it reaches the canonical door. The
//! ordinary checkout's materialize, inspect and collect stay as they are.

#![allow(
    dead_code,
    reason = "FIX 7608: the initial-head check is kept for a later caller"
)]

use std::fs;
use std::path::Path;

use super::argv::FrozenGitArgv;
use super::checkout::{checkout_handle_dir_for, uncertain_inspection, verify_checkout_head};
use super::checkout_remote::served_repo_name;
use super::{GitOid, GitWire, GitWireRepo, GitWireResult, lock_repository};
use crate::checkout::lease::{
    CheckoutError, CheckoutLeaseAct, CheckoutResult, CheckoutTeardownInspection,
    GitOid as LeaseGitOid, PushedHeadReceipt, TeardownReceiptMatch,
};
use crate::codebase::RepoRef;
use crate::origin::lfs::lfs_repo_id;
use crate::origin::secret_projection::checkout::{
    bind_projected_checkout, retained_projected_checkout,
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

    /// Materializes exactly the copy commit into the lease's owned handle
    /// under the copy store, as the ordinary checkout does the original:
    /// the handle is claimed exclusively, a failed add withdraws it, the
    /// head is proved, and the door remote names the canonical store.
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
        if !self.claim_checkout_handle(&binding.copy_store, &handle)? {
            self.verify_projected_checkout_head(binding, &tree)?;
            return self.configure_projected_remote(&canonical, binding, &tree, lease);
        }
        if let Err(error) =
            self.add_worktree(&binding.copy_store, &tree, &binding.copy, lease.updated_at)
        {
            let _ = fs::remove_dir_all(&handle);
            return Err(CheckoutError::from(error));
        }
        self.verify_projected_checkout_head(binding, &tree)?;
        self.configure_projected_remote(&canonical, binding, &tree, lease)
    }

    /// Proves the copy worktree at `tree` is registered with the copy store
    /// and carries the copy commit.
    ///
    /// # Errors
    /// An unregistered worktree or another head.
    pub(crate) fn verify_projected_checkout_head(
        &self,
        binding: &RepoProjectedCheckoutBinding,
        tree: &Path,
    ) -> CheckoutResult<()> {
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
        if !tree.exists() || !self.worktree_registered(&binding.copy_store, &tree)? {
            return Ok(uncertain_inspection());
        }
        let worktree = self.open_repo(binding.copy_store.repo_ref().clone(), &tree)?;
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

    /// Collects only the proven owned copy handle, and reconciles the copy
    /// store's worktree registration afterwards.
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
    /// name, under the copy store's coordinator.
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
        let _guard = lock_repository(binding.copy_store.common_dir())?;
        let name = served_repo_name(canonical)?;
        self.configure_checkout_remote_named(&binding.copy_store, tree, lease, name)
            .map_err(CheckoutError::from)
    }
}
