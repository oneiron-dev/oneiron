//! Checkout custody: owned handle directories plus the `CheckoutRepoOps` trait impl.

use std::fs;
use std::path::{Path, PathBuf};

use super::argv::FrozenGitArgv;
use super::{GIT_WIRE_CHECKOUT_ROOT_NAME, GitOid, GitWire, GitWireProcessEnv, GitWireRepo};
use crate::checkout::lease::{
    CheckoutError, CheckoutLeaseAct, CheckoutRepoOps, CheckoutResult, CheckoutTeardownInspection,
    GitOid as LeaseGitOid, PushedHeadReceipt, TeardownReceiptMatch,
};
use crate::codebase::RepoRef;
use crate::error::Error;

impl GitWire<'_> {
    /// The private, repository- and epoch-bound directory that owns one lease's
    /// worktree. Nothing outside this root is ever created or removed.
    pub fn checkout_handle_dir(&self, lease: &CheckoutLeaseAct) -> CheckoutResult<PathBuf> {
        let repo = self.checkout_repo(lease)?;
        Ok(checkout_handle_dir_for(&self.process_env, &repo, lease))
    }

    /// The worktree path inside the owned handle.
    pub fn checkout_worktree_path(&self, lease: &CheckoutLeaseAct) -> CheckoutResult<PathBuf> {
        Ok(self.checkout_handle_dir(lease)?.join("tree"))
    }

    fn checkout_repo(&self, lease: &CheckoutLeaseAct) -> CheckoutResult<GitWireRepo> {
        let RepoRef::LocalFolder { path, .. } = &lease.repo_ref else {
            return Err(CheckoutError::Invalid(
                "checkout repo must be a local folder",
            ));
        };
        Ok(self.open_repo(lease.repo_ref.clone(), Path::new(path))?)
    }

    /// Proves the handle is registered with git and materializes exactly the
    /// pinned commit.
    fn claim_checkout_handle(&self, repo: &GitWireRepo, handle: &Path) -> CheckoutResult<bool> {
        if let Some(parent) = handle.parent() {
            fs::create_dir_all(parent).map_err(Error::from)?;
        }
        match fs::create_dir(handle) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let tree = handle.join("tree");
                if self.worktree_registered(repo, &tree)? {
                    return Ok(false);
                }
                Err(CheckoutError::RepoOps(
                    "checkout handle path already exists and is not an owned worktree".to_owned(),
                ))
            }
            Err(error) => Err(CheckoutError::Store(Error::from(error))),
        }
    }
}

fn checkout_handle_dir_for(
    process_env: &GitWireProcessEnv,
    repo: &GitWireRepo,
    lease: &CheckoutLeaseAct,
) -> PathBuf {
    let scope = repo.identity().as_hex();
    process_env
        .tmpdir
        .join(GIT_WIRE_CHECKOUT_ROOT_NAME)
        .join(&scope[..32])
        .join(format!("{}-{}", lease.checkout_id, lease.epoch))
}

/// ONE-1901's repo port, served by the same frozen seam as every other git
/// effect, so neither ONE-1904 dispatch nor ORIGIN ever constructs a
/// subprocess of its own.
impl CheckoutRepoOps for GitWire<'_> {
    /// Materializes exactly `repo_ref.commit` into a proven owned handle.
    ///
    /// The handle directory is created exclusively, so a pre-created path is
    /// refused rather than trusted, and the repository head is never moved.
    fn materialize(&self, lease: &CheckoutLeaseAct) -> CheckoutResult<()> {
        let repo = self.checkout_repo(lease)?;
        let commit = repo.pinned_commit()?;
        let handle = checkout_handle_dir_for(&self.process_env, &repo, lease);
        let tree = handle.join("tree");
        if !self.claim_checkout_handle(&repo, &handle)? {
            return verify_checkout_head(self, &repo, &tree, &commit);
        }
        // The handle was created exclusively by this call, so it is ours to
        // withdraw if the checkout itself fails; leaving it behind would turn a
        // transient failure into a permanently poisoned path.
        if let Err(error) = self.add_worktree(&repo, &tree, &commit, lease.updated_at) {
            let _ = fs::remove_dir_all(&handle);
            return Err(CheckoutError::from(error));
        }
        verify_checkout_head(self, &repo, &tree, &commit)
    }

    /// Observes the checkout without mutating it: registration is proven, no
    /// optional lock is taken, and no index is refreshed.
    fn inspect_teardown(
        &self,
        lease: &CheckoutLeaseAct,
        receipt: &PushedHeadReceipt,
    ) -> CheckoutResult<CheckoutTeardownInspection> {
        let repo = self.checkout_repo(lease)?;
        let tree = checkout_handle_dir_for(&self.process_env, &repo, lease).join("tree");
        if !tree.exists() || !self.worktree_registered(&repo, &tree)? {
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

    /// Collects only a proven owned handle, and reconciles git's worktree
    /// registration afterwards.
    fn collect(&self, lease: &CheckoutLeaseAct) -> CheckoutResult<()> {
        let repo = self.checkout_repo(lease)?;
        let handle = checkout_handle_dir_for(&self.process_env, &repo, lease);
        let tree = handle.join("tree");
        if !handle.exists() {
            self.prune_worktrees(&repo)?;
            return Ok(());
        }
        let _journal = self.remove_worktree(&repo, &tree, lease.updated_at)?;
        if handle.exists() {
            fs::remove_dir_all(&handle).map_err(Error::from)?;
        }
        self.prune_worktrees(&repo)?;
        if handle.exists() {
            return Err(CheckoutError::RepoOps(
                "checkout handle survived collection".to_owned(),
            ));
        }
        Ok(())
    }
}

fn verify_checkout_head(
    wire: &GitWire<'_>,
    repo: &GitWireRepo,
    tree: &Path,
    commit: &GitOid,
) -> CheckoutResult<()> {
    if !wire.worktree_registered(repo, tree)? {
        return Err(CheckoutError::RepoOps(
            "checkout worktree is not registered with the repository".to_owned(),
        ));
    }
    let worktree = wire.open_repo(repo.repo_ref().clone(), tree)?;
    let observed = wire.resolve_commit(&worktree, "HEAD")?;
    if &observed != commit {
        return Err(CheckoutError::RepoOps(
            "checkout worktree does not carry the pinned commit".to_owned(),
        ));
    }
    Ok(())
}

fn uncertain_inspection() -> CheckoutTeardownInspection {
    CheckoutTeardownInspection {
        observed_head: None,
        dirty: false,
        receipt_match: TeardownReceiptMatch::Uncertain,
        occupant: None,
    }
}
