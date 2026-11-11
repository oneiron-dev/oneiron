//! Non-run checkout materialization under the holder's own repo read Grant.

use std::collections::BTreeSet;
use std::path::Path;

use super::custody::served_repo_name;
use super::{
    REPO_LANE_UNREADABLE, RepoCheckoutBindInput, RepoCheckoutBindOutput, refusal_error, repo_target,
};
use crate::checkout::lease::{CheckoutLeaseAct, CheckoutRepoOps};
use crate::claim::ClaimReadStatus;
use crate::codebase::RepoRef;
use crate::federation::repo_access::RepoMembership;
use crate::git_wire::{GitOid, GitRefName, GitWire, GitWireRepo, lock_repository};
use crate::memory::{MEMORY_CODE_INVALID_STATE, Memory, MemoryError, MemoryResult};
use crate::origin::secret_projection::RepoRevealRecipient;
use crate::origin::secret_projection::checkout_recipient::record_projected_checkout_recipient;
use crate::origin::secret_projection::recipient::RepoProjectionRevealBinding;
use crate::origin::smart_http::{origin_repo_dir, push_queue_key};
use oneiron_authority::federation::{RepoAccessRefusal, RepoTarget};

impl Memory<'_> {
    /// Materializes this caller's existing live checkout without inventing a
    /// run. One current Grant must read the named ref and every path of the
    /// lease's pinned tree; the ticket alone grants no repository read.
    pub fn repo_checkout_bind_for_holder(
        &self,
        input: RepoCheckoutBindInput,
    ) -> MemoryResult<RepoCheckoutBindOutput> {
        let git_ref = GitRefName::parse_full(input.git_ref.clone())?;
        let mut target = repo_target(input.repo, git_ref.as_str(), BTreeSet::<String>::new());
        // The first admission permits resolving the anchor, not releasing its
        // tree. The complete target is judged again before materialization.
        let (_, lease, served) = self.holder_checkout_admission(&target, &input)?;
        let wire = match input.endpoint.as_deref() {
            Some(endpoint) => GitWire::new(self.vault)?.with_checkout_door(endpoint)?,
            None => GitWire::new(self.vault)?,
        };
        let RepoRef::LocalFolder { path, .. } = &lease.repo_ref else {
            return Err(refusal_error(RepoAccessRefusal::WrongRepo));
        };
        let repo = wire.open_repo(lease.repo_ref.clone(), Path::new(path))?;
        if repo.common_dir() != push_queue_key(self.vault, &served)?.as_path() {
            return Err(refusal_error(RepoAccessRefusal::WrongRepo));
        }
        let pin = repo.pinned_commit()?;
        holder_checkout_ref(&wire, &repo, &git_ref, &pin)?;
        target.paths = holder_checkout_paths(&wire, &repo, &pin)?;
        // Only final validation holds the source coordinator. Projection and
        // worktree effects keep their own locks; the tree pin is immutable.
        let repository = lock_repository(repo.common_dir())?;
        let (admitted, current, current_served) =
            self.holder_checkout_admission(&target, &input)?;
        if current.repo_ref != lease.repo_ref
            || current.task_ref != lease.task_ref
            || current_served != served
        {
            return Err(refusal_error(RepoAccessRefusal::StaleLease));
        }
        holder_checkout_ref(&wire, &repo, &git_ref, &pin)?;
        drop(repository);
        wire.select_projected_checkout(&current, true)
            .map_err(crate::memory::checkout_doors::refusal)?;
        if admitted.class == crate::EdgeActorClass::Agent {
            let recipient = RepoRevealRecipient::proven_agent(admitted.actor)
                .in_project(Some(admitted.bounds.project))
                .for_run(None);
            // Keep the exact immutable companion. A different run binding
            // cannot stand in for this caller's actual lack of a run.
            record_projected_checkout_recipient(
                self.vault,
                &current,
                RepoProjectionRevealBinding::of(input.repo, &recipient),
            )?;
        }
        wire.materialize(&current)
            .map_err(crate::memory::checkout_doors::refusal)?;
        self.produced_from([input.repo]);
        let checkout = current.checkout_id.to_string();
        let remote_url = input.endpoint.as_deref().map(|endpoint| {
            format!(
                "{endpoint}/lease/{checkout}.{}/{}.git",
                current.epoch, served
            )
        });
        Ok(RepoCheckoutBindOutput {
            repo: input.repo,
            git_ref: input.git_ref,
            checkout,
            epoch: current.epoch,
            remote_url,
        })
    }

    /// Repo scope, credential read ceilings and lease redemption in one
    /// snapshot. The caller's actor is bound by its Memory, not the input.
    fn holder_checkout_admission(
        &self,
        target: &RepoTarget,
        input: &RepoCheckoutBindInput,
    ) -> MemoryResult<(RepoMembership, CheckoutLeaseAct, String)> {
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let txn = self
            .vault
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)?;
        let admitted = self
            .vault
            .admit_repo_read_in_txn(&txn, self.actor, self.actor_class, input.repo, target)?
            .map_err(refusal_error)?;
        if !lane
            .entities_readable_in_txn(&txn, &[input.repo])?
            .into_iter()
            .all(|readable| readable)
        {
            return Err(MemoryError::new(
                REPO_LANE_UNREADABLE,
                "the checkout holder's read lane does not read its repository rows",
                &[],
            ));
        }
        let served = served_repo_name(self.vault, &admitted.repo_ref)
            .ok_or_else(|| refusal_error(RepoAccessRefusal::WrongRepo))?;
        let repo_dir = origin_repo_dir(self.vault, &served)?;
        let store = RepoRef::LocalFolder {
            path: repo_dir.to_string_lossy().into_owned(),
            commit: "0".repeat(crate::codebase::CODEBASE_COMMIT_HASH_HEX_LEN),
        };
        let ticket = format!("{}.{}", input.checkout, input.epoch);
        let lease = crate::credential_door::require_checkout_lease_in_txn(
            self.vault,
            &txn,
            &ticket,
            &self.actor.to_hex(),
            &store,
        )
        .map_err(|_| refusal_error(RepoAccessRefusal::StaleLease))?;
        Ok((admitted, lease, served))
    }
}

fn holder_checkout_ref(
    wire: &GitWire<'_>,
    repo: &GitWireRepo,
    git_ref: &GitRefName,
    pin: &GitOid,
) -> MemoryResult<()> {
    if wire.resolve_commit(repo, git_ref.as_str())? != *pin {
        return Err(refusal_error(RepoAccessRefusal::WrongRef));
    }
    Ok(())
}

/// Names only: do not read file bodies to judge complete-tree repo bounds.
fn holder_checkout_paths(
    wire: &GitWire<'_>,
    repo: &GitWireRepo,
    pin: &GitOid,
) -> MemoryResult<BTreeSet<String>> {
    let mut paths = BTreeSet::new();
    let mut pending = vec![(String::new(), pin.clone())];
    while let Some((prefix, tree)) = pending.pop() {
        for entry in wire.read_tree(repo, &tree)? {
            let name = std::str::from_utf8(&entry.name).map_err(|_| {
                MemoryError::new(
                    MEMORY_CODE_INVALID_STATE,
                    "checkout tree paths must be UTF-8 to judge repo bounds",
                    &[],
                )
            })?;
            let path = if prefix.is_empty() {
                name.to_owned()
            } else {
                format!("{prefix}/{name}")
            };
            if entry.mode == 0o040000 {
                pending.push((path, entry.oid));
            } else {
                paths.insert(path);
            }
        }
    }
    Ok(paths)
}
