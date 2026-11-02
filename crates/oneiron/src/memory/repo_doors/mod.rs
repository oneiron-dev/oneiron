//! The run repo doors (FIX 6867, L11 G1 PR2a): a leased agent run's own
//! reads of the repos its owner's Grant names, its import of one of them and
//! its own private work at the repo queue's green commit.
//!
//! No owner proof is read or borrowed, and no owner door changes. Authority
//! is the run's host binding ([`RepoRunBinding`]: the real actor and class,
//! the sealed lease, the TASK and the executor run) and the L02 seams on the
//! actor's Grant, judged together by [`Vault::admit_repo_run_in_txn`] before
//! anything the run named resolves, and again in every writer before it
//! puts a row. Reads go through the read lane the run's door admitted the
//! call with. A refusal is the typed [`RepoAccessRefusal`] code; a work id
//! that is not this run's reads as no membership, and one whose run holds
//! another lease now as a stale lease. PR2b adds the run's symbol
//! declarations, its proposals and its queue entries (`symbols`,
//! `proposals`), fenced by its declaration in each writer. PR3b adds the
//! public run binding (`host`), the run's checkout and export (`custody`)
//! and the host's stock review policy (`review_policy`).

mod custody;
mod host;
mod proposals;
mod reads;
mod review_policy;
mod symbols;
mod types;
mod work;

pub use custody::{
    REPO_PUBLICATION_POLICY_REQUIRED, RepoCheckoutBindInput, RepoCheckoutBindOutput,
    RepoExportInput, RepoExportOutput,
};
pub use host::repo_provenance_unwitnessed;
pub use proposals::{
    REPO_PROVENANCE_REQUIRED, REPO_REVIEW_POLICY_REQUIRED, RepoReviewPolicy, RepoRunSources,
};
pub use review_policy::OwnerProposalReviewPolicy;
pub use types::*;

use crate::attempt_queue::AttemptId;
use crate::claim::{ClaimReadStatus, PointRead, ScopedReadActorKey};
use crate::error::{Error, Result};
use crate::federation::repo_access::RepoMembership;
use crate::federation::{RepoAccessIntent, RepoAccessRefusal, RepoTarget};
use crate::task_verb::HostBinding;
use crate::{EntityId, Vault, WriteActor};

use super::{Memory, MemoryError, MemoryResult};

/// The run a repo door call comes from, as its host bound it. Only the
/// code-run host builds one, from the live lease it holds; no field comes
/// from the guest, and none deserializes.
pub struct RepoRunBinding {
    actor: WriteActor,
    lease: HostBinding,
    task: EntityId,
    executor_run: EntityId,
    reader: ScopedReadActorKey,
}

impl RepoRunBinding {
    /// The binding of the run `lease` seals, as `actor`, realizing `task`,
    /// reading on `reader`. `None` for a lease sealed with no executor run.
    pub(crate) fn new(
        actor: WriteActor,
        lease: HostBinding,
        task: EntityId,
        reader: ScopedReadActorKey,
    ) -> Option<Self> {
        Some(Self {
            executor_run: lease.executor_run()?,
            actor,
            lease,
            task,
            reader,
        })
    }
}

/// A run repo door's answer and the rows it was read from, for the run's
/// replay and its send-time release.
pub struct RepoRunAnswer<T> {
    pub output: T,
    pub rows: Vec<EntityId>,
}

/// What one admitted run repo act stands on, as its snapshot read it.
pub(crate) struct RepoRunAdmitted {
    pub(crate) membership: RepoMembership,
    pub(crate) attempt: AttemptId,
    pub(crate) lease_owner: String,
    pub(crate) generation: u32,
    pub(crate) task: EntityId,
}

impl RepoRunAdmitted {
    /// Whether `other` was admitted under the same lease of the same try.
    pub(crate) fn same_lease(&self, other: &Self) -> bool {
        self.attempt == other.attempt
            && self.lease_owner == other.lease_owner
            && self.generation == other.generation
            && self.task == other.task
    }

    /// Whether `stamp` was bound under this admission's lease.
    pub(crate) fn holds(&self, stamp: &RepoRunStamp) -> bool {
        self.attempt == stamp.attempt
            && self.lease_owner == stamp.lease_owner
            && self.generation == stamp.generation
            && self.task == stamp.task
    }

    /// The stamp a work `work` binds under this admission.
    pub(crate) fn stamp(
        &self,
        binding: &RepoRunBinding,
        git_ref: &str,
        base_green: &str,
        base_snapshot: [u8; 32],
        work: EntityId,
    ) -> RepoRunStamp {
        RepoRunStamp {
            attempt: self.attempt,
            lease_owner: self.lease_owner.clone(),
            generation: self.generation,
            executor_run: binding.executor_run,
            task: self.task,
            project: self.membership.bounds.project,
            repo: self.membership.bounds.repo,
            grant: self.membership.grant,
            git_ref: git_ref.to_owned(),
            base_green: base_green.to_owned(),
            base_snapshot,
            work,
            symbol_fence: None,
        }
    }
}

/// A run admission: what it stands on, or the typed reason it was refused.
pub(crate) type RepoRunAdmission = std::result::Result<RepoRunAdmitted, RepoAccessRefusal>;

impl Vault {
    /// Admits the run `binding` binds to `target` for `intent` in the
    /// caller's snapshot `txn`: the sealed try still holds its lease and
    /// realizes the binding's TASK while that TASK stands, then the L02 seam
    /// admits the binding's actor and class under one Grant, with the
    /// target's repo as the handle. A lapsed lease or TASK is
    /// [`RepoAccessRefusal::StaleLease`]; the seam's own refusals pass as
    /// they are.
    ///
    /// # Errors
    /// A store, fold or clock failure; never a refusal.
    pub(crate) fn admit_repo_run_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        binding: &RepoRunBinding,
        target: &RepoTarget,
        intent: RepoAccessIntent,
    ) -> Result<RepoRunAdmission> {
        let Some((record, task)) = binding.lease.leased_task_in_txn(self, txn)? else {
            return Ok(Err(RepoAccessRefusal::StaleLease));
        };
        let Some(lease_owner) = record.lease_owner else {
            return Ok(Err(RepoAccessRefusal::StaleLease));
        };
        if task != binding.task {
            return Ok(Err(RepoAccessRefusal::StaleLease));
        }
        let (actor, class) = (binding.actor.entity_ref(), binding.actor.actor_class());
        let admitted = match intent {
            RepoAccessIntent::Read => {
                self.admit_repo_read_in_txn(txn, actor, class, target.repo, target)?
            }
            RepoAccessIntent::Edit => {
                self.admit_repo_edit_in_txn(txn, actor, class, target.repo, target)?
            }
        };
        let membership = match admitted {
            Ok(membership) => membership,
            Err(refused) => return Ok(Err(refused)),
        };
        if membership.actor != actor || membership.class != class {
            return Err(Error::InvariantViolation(
                "repo admission answered another actor",
            ));
        }
        Ok(Ok(RepoRunAdmitted {
            membership,
            attempt: record.id,
            lease_owner,
            generation: record.attempt_count,
            task,
        }))
    }
}

/// The door error a refusal answers: its stable public code and message.
pub(crate) fn refusal_error(refusal: RepoAccessRefusal) -> MemoryError {
    MemoryError::new(refusal.public_code(), refusal.message(), &[])
}

/// Whether `code` is one of the typed repo refusals, or one of a run
/// proposal's or export's typed holds.
pub(crate) fn is_repo_refusal_code(code: &str) -> bool {
    RepoAccessRefusal::ALL
        .iter()
        .any(|refusal| refusal.public_code() == code)
        || [
            REPO_REVIEW_POLICY_REQUIRED,
            REPO_PROVENANCE_REQUIRED,
            REPO_PUBLICATION_POLICY_REQUIRED,
        ]
        .contains(&code)
}

/// A ref-level act's paths: none.
pub(crate) const NO_PATHS: [&str; 0] = [];

/// The act on `repo` at `git_ref` reading or changing `paths`.
pub(crate) fn repo_target<S: AsRef<str>>(
    repo: EntityId,
    git_ref: &str,
    paths: impl IntoIterator<Item = S>,
) -> RepoTarget {
    RepoTarget {
        repo,
        git_ref: git_ref.to_owned(),
        paths: paths
            .into_iter()
            .map(|path| path.as_ref().to_owned())
            .collect(),
    }
}

impl Memory<'_> {
    /// [`Vault::admit_repo_run_in_txn`] in a snapshot of its own, a refusal
    /// as its door error.
    fn repo_run_admit(
        &self,
        binding: &RepoRunBinding,
        target: &RepoTarget,
        intent: RepoAccessIntent,
    ) -> MemoryResult<RepoRunAdmitted> {
        let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
        self.vault
            .admit_repo_run_in_txn(&txn, binding, target, intent)?
            .map_err(refusal_error)
    }

    /// The ones of `ids` the run's read lane reads, bodies included, in one
    /// snapshot, in order: what a blocker list shows the run.
    fn repo_lane_readable(
        &self,
        binding: &RepoRunBinding,
        ids: Vec<EntityId>,
    ) -> MemoryResult<Vec<EntityId>> {
        if ids.is_empty() {
            return Ok(ids);
        }
        let points: Vec<_> = ids.iter().copied().map(PointRead::id).collect();
        let checked = self
            .vault
            .scoped_read(binding.reader.clone())
            .with_claim_status(ClaimReadStatus::Recorded)
            .read(&points, None)?;
        Ok(ids
            .into_iter()
            .zip(&checked.value)
            .filter(|(_, row)| row.as_ref().is_some_and(|row| row.body.is_some()))
            .map(|(id, _)| id)
            .collect())
    }

    /// Whether the run's read lane reads every one of `refs`, bodies
    /// included, in one snapshot. A row it does not read is no membership:
    /// the Grant's bounds never widen what the run's lane reads.
    fn repo_lane_reads(&self, binding: &RepoRunBinding, refs: &[EntityId]) -> MemoryResult<()> {
        let points: Vec<_> = refs.iter().copied().map(PointRead::id).collect();
        let checked = self
            .vault
            .scoped_read(binding.reader.clone())
            .with_claim_status(ClaimReadStatus::Recorded)
            .read(&points, None)?;
        if checked
            .value
            .iter()
            .all(|row| row.as_ref().is_some_and(|row| row.body.is_some()))
        {
            return Ok(());
        }
        Err(refusal_error(RepoAccessRefusal::NoMembership))
    }
}
