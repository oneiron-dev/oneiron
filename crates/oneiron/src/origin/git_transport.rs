//! The served host's transport for an origin mirror's outbound git: an exact
//! publish's and an automatic mirror push plan's (ARCH-0069 OSH-3, ARCH-0068
//! RC4, FIX 19083), and a mirror run's Git-LFS upload (FIX 19876).
//!
//! A served host installs one per open vault
//! ([`Vault::install_origin_git_transport`]). Once it is installed, every
//! authenticated read at the mirror and every push to it go through it
//! alone: an exact publish's reads of its branch and its one push, a plan's
//! reads of its refs and its pushes of frozen batches, and the LFS batch
//! calls and object actions of a run's upload. The host sends each git and
//! LFS exchange through its credential broker, which alone installs the
//! mirror's credential, so neither the Git child nor the daemon's own HTTP
//! client holds it. A broker that cannot be reached, or that refuses, fails
//! the read, leaves the push unproven under the caller's own rules, or
//! leaves the LFS objects missing; nothing falls back to the direct path. A
//! vault opened with no host keeps the direct path (`publish::reconcile`,
//! `publish::mirror_plan_remote`, `publish::mirror_lfs`): the custody door
//! hands the mirror's credential to the child as one header, and to the
//! daemon's LFS client as its batch calls' header.
//!
//! The port carries transport only, and sends each exchange once. The
//! approval, the frozen tuple or plan, the publication gate, the claims, the
//! settlement, an exact publish's no-resend rule and a plan's reconcile and
//! same-plan resend stay in the engine, and so do the LFS upload's batching,
//! ordering and store checks (`lfs::upload_lfs_objects`, which the host runs
//! over its broker's transport) and the run's readiness.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::git_wire::{
    GitOid, GitPlanPushReport, GitPlanRef, GitPublishPushOutcome, GitRefName, GitRemoteTip,
    GitWire, GitWireRepo,
};
use crate::llm::BrokerIsolation;
use crate::origin::lfs::{LfsOid, LfsTransferReport};
use crate::origin::publish::OriginPublishDestination;

/// The transport a served host lends an origin mirror's git. It never runs
/// under an LMDB writer.
pub trait OriginGitTransport: Send + Sync {
    /// Reads `name` at `destination`'s mirror for the repository `repo`, as
    /// [`GitWire::read_remote_branch`] does.
    ///
    /// # Errors
    /// A read that cannot prove what the mirror holds, its broker refusal
    /// named; never an absent branch.
    fn read_remote_branch(
        &self,
        wire: &GitWire<'_>,
        repo: &GitWireRepo,
        destination: &OriginPublishDestination,
        name: &GitRefName,
    ) -> Result<GitRemoteTip>;

    /// Pushes `push`'s exact commit to its branch once, as
    /// [`GitWire::push_publish`] does, from the repository `repo`. The caller
    /// never sends it again.
    fn push_publish(
        &self,
        wire: &GitWire<'_>,
        repo: &GitWireRepo,
        push: &OriginGitPublishPush<'_>,
    ) -> OriginGitPushReport;

    /// Reads `names` at `destination`'s mirror for the repository `repo`, as
    /// [`GitWire::read_remote_refs`] does: the tip of each name the mirror
    /// holds; a name it lacks is absent from the map.
    ///
    /// # Errors
    /// A read that cannot prove what the mirror holds, its broker refusal
    /// named; never an absent ref.
    fn read_remote_refs(
        &self,
        wire: &GitWire<'_>,
        repo: &GitWireRepo,
        destination: &OriginPublishDestination,
        names: &[GitRefName],
    ) -> Result<BTreeMap<GitRefName, GitOid>>;

    /// Pushes `push`'s one frozen plan batch once, as
    /// [`GitWire::push_mirror_plan_batch`] does, from the repository `repo`.
    /// A resend is the plan's own call, under its reconcile.
    fn push_mirror_plan_batch(
        &self,
        wire: &GitWire<'_>,
        repo: &GitWireRepo,
        push: &OriginGitPlanPush<'_>,
    ) -> OriginGitPlanPushReport;

    /// Sends each of `objects` the mirror at `destination` does not hold
    /// yet, from the store of the repository `repo_id`'s vault, through
    /// [`crate::origin::lfs::upload_lfs_objects`] over the host's broker:
    /// `destination` is judged again before each exchange, and the mirror's
    /// credential is installed by the broker alone. Each exchange goes once.
    /// The report carries the orchestration's answer, the broker's
    /// isolation and its credential rewrite count.
    fn push_lfs_objects(
        &self,
        repo_id: EntityId,
        destination: &OriginPublishDestination,
        objects: &[(LfsOid, u64)],
    ) -> LfsTransferReport;
}

/// One exact publish's push: its repository's id and the destination the
/// request recorded, which the host judges again before each exchange, and
/// the branch, commit, lease and mirror hold the push carries.
pub struct OriginGitPublishPush<'a> {
    pub repo_id: EntityId,
    pub destination: &'a OriginPublishDestination,
    pub name: &'a GitRefName,
    pub commit: &'a GitOid,
    /// The tip the lease expects at the branch; `None`: absent.
    pub expected: Option<&'a GitOid>,
    /// The mirror's push hold, which the push's child inherits.
    pub hold: &'a Path,
}

/// How one exact push ended, and how the credential broker its exchanges
/// went through is kept apart from the daemon (`None` when none did).
pub struct OriginGitPushReport {
    pub outcome: Result<GitPublishPushOutcome>,
    pub broker_isolation: Option<BrokerIsolation>,
}

/// One frozen plan batch's push: its repository's id and the destination
/// the plan froze, which the host judges again before each exchange, and
/// the batch's refs, each with its frozen object and lease, and the mirror
/// hold the push's child inherits.
pub struct OriginGitPlanPush<'a> {
    pub repo_id: EntityId,
    pub destination: &'a OriginPublishDestination,
    pub refs: &'a [GitPlanRef],
    /// The mirror's push hold, which the push's child inherits.
    pub hold: &'a Path,
}

/// What one plan batch's push reported, and how the credential broker its
/// exchanges went through is kept apart from the daemon (`None` when none
/// did).
pub struct OriginGitPlanPushReport {
    pub report: Result<GitPlanPushReport>,
    pub broker_isolation: Option<BrokerIsolation>,
}

impl Vault {
    /// Installs the served host's transport this vault's origin mirror git
    /// goes through (FIX 19083). A second install does nothing. Without one,
    /// the direct path stays.
    pub fn install_origin_git_transport(&self, transport: Arc<dyn OriginGitTransport>) {
        let _ = self.origin_git_transport.set(transport);
    }

    /// The installed transport, if any.
    pub(crate) fn served_origin_git_transport(&self) -> Option<Arc<dyn OriginGitTransport>> {
        self.origin_git_transport.get().cloned()
    }
}
