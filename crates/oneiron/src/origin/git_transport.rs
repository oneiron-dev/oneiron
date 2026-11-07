//! The served host's transport for an exact publish's outbound git
//! (ARCH-0069 OSH-3, ARCH-0068 RC4, FIX 19083).
//!
//! A served host installs one per open vault
//! ([`Vault::install_origin_git_transport`]). Once it is installed, an exact
//! publish's authenticated reads of the mirror's branch and its one push go
//! through it alone: the host sends each git exchange through its
//! credential broker, which alone installs the mirror's credential, so the
//! Git child never holds it. A broker that cannot be reached, or that
//! refuses, fails the read or leaves the push unproven under the publish's
//! own rules; nothing falls back to the direct path. A vault opened with no
//! host keeps the direct path (`publish::reconcile`): the custody door hands
//! the mirror's credential to the child as one header.
//!
//! The port carries transport only. The approval, the frozen tuple, the
//! publication gate, the claim, the settlement and its no-resend rule stay
//! in the engine. The automatic mirror pushes do not use it yet.

use std::path::Path;
use std::sync::Arc;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::git_wire::{
    GitOid, GitPublishPushOutcome, GitRefName, GitRemoteTip, GitWire, GitWireRepo,
};
use crate::llm::BrokerIsolation;
use crate::origin::publish::OriginPublishDestination;

/// The transport a served host lends an exact publish's mirror git. It
/// never runs under an LMDB writer.
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

impl Vault {
    /// Installs the served host's transport this vault's exact publishes
    /// send their mirror git through (FIX 19083). A second install does
    /// nothing. Without one, the direct path stays.
    pub fn install_origin_git_transport(&self, transport: Arc<dyn OriginGitTransport>) {
        let _ = self.origin_git_transport.set(transport);
    }

    /// The installed transport, if any.
    pub(crate) fn served_origin_git_transport(&self) -> Option<Arc<dyn OriginGitTransport>> {
        self.origin_git_transport.get().cloned()
    }
}
