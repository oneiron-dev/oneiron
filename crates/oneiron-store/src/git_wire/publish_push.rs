//! The outbound half of one exact publish (FIX 6866): an authenticated read
//! of one branch at an https mirror, and one push of exactly one commit to
//! exactly that branch, leased on the tip that read saw.
//!
//! Both ride the mirror push's fixed profile (https only, no redirect, no
//! proxy, no hook, no LFS bytes, no submodule, no follow-tags; the one
//! credential is the `Authorization` header the custody door hands this
//! child). The push carries no `+` refspec and no deletion: the lease is its
//! only force, so a mirror whose branch moved since the read refuses it, and
//! a protected branch the mirror guards stays guarded. A read that cannot
//! prove what the mirror holds is an error, never an absent branch.

use std::path::Path;
use std::time::Duration;

use crate::git_wire::failure::invalid;
use crate::git_wire::ids::GitOid;
use crate::git_wire::ids::GitRefName;
use crate::git_wire::mirror_push::MirrorEgress;
use crate::git_wire::operation::GitWireOperation;
use crate::git_wire::repo::GitWireRepo;
use oneiron_base::error::Result;

/// How long one remote read may run.
pub const REMOTE_READ_TIMEOUT: Duration = Duration::from_secs(2 * 60);

/// How long one exact publish push may run: the mirror push's bound.
pub const PUBLISH_PUSH_TIMEOUT: Duration = Duration::from_secs(10 * 60);

/// Captured output of one remote read or exact push: a few lines.
pub const PUBLISH_OUTPUT_BYTES: usize = 1024 * 1024;

/// What one authenticated read saw at a mirror's branch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GitRemoteTip {
    /// The mirror holds no such branch.
    Absent,
    /// The mirror's branch stands at this object.
    At(GitOid),
}

impl GitRemoteTip {
    /// The object, unless the branch is absent.
    #[must_use]
    pub fn oid(&self) -> Option<&GitOid> {
        match self {
            Self::Absent => None,
            Self::At(oid) => Some(oid),
        }
    }
}

/// How one exact publish push ended, as the child reported it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GitPublishPushOutcome {
    /// The mirror took the commit at the branch, or already held it there.
    Applied,
    /// The mirror refused this branch's update (a stale lease, a protected
    /// branch, a hook): its `!` porcelain line, with the class and exit.
    Rejected(String),
    /// Anything else: the child failed, timed out or named no outcome for
    /// the branch. What the mirror holds is unknown.
    Unknown(String),
}
