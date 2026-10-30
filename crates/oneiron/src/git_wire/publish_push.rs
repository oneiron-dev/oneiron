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

use super::argv::FrozenGitArgv;
use super::execution_context::GitCommandSpec;
use super::failure::{classify_failure, invalid};
use super::mirror_push::MirrorEgress;
use super::process::{GitWireProcessOutput, spawn_git};
use super::{GitOid, GitRefName, GitWire, GitWireOperation, GitWireProcessEnv, GitWireRepo};
use crate::error::Result;

/// How long one remote read may run.
pub(super) const REMOTE_READ_TIMEOUT: Duration = Duration::from_secs(2 * 60);

/// How long one exact publish push may run: the mirror push's bound.
const PUBLISH_PUSH_TIMEOUT: Duration = Duration::from_secs(10 * 60);

/// Captured output of one remote read or exact push: a few lines.
const PUBLISH_OUTPUT_BYTES: usize = 1024 * 1024;

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

impl GitWire<'_> {
    /// Reads `name` at the https mirror `url` with `authorization` (the full
    /// header value). A failed read is an error naming its class and exit,
    /// never git's diagnostics and never an absent branch.
    pub fn read_remote_branch(
        &self,
        repo: &GitWireRepo,
        url: &str,
        name: &GitRefName,
        authorization: &str,
    ) -> Result<GitRemoteTip> {
        let env = self.egress_env(repo, url, authorization, REMOTE_READ_TIMEOUT)?;
        let argv = FrozenGitArgv::remote_ref(url, name)?;
        let output = spawn_git(&env, &GitCommandSpec::wire(&repo.repo_root, &argv))?;
        if !output.success {
            return Err(classify_failure(&output).error(GitWireOperation::RemoteRefs));
        }
        let text = std::str::from_utf8(&output.stdout)
            .map_err(|_| invalid("git remote listing must be UTF-8"))?;
        for line in text.lines() {
            let mut fields = line.split('\t');
            let (Some(oid), Some(listed)) = (fields.next(), fields.next()) else {
                return Err(invalid("git remote listing line is malformed"));
            };
            if listed == name.as_str() {
                return Ok(GitRemoteTip::At(GitOid::parse_hex(oid)?));
            }
        }
        Ok(GitRemoteTip::Absent)
    }

    /// Pushes exactly `commit` to `name` at the https mirror `url`, only
    /// while the mirror's branch holds `expected` (`None`: while it does not
    /// exist), in one child that inherits the hold this thread took on
    /// `hold`: a child that outlives its host keeps the mirror held until it
    /// exits. Run once: the caller never sends it again.
    #[expect(
        clippy::too_many_arguments,
        reason = "one exact push names its repository, mirror, branch, commit, lease, hold, credential"
    )]
    pub fn push_publish(
        &self,
        repo: &GitWireRepo,
        url: &str,
        name: &GitRefName,
        commit: &GitOid,
        expected: Option<&GitOid>,
        hold: &Path,
        authorization: &str,
    ) -> Result<GitPublishPushOutcome> {
        let env = self.egress_env(repo, url, authorization, PUBLISH_PUSH_TIMEOUT)?;
        let argv = FrozenGitArgv::publish_push(url, name, commit, expected)?;
        let command = GitCommandSpec::wire(&repo.repo_root, &argv).holding(hold);
        let output = spawn_git(&env, &command)?;
        Ok(push_outcome(&output, commit, name))
    }

    /// The outbound profile of one call to `url`, bound to `repo`.
    pub(super) fn egress_env(
        &self,
        repo: &GitWireRepo,
        url: &str,
        authorization: &str,
        timeout: Duration,
    ) -> Result<GitWireProcessEnv> {
        if !url.starts_with("https://") {
            return Err(invalid("an exact publish needs an https URL"));
        }
        if authorization.bytes().any(|byte| byte.is_ascii_control()) {
            return Err(invalid("publish authorization holds a control byte"));
        }
        if self.canonical_common_dir(&repo.repo_root)? != repo.common_dir {
            return Err(invalid("git wire repository binding changed"));
        }
        let mut env = self
            .process_env
            .clone()
            .with_limits(timeout, PUBLISH_OUTPUT_BYTES)?;
        env.mirror_egress = Some(MirrorEgress::with_authorization(authorization));
        Ok(env)
    }
}

/// The outcome a `push --porcelain` child reports for `commit` at `name`.
fn push_outcome(
    output: &GitWireProcessOutput,
    commit: &GitOid,
    name: &GitRefName,
) -> GitPublishPushOutcome {
    let spec = format!("{}:{}", commit.as_str(), name.as_str());
    let flag = String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| {
            let mut fields = line.split('\t');
            let flag = fields.next()?;
            (fields.next()? == spec).then(|| flag.to_owned())
        });
    let failure = || classify_failure(output).message(GitWireOperation::PublishPush);
    match flag.as_deref() {
        Some(" " | "+" | "*" | "=") if output.success => GitPublishPushOutcome::Applied,
        Some("!") => GitPublishPushOutcome::Rejected(failure()),
        _ if output.success => GitPublishPushOutcome::Unknown(
            "git publish_push named no outcome for the branch".to_owned(),
        ),
        _ => GitPublishPushOutcome::Unknown(failure()),
    }
}
