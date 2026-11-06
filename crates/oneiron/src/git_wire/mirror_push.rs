//! Core half of `git_wire::mirror_push`: its store-layer items live in `oneiron_store::git_wire::mirror_push` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::git_wire::mirror_push::*;

use super::argv::FrozenGitArgv;
use super::execution_context::GitCommandSpec;
use super::failure::{classify_failure, invalid, uncertain};
use super::process::spawn_git;
use super::{GitOid, GitRefName, GitWire, GitWireOperation, GitWireRepo};
use crate::error::Result;
use std::process::Command;
use std::time::Duration;

impl GitWire<'_> {
    /// Pushes exactly `refs`, forced, to the https mirror at `url` and deletes
    /// exactly `deletions` there. `authorization` is the full header value
    /// (`Basic ...` or `Bearer ...`). A failure carries the class, exit code
    /// and the refs the mirror rejected, never git's diagnostics.
    pub fn push_mirror(
        &self,
        repo: &GitWireRepo,
        url: &str,
        refs: &[(GitRefName, GitOid)],
        deletions: &[GitRefName],
        authorization: &str,
    ) -> Result<()> {
        if !url.starts_with("https://") {
            return Err(invalid("mirror push needs an https URL"));
        }
        if authorization.bytes().any(|byte| byte.is_ascii_control()) {
            return Err(invalid("mirror push authorization holds a control byte"));
        }
        if self.canonical_common_dir(&repo.repo_root)? != repo.common_dir {
            return Err(invalid("git wire repository binding changed"));
        }
        let mut env = self
            .process_env
            .clone()
            .with_limits(MIRROR_PUSH_TIMEOUT, MIRROR_PUSH_MAX_OUTPUT_BYTES)?;
        env.mirror_egress = Some(MirrorEgress {
            authorization: zeroize::Zeroizing::new(format!("Authorization: {authorization}")),
        });
        let batches = refs
            .chunks(MIRROR_PUSH_REFSPECS)
            .map(|chunk| (chunk, &[][..]))
            .chain(
                deletions
                    .chunks(MIRROR_PUSH_REFSPECS)
                    .map(|chunk| (&[][..], chunk)),
            );
        for (pairs, gone) in batches {
            let argv = FrozenGitArgv::mirror_push(url, pairs, gone)?;
            let output = spawn_git(&env, &GitCommandSpec::wire(&repo.repo_root, &argv))?;
            if output.success {
                continue;
            }
            let failure = classify_failure(&output).message(GitWireOperation::MirrorPush);
            let rejected = rejected_refs(&output.stdout);
            return Err(uncertain(if rejected.is_empty() {
                failure
            } else {
                format!("{failure} rejected={}", rejected.join(","))
            }));
        }
        Ok(())
    }
}
