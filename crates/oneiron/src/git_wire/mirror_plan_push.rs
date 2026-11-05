//! Core half of `git_wire::mirror_plan_push`: its store-layer items live in `oneiron_store::git_wire::mirror_plan_push` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::git_wire::mirror_plan_push::*;

use super::argv::{FrozenGitArgv, os_args, validate_argv_token};
use super::execution_context::GitCommandSpec;
use super::failure::{classify_failure, invalid};
use super::mirror_push::{
    MIRROR_PUSH_MAX_OUTPUT_BYTES, MIRROR_PUSH_REFSPECS, MIRROR_PUSH_TIMEOUT, MirrorEgress,
};
use super::process::spawn_git;
use super::publish_push::REMOTE_READ_TIMEOUT;
use super::{GitOid, GitRefName, GitWire, GitWireOperation, GitWireRepo};
use crate::error::Result;
use std::collections::{BTreeMap, HashMap};
use std::ffi::OsString;
use std::path::Path;

impl GitWire<'_> {
    /// Reads `names` at the https mirror `url` with `authorization` (the full
    /// header value), at most [`MIRROR_PUSH_REFSPECS`] names a read: the tip
    /// of each name the mirror holds. A name it lacks is absent from the map.
    /// A failed read is an error naming its class and exit, never an absent
    /// ref, and never git's diagnostics.
    pub fn read_remote_refs(
        &self,
        repo: &GitWireRepo,
        url: &str,
        names: &[GitRefName],
        authorization: &str,
    ) -> Result<BTreeMap<GitRefName, GitOid>> {
        let mut tips = BTreeMap::new();
        if names.is_empty() {
            return Ok(tips);
        }
        validate_argv_token(url)?;
        let env = self.egress_env(repo, url, authorization, REMOTE_READ_TIMEOUT)?;
        for chunk in names.chunks(MIRROR_PUSH_REFSPECS) {
            let mut tail = os_args(&["ls-remote", "--refs", "--"]);
            tail.push(OsString::from(url));
            tail.extend(chunk.iter().map(|name| OsString::from(name.as_str())));
            let argv = FrozenGitArgv::frozen(GitWireOperation::RemoteRefs, tail);
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
                // A pattern matches a ref's tail; only the exact name counts.
                if let Some(name) = chunk.iter().find(|name| name.as_str() == listed) {
                    tips.insert(name.clone(), GitOid::parse_hex(oid)?);
                }
            }
        }
        Ok(tips)
    }

    /// Pushes one frozen batch to the https mirror `url`, each ref as its
    /// [`GitPlanRef`] says, in one child that inherits the hold this thread
    /// took on `hold`. Never `--mirror`, and never a ref beyond the batch.
    pub fn push_mirror_plan_batch(
        &self,
        repo: &GitWireRepo,
        url: &str,
        refs: &[GitPlanRef],
        hold: &Path,
        authorization: &str,
    ) -> Result<GitPlanPushReport> {
        if refs.is_empty() || refs.len() > MIRROR_PUSH_REFSPECS {
            return Err(invalid("a mirror plan batch holds 1 to 256 refs"));
        }
        if !url.starts_with("https://") {
            return Err(invalid("mirror push needs an https URL"));
        }
        if authorization.bytes().any(|byte| byte.is_ascii_control()) {
            return Err(invalid("mirror push authorization holds a control byte"));
        }
        if self.canonical_common_dir(&repo.repo_root)? != repo.common_dir {
            return Err(invalid("git wire repository binding changed"));
        }
        validate_argv_token(url)?;
        let mut env = self
            .process_env
            .clone()
            .with_limits(MIRROR_PUSH_TIMEOUT, MIRROR_PUSH_MAX_OUTPUT_BYTES)?;
        env.mirror_egress = Some(MirrorEgress::with_authorization(authorization));
        let argv = plan_push_argv(url, refs);
        let command = GitCommandSpec::wire(&repo.repo_root, &argv).holding(hold);
        let output = spawn_git(&env, &command)?;
        let flags = porcelain_flags(&output.stdout);
        // A ref the mirror already held prints no line without `--verbose`;
        // a child that exited zero, untruncated, took or held every ref.
        let outcomes = refs
            .iter()
            .map(|plan_ref| match flags.get(plan_ref.name.as_str()) {
                Some(' ' | '+' | '*' | '-' | '=') => GitPlanRefOutcome::Applied,
                Some('!') => GitPlanRefOutcome::Rejected,
                None if output.success => GitPlanRefOutcome::Applied,
                _ => GitPlanRefOutcome::Unknown,
            })
            .collect();
        let failure = (!output.success)
            .then(|| classify_failure(&output).message(GitWireOperation::MirrorPush));
        Ok(GitPlanPushReport { outcomes, failure })
    }
}

/// `push --porcelain --no-verify --no-recurse-submodules
/// [--force-with-lease=<ref>:<tip>]... -- <url> <refspec>...`.
fn plan_push_argv(url: &str, refs: &[GitPlanRef]) -> FrozenGitArgv {
    let mut tail = os_args(&[
        "push",
        "--porcelain",
        "--no-verify",
        "--no-recurse-submodules",
    ]);
    for plan_ref in refs {
        if let Some(lease) = &plan_ref.lease {
            tail.push(OsString::from(format!(
                "--force-with-lease={}:{}",
                plan_ref.name.as_str(),
                lease.as_ref().map_or("", GitOid::as_str)
            )));
        }
    }
    tail.push(OsString::from("--"));
    tail.push(OsString::from(url));
    for plan_ref in refs {
        let name = plan_ref.name.as_str();
        let spec = match (&plan_ref.new, plan_ref.lease.is_some()) {
            (Some(new), true) => format!("{}:{name}", new.as_str()),
            (Some(new), false) => format!("+{}:{name}", new.as_str()),
            (None, _) => format!(":{name}"),
        };
        tail.push(OsString::from(spec));
    }
    FrozenGitArgv::frozen(GitWireOperation::MirrorPush, tail)
}
