//! The outbound half of an automatic mirror push plan (FIX 6866 part 2): an
//! authenticated read of a frozen plan's refs at an https mirror, and one
//! push of one frozen batch of them.
//!
//! Both ride the mirror push's fixed profile: https only, no redirect, no
//! proxy, no hook, no Git-LFS bytes, no submodule, no follow-tags, the one
//! credential the custody door's `Authorization` header, and the mirror
//! push's own ten minutes and 4 MiB of output a child, at most
//! [`MIRROR_PUSH_REFSPECS`] refs a child. A ref whose tip the plan read goes
//! as `<new>:<ref>` (a deletion `:<ref>`) under
//! `--force-with-lease=<ref>:<tip read>` (empty: absent): the lease alone
//! permits the forced update, so a mirror whose ref moved since refuses it
//! and no `+` refspec overrides the lease. A ref whose tip could not be read
//! goes as the scheduled mirror always sent it, `+<new>:<ref>` or `:<ref>`,
//! unleased (CALLS "FIX 6866 automatic unknown tip"): never a lease on a
//! guessed absence. Each child inherits the caller's per-mirror hold and
//! never the repository's coordinator, so a child that outlives its parent
//! keeps the mirror held until it exits and no inbound push waits on it.

use std::collections::{BTreeMap, HashMap};
use std::ffi::OsString;
use std::path::Path;

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

/// One ref of a frozen plan batch, as it goes out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitPlanRef {
    /// The full ref at the mirror.
    pub name: GitRefName,
    /// What the mirror's ref becomes; `None` deletes it.
    pub new: Option<GitOid>,
    /// What the plan read there: `Some(None)` absent, `Some(Some(oid))` at
    /// `oid`. `None` when the read failed: the ref goes unleased.
    pub lease: Option<Option<GitOid>>,
}

/// How one ref of a pushed batch ended, as the child's porcelain said (or,
/// for a ref the mirror already held, the child's clean exit).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitPlanRefOutcome {
    /// The mirror took it, or already held it.
    Applied,
    /// The mirror refused it: a stale lease, a protected ref, a hook.
    Rejected,
    /// No outcome for it: the child failed, timed out or named none.
    Unknown,
}

/// What one batch push reported: each ref's outcome, in batch order, and
/// the redacted cause (class, exit, digest) when the child did not succeed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitPlanPushReport {
    pub outcomes: Vec<GitPlanRefOutcome>,
    pub failure: Option<String>,
}

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

/// Each ref a `push --porcelain` run reported, by its destination name, with
/// its one-byte flag.
fn porcelain_flags(stdout: &[u8]) -> HashMap<String, char> {
    let mut flags = HashMap::new();
    for line in String::from_utf8_lossy(stdout).lines() {
        let mut fields = line.split('\t');
        let (Some(flag), Some(spec)) = (fields.next(), fields.next()) else {
            continue;
        };
        let mut chars = flag.chars();
        let (Some(flag), None) = (chars.next(), chars.next()) else {
            continue;
        };
        if let Some((_, to)) = spec.rsplit_once(':') {
            flags.insert(to.to_owned(), flag);
        }
    }
    flags
}
