//! The outside import's Git legs (FIX 6871, G7 PR1): one exact fetch of one
//! outside ref into a fresh private bare scratch store, and one stock push of
//! one scratch commit to one served ref through the authenticated door.
//!
//! The scratch store is disposable and opaque: [`FetchedExternalGit`] owns
//! it, names no path in its `Debug`, and is removed on drop. Its fetch takes
//! the full reachable history of exactly the named ref (no depth, filter,
//! promisor, tags, submodules or alternates), and the result is proved
//! before anyone pushes it: the ref names the frozen head, the head and base
//! are commits, the base is the head's ancestor and the head's whole graph
//! is present. Nothing here writes a served store's objects or refs: the
//! door's receive-pack quarantine is the only way the bytes enter one.
//!
//! Both legs run through the one process constructor (`spawn_git`) with the
//! captured process bounds and the fixed import profile
//! ([`profile::ImportProcessProfile`]). A failure names its class and exit,
//! never git's diagnostics, a URL credential or a scratch path.

use std::ffi::OsString;
use std::path::Path;

use super::argv::{FrozenGitArgv, os_args, validate_argv_token};
use super::execution_context::GitCommandSpec;
use super::failure::{classify_failure, invalid};
use super::process::{GitWireProcessOutput, spawn_git};
use super::{GitOid, GitRefName, GitWire, GitWireOperation, GitWireRepo};
use crate::codebase::RepoRef;
use crate::error::Result;

mod profile;
pub(super) use profile::ImportProcessProfile;

/// The scratch ref the one fetched outside ref lands on.
const IMPORT_SCRATCH_REF: &str = "refs/oneiron-import/source";

/// The bare store's directory inside its private scratch root.
const IMPORT_SCRATCH_REPO: &str = "repo";

/// One proved outside fetch: a private bare scratch store holding the frozen
/// head's whole history, and the base and head it was proved for. Opaque:
/// no path, URL or credential leaves it, and dropping it removes the store.
pub struct FetchedExternalGit {
    scratch: tempfile::TempDir,
    repo: GitWireRepo,
    base: GitOid,
    head: GitOid,
}

impl FetchedExternalGit {
    /// The frozen head this fetch proved.
    #[must_use]
    pub fn head(&self) -> &GitOid {
        &self.head
    }

    /// The base this fetch proved an ancestor of the head.
    #[must_use]
    pub fn base(&self) -> &GitOid {
        &self.base
    }
}

impl std::fmt::Debug for FetchedExternalGit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FetchedExternalGit")
            .field("base", &self.base)
            .field("head", &self.head)
            .finish_non_exhaustive()
    }
}

/// How one exact outside fetch ended.
#[derive(Debug)]
pub enum GitImportFetchOutcome {
    /// The ref named the frozen head, and its graph is proved.
    Fetched(FetchedExternalGit),
    /// The outside ref names another commit now: the frozen head was not
    /// fetched, and no replacement is guessed.
    Moved,
    /// The fetch or one of its proofs refused, with a stable reason code.
    Refused(String),
}

/// How one push to the door ended, as the stock Git child reported it. A
/// transport hint, never a receipt: only the door's own receive records
/// prove what landed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GitImportPushOutcome {
    /// The door took the commit at the ref, or already held it there.
    Applied,
    /// The door refused this ref's update, with a stable reason code.
    Rejected(String),
    /// Anything else: what the door holds is unknown.
    Unknown(String),
}

/// `init --bare --quiet --template= <name>` under the private directory
/// `root`, through the one process constructor under `env`: a fresh bare
/// store with no template, hook, alternate or shared object directory. The
/// import's scratch store and a masked copy's store (FIX 7608 slice 2b-i)
/// are both made here.
pub(super) fn init_private_bare_store(
    env: &super::GitWireProcessEnv,
    root: &Path,
    name: &str,
) -> Result<GitWireProcessOutput> {
    let init = FrozenGitArgv::frozen(
        GitWireOperation::ImportScratchInit,
        os_args(&["init", "--bare", "--quiet", "--template=", name]),
    );
    spawn_git(env, &GitCommandSpec::wire(root, &init))
}

impl GitWire<'_> {
    /// Fetches exactly `source_ref` from the https repository `url` into a
    /// fresh private bare scratch store, then proves it: the ref names
    /// `head`, `head` and `base` are commits, `base` is an ancestor of
    /// `head`, and `head`'s whole graph is present. `authorization`, when
    /// given, is the complete `Authorization` header value the custody door
    /// handed this call; it reaches the child's environment only.
    ///
    /// # Errors
    /// A malformed URL or credential, a scratch store that cannot be made,
    /// or a local read failure. A refused fetch or proof is an outcome.
    pub fn fetch_external_exact(
        &self,
        url: &str,
        source_ref: &GitRefName,
        base: &GitOid,
        head: &GitOid,
        authorization: Option<&str>,
    ) -> Result<GitImportFetchOutcome> {
        validate_source_url(url)?;
        let scratch = tempfile::Builder::new()
            .prefix("oneiron-import-")
            .tempdir_in(&self.process_env.tmpdir)?;
        let root = scratch.path().canonicalize()?;
        let mut env = self.process_env.clone();
        env.import_profile = Some(ImportProcessProfile::source(&root, authorization)?);
        let output = init_private_bare_store(&env, &root, IMPORT_SCRATCH_REPO)?;
        if !output.success {
            return Ok(refused(&output, GitWireOperation::ImportScratchInit));
        }
        let repo_dir = root.join(IMPORT_SCRATCH_REPO);
        let mut tail = os_args(&[
            "fetch",
            "--quiet",
            "--no-tags",
            "--no-recurse-submodules",
            "--no-write-fetch-head",
            "--",
        ]);
        tail.push(OsString::from(url));
        tail.push(OsString::from(format!(
            "{}:{IMPORT_SCRATCH_REF}",
            source_ref.as_str()
        )));
        let fetch = FrozenGitArgv::frozen(GitWireOperation::ImportFetch, tail);
        let output = spawn_git(&env, &GitCommandSpec::wire(&repo_dir, &fetch))?;
        if !output.success {
            return Ok(refused(&output, GitWireOperation::ImportFetch));
        }
        if self.scratch_ref(&repo_dir)?.as_ref() != Some(head) {
            return Ok(GitImportFetchOutcome::Moved);
        }
        let repo = self.open_repo(
            RepoRef::LocalFolder {
                path: repo_dir.to_string_lossy().into_owned(),
                commit: head.as_str().to_owned(),
            },
            &repo_dir,
        )?;
        let kinds = self.object_info(&repo, &[base.clone(), head.clone()])?;
        if kinds.get(head).map(String::as_str) != Some("commit") {
            return Ok(GitImportFetchOutcome::Refused(
                "head_not_a_commit".to_owned(),
            ));
        }
        if kinds.get(base).map(String::as_str) != Some("commit") {
            return Ok(GitImportFetchOutcome::Refused(
                "base_not_in_source_history".to_owned(),
            ));
        }
        if !self
            .merge_base(&repo, base.as_str(), head.as_str())
            .is_ok_and(|found| found == *base)
        {
            return Ok(GitImportFetchOutcome::Refused(
                "base_not_an_ancestor".to_owned(),
            ));
        }
        if !self.reachable_objects_present(&repo, head, &[])? {
            return Ok(GitImportFetchOutcome::Refused(
                "source_history_incomplete".to_owned(),
            ));
        }
        Ok(GitImportFetchOutcome::Fetched(FetchedExternalGit {
            scratch,
            repo,
            base: base.clone(),
            head: head.clone(),
        }))
    }

    /// Pushes exactly `commit` from `fetched` to `name` at the loopback door
    /// relay `door_url`, only while the door's ref holds `expected` (`None`:
    /// while it does not exist). No `+`, wildcard, deletion, tag or mirror;
    /// run once, never retried here.
    ///
    /// # Errors
    /// A door URL that is not the loopback relay, or a process failure.
    pub fn push_external_to_door(
        &self,
        fetched: &FetchedExternalGit,
        door_url: &str,
        name: &GitRefName,
        commit: &GitOid,
        expected: Option<&GitOid>,
    ) -> Result<GitImportPushOutcome> {
        if commit != fetched.base() && commit != fetched.head() {
            return Err(invalid("an import push sends only its proved base or head"));
        }
        let root = fetched.scratch.path().canonicalize()?;
        let mut env = self.process_env.clone();
        env.import_profile = Some(ImportProcessProfile::relay(&root, door_url)?);
        let mut tail = os_args(&[
            "push",
            "--porcelain",
            "--no-verify",
            "--no-recurse-submodules",
        ]);
        tail.push(OsString::from(format!(
            "--force-with-lease={}:{}",
            name.as_str(),
            expected.map_or("", GitOid::as_str)
        )));
        tail.push(OsString::from("--"));
        tail.push(OsString::from(door_url));
        tail.push(OsString::from(format!(
            "{}:{}",
            commit.as_str(),
            name.as_str()
        )));
        let push = FrozenGitArgv::frozen(GitWireOperation::ImportDoorPush, tail);
        let output = spawn_git(&env, &GitCommandSpec::wire(fetched.repo.repo_root(), &push))?;
        Ok(push_outcome(&output, commit, name))
    }

    /// The scratch ref's value, read from the scratch store itself.
    fn scratch_ref(&self, repo_dir: &Path) -> Result<Option<GitOid>> {
        let name = GitRefName::parse_full(IMPORT_SCRATCH_REF)?;
        let argv = FrozenGitArgv::read_refs(std::slice::from_ref(&name));
        let output = spawn_git(&self.process_env, &GitCommandSpec::wire(repo_dir, &argv))?;
        if !output.success {
            return Err(classify_failure(&output).error(GitWireOperation::ReadRefs));
        }
        let text = std::str::from_utf8(&output.stdout)
            .map_err(|_| invalid("git ref listing must be UTF-8"))?;
        for line in text.lines() {
            let Some((oid, listed)) = line.split_once(' ') else {
                return Err(invalid("git ref listing line is malformed"));
            };
            if listed == IMPORT_SCRATCH_REF {
                return Ok(Some(GitOid::parse_hex(oid)?));
            }
        }
        Ok(None)
    }
}

/// An outside source URL: https, a host, a path, and no userinfo, query,
/// fragment, space or control byte.
fn validate_source_url(url: &str) -> Result<()> {
    validate_argv_token(url)?;
    let Some(rest) = url.strip_prefix("https://") else {
        return Err(invalid("an outside import fetches over https only"));
    };
    let host = rest.split('/').next().unwrap_or_default();
    if host.is_empty()
        || rest.len() == host.len()
        || url.contains(['@', '?', '#'])
        || url
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ' || byte == b'\\')
    {
        return Err(invalid(
            "an outside import URL names a host and a path, with no userinfo, query or fragment",
        ));
    }
    Ok(())
}

/// A refused leg's stable reason: the operation and its failure class.
fn refused(output: &GitWireProcessOutput, operation: GitWireOperation) -> GitImportFetchOutcome {
    let class = classify_failure(output).class().as_str();
    GitImportFetchOutcome::Refused(format!("{}_failed:{class}", operation.as_str()))
}

/// The outcome a `push --porcelain` child reports for `commit` at `name`.
fn push_outcome(
    output: &GitWireProcessOutput,
    commit: &GitOid,
    name: &GitRefName,
) -> GitImportPushOutcome {
    let spec = format!("{}:{}", commit.as_str(), name.as_str());
    let line = String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| {
            let mut fields = line.split('\t');
            let flag = fields.next()?.to_owned();
            (fields.next()? == spec).then(|| (flag, fields.next().unwrap_or_default().to_owned()))
        });
    let class = classify_failure(output).class().as_str();
    match line {
        Some((flag, _)) if matches!(flag.as_str(), " " | "+" | "*" | "=") && output.success => {
            GitImportPushOutcome::Applied
        }
        Some((flag, summary)) if flag == "!" => {
            GitImportPushOutcome::Rejected(if summary.contains("stale info") {
                "lease_mismatch".to_owned()
            } else if summary.contains("remote rejected") {
                "door_rejected".to_owned()
            } else {
                "push_rejected".to_owned()
            })
        }
        _ if output.success => GitImportPushOutcome::Unknown("push_named_no_outcome".to_owned()),
        _ => GitImportPushOutcome::Unknown(format!("import_door_push_failed:{class}")),
    }
}
