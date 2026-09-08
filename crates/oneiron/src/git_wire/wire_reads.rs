//! The `GitWire` handle, its constructors, the process seam, and the read path.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use super::argv::FrozenGitArgv;
use super::failure::{classify_failure, invalid};
use super::objects::parse_tree_entries;
use super::process::spawn_git;
use super::repo::repo_identity_for;
use super::{
    GitOid, GitRefName, GitTreeEntry, GitWireFailure, GitWireProcessEnv, GitWireProcessOutput,
    GitWireRepo, GitWireResult, ObservedGitRef,
};
use crate::Vault;
use crate::codebase::RepoRef;
use crate::error::{Error, Result};

/// The typed git seam. One handle owns the pinned process baseline and the
/// vault its durable records live in.
pub struct GitWire<'a> {
    pub(super) vault: &'a Vault,
    pub(super) process_env: GitWireProcessEnv,
}

impl<'a> GitWire<'a> {
    /// Opens the wire over a vault with a freshly pinned process baseline.
    pub fn new(vault: &'a Vault) -> GitWireResult<Self> {
        Ok(Self {
            vault,
            process_env: GitWireProcessEnv::capture()?,
        })
    }

    /// Opens the wire with an explicit process baseline.
    pub fn with_process_env(vault: &'a Vault, process_env: GitWireProcessEnv) -> Self {
        Self { vault, process_env }
    }
}

impl GitWire<'_> {
    /// The frozen process baseline every child inherits.
    pub fn process_env(&self) -> &GitWireProcessEnv {
        &self.process_env
    }

    /// Proves that a repo_ref, a working root, and a pinned commit all name one
    /// object store, and binds them into a handle.
    ///
    /// The proof is what stops a receipt written against one clone from being
    /// replayed against another clone that happens to share a `RepoRef`.
    pub fn open_repo(&self, repo_ref: RepoRef, repo_root: &Path) -> GitWireResult<GitWireRepo> {
        let repo_root = repo_root
            .canonicalize()
            .map_err(|_| invalid("git wire repo root does not resolve"))?;
        let common_dir = self.canonical_common_dir(&repo_root)?;
        let identity = repo_identity_for(&common_dir);
        let repo = GitWireRepo {
            repo_ref,
            repo_root,
            common_dir,
            identity,
        };
        self.prove_repo_correspondence(&repo)?;
        Ok(repo)
    }

    fn canonical_common_dir(&self, root: &Path) -> Result<PathBuf> {
        let output = self.run_at(root, &FrozenGitArgv::git_common_dir())?;
        let text = String::from_utf8_lossy(&output.stdout);
        let path = PathBuf::from(text.trim_end_matches(['\r', '\n']));
        let path = if path.is_absolute() {
            path
        } else {
            root.join(path)
        };
        path.canonicalize()
            .map_err(|_| invalid("git common dir does not resolve"))
    }

    /// Verifies that the repo_ref's own path resolves to the same object store
    /// and that the pinned commit is a commit in that store.
    fn prove_repo_correspondence(&self, repo: &GitWireRepo) -> Result<()> {
        let commit = repo.pinned_commit()?;
        let info = self.object_info(repo, std::slice::from_ref(&commit))?;
        if info.get(&commit).map(String::as_str) != Some("commit") {
            return Err(invalid(
                "repo_ref pins a commit that is not present in this object store",
            ));
        }
        let RepoRef::LocalFolder { path, .. } = repo.repo_ref() else {
            return Ok(());
        };
        let declared = Path::new(path)
            .canonicalize()
            .map_err(|_| invalid("local repo_ref path does not resolve"))?;
        let declared_common = self.canonical_common_dir(&declared)?;
        if declared_common != repo.common_dir {
            return Err(invalid(
                "local repo_ref path and working root are different repositories",
            ));
        }
        Ok(())
    }

    // -- process seam ------------------------------------------------------

    fn run_at(&self, root: &Path, argv: &FrozenGitArgv) -> Result<GitWireProcessOutput> {
        let output = self.run_raw_at(root, argv)?;
        if output.success {
            return Ok(output);
        }
        Err(classify_failure(&output).error(argv.operation()))
    }

    fn run_raw_at(&self, root: &Path, argv: &FrozenGitArgv) -> Result<GitWireProcessOutput> {
        spawn_git(&self.process_env, root, argv.args(), argv.stdin())
    }

    /// Runs a read. Every operation whose effect class is not [`Read`] is
    /// refused before a child can be spawned, so a "read" can never remove a
    /// worktree or move a ref.
    ///
    /// [`Read`]: GitWireEffectClass::Read
    pub(super) fn run_read(
        &self,
        repo: &GitWireRepo,
        argv: &FrozenGitArgv,
    ) -> Result<GitWireProcessOutput> {
        if !argv.operation().effect_class().is_read() {
            return Err(invalid("git wire read phase refuses a mutating operation"));
        }
        self.run_at(&repo.repo_root, argv)
    }

    /// Runs a mutation. A read is refused here in the same way, so a read can
    /// never be laundered into a durable mutation record.
    pub(super) fn run_mutation(
        &self,
        repo: &GitWireRepo,
        argv: &FrozenGitArgv,
    ) -> Result<GitWireProcessOutput> {
        if argv.operation().effect_class().is_read() {
            return Err(invalid(
                "git wire mutation phase refuses a read-only operation",
            ));
        }
        self.run_at(&repo.repo_root, argv)
    }

    /// Runs a ref publication. Object-producing work is structurally impossible
    /// here, so the transactional phase can never create objects.
    pub(super) fn run_publication(
        &self,
        repo: &GitWireRepo,
        argv: &FrozenGitArgv,
    ) -> Result<std::result::Result<GitWireProcessOutput, GitWireFailure>> {
        if argv.operation().effect_class().writes_objects() {
            return Err(Error::InvariantViolation(
                "git wire publication phase refuses an object-producing operation",
            ));
        }
        let output = self.run_raw_at(&repo.repo_root, argv)?;
        if output.success {
            return Ok(Ok(output));
        }
        Ok(Err(classify_failure(&output)))
    }

    // -- reads -------------------------------------------------------------

    /// Reads several full refs at once. A ref that does not exist is reported
    /// as absent from a successful command, never as an exit status.
    pub fn read_refs(
        &self,
        repo: &GitWireRepo,
        names: &[GitRefName],
    ) -> GitWireResult<Vec<ObservedGitRef>> {
        if names.is_empty() {
            return Ok(Vec::new());
        }
        let output = self.run_read(repo, &FrozenGitArgv::read_refs(names))?;
        let present = parse_ref_listing(&output.stdout)?;
        let mut observed = Vec::with_capacity(names.len());
        for name in names {
            observed.push(ObservedGitRef {
                name: name.clone(),
                oid: present.get(name.as_str()).cloned(),
            });
        }
        Ok(observed)
    }

    /// Reads one full ref, or `None` when it does not exist.
    pub fn read_ref(&self, repo: &GitWireRepo, name: &GitRefName) -> GitWireResult<Option<GitOid>> {
        let observed = self.read_refs(repo, std::slice::from_ref(name))?;
        Ok(observed.into_iter().next().and_then(|entry| entry.oid))
    }

    /// The git type of each named object, absent when the object is missing.
    pub fn object_info(
        &self,
        repo: &GitWireRepo,
        oids: &[GitOid],
    ) -> GitWireResult<HashMap<GitOid, String>> {
        if oids.is_empty() {
            return Ok(HashMap::new());
        }
        let output = self.run_read(repo, &FrozenGitArgv::object_info(oids))?;
        parse_object_info(&output.stdout)
    }

    /// Whether an object is present in this object store.
    pub fn object_exists(&self, repo: &GitWireRepo, oid: &GitOid) -> GitWireResult<bool> {
        let info = self.object_info(repo, std::slice::from_ref(oid))?;
        Ok(info.contains_key(oid))
    }

    /// Whether the *whole* graph reachable from `tip` is present, excluding
    /// what is already reachable from `already_verified`.
    ///
    /// Tip presence alone is not enough to publish a ref: a ref that names a
    /// commit whose tree or parent is missing is an unusable ref.
    ///
    /// Every entry of `already_verified` must have been *proved* complete by
    /// the caller. Git stops the walk at those objects, so an exclusion the
    /// caller merely assumes is whole answers `true` over a graph nobody
    /// checked, including the part of it the tip itself needs.
    pub fn reachable_objects_present(
        &self,
        repo: &GitWireRepo,
        tip: &GitOid,
        already_verified: &[GitOid],
    ) -> GitWireResult<bool> {
        let info = self.object_info(repo, std::slice::from_ref(tip))?;
        let Some(kind) = info.get(tip) else {
            return Ok(false);
        };
        // A blob has no outgoing edges, so its own presence is its whole graph.
        if kind == "blob" {
            return Ok(true);
        }
        let argv = FrozenGitArgv::reachable_objects(tip, already_verified);
        let output = self.run_read(repo, &argv)?;
        let complete = !output
            .stdout
            .split(|byte| *byte == b'\n')
            .any(|line| line.first() == Some(&b'?'));
        Ok(complete)
    }

    /// The direct entries of one tree object.
    pub fn read_tree(&self, repo: &GitWireRepo, tree: &GitOid) -> GitWireResult<Vec<GitTreeEntry>> {
        let output = self.run_read(repo, &FrozenGitArgv::read_tree(tree))?;
        parse_tree_entries(&output.stdout)
    }

    /// The raw stored bytes of one object, in git's own encoding for its type.
    pub fn read_object(&self, repo: &GitWireRepo, oid: &GitOid) -> GitWireResult<Vec<u8>> {
        let info = self.object_info(repo, std::slice::from_ref(oid))?;
        let kind = info
            .get(oid)
            .ok_or_else(|| invalid("git object is not present in this object store"))?;
        if !matches!(kind.as_str(), "blob" | "tree" | "commit" | "tag") {
            return Err(invalid("git object type is not readable"));
        }
        let argv = FrozenGitArgv::read_object(kind, oid);
        Ok(self.run_read(repo, &argv)?.stdout)
    }

    /// Resolves a revision to the commit it names.
    pub fn resolve_commit(&self, repo: &GitWireRepo, revision: &str) -> GitWireResult<GitOid> {
        let argv = FrozenGitArgv::rev_parse_commit(revision)?;
        let output = self.run_read(repo, &argv)?;
        parse_oid_output(&output.stdout)
    }

    /// The merge base of two revisions.
    pub fn merge_base(&self, repo: &GitWireRepo, left: &str, right: &str) -> GitWireResult<GitOid> {
        let argv = FrozenGitArgv::merge_base(left, right)?;
        let output = self.run_read(repo, &argv)?;
        parse_oid_output(&output.stdout)
    }

    /// The note recorded for a commit, or `None` when there is none.
    pub fn read_note(
        &self,
        repo: &GitWireRepo,
        notes_ref: &GitRefName,
        commit: &GitOid,
    ) -> GitWireResult<Option<Vec<u8>>> {
        let head = self.read_ref(repo, notes_ref)?;
        if head.is_none() {
            return Ok(None);
        }
        let argv = FrozenGitArgv::notes_show(notes_ref, commit);
        match self.run_read(repo, &argv) {
            Ok(output) => Ok(Some(output.stdout)),
            Err(_) => Ok(None),
        }
    }
}

fn parse_ref_listing(stdout: &[u8]) -> Result<HashMap<String, GitOid>> {
    let text = std::str::from_utf8(stdout).map_err(|_| invalid("git ref listing must be UTF-8"))?;
    let mut present = HashMap::new();
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        let (oid, name) = line
            .split_once(' ')
            .ok_or_else(|| invalid("git ref listing record is malformed"))?;
        present.insert(name.to_owned(), GitOid::parse_hex(oid)?);
    }
    Ok(present)
}

fn parse_object_info(stdout: &[u8]) -> Result<HashMap<GitOid, String>> {
    let text = String::from_utf8_lossy(stdout);
    let mut info = HashMap::new();
    for line in text.lines() {
        let mut fields = line.split(' ');
        let Some(oid) = fields.next() else {
            continue;
        };
        let Some(kind) = fields.next() else {
            continue;
        };
        if kind == "missing" {
            continue;
        }
        info.insert(GitOid::parse_hex(oid)?, kind.to_owned());
    }
    Ok(info)
}

pub(super) fn parse_oid_output(stdout: &[u8]) -> Result<GitOid> {
    let text = String::from_utf8_lossy(stdout);
    let field = text
        .split_whitespace()
        .next()
        .ok_or_else(|| invalid("git did not print an object id"))?;
    GitOid::parse_hex(field)
}
