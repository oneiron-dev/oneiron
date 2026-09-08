//! Frozen typed argv: one constructor per git verb plus the token validators.

use std::ffi::OsString;
use std::path::Path;

use super::config::{GIT_WIRE_MAX_ARG_BYTES, GIT_WIRE_MAX_REF_BYTES};
use super::failure::invalid;
use super::objects::encode_mktree_entries;
use super::{
    GitCommitRequest, GitOid, GitRefName, GitRefPublication, GitTreeEntry, GitWireOperation,
    GitWireResult,
};
use crate::error::Result;

/// A frozen git argv: a fixed verb, validated argument positions, and an
/// optional stdin payload.
///
/// Every field is private and every constructor is typed, so no caller can
/// assemble an arbitrary vector or a shell string. Every GitWire argv requires
/// exit status zero: absence is always read from output, never from a status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct FrozenGitArgv {
    operation: GitWireOperation,
    args: Vec<OsString>,
    stdin: Option<Vec<u8>>,
}

impl FrozenGitArgv {
    pub(super) fn frozen(operation: GitWireOperation, tail: Vec<OsString>) -> Self {
        Self {
            operation,
            args: tail,
            stdin: None,
        }
    }

    fn with_stdin(mut self, payload: Vec<u8>) -> Self {
        self.stdin = Some(payload);
        self
    }

    /// `for-each-ref` over exact full ref names. A ref that does not exist is
    /// simply absent from the output; the status stays zero.
    pub(super) fn read_refs(names: &[GitRefName]) -> Self {
        let mut tail = os_args(&["for-each-ref", "--format=%(objectname) %(refname)"]);
        for name in names {
            tail.push(OsString::from(name.as_str()));
        }
        Self::frozen(GitWireOperation::ReadRefs, tail)
    }

    /// `cat-file --batch-check` over oids on stdin. A missing object is
    /// reported as `<oid> missing`, so absence is a positive answer.
    pub(super) fn object_info(oids: &[GitOid]) -> Self {
        let tail = os_args(&["cat-file", "--batch-check", "--buffer"]);
        let mut payload = Vec::new();
        for oid in oids {
            payload.extend_from_slice(oid.as_str().as_bytes());
            payload.push(b'\n');
        }
        Self::frozen(GitWireOperation::ObjectInfo, tail).with_stdin(payload)
    }

    /// `rev-list --objects --missing=print`: walks the full reachable graph and
    /// prints every missing object with a `?` prefix instead of failing or
    /// lazily fetching it.
    pub(super) fn reachable_objects(tip: &GitOid, exclude: &[GitOid]) -> Self {
        let mut tail = os_args(&[
            "rev-list",
            "--objects",
            "--no-object-names",
            "--missing=print",
        ]);
        tail.push(OsString::from(tip.as_str()));
        for oid in exclude {
            // `^<oid>` rather than `--not`: `--not` toggles the sense of every
            // following revision, so a second one would silently re-include the
            // first exclusion.
            tail.push(OsString::from(format!("^{}", oid.as_str())));
        }
        Self::frozen(GitWireOperation::ReachableObjects, tail)
    }

    /// `ls-tree -z`: the direct entries of one tree.
    pub(super) fn read_tree(tree: &GitOid) -> Self {
        let tail = os_args(&["ls-tree", "-z", tree.as_str()]);
        Self::frozen(GitWireOperation::ReadTree, tail)
    }

    /// `cat-file <type> <oid>`: the raw stored bytes of one object.
    pub(super) fn read_object(kind: &str, oid: &GitOid) -> Self {
        let tail = os_args(&["cat-file", kind, oid.as_str()]);
        Self::frozen(GitWireOperation::ReadObject, tail)
    }

    /// `rev-parse --verify <revision>^{commit}`.
    pub(super) fn rev_parse_commit(revision: &str) -> GitWireResult<Self> {
        validate_revision(revision)?;
        let peeled = format!("{revision}^{{commit}}");
        let tail = os_args(&["rev-parse", "--verify", "--end-of-options", &peeled]);
        Ok(Self::frozen(GitWireOperation::RevParse, tail))
    }

    /// `merge-base` over two validated revisions.
    pub(super) fn merge_base(left: &str, right: &str) -> GitWireResult<Self> {
        validate_revision(left)?;
        validate_revision(right)?;
        let tail = os_args(&["merge-base", "--end-of-options", left, right]);
        Ok(Self::frozen(GitWireOperation::MergeBase, tail))
    }

    /// `rev-parse --path-format=absolute --git-common-dir`.
    pub(super) fn git_common_dir() -> Self {
        let tail = os_args(&["rev-parse", "--path-format=absolute", "--git-common-dir"]);
        Self::frozen(GitWireOperation::GitPath, tail)
    }

    /// `worktree list --porcelain -z`.
    pub(super) fn worktree_list() -> Self {
        let tail = os_args(&["worktree", "list", "--porcelain", "-z"]);
        Self::frozen(GitWireOperation::WorktreeList, tail)
    }

    /// `--no-optional-locks status --porcelain -z`: inspection that refreshes
    /// no index and takes no optional lock.
    pub(super) fn status_porcelain() -> Self {
        let tail = os_args(&[
            "--no-optional-locks",
            "status",
            "--porcelain",
            "-z",
            "--ignore-submodules=all",
        ]);
        Self::frozen(GitWireOperation::StatusPorcelain, tail)
    }

    /// `notes --ref <ref> show <commit>`.
    pub(super) fn notes_show(notes_ref: &GitRefName, commit: &GitOid) -> Self {
        let tail = os_args(&[
            "notes",
            "--ref",
            notes_ref.as_str(),
            "show",
            commit.as_str(),
        ]);
        Self::frozen(GitWireOperation::NotesShow, tail)
    }

    /// `hash-object -t blob -w --stdin` with the content on stdin.
    pub(super) fn write_blob(bytes: &[u8]) -> Self {
        let tail = os_args(&["hash-object", "-t", "blob", "-w", "--stdin"]);
        Self::frozen(GitWireOperation::WriteBlob, tail).with_stdin(bytes.to_vec())
    }

    /// `mktree -z` with NUL-terminated entry records on stdin. NUL framing
    /// makes every legal git path name expressible, newlines included.
    pub(super) fn write_tree(entries: &[GitTreeEntry]) -> GitWireResult<Self> {
        let payload = encode_mktree_entries(entries)?;
        let tail = os_args(&["mktree", "-z"]);
        Ok(Self::frozen(GitWireOperation::WriteTree, tail).with_stdin(payload))
    }

    /// `hash-object -t commit -w --stdin` with the serialized commit on stdin.
    pub(super) fn write_commit(request: &GitCommitRequest) -> GitWireResult<Self> {
        let payload = request.to_object_bytes()?;
        let tail = os_args(&["hash-object", "-t", "commit", "-w", "--stdin"]);
        Ok(Self::frozen(GitWireOperation::WriteCommit, tail).with_stdin(payload))
    }

    /// `update-ref --stdin --no-deref`: the one transactional publication.
    /// git applies the batch atomically, so no partial multi-ref state exists.
    pub(super) fn publish_refs(publications: &[GitRefPublication]) -> Self {
        let tail = os_args(&["update-ref", "--no-deref", "--stdin"]);
        let mut payload = String::new();
        for publication in publications {
            payload.push_str(&publication.stdin_line());
        }
        Self::frozen(GitWireOperation::PublishRefs, tail).with_stdin(payload.into_bytes())
    }

    /// `worktree add --detach -- <path> <commit>`: materializes exactly one
    /// commit and never moves the repository head.
    pub(super) fn worktree_add(path: &Path, commit: &GitOid) -> GitWireResult<Self> {
        validate_path_arg(path)?;
        let mut tail = os_args(&["worktree", "add", "--detach", "--"]);
        tail.push(path.as_os_str().to_owned());
        tail.push(OsString::from(commit.as_str()));
        Ok(Self::frozen(GitWireOperation::WorktreeAdd, tail))
    }

    /// `worktree remove --force -- <path>`.
    pub(super) fn worktree_remove(path: &Path) -> GitWireResult<Self> {
        validate_path_arg(path)?;
        let mut tail = os_args(&["worktree", "remove", "--force", "--"]);
        tail.push(path.as_os_str().to_owned());
        Ok(Self::frozen(GitWireOperation::WorktreeRemove, tail))
    }

    /// `worktree prune`: reconciles registration with the filesystem.
    pub(super) fn worktree_prune() -> Self {
        Self::frozen(
            GitWireOperation::WorktreePrune,
            os_args(&["worktree", "prune"]),
        )
    }

    pub(super) const fn operation(&self) -> GitWireOperation {
        self.operation
    }

    pub(super) fn args(&self) -> &[OsString] {
        &self.args
    }

    pub(super) fn stdin(&self) -> Option<&[u8]> {
        self.stdin.as_deref()
    }
}

pub(super) fn os_args(args: &[&str]) -> Vec<OsString> {
    args.iter().map(|arg| OsString::from(*arg)).collect()
}

fn validate_revision(revision: &str) -> Result<()> {
    if revision.is_empty() || revision.len() > GIT_WIRE_MAX_REF_BYTES {
        return Err(invalid("git revision must be non-empty and bounded"));
    }
    if revision.starts_with('-') {
        return Err(invalid("git revision must not be parsed as an option"));
    }
    if revision
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte == b' ')
    {
        return Err(invalid(
            "git revision must not contain control or space bytes",
        ));
    }
    Ok(())
}

fn validate_path_arg(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty() {
        return Err(invalid("git path argument must be non-empty"));
    }
    if path.as_os_str().as_encoded_bytes().contains(&0) {
        return Err(invalid("git path argument must not contain NUL"));
    }
    if !path.is_absolute() {
        return Err(invalid("git path argument must be absolute"));
    }
    Ok(())
}

pub(super) fn validate_argv_token(arg: &str) -> Result<()> {
    if arg.len() > GIT_WIRE_MAX_ARG_BYTES {
        return Err(invalid("git argument exceeds the frozen length bound"));
    }
    if arg.contains('\0') {
        return Err(invalid("git argument must not contain NUL"));
    }
    Ok(())
}
