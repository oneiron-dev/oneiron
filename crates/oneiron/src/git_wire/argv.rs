//! Frozen typed argv: one constructor per git verb plus the token validators.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use super::config::{GIT_WIRE_MAX_ARG_BYTES, GIT_WIRE_MAX_REF_BYTES};
use super::failure::invalid;
use super::objects::encode_mktree_entries;
use super::retained_object::{GitRetainedObject, RetainedGitIo};
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
    worktree: Option<(PathBuf, GitOid)>,
    /// Spooled stdin and stdout (FIX 7608 slice 2b-i); none for a captured
    /// call.
    retained: RetainedGitIo,
}

impl FrozenGitArgv {
    pub(super) fn frozen(operation: GitWireOperation, tail: Vec<OsString>) -> Self {
        Self {
            operation,
            args: tail,
            stdin: None,
            worktree: None,
            retained: RetainedGitIo::default(),
        }
    }

    fn with_stdin(mut self, payload: Vec<u8>) -> Self {
        self.stdin = Some(payload);
        self
    }

    /// `for-each-ref` over exact full ref names. A ref that does not exist is
    /// simply absent from the output; the status stays zero.
    ///
    /// git matches a plain pattern "completely or up to a slash", so an absent
    /// name would list every ref beneath it. Each name goes in with its last
    /// byte escaped: no ref name holds a backslash, so the plain match never
    /// applies, and the glob match takes the name alone.
    pub(super) fn read_refs(names: &[GitRefName]) -> Self {
        let mut tail = os_args(&["for-each-ref", "--format=%(objectname) %(refname)"]);
        for name in names {
            // A GitRefName is [A-Za-z0-9._-/], never empty and never ends in
            // `/`: it holds no glob byte, and its last byte escapes to itself.
            let (head, last) = name.as_str().split_at(name.as_str().len() - 1);
            tail.push(OsString::from(format!("{head}\\{last}")));
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

    /// `rev-list --objects --stdin` over the tips on stdin, with git leaving
    /// out every blob of `below_bytes` or more: each commit, tree and tag the
    /// tips' whole history reaches, and each smaller blob, once. A missing
    /// object prints with a `?` prefix. Stdin carries the tips, so no ref
    /// count is bounded by argv.
    ///
    /// `exclude` goes on stdin as `^<oid>` lines: git walks none of the
    /// commits they reach, and lists none of the objects their trees reach.
    pub(super) fn reachable_objects_below(
        tips: &[GitOid],
        exclude: &[GitOid],
        below_bytes: u64,
    ) -> Self {
        let mut tail = os_args(&[
            "rev-list",
            "--objects",
            "--no-object-names",
            "--missing=print",
        ]);
        tail.push(OsString::from(format!("--filter=blob:limit={below_bytes}")));
        tail.push(OsString::from("--stdin"));
        Self::frozen(GitWireOperation::ReachableObjects, tail)
            .with_stdin(revision_lines(tips, exclude))
    }

    /// `rev-list --topo-order --parents --max-count=<count> --stdin`: up to
    /// `count` of the commits the tips on stdin reach and the `^<oid>` lines
    /// do not, each before its parents, each line the commit then its
    /// parents.
    pub(super) fn commit_page(tips: &[GitOid], exclude: &[GitOid], count: usize) -> Self {
        let mut tail = os_args(&["rev-list", "--topo-order", "--parents"]);
        tail.push(OsString::from(format!("--max-count={count}")));
        tail.push(OsString::from("--stdin"));
        Self::frozen(GitWireOperation::ReachableObjects, tail)
            .with_stdin(revision_lines(tips, exclude))
    }

    /// `rev-list --max-count=1 --stdin`: one commit that `commits` reach and
    /// `tips` do not, or nothing at all.
    pub(super) fn commits_outside(commits: &[GitOid], tips: &[GitOid]) -> Self {
        let tail = os_args(&["rev-list", "--max-count=1", "--stdin"]);
        Self::frozen(GitWireOperation::ReachableObjects, tail)
            .with_stdin(revision_lines(commits, tips))
    }

    /// `cat-file --batch-check` over `<oid><peel>` names on stdin, `peel`
    /// being `^{}` (through every tag) or `^{tree}`: per name, the object
    /// it peels to as `<oid> <type> <size>`, or `<name> missing`.
    pub(super) fn object_info_peeled(oids: &[GitOid], peel: &str) -> Self {
        let tail = os_args(&["cat-file", "--batch-check", "--buffer"]);
        let mut payload = Vec::new();
        for oid in oids {
            payload.extend_from_slice(oid.as_str().as_bytes());
            payload.extend_from_slice(peel.as_bytes());
            payload.push(b'\n');
        }
        Self::frozen(GitWireOperation::ObjectInfo, tail).with_stdin(payload)
    }

    /// `cat-file --batch` over oids on stdin: per object a `<oid> <type>
    /// <size>` line, its raw bytes and a newline; a missing one is reported
    /// as `<oid> missing`.
    pub(super) fn read_objects(oids: &[GitOid]) -> Self {
        let tail = os_args(&["cat-file", "--batch", "--buffer"]);
        let mut payload = Vec::new();
        for oid in oids {
            payload.extend_from_slice(oid.as_str().as_bytes());
            payload.push(b'\n');
        }
        Self::frozen(GitWireOperation::ReadObject, tail).with_stdin(payload)
    }

    /// `ls-tree -z`: the direct entries of one tree.
    pub(super) fn read_tree(tree: &GitOid) -> Self {
        let tail = os_args(&["ls-tree", "-z", tree.as_str()]);
        Self::frozen(GitWireOperation::ReadTree, tail)
    }

    /// `ls-tree -z <tree> -- :(top,literal)<name>`: only the entry `name`
    /// names in one tree, so the output stays one entry however wide the tree
    /// is. The magic reads `name` as one literal component from the root,
    /// never as a glob or as relative to the working directory.
    pub(super) fn read_tree_entry(tree: &GitOid, name: &str) -> GitWireResult<Self> {
        if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\0']) {
            return Err(invalid("git tree entry name must be one path component"));
        }
        let mut tail = os_args(&["ls-tree", "-z", tree.as_str(), "--"]);
        tail.push(OsString::from(format!(":(top,literal){name}")));
        Ok(Self::frozen(GitWireOperation::ReadTree, tail))
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

    /// `hash-object -t <type> -w --literally --stdin` with one retained
    /// object streamed from its spool (FIX 7608 slice 2b-i), for each of
    /// the four types. `--literally` keeps a stored object's bytes exact
    /// however old its format: the copy is the object, not a reparse.
    pub(super) fn write_retained(object: &GitRetainedObject) -> Self {
        let kind = object.kind();
        let tail = os_args(&[
            "hash-object",
            "-t",
            kind.as_str(),
            "-w",
            "--literally",
            "--stdin",
        ]);
        let mut argv = Self::frozen(kind.write_operation(), tail);
        argv.retained = RetainedGitIo::default().with_stdin(object.spool().clone());
        argv
    }

    /// The same call with its stdout spooled whole instead of captured
    /// (FIX 7608 slice 2b-i): no output or wall-clock bound.
    pub(super) fn with_spooled_stdout(mut self) -> Self {
        self.retained = self.retained.with_spooled_stdout();
        self
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

    /// `push --porcelain --no-verify -- <url> +<oid>:<ref>... :<ref>...`: the
    /// mirror takes exactly the named pairs, forced, and loses exactly the
    /// named deletions. Never `--mirror`: keep-refs and unpublished refs stay
    /// home.
    pub(super) fn mirror_push(
        url: &str,
        refs: &[(GitRefName, GitOid)],
        deletions: &[GitRefName],
    ) -> GitWireResult<Self> {
        validate_argv_token(url)?;
        let mut tail = os_args(&[
            "push",
            "--porcelain",
            "--no-verify",
            "--no-recurse-submodules",
            "--",
        ]);
        tail.push(OsString::from(url));
        for (name, oid) in refs {
            tail.push(OsString::from(format!(
                "+{}:{}",
                oid.as_str(),
                name.as_str()
            )));
        }
        for name in deletions {
            tail.push(OsString::from(format!(":{}", name.as_str())));
        }
        Ok(Self::frozen(GitWireOperation::MirrorPush, tail))
    }

    /// `ls-remote --refs -- <url> <ref>`: what one https mirror holds at one
    /// full ref (FIX 6866). A ref the mirror lacks is absent from a
    /// successful listing; the caller takes only the exact name.
    pub(super) fn remote_ref(url: &str, name: &GitRefName) -> GitWireResult<Self> {
        validate_argv_token(url)?;
        let mut tail = os_args(&["ls-remote", "--refs", "--"]);
        tail.push(OsString::from(url));
        tail.push(OsString::from(name.as_str()));
        Ok(Self::frozen(GitWireOperation::RemoteRefs, tail))
    }

    /// `push --porcelain --no-verify --no-recurse-submodules
    /// --force-with-lease=<ref>:<old> -- <url> <oid>:<ref>`: exactly one
    /// commit to exactly one ref (FIX 6866), and only while the mirror's ref
    /// still holds `expected` (`None`: while it does not exist). No `+`
    /// refspec overrides the lease, and nothing is deleted.
    pub(super) fn publish_push(
        url: &str,
        name: &GitRefName,
        commit: &GitOid,
        expected: Option<&GitOid>,
    ) -> GitWireResult<Self> {
        validate_argv_token(url)?;
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
        tail.push(OsString::from(url));
        tail.push(OsString::from(format!(
            "{}:{}",
            commit.as_str(),
            name.as_str()
        )));
        Ok(Self::frozen(GitWireOperation::PublishPush, tail))
    }

    /// `diff-tree --stdin -r -m --root --no-renames -z --raw`, each stdin
    /// line a commit then the parents it is diffed against (FIX 6866): per
    /// commit and parent, every path whose entry differs, NUL-framed; a root
    /// commit against the empty tree. A commit that changes nothing prints
    /// nothing.
    pub(super) fn review_diffs(commits: &[(GitOid, Vec<GitOid>)]) -> Self {
        let tail = os_args(&[
            "diff-tree",
            "--stdin",
            "-r",
            "-m",
            "--root",
            "--no-renames",
            "-z",
            "--raw",
        ]);
        let mut payload = Vec::new();
        for (commit, parents) in commits {
            payload.extend_from_slice(commit.as_str().as_bytes());
            for parent in parents {
                payload.push(b' ');
                payload.extend_from_slice(parent.as_str().as_bytes());
            }
            payload.push(b'\n');
        }
        Self::frozen(GitWireOperation::ReviewDiffs, tail).with_stdin(payload)
    }

    /// `worktree add --detach -- <path> <commit>`: materializes exactly one
    /// commit and never moves the repository head.
    pub(super) fn worktree_add(path: &Path, commit: &GitOid) -> GitWireResult<Self> {
        validate_path_arg(path)?;
        let mut tail = os_args(&["worktree", "add", "--detach", "--"]);
        tail.push(path.as_os_str().to_owned());
        tail.push(OsString::from(commit.as_str()));
        let mut argv = Self::frozen(GitWireOperation::WorktreeAdd, tail);
        argv.worktree = Some((path.to_path_buf(), commit.clone()));
        Ok(argv)
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

    pub(super) const fn retained(&self) -> &RetainedGitIo {
        &self.retained
    }

    pub(super) fn worktree_target(&self) -> Option<(&Path, &GitOid)> {
        self.worktree
            .as_ref()
            .map(|(path, commit)| (path.as_path(), commit))
    }
}

/// Stdin revisions for a `--stdin` walk: each of `include`, then each of
/// `exclude` as `^<oid>`.
fn revision_lines(include: &[GitOid], exclude: &[GitOid]) -> Vec<u8> {
    let mut payload = Vec::new();
    for oid in include {
        payload.extend_from_slice(oid.as_str().as_bytes());
        payload.push(b'\n');
    }
    for oid in exclude {
        payload.push(b'^');
        payload.extend_from_slice(oid.as_str().as_bytes());
        payload.push(b'\n');
    }
    payload
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
