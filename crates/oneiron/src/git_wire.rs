//! Engine-owned typed git subprocess boundary (ONE-1903, RC6/ARCH-0068).
//!
//! Every engine-initiated git call is a GitWire-class effect: frozen argv,
//! scoped environment, no inherited hooks, no ambient credential helper,
//! observed-ref idempotency, receipts, and crash-consistent two-phase object
//! staging. [`spawn_git`] is the crate's single production git subprocess
//! constructor; the `repo_mutation` helper cluster and the ONE-1901
//! [`CheckoutRepoOps`] port both route through it, so there is no second
//! subprocess path.
//!
//! Receipts stay local to this module under the `git_wire:receipt:v1:` and
//! `git_wire:prepared:v1:` `vault_meta` prefixes; no global `ReceiptKind` is
//! added and nothing in `receipt/` is touched.

use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::checkout::lease::{
    CheckoutError, CheckoutLeaseAct, CheckoutRepoOps, CheckoutResult, CheckoutTeardownInspection,
    GitOid as LeaseGitOid, PushedHeadReceipt, TeardownReceiptMatch,
};
use crate::codebase::RepoRef;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

#[cfg(test)]
mod tests;

/// Schema version of the durable GitWire receipt and prepared rows.
pub const GIT_WIRE_SCHEMA_VERSION: u8 = 1;
/// Domain separator of the observed-ref idempotency key.
pub const GIT_WIRE_IDEMPOTENCY_DOMAIN: &[u8] = b"oneiron:git-wire:v1";
/// `vault_meta` keyspace of GitWire receipts.
pub const GIT_WIRE_RECEIPT_KEY_PREFIX: &[u8] = b"git_wire:receipt:v1:";
/// `vault_meta` keyspace of GitWire prepared (staged-object) rows.
pub const GIT_WIRE_PREPARED_KEY_PREFIX: &[u8] = b"git_wire:prepared:v1:";
/// Inherited from the process baseline: PATH, TMPDIR, LANG, LC_ALL only.
/// `GIT_CONFIG_NOSYSTEM` and `GIT_TERMINAL_PROMPT` are NOT inherited — GitWire
/// assigns them fixed values (=1 and =0) after `env_clear`, ignoring ambient
/// values.
pub const GIT_WIRE_INHERITED_ENV_KEYS: [&str; 4] = ["PATH", "TMPDIR", "LANG", "LC_ALL"];
/// Environment pairs GitWire forces on every child regardless of the ambient
/// environment.
pub const GIT_WIRE_FIXED_ENV: [(&str, &str); 2] =
    [("GIT_CONFIG_NOSYSTEM", "1"), ("GIT_TERMINAL_PROMPT", "0")];
/// `core.hooksPath` every child is pinned to, so ambient hooks never run.
pub const GIT_WIRE_HOOKS_PATH: &str = "/dev/null";
/// Namespace of the keep-refs GitWire writes to hold staged object sets alive.
pub const GIT_WIRE_KEEP_REF_PREFIX: &str = "refs/oneiron/keep/";
/// Prefix of the checkout worktrees the [`CheckoutRepoOps`] port materializes.
pub const GIT_WIRE_CHECKOUT_WORKTREE_PREFIX: &str = "oneiron-checkout-";

/// Frozen commit identity of engine-authored notes, pinned to the value
/// `repo_mutation::trailer` already passes per call so exported notes keep
/// hashing identically.
const GIT_WIRE_NOTES_IDENTITY_NAME: &str = "Oneiron";
const GIT_WIRE_NOTES_IDENTITY_EMAIL: &str = "oneiron@example.invalid";

const GIT_WIRE_DEFAULT_BINARY: &str = "git";
const GIT_WIRE_MAX_ARG_BYTES: usize = 65_536;
const GIT_WIRE_MAX_ARGS: usize = 64;
const GIT_WIRE_MAX_REF_BYTES: usize = 255;
const GIT_WIRE_MAX_FAILURE_BYTES: usize = 4096;
const GIT_WIRE_MAX_RECEIPT_VALUE_BYTES: usize = 4096;
const GIT_WIRE_OID_HEX_LEN: usize = 40;
const GIT_WIRE_NULL_OID: &str = "0000000000000000000000000000000000000000";
/// The only `-c <key>=<value>` pairs the migration bridge accepts ahead of the
/// verb; the hooks/credential pins are added by GitWire itself.
const GIT_WIRE_BRIDGED_CONFIG_KEYS: [&str; 2] = ["user.name", "user.email"];
/// Commit-object headers a caller may never shadow through `extra_headers`.
const GIT_WIRE_RESERVED_COMMIT_HEADERS: [&str; 7] = [
    "tree",
    "parent",
    "author",
    "committer",
    "encoding",
    "gpgsig",
    "mergetag",
];

/// Result alias of every GitWire operation.
pub type GitWireResult<T> = Result<T>;

fn invalid(message: &'static str) -> Error {
    Error::InvalidRepoMutationRecord(message)
}

/// Typed name of a git effect. The wire name is what receipts and idempotency
/// keys carry, so it is stable across releases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitWireOperation {
    ObjectExists,
    ReadRef,
    RevParse,
    MergeBase,
    ReadTree,
    WriteBlob,
    WriteTree,
    WriteCommit,
    Notes,
    WorktreeAdd,
    WorktreeDrop,
    UpdateRefCas,
    SetRef,
    DeleteRef,
    WriteKeepRef,
    DeleteKeepRef,
    StageObjects,
    ReceivePack,
}

impl GitWireOperation {
    /// Stable wire name recorded in receipts and hashed into idempotency keys.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ObjectExists => "object_exists",
            Self::ReadRef => "read_ref",
            Self::RevParse => "rev_parse",
            Self::MergeBase => "merge_base",
            Self::ReadTree => "read_tree",
            Self::WriteBlob => "write_blob",
            Self::WriteTree => "write_tree",
            Self::WriteCommit => "write_commit",
            Self::Notes => "notes",
            Self::WorktreeAdd => "worktree_add",
            Self::WorktreeDrop => "worktree_drop",
            Self::UpdateRefCas => "update_ref_cas",
            Self::SetRef => "set_ref",
            Self::DeleteRef => "delete_ref",
            Self::WriteKeepRef => "write_keep_ref",
            Self::DeleteKeepRef => "delete_keep_ref",
            Self::StageObjects => "stage_objects",
            Self::ReceivePack => "receive_pack",
        }
    }

    /// Whether the operation can add objects to the repository object store.
    ///
    /// Object-producing work is only ever launched by [`GitWire::stage_objects`],
    /// before any LMDB write transaction is open. `worktree_add` is classified
    /// honestly: its checkout can materialize objects and index state.
    pub const fn may_write_objects(self) -> bool {
        matches!(
            self,
            Self::WriteBlob
                | Self::WriteTree
                | Self::WriteCommit
                | Self::Notes
                | Self::WorktreeAdd
                | Self::StageObjects
                | Self::ReceivePack
        )
    }

    /// Whether the operation can move a ref.
    pub const fn may_update_refs(self) -> bool {
        matches!(
            self,
            Self::Notes
                | Self::UpdateRefCas
                | Self::SetRef
                | Self::DeleteRef
                | Self::WriteKeepRef
                | Self::DeleteKeepRef
                | Self::ReceivePack
        )
    }

    fn parse(value: &str) -> Result<Self> {
        const ALL: [GitWireOperation; 18] = [
            GitWireOperation::ObjectExists,
            GitWireOperation::ReadRef,
            GitWireOperation::RevParse,
            GitWireOperation::MergeBase,
            GitWireOperation::ReadTree,
            GitWireOperation::WriteBlob,
            GitWireOperation::WriteTree,
            GitWireOperation::WriteCommit,
            GitWireOperation::Notes,
            GitWireOperation::WorktreeAdd,
            GitWireOperation::WorktreeDrop,
            GitWireOperation::UpdateRefCas,
            GitWireOperation::SetRef,
            GitWireOperation::DeleteRef,
            GitWireOperation::WriteKeepRef,
            GitWireOperation::DeleteKeepRef,
            GitWireOperation::StageObjects,
            GitWireOperation::ReceivePack,
        ];
        ALL.into_iter()
            .find(|operation| operation.as_str() == value)
            .ok_or_else(|| invalid("unknown git wire operation"))
    }
}

/// A validated full git ref name (`HEAD` or `refs/...`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GitRefName(String);

impl GitRefName {
    /// Parses a full ref name. Short names, option-looking values, revision
    /// syntax, and lock/control shapes are rejected by construction.
    pub fn parse_full(value: impl Into<String>) -> GitWireResult<Self> {
        let value = value.into();
        validate_full_ref_name(&value)?;
        Ok(Self(value))
    }

    /// The validated ref name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn validate_full_ref_name(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > GIT_WIRE_MAX_REF_BYTES {
        return Err(invalid("git ref name must be non-empty and bounded"));
    }
    if value != "HEAD" && !value.starts_with("refs/") {
        return Err(invalid("git ref name must be HEAD or a full refs/ name"));
    }
    if value.contains("..")
        || value.contains("@{")
        || value.contains("//")
        || value.starts_with('/')
        || value.ends_with('/')
        || value.ends_with(".lock")
    {
        return Err(invalid("git ref name must not use revision or lock syntax"));
    }
    let forbidden = [b' ', b'~', b'^', b':', b'?', b'*', b'[', b'\\', 0x7f];
    if value
        .bytes()
        .any(|byte| byte.is_ascii_control() || forbidden.contains(&byte))
    {
        return Err(invalid(
            "git ref name must not contain control or glob bytes",
        ));
    }
    for part in value.split('/') {
        if part.is_empty() || part.starts_with('.') || part.ends_with(".lock") {
            return Err(invalid("git ref name component is not a valid ref path"));
        }
    }
    Ok(())
}

/// A validated 40-character lower-hex, non-zero git object id.
///
/// `checkout::lease` owns a byte-array `GitOid` of its own; the two convert
/// through hex at the [`CheckoutRepoOps`] boundary and never alias.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GitOid(String);

impl GitOid {
    /// Parses a 40-character lower-hex object id.
    pub fn parse_hex(value: impl Into<String>) -> GitWireResult<Self> {
        let value = value.into();
        if value.len() != GIT_WIRE_OID_HEX_LEN
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(invalid("git oid must be 40 lower-hex characters"));
        }
        if value == GIT_WIRE_NULL_OID {
            return Err(invalid("git oid must not be the null oid"));
        }
        Ok(Self(value))
    }

    /// The validated object id.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A ref and the value GitWire observed for it before an effect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedGitRef {
    pub name: GitRefName,
    pub oid: Option<GitOid>,
}

/// A frozen source/destination refspec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitRefSpec {
    pub source: GitRefName,
    pub destination: GitRefName,
    pub force: bool,
}

/// One entry of a git tree object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitTreeEntry {
    pub mode: u32,
    pub name: Vec<u8>,
    pub oid: GitOid,
}

/// A validated extra commit-object header (e.g. ORIGIN's pinned `jj:trees` /
/// `jj:conflict-labels`). Names are restricted to `[a-z0-9-]+(:[a-z0-9-]+)*`,
/// never a standard header; values are single-line with no NUL/CR/LF. This is
/// data validation, not argv — headers are serialized into the commit object
/// body, never passed on a git command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitCommitHeader {
    name: String,
    value: Vec<u8>,
}

impl GitCommitHeader {
    /// Parses an extra commit header, rejecting standard-header shadowing and
    /// any multi-line or NUL-carrying value.
    pub fn parse(name: impl Into<String>, value: impl Into<Vec<u8>>) -> GitWireResult<Self> {
        let name = name.into();
        let value = value.into();
        validate_commit_header_name(&name)?;
        if value.is_empty() || value.len() > GIT_WIRE_MAX_ARG_BYTES {
            return Err(invalid("commit header value must be non-empty and bounded"));
        }
        if value.iter().any(|byte| matches!(byte, 0 | b'\n' | b'\r')) {
            return Err(invalid("commit header value must be a single line"));
        }
        Ok(Self { name, value })
    }

    /// The validated header name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The validated header value.
    pub fn value(&self) -> &[u8] {
        &self.value
    }
}

fn validate_commit_header_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > GIT_WIRE_MAX_REF_BYTES {
        return Err(invalid("commit header name must be non-empty and bounded"));
    }
    if GIT_WIRE_RESERVED_COMMIT_HEADERS.contains(&name) {
        return Err(invalid(
            "commit header name must not shadow a standard header",
        ));
    }
    for segment in name.split(':') {
        if segment.is_empty() {
            return Err(invalid("commit header name segment must be non-empty"));
        }
        let shaped = segment
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
        if !shaped {
            return Err(invalid(
                "commit header name must match [a-z0-9-]+(:[a-z0-9-]+)*",
            ));
        }
    }
    Ok(())
}

/// A commit object GitWire serializes and writes through `hash-object`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitCommitRequest {
    pub tree: GitOid,
    pub parents: Vec<GitOid>,
    pub author_name: String,
    pub author_email: String,
    pub authored_at: i64,
    pub message: Vec<u8>,
    /// Extra object headers after the standard set. Empty for ordinary
    /// commits; required by ORIGIN for jj conflict metadata.
    pub extra_headers: Vec<GitCommitHeader>,
}

impl GitCommitRequest {
    /// Serializes the loose commit object body byte-exactly.
    fn to_object_bytes(&self) -> Result<Vec<u8>> {
        validate_commit_identity(&self.author_name)?;
        validate_commit_identity(&self.author_email)?;
        if self.message.contains(&0) {
            return Err(invalid("commit message must not contain NUL"));
        }
        let mut object = Vec::with_capacity(256 + self.message.len());
        object.extend_from_slice(format!("tree {}\n", self.tree.as_str()).as_bytes());
        for parent in &self.parents {
            object.extend_from_slice(format!("parent {}\n", parent.as_str()).as_bytes());
        }
        let identity = format!(
            "{} <{}> {} +0000",
            self.author_name, self.author_email, self.authored_at
        );
        object.extend_from_slice(format!("author {identity}\n").as_bytes());
        object.extend_from_slice(format!("committer {identity}\n").as_bytes());
        for header in &self.extra_headers {
            object.extend_from_slice(header.name().as_bytes());
            object.push(b' ');
            object.extend_from_slice(header.value());
            object.push(b'\n');
        }
        object.push(b'\n');
        object.extend_from_slice(&self.message);
        Ok(object)
    }
}

fn validate_commit_identity(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > GIT_WIRE_MAX_REF_BYTES {
        return Err(invalid("commit identity must be non-empty and bounded"));
    }
    if value
        .bytes()
        .any(|byte| byte.is_ascii_control() || matches!(byte, b'<' | b'>'))
    {
        return Err(invalid(
            "commit identity must not contain angle or control bytes",
        ));
    }
    Ok(())
}

/// Outcome of a compare-and-set ref update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GitRefCasOutcome {
    Updated {
        previous: Option<GitOid>,
        current: GitOid,
    },
    Mismatch {
        observed: Option<GitOid>,
    },
}

/// The repository an effect targets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitWireRepo {
    pub repo_ref: RepoRef,
    pub repo_root: PathBuf,
}

impl GitWireRepo {
    /// Binds a repo_ref to the resolved working root.
    pub fn new(repo_ref: RepoRef, repo_root: PathBuf) -> Self {
        Self {
            repo_ref,
            repo_root,
        }
    }

    /// Canonical repository identity hashed into idempotency keys and stored
    /// on receipts. Local repositories key on the resolved root, matching
    /// `repo_mutation`'s `canonical_repo_ref_for_root` semantics.
    pub fn canonical_identity(&self) -> String {
        match &self.repo_ref {
            RepoRef::LocalFolder { .. } => format!("local:{}", self.repo_root.display()),
            RepoRef::GitHubAtCommit { .. } => self.repo_ref.canonical(),
        }
    }
}

/// The process baseline every child inherits, captured once per handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitWireProcessEnv {
    pub git_binary: PathBuf,
    pub path: OsString,
    pub tmpdir: PathBuf,
}

impl GitWireProcessEnv {
    /// Captures the allowed process baseline (`PATH`, `TMPDIR`) and the git
    /// binary name. Nothing else is carried into a child.
    pub fn capture() -> Self {
        Self {
            git_binary: PathBuf::from(GIT_WIRE_DEFAULT_BINARY),
            path: std::env::var_os("PATH").unwrap_or_default(),
            tmpdir: std::env::temp_dir(),
        }
    }
}

/// A frozen git argv: a fixed verb, validated argument positions, an optional
/// guarded ref, an optional stdin payload, and a frozen allowed-exit-code set.
///
/// Every field is private and every constructor is typed, so no caller can
/// assemble an arbitrary vector or a shell string, and the forbidden
/// repo-mutation verb shapes are unreachable by construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrozenGitArgv {
    operation: GitWireOperation,
    args: Vec<OsString>,
    stdin: Option<Vec<u8>>,
    guarded_ref: Option<GitRefName>,
    allowed_exit_codes: Vec<i32>,
}

impl FrozenGitArgv {
    fn frozen(operation: GitWireOperation, tail: Vec<OsString>, allowed: &[i32]) -> Self {
        let mut args = policy_argv();
        args.extend(tail);
        Self {
            operation,
            args,
            stdin: None,
            guarded_ref: None,
            allowed_exit_codes: allowed.to_vec(),
        }
    }

    fn with_stdin(mut self, payload: Vec<u8>) -> Self {
        self.stdin = Some(payload);
        self
    }

    fn with_guarded_ref(mut self, name: GitRefName) -> Self {
        self.guarded_ref = Some(name);
        self
    }

    /// `show-ref --verify` for one full ref name. A missing ref exits non-zero
    /// (git reports it as a fatal 128), which the call site reads as absent.
    pub fn read_ref(name: GitRefName) -> Self {
        let tail = os_args(&["show-ref", "--verify", "--", name.as_str()]);
        Self::frozen(GitWireOperation::ReadRef, tail, &[0, 1, 128]).with_guarded_ref(name)
    }

    /// `rev-parse --verify`; a missing revision exits non-zero and the call
    /// site decides what that means.
    pub fn rev_parse(revision: &str) -> GitWireResult<Self> {
        validate_revision(revision)?;
        let tail = os_args(&["rev-parse", "--verify", revision]);
        Ok(Self::frozen(GitWireOperation::RevParse, tail, &[0, 1, 128]))
    }

    /// `merge-base` over two validated revisions.
    pub fn merge_base(left: &str, right: &str) -> GitWireResult<Self> {
        validate_revision(left)?;
        validate_revision(right)?;
        let tail = os_args(&["merge-base", left, right]);
        Ok(Self::frozen(GitWireOperation::MergeBase, tail, &[0, 1]))
    }

    /// `worktree add --detach -- <path> <base>`.
    pub fn worktree_add(path: PathBuf, base: GitRefName) -> GitWireResult<Self> {
        validate_path_arg(&path)?;
        let mut tail = os_args(&["worktree", "add", "--detach", "--"]);
        tail.push(path.into_os_string());
        tail.push(OsString::from(base.as_str()));
        Ok(Self::frozen(GitWireOperation::WorktreeAdd, tail, &[0]))
    }

    /// `worktree remove --force -- <path>`; a missing worktree exits non-zero
    /// and the call site treats that as already collected.
    pub fn worktree_drop(path: PathBuf) -> GitWireResult<Self> {
        validate_path_arg(&path)?;
        let mut tail = os_args(&["worktree", "remove", "--force", "--"]);
        tail.push(path.into_os_string());
        Ok(Self::frozen(
            GitWireOperation::WorktreeDrop,
            tail,
            &[0, 1, 128],
        ))
    }

    /// `worktree list --porcelain -z`.
    pub fn worktree_list() -> Self {
        let tail = os_args(&["worktree", "list", "--porcelain", "-z"]);
        Self::frozen(GitWireOperation::ReadTree, tail, &[0])
    }

    /// Compare-and-set ref update. An absent expected value pins the null oid,
    /// so the update only applies when the ref does not exist yet.
    pub fn update_ref(expected: ObservedGitRef, next: GitOid) -> Self {
        let previous = expected
            .oid
            .as_ref()
            .map_or(GIT_WIRE_NULL_OID, GitOid::as_str);
        let tail = os_args(&[
            "update-ref",
            expected.name.as_str(),
            next.as_str(),
            previous,
        ]);
        Self::frozen(GitWireOperation::UpdateRefCas, tail, &[0, 1, 128])
            .with_guarded_ref(expected.name)
    }

    /// Unconditional ref write.
    pub fn set_ref(name: GitRefName, next: &GitOid) -> Self {
        let tail = os_args(&["update-ref", name.as_str(), next.as_str()]);
        Self::frozen(GitWireOperation::SetRef, tail, &[0]).with_guarded_ref(name)
    }

    /// Ref deletion, optionally compare-and-set against an expected value.
    pub fn delete_ref(name: GitRefName, expected: Option<&GitOid>) -> Self {
        let mut tail = os_args(&["update-ref", "-d", name.as_str()]);
        if let Some(expected) = expected {
            tail.push(OsString::from(expected.as_str()));
        }
        Self::frozen(GitWireOperation::DeleteRef, tail, &[0, 1, 128]).with_guarded_ref(name)
    }

    /// `cat-file -e`: exit 0 means the object is present.
    pub fn object_exists(oid: &GitOid) -> Self {
        let tail = os_args(&["cat-file", "-e", oid.as_str()]);
        Self::frozen(GitWireOperation::ObjectExists, tail, &[0, 1, 128])
    }

    /// `cat-file -p`: the raw bytes of one object.
    pub fn read_object(oid: &GitOid) -> Self {
        let tail = os_args(&["cat-file", "-p", oid.as_str()]);
        Self::frozen(GitWireOperation::ReadTree, tail, &[0])
    }

    /// `ls-tree -z`: the direct entries of one tree.
    pub fn read_tree(tree: &GitOid) -> Self {
        let tail = os_args(&["ls-tree", "-z", tree.as_str()]);
        Self::frozen(GitWireOperation::ReadTree, tail, &[0])
    }

    /// `status --porcelain -z`: read-only worktree state inspection.
    pub fn status_porcelain() -> Self {
        let tail = os_args(&["status", "--porcelain", "-z"]);
        Self::frozen(GitWireOperation::ReadTree, tail, &[0])
    }

    /// `rev-parse --git-path <name>`: resolves a repository-internal path.
    pub fn git_path(name: &str) -> GitWireResult<Self> {
        validate_revision(name)?;
        let tail = os_args(&["rev-parse", "--git-path", name]);
        Ok(Self::frozen(GitWireOperation::RevParse, tail, &[0]))
    }

    /// `hash-object -w -t blob --stdin` with the content on stdin.
    pub fn write_blob(bytes: &[u8]) -> Self {
        let tail = os_args(&["hash-object", "-t", "blob", "-w", "--stdin"]);
        Self::frozen(GitWireOperation::WriteBlob, tail, &[0]).with_stdin(bytes.to_vec())
    }

    /// `mktree -z` with NUL-terminated entry records on stdin.
    pub fn write_tree(entries: &[GitTreeEntry]) -> GitWireResult<Self> {
        let payload = encode_mktree_entries(entries)?;
        let tail = os_args(&["mktree", "-z"]);
        Ok(Self::frozen(GitWireOperation::WriteTree, tail, &[0]).with_stdin(payload))
    }

    /// `hash-object -t commit -w --stdin` with the serialized commit object on
    /// stdin. Extra headers ride the object body, never the command line.
    pub fn write_commit(request: &GitCommitRequest) -> GitWireResult<Self> {
        let payload = request.to_object_bytes()?;
        let tail = os_args(&["hash-object", "-t", "commit", "-w", "--stdin"]);
        Ok(Self::frozen(GitWireOperation::WriteCommit, tail, &[0]).with_stdin(payload))
    }

    /// `notes --ref <ref> add -f -m <note> <commit>` with the engine's frozen
    /// commit identity.
    pub fn notes_add(notes_ref: GitRefName, commit: &GitOid, note: &str) -> GitWireResult<Self> {
        validate_argv_token(note)?;
        let identity_name = format!("user.name={GIT_WIRE_NOTES_IDENTITY_NAME}");
        let identity_email = format!("user.email={GIT_WIRE_NOTES_IDENTITY_EMAIL}");
        let tail = os_args(&[
            "-c",
            identity_name.as_str(),
            "-c",
            identity_email.as_str(),
            "notes",
            "--ref",
            notes_ref.as_str(),
            "add",
            "-f",
            "-m",
            note,
            commit.as_str(),
        ]);
        Ok(Self::frozen(GitWireOperation::Notes, tail, &[0]).with_guarded_ref(notes_ref))
    }

    /// `notes --ref <ref> show <commit>`; a missing note exits non-zero.
    pub fn notes_show(notes_ref: &GitRefName, commit: &GitOid) -> Self {
        let tail = os_args(&[
            "notes",
            "--ref",
            notes_ref.as_str(),
            "show",
            commit.as_str(),
        ]);
        Self::frozen(GitWireOperation::ReadTree, tail, &[0, 1, 128])
    }

    /// Reserved ORIGIN transport shape. ORIGIN owns the smart-HTTP serve path
    /// at runtime; GitWire models the effect so its refs and keep-refs still
    /// commit through this seam.
    pub fn receive_pack_stage() -> Self {
        let tail = os_args(&["receive-pack", "--stateless-rpc", "."]);
        Self::frozen(GitWireOperation::ReceivePack, tail, &[0])
    }

    /// The frozen operation.
    pub fn operation(&self) -> GitWireOperation {
        self.operation
    }

    /// The ref this effect guards, when it has one.
    pub fn guarded_ref(&self) -> Option<&GitRefName> {
        self.guarded_ref.as_ref()
    }

    /// BLAKE3 over the wire name and every frozen argument position,
    /// including the leading hooks/credential pins.
    pub fn argv_hash(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hash_field(&mut hasher, self.operation.as_str().as_bytes());
        for arg in &self.args {
            hash_field(&mut hasher, arg.as_encoded_bytes());
        }
        *hasher.finalize().as_bytes()
    }

    /// BLAKE3 over the exact stdin bytes, all-zero when there is no stdin.
    /// Load-bearing: fixed argv plus content-on-stdin would otherwise collide
    /// two distinct writes onto one idempotency key.
    pub fn stdin_hash(&self) -> [u8; 32] {
        self.stdin
            .as_deref()
            .map_or([0_u8; 32], |bytes| *blake3::hash(bytes).as_bytes())
    }

    fn args(&self) -> &[OsString] {
        &self.args
    }

    fn stdin(&self) -> Option<&[u8]> {
        self.stdin.as_deref()
    }

    fn accepts(&self, output: &GitWireProcessOutput) -> bool {
        if output.success {
            return true;
        }
        output
            .exit_code
            .is_some_and(|code| self.allowed_exit_codes.contains(&code))
    }
}

fn policy_argv() -> Vec<OsString> {
    vec![
        OsString::from("-c"),
        OsString::from(format!("core.hooksPath={GIT_WIRE_HOOKS_PATH}")),
        OsString::from("-c"),
        OsString::from("credential.helper="),
    ]
}

fn os_args(args: &[&str]) -> Vec<OsString> {
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
    Ok(())
}

fn validate_argv_token(arg: &str) -> Result<()> {
    if arg.len() > GIT_WIRE_MAX_ARG_BYTES {
        return Err(invalid("git argument exceeds the frozen length bound"));
    }
    if arg.contains('\0') {
        return Err(invalid("git argument must not contain NUL"));
    }
    Ok(())
}

fn encode_mktree_entries(entries: &[GitTreeEntry]) -> Result<Vec<u8>> {
    let mut payload = Vec::new();
    for entry in entries {
        if entry.name.is_empty() || entry.name.contains(&0) || entry.name.contains(&b'\n') {
            return Err(invalid("tree entry name must be non-empty and single-line"));
        }
        let kind = match entry.mode {
            0o040_000 => "tree",
            0o160_000 => "commit",
            _ => "blob",
        };
        let record = format!("{:06o} {kind} {}\t", entry.mode, entry.oid.as_str());
        payload.extend_from_slice(record.as_bytes());
        payload.extend_from_slice(&entry.name);
        payload.push(0);
    }
    Ok(payload)
}

fn parse_tree_entries(stdout: &[u8]) -> Result<Vec<GitTreeEntry>> {
    let mut entries = Vec::new();
    for record in stdout.split(|byte| *byte == 0) {
        if record.is_empty() {
            continue;
        }
        let split = record
            .iter()
            .position(|byte| *byte == b'\t')
            .ok_or_else(|| invalid("git tree record is missing its name separator"))?;
        let header = std::str::from_utf8(&record[..split])
            .map_err(|_| invalid("git tree record header must be UTF-8"))?;
        let mut fields = header.split(' ');
        let mode = fields
            .next()
            .ok_or_else(|| invalid("git tree record is missing its mode"))?;
        let _kind = fields
            .next()
            .ok_or_else(|| invalid("git tree record is missing its type"))?;
        let oid = fields
            .next()
            .ok_or_else(|| invalid("git tree record is missing its oid"))?;
        entries.push(GitTreeEntry {
            mode: u32::from_str_radix(mode, 8)
                .map_err(|_| invalid("git tree record mode must be octal"))?,
            name: record[split + 1..].to_vec(),
            oid: GitOid::parse_hex(oid)?,
        });
    }
    Ok(entries)
}

/// Captured result of one git child process.
#[derive(Debug, Clone)]
pub(crate) struct GitWireProcessOutput {
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
    pub(crate) exit_code: Option<i32>,
    pub(crate) success: bool,
}

/// The single production git subprocess constructor in this crate.
///
/// Shape: `git -C <repo_root> -c core.hooksPath=/dev/null -c credential.helper=
/// <frozen argv>`. The environment is cleared and rebuilt from
/// [`GIT_WIRE_INHERITED_ENV_KEYS`] plus the forced [`GIT_WIRE_FIXED_ENV`]
/// pairs, so ambient hooks, ambient git configuration, and ambient credential
/// helpers can never run. stdio is always captured; no shell is ever spawned.
fn spawn_git(
    process_env: &GitWireProcessEnv,
    repo_root: &Path,
    args: &[OsString],
    stdin_payload: Option<&[u8]>,
) -> Result<GitWireProcessOutput> {
    let mut command = Command::new(process_env.git_binary.as_os_str());
    command.arg("-C").arg(repo_root).args(args);
    command.env_clear();
    for (key, value) in child_env(process_env) {
        command.env(key, value);
    }
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let output = match stdin_payload {
        Some(payload) => {
            command.stdin(Stdio::piped());
            let mut child = command.spawn()?;
            if let Some(mut sink) = child.stdin.take() {
                sink.write_all(payload)?;
            }
            child.wait_with_output()?
        }
        None => {
            command.stdin(Stdio::null());
            command.output()?
        }
    };
    Ok(GitWireProcessOutput {
        stdout: output.stdout,
        stderr: output.stderr,
        exit_code: output.status.code(),
        success: output.status.success(),
    })
}

/// The complete environment of a GitWire child after `env_clear`.
fn child_env(process_env: &GitWireProcessEnv) -> Vec<(&'static str, OsString)> {
    child_env_from(process_env, ambient_env)
}

/// The only ambient-environment read GitWire performs.
fn ambient_env(key: &str) -> Option<OsString> {
    std::env::var_os(key)
}

/// The environment builder with the ambient lookup injected.
///
/// Only [`GIT_WIRE_INHERITED_ENV_KEYS`] is ever asked of `ambient`, and the
/// [`GIT_WIRE_FIXED_ENV`] pairs are appended last so `Command::env` resolves
/// them over anything that came before. An ambient `GIT_CONFIG_NOSYSTEM=0` or
/// `GIT_TERMINAL_PROMPT=1` therefore cannot reach a child: those two keys are
/// never read from the parent environment at all.
fn child_env_from<F>(process_env: &GitWireProcessEnv, ambient: F) -> Vec<(&'static str, OsString)>
where
    F: Fn(&str) -> Option<OsString>,
{
    let capacity = GIT_WIRE_INHERITED_ENV_KEYS.len() + GIT_WIRE_FIXED_ENV.len();
    let mut pairs = Vec::with_capacity(capacity);
    pairs.push(("PATH", process_env.path.clone()));
    pairs.push(("TMPDIR", process_env.tmpdir.clone().into_os_string()));
    for key in ["LANG", "LC_ALL"] {
        if let Some(value) = ambient(key) {
            pairs.push((key, value));
        }
    }
    for (key, value) in GIT_WIRE_FIXED_ENV {
        pairs.push((key, OsString::from(value)));
    }
    pairs
}

/// Migration bridge for the `repo_mutation` helper cluster.
///
/// `repo_mutation`'s five `pub(super)` helpers are free functions with no
/// `Vault` handle, so they carry no receipts or idempotency keys of their own;
/// their durability rides the repo-mutation oplog. They keep their exact
/// signatures and delegate here so the crate still has exactly one spawn site
/// and one environment policy. The argv is validated position by position, the
/// only pre-verb options accepted are the frozen `user.name`/`user.email`
/// identity pairs, and the forbidden repo-mutation verb shapes are rejected.
///
/// Boundary: this entry is `pub(crate)` on purpose. No public arbitrary-vector
/// or shell-string constructor exists anywhere in the module.
pub(crate) fn run_bridged_git_argv(
    repo_root: &Path,
    args: &[String],
) -> Result<GitWireProcessOutput> {
    let argv = bridged_argv(args)?;
    spawn_git(&GitWireProcessEnv::capture(), repo_root, &argv, None)
}

fn bridged_argv(args: &[String]) -> Result<Vec<OsString>> {
    if args.is_empty() || args.len() > GIT_WIRE_MAX_ARGS {
        return Err(invalid("git argv must be non-empty and bounded"));
    }
    let verb_index = bridged_verb_index(args)?;
    validate_bridged_prefix(&args[..verb_index])?;
    validate_forbidden_shape(&args[verb_index..])?;
    let mut argv = policy_argv();
    for arg in args {
        validate_argv_token(arg)?;
        argv.push(OsString::from(arg));
    }
    Ok(argv)
}

fn bridged_verb_index(args: &[String]) -> Result<usize> {
    let mut index = 0;
    while index < args.len() {
        let arg = args[index].as_str();
        if arg == "-c" {
            index += 2;
            continue;
        }
        if arg.starts_with('-') {
            index += 1;
            continue;
        }
        return Ok(index);
    }
    Err(invalid("git argv must carry a verb"))
}

fn validate_bridged_prefix(prefix: &[String]) -> Result<()> {
    let mut index = 0;
    while index < prefix.len() {
        if prefix[index] != "-c" {
            return Err(invalid("git argv accepts only frozen -c identity pairs"));
        }
        let pair = prefix
            .get(index + 1)
            .ok_or_else(|| invalid("git -c option is missing its value"))?;
        let key = pair
            .split_once('=')
            .map(|(key, _)| key)
            .ok_or_else(|| invalid("git -c option must be key=value"))?;
        if !GIT_WIRE_BRIDGED_CONFIG_KEYS.contains(&key) {
            return Err(invalid("git -c option key is not an allowed identity key"));
        }
        index += 2;
    }
    Ok(())
}

fn validate_forbidden_shape(tail: &[String]) -> Result<()> {
    let verb = tail
        .first()
        .ok_or_else(|| invalid("git argv must carry a verb"))?;
    // The scan deliberately runs over `iter().skip(1)` rather than a `&tail[1..]`
    // slice: the forbidden shapes are argument *positions* after the verb, and
    // the iterator form keeps this a shape check rather than a slice membership
    // test over owned `String`s.
    let forbidden = match verb.as_str() {
        "clean" => true,
        "reset" => tail.iter().skip(1).any(|arg| arg == "--hard"),
        "checkout" => tail.iter().skip(1).any(|arg| arg == "."),
        _ => false,
    };
    if forbidden {
        return Err(invalid("git verb shape is forbidden for repo mutations"));
    }
    Ok(())
}

/// One typed request against the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitWireRequest {
    pub repo: GitWireRepo,
    pub argv: FrozenGitArgv,
    pub observed_ref: Option<ObservedGitRef>,
    pub actor_ref: Option<EntityId>,
    pub session_ref: Option<EntityId>,
    pub requested_at: u64,
}

impl GitWireRequest {
    /// Builds a request with no observation and no actor attribution.
    pub fn new(repo: GitWireRepo, argv: FrozenGitArgv, requested_at: u64) -> Self {
        Self {
            repo,
            argv,
            observed_ref: None,
            actor_ref: None,
            session_ref: None,
            requested_at,
        }
    }

    /// Pins the ref value this effect was decided against.
    pub fn with_observed_ref(mut self, observed: ObservedGitRef) -> Self {
        self.observed_ref = Some(observed);
        self
    }

    /// Attributes the effect to an actor.
    pub fn with_actor_ref(mut self, actor_ref: EntityId) -> Self {
        self.actor_ref = Some(actor_ref);
        self
    }

    /// Attributes the effect to a session.
    pub fn with_session_ref(mut self, session_ref: EntityId) -> Self {
        self.session_ref = Some(session_ref);
        self
    }
}

/// An object set staged outside any LMDB write transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitWireStagedObjects {
    pub idempotency_key: [u8; 32],
    pub repo: GitWireRepo,
    pub quarantine_path: PathBuf,
    pub object_set_hash: [u8; 32],
    pub observed_refs: Vec<ObservedGitRef>,
    pub proposed_refs: Vec<(GitRefName, GitOid)>,
    pub staged_at: u64,
}

/// Whether the recorded effect applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitWireReceiptDisposition {
    Applied,
    Failed,
}

impl GitWireReceiptDisposition {
    /// Stable wire name recorded on receipts.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::Failed => "failed",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "applied" => Ok(Self::Applied),
            "failed" => Ok(Self::Failed),
            _ => Err(invalid("unknown git wire receipt disposition")),
        }
    }
}

/// The durable audit row of one git effect. It carries no environment values
/// and no payload bytes beyond hashes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitWireReceipt {
    pub receipt_id: [u8; 32],
    pub idempotency_key: [u8; 32],
    pub operation: GitWireOperation,
    pub repo_ref: RepoRef,
    pub argv_hash: [u8; 32],
    pub observed_before: Vec<ObservedGitRef>,
    pub observed_after: Vec<ObservedGitRef>,
    pub disposition: GitWireReceiptDisposition,
    pub exit_code: Option<i32>,
    pub stdout_hash: [u8; 32],
    pub stderr_hash: [u8; 32],
    pub started_at: u64,
    pub finished_at: u64,
}

/// Whether a value came from a git call made now, or from a durable receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GitWireOutcome<T> {
    Applied { value: T, receipt: GitWireReceipt },
    Replayed { value: T, receipt: GitWireReceipt },
}

impl<T> GitWireOutcome<T> {
    /// The produced value, however it was obtained.
    pub fn value(&self) -> &T {
        match self {
            Self::Applied { value, .. } | Self::Replayed { value, .. } => value,
        }
    }

    /// The receipt behind the value.
    pub fn receipt(&self) -> &GitWireReceipt {
        match self {
            Self::Applied { receipt, .. } | Self::Replayed { receipt, .. } => receipt,
        }
    }

    /// Whether the value was served from a durable receipt without launching
    /// git.
    pub fn is_replayed(&self) -> bool {
        matches!(self, Self::Replayed { .. })
    }

    fn map_value<U, F>(self, map: F) -> Result<GitWireOutcome<U>>
    where
        F: FnOnce(T) -> Result<U>,
    {
        match self {
            Self::Applied { value, receipt } => Ok(GitWireOutcome::Applied {
                value: map(value)?,
                receipt,
            }),
            Self::Replayed { value, receipt } => Ok(GitWireOutcome::Replayed {
                value: map(value)?,
                receipt,
            }),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredObservedRef {
    name: String,
    oid: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredGitWireReceipt {
    schema_version: u8,
    receipt_id: [u8; 32],
    idempotency_key: [u8; 32],
    operation: String,
    repo_ref: String,
    argv_hash: [u8; 32],
    observed_before: Vec<StoredObservedRef>,
    observed_after: Vec<StoredObservedRef>,
    disposition: String,
    exit_code: Option<i32>,
    stdout_hash: [u8; 32],
    stderr_hash: [u8; 32],
    started_at: u64,
    finished_at: u64,
    value: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredGitWirePrepared {
    schema_version: u8,
    idempotency_key: [u8; 32],
    repo_identity: String,
    repo_ref: String,
    operation: String,
    quarantine_path: String,
    object_set_hash: [u8; 32],
    observed_refs: Vec<StoredObservedRef>,
    proposed_refs: Vec<(String, String)>,
    staged_at: u64,
}

/// The typed git seam. One handle owns the process baseline and the vault the
/// receipts live in.
pub struct GitWire<'a> {
    vault: &'a Vault,
    process_env: GitWireProcessEnv,
}

impl<'a> GitWire<'a> {
    /// Opens the wire over a vault with the captured process baseline.
    pub fn new(vault: &'a Vault) -> Self {
        Self {
            vault,
            process_env: GitWireProcessEnv::capture(),
        }
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

    fn run(&self, repo: &GitWireRepo, argv: &FrozenGitArgv) -> Result<GitWireProcessOutput> {
        let output = spawn_git(
            &self.process_env,
            &repo.repo_root,
            argv.args(),
            argv.stdin(),
        )?;
        if argv.accepts(&output) {
            return Ok(output);
        }
        Err(Error::RepoMutationFailed(format_git_wire_failure(
            argv, &output,
        )))
    }

    /// Runs an effect that the transactional phase is allowed to launch.
    ///
    /// RC6 makes "`commit_staged_refs` never launches object-producing work" an
    /// invariant of the code rather than of the call sites: every git call made
    /// while the ref-commit phase is running goes through here, and an
    /// object-producing operation is refused before it can spawn.
    fn run_ref_only(
        &self,
        repo: &GitWireRepo,
        argv: &FrozenGitArgv,
    ) -> Result<GitWireProcessOutput> {
        if argv.operation().may_write_objects() {
            return Err(Error::InvariantViolation(
                "git wire ref-commit phase refuses an object-producing operation",
            ));
        }
        self.run(repo, argv)
    }

    /// Runs a read-only effect. Reads never mutate refs or objects, so they
    /// carry an in-memory receipt and never take an idempotency row.
    pub fn execute_read(&self, request: GitWireRequest) -> GitWireResult<GitWireOutcome<Vec<u8>>> {
        let operation = request.argv.operation();
        if operation.may_write_objects() || operation.may_update_refs() {
            return Err(invalid(
                "execute_read refuses an object- or ref-writing operation",
            ));
        }
        let output = self.run(&request.repo, &request.argv)?;
        let receipt = receipt_for(
            ReceiptInputs {
                repo: &request.repo,
                argv: &request.argv,
                idempotency_key: git_wire_idempotency_key(&request),
                observed_before: Vec::new(),
                observed_after: Vec::new(),
                started_at: request.requested_at,
                finished_at: request.requested_at,
            },
            &output,
        );
        Ok(GitWireOutcome::Applied {
            value: output.stdout,
            receipt,
        })
    }

    /// Runs a mutating effect under observed-ref idempotency.
    ///
    /// A durable applied receipt for the same key returns `Replayed` without
    /// launching git. Otherwise the guarded ref is observed, git runs, and an
    /// applied receipt is persisted; failures leave no row so a retry re-runs.
    pub fn execute_mutation(
        &self,
        request: GitWireRequest,
    ) -> GitWireResult<GitWireOutcome<Vec<u8>>> {
        let key = git_wire_idempotency_key(&request);
        if let Some(stored) = self.replayable_receipt(&key)? {
            let receipt = receipt_from_stored(&stored)?;
            return Ok(GitWireOutcome::Replayed {
                value: stored.value,
                receipt,
            });
        }
        let observed_before = self.observe_guarded(&request)?;
        let output = self.run(&request.repo, &request.argv)?;
        let observed_after = self.observe_guarded(&request)?;
        let receipt = receipt_for(
            ReceiptInputs {
                repo: &request.repo,
                argv: &request.argv,
                idempotency_key: key,
                observed_before,
                observed_after,
                started_at: request.requested_at,
                finished_at: request.requested_at,
            },
            &output,
        );
        if receipt.disposition == GitWireReceiptDisposition::Applied {
            self.put_receipt(&receipt, &output.stdout)?;
        }
        Ok(GitWireOutcome::Applied {
            value: output.stdout,
            receipt,
        })
    }

    fn observe_guarded(&self, request: &GitWireRequest) -> Result<Vec<ObservedGitRef>> {
        let Some(name) = request.argv.guarded_ref() else {
            return Ok(Vec::new());
        };
        let oid = self.read_ref(&request.repo, name)?;
        Ok(vec![ObservedGitRef {
            name: name.clone(),
            oid,
        }])
    }

    /// Whether an object is present in the repository object store.
    pub fn object_exists(&self, repo: &GitWireRepo, oid: &GitOid) -> GitWireResult<bool> {
        let output = self.run(repo, &FrozenGitArgv::object_exists(oid))?;
        Ok(output.success)
    }

    /// The direct entries of one tree object.
    pub fn read_tree(&self, repo: &GitWireRepo, tree: &GitOid) -> GitWireResult<Vec<GitTreeEntry>> {
        let output = self.run(repo, &FrozenGitArgv::read_tree(tree))?;
        parse_tree_entries(&output.stdout)
    }

    /// The raw bytes of one object, exactly as git stores them.
    pub fn read_object(&self, repo: &GitWireRepo, oid: &GitOid) -> GitWireResult<Vec<u8>> {
        let output = self.run(repo, &FrozenGitArgv::read_object(oid))?;
        Ok(output.stdout)
    }

    /// Writes a blob object.
    pub fn write_blob(
        &self,
        repo: &GitWireRepo,
        bytes: &[u8],
        now: u64,
    ) -> GitWireResult<GitWireOutcome<GitOid>> {
        let argv = FrozenGitArgv::write_blob(bytes);
        self.execute_oid_mutation(GitWireRequest::new(repo.clone(), argv, now))
    }

    /// Writes a tree object from validated entries.
    pub fn write_tree(
        &self,
        repo: &GitWireRepo,
        entries: &[GitTreeEntry],
        now: u64,
    ) -> GitWireResult<GitWireOutcome<GitOid>> {
        let argv = FrozenGitArgv::write_tree(entries)?;
        self.execute_oid_mutation(GitWireRequest::new(repo.clone(), argv, now))
    }

    /// Writes a commit object, including validated extra headers.
    pub fn write_commit(
        &self,
        repo: &GitWireRepo,
        request: &GitCommitRequest,
        now: u64,
    ) -> GitWireResult<GitWireOutcome<GitOid>> {
        let argv = FrozenGitArgv::write_commit(request)?;
        self.execute_oid_mutation(GitWireRequest::new(repo.clone(), argv, now))
    }

    fn execute_oid_mutation(&self, request: GitWireRequest) -> Result<GitWireOutcome<GitOid>> {
        self.execute_mutation(request)?
            .map_value(|stdout| parse_oid_output(&stdout))
    }

    /// Reads one full ref, or `None` when it does not exist.
    pub fn read_ref(&self, repo: &GitWireRepo, name: &GitRefName) -> GitWireResult<Option<GitOid>> {
        let output = self.run(repo, &FrozenGitArgv::read_ref(name.clone()))?;
        if !output.success {
            return Ok(None);
        }
        let text = String::from_utf8_lossy(&output.stdout);
        let Some(field) = text.split_whitespace().next() else {
            return Ok(None);
        };
        Ok(Some(GitOid::parse_hex(field)?))
    }

    /// Compare-and-set ref update against an observed value.
    pub fn update_ref_cas(
        &self,
        repo: &GitWireRepo,
        name: &GitRefName,
        expected: Option<&GitOid>,
        next: &GitOid,
        now: u64,
    ) -> GitWireResult<GitWireOutcome<GitRefCasOutcome>> {
        let observed = ObservedGitRef {
            name: name.clone(),
            oid: expected.cloned(),
        };
        let argv = FrozenGitArgv::update_ref(observed.clone(), next.clone());
        let request = GitWireRequest::new(repo.clone(), argv, now).with_observed_ref(observed);
        let outcome = self.execute_mutation(request)?;
        if outcome.receipt().disposition == GitWireReceiptDisposition::Applied {
            return outcome.map_value(|_| {
                Ok(GitRefCasOutcome::Updated {
                    previous: expected.cloned(),
                    current: next.clone(),
                })
            });
        }
        let observed = self.read_ref(repo, name)?;
        outcome.map_value(|_| Ok(GitRefCasOutcome::Mismatch { observed }))
    }

    /// Unconditional ref write.
    pub fn set_ref(
        &self,
        repo: &GitWireRepo,
        name: &GitRefName,
        next: &GitOid,
        now: u64,
    ) -> GitWireResult<GitWireOutcome<GitOid>> {
        let argv = FrozenGitArgv::set_ref(name.clone(), next);
        let request = GitWireRequest::new(repo.clone(), argv, now);
        let next = next.clone();
        self.execute_mutation(request)?.map_value(|_| Ok(next))
    }

    /// Deletes a ref, optionally compare-and-set against an expected value.
    pub fn delete_ref(
        &self,
        repo: &GitWireRepo,
        name: &GitRefName,
        expected: Option<&GitOid>,
        now: u64,
    ) -> GitWireResult<GitWireOutcome<Option<GitOid>>> {
        let argv = FrozenGitArgv::delete_ref(name.clone(), expected);
        let request = GitWireRequest::new(repo.clone(), argv, now);
        let expected = expected.cloned();
        self.execute_mutation(request)?.map_value(|_| Ok(expected))
    }

    /// Writes the keep-ref that holds a staged object set alive.
    pub fn write_keep_ref(
        &self,
        repo: &GitWireRepo,
        oid: &GitOid,
        now: u64,
    ) -> GitWireResult<GitWireOutcome<GitRefName>> {
        let name = keep_ref_name(oid)?;
        let argv = FrozenGitArgv::set_ref(name.clone(), oid);
        let request = GitWireRequest::new(repo.clone(), argv, now);
        self.execute_mutation(request)?.map_value(|_| Ok(name))
    }

    /// Deletes a keep-ref, reporting the name when one was present.
    pub fn delete_keep_ref(
        &self,
        repo: &GitWireRepo,
        oid: &GitOid,
        now: u64,
    ) -> GitWireResult<GitWireOutcome<Option<GitRefName>>> {
        let name = keep_ref_name(oid)?;
        let present = self.read_ref(repo, &name)?.is_some();
        let argv = FrozenGitArgv::delete_ref(name.clone(), None);
        let request = GitWireRequest::new(repo.clone(), argv, now);
        self.execute_mutation(request)?
            .map_value(|_| Ok(present.then_some(name)))
    }

    /// The durable receipt for an idempotency key, whatever its disposition.
    pub fn receipt(&self, idempotency_key: &[u8; 32]) -> GitWireResult<Option<GitWireReceipt>> {
        let Some(stored) = self.stored_receipt(idempotency_key)? else {
            return Ok(None);
        };
        Ok(Some(receipt_from_stored(&stored)?))
    }

    fn stored_receipt(&self, key: &[u8; 32]) -> Result<Option<StoredGitWireReceipt>> {
        let rtxn = self.vault.store.env.read_txn()?;
        let Some(bytes) = self.vault.store.vault_meta.get(&rtxn, &receipt_key(key))? else {
            return Ok(None);
        };
        Ok(Some(decode_receipt(&bytes)?))
    }

    fn replayable_receipt(&self, key: &[u8; 32]) -> Result<Option<StoredGitWireReceipt>> {
        let Some(stored) = self.stored_receipt(key)? else {
            return Ok(None);
        };
        if stored.disposition == GitWireReceiptDisposition::Applied.as_str() {
            return Ok(Some(stored));
        }
        Ok(None)
    }

    fn put_receipt(&self, receipt: &GitWireReceipt, value: &[u8]) -> Result<()> {
        let stored = stored_receipt_row(receipt, value);
        let encoded = encode_receipt(&stored)?;
        let key = receipt_key(&receipt.idempotency_key);
        self.vault.with_write_txn(|txn| {
            self.vault.store.vault_meta.put(txn, &key, &encoded)?;
            Ok(())
        })
    }
}

/// Two-phase object staging and ref commit.
impl GitWire<'_> {
    /// Runs all object-producing work before an LMDB write transaction exists
    /// and records the prepared row for recovery.
    pub fn stage_objects(&self, request: GitWireRequest) -> GitWireResult<GitWireStagedObjects> {
        if !request.argv.operation().may_write_objects() {
            return Err(invalid(
                "stage_objects requires an object-producing operation",
            ));
        }
        let idempotency_key = git_wire_idempotency_key(&request);
        let observed_refs = Vec::from_iter(request.observed_ref.clone());
        let output = self.run(&request.repo, &request.argv)?;
        let proposed_refs = proposed_refs_for(&request, &output);
        let staged = GitWireStagedObjects {
            idempotency_key,
            repo: request.repo.clone(),
            quarantine_path: self.object_directory(&request.repo)?,
            object_set_hash: *blake3::hash(&output.stdout).as_bytes(),
            observed_refs,
            proposed_refs,
            staged_at: request.requested_at,
        };
        self.put_prepared(&staged, request.argv.operation())?;
        Ok(staged)
    }

    /// Rechecks the observed refs, commits refs only, and records the receipt
    /// while LMDB is open. It never launches object-producing work.
    pub fn commit_staged_refs(
        &self,
        staged: GitWireStagedObjects,
        now: u64,
    ) -> GitWireResult<GitWireOutcome<GitWireReceipt>> {
        if let Some(stored) = self.replayable_receipt(&staged.idempotency_key)? {
            let receipt = receipt_from_stored(&stored)?;
            return Ok(GitWireOutcome::Replayed {
                value: receipt.clone(),
                receipt,
            });
        }
        self.require_fresh_observed_refs(&staged)?;
        self.require_available_objects(&staged)?;
        let observed_after = self.advance_staged_refs(&staged)?;
        let receipt = staged_receipt(
            &staged,
            observed_after,
            now,
            GitWireReceiptDisposition::Applied,
        );
        self.commit_staged_receipt(&staged, &receipt)?;
        Ok(GitWireOutcome::Applied {
            value: receipt.clone(),
            receipt,
        })
    }

    fn require_fresh_observed_refs(&self, staged: &GitWireStagedObjects) -> Result<()> {
        for observed in &staged.observed_refs {
            let current = self.read_ref(&staged.repo, &observed.name)?;
            if current != observed.oid {
                return Err(Error::ConcurrentWrite(
                    "git wire guarded ref changed between staging and commit",
                ));
            }
        }
        Ok(())
    }

    fn require_available_objects(&self, staged: &GitWireStagedObjects) -> Result<()> {
        for (_, oid) in &staged.proposed_refs {
            if !self.object_exists(&staged.repo, oid)? {
                return Err(Error::RepoMutationFailed(
                    "git wire staged object set is unavailable; refusing the ref advance"
                        .to_owned(),
                ));
            }
        }
        Ok(())
    }

    fn advance_staged_refs(&self, staged: &GitWireStagedObjects) -> Result<Vec<ObservedGitRef>> {
        let mut observed_after = Vec::with_capacity(staged.proposed_refs.len());
        for (name, oid) in &staged.proposed_refs {
            let expected = staged
                .observed_refs
                .iter()
                .find(|observed| observed.name == *name)
                .and_then(|observed| observed.oid.clone());
            let argv = FrozenGitArgv::update_ref(
                ObservedGitRef {
                    name: name.clone(),
                    oid: expected,
                },
                oid.clone(),
            );
            let output = self.run_ref_only(&staged.repo, &argv)?;
            if !output.success {
                return Err(Error::ConcurrentWrite(
                    "git wire staged ref advance lost its compare-and-set",
                ));
            }
            observed_after.push(ObservedGitRef {
                name: name.clone(),
                oid: self.read_ref(&staged.repo, name)?,
            });
        }
        Ok(observed_after)
    }

    fn commit_staged_receipt(
        &self,
        staged: &GitWireStagedObjects,
        receipt: &GitWireReceipt,
    ) -> Result<()> {
        let encoded = encode_receipt(&stored_receipt_row(receipt, &[]))?;
        let receipt_row = receipt_key(&receipt.idempotency_key);
        let prepared_row = prepared_key(&staged.idempotency_key);
        self.vault.with_write_txn(|txn| {
            self.vault
                .store
                .vault_meta
                .put(txn, &receipt_row, &encoded)?;
            self.vault.store.vault_meta.delete(txn, &prepared_row)?;
            Ok(())
        })
    }

    fn object_directory(&self, repo: &GitWireRepo) -> Result<PathBuf> {
        let output = self.run(repo, &FrozenGitArgv::git_path("objects")?)?;
        let text = String::from_utf8_lossy(&output.stdout);
        let path = PathBuf::from(text.trim_end_matches(['\r', '\n']));
        if path.is_absolute() {
            return Ok(path);
        }
        Ok(repo.repo_root.join(path))
    }

    fn put_prepared(
        &self,
        staged: &GitWireStagedObjects,
        operation: GitWireOperation,
    ) -> Result<()> {
        let stored = StoredGitWirePrepared {
            schema_version: GIT_WIRE_SCHEMA_VERSION,
            idempotency_key: staged.idempotency_key,
            repo_identity: staged.repo.canonical_identity(),
            repo_ref: staged.repo.repo_ref.canonical(),
            operation: operation.as_str().to_owned(),
            quarantine_path: staged.quarantine_path.display().to_string(),
            object_set_hash: staged.object_set_hash,
            observed_refs: staged.observed_refs.iter().map(stored_observed).collect(),
            proposed_refs: staged
                .proposed_refs
                .iter()
                .map(|(name, oid)| (name.as_str().to_owned(), oid.as_str().to_owned()))
                .collect(),
            staged_at: staged.staged_at,
        };
        let encoded = rmp_serde::to_vec_named(&stored)
            .map_err(|_| Error::InvariantViolation("git wire prepared row encode failed"))?;
        let key = prepared_key(&staged.idempotency_key);
        self.vault.with_write_txn(|txn| {
            self.vault.store.vault_meta.put(txn, &key, &encoded)?;
            Ok(())
        })
    }

    /// Finishes or discards every prepared row of one repository.
    ///
    /// A row whose refs already carry the staged object set rolls forward to an
    /// applied receipt. A row whose object set is still available and whose
    /// observed refs are unchanged completes its ref advance. Anything else is
    /// discarded with a failed receipt and no ref is moved, so no ref can point
    /// at an unavailable staged object set.
    pub fn recover_prepared_refs(
        &self,
        repo: &GitWireRepo,
        now: u64,
    ) -> GitWireResult<Vec<GitWireReceipt>> {
        let identity = repo.canonical_identity();
        let mut receipts = Vec::new();
        for stored in self.prepared_rows(&identity)? {
            let staged = staged_from_stored(&stored, repo)?;
            if self.stored_receipt(&staged.idempotency_key)?.is_some() {
                self.drop_prepared(&staged)?;
                continue;
            }
            receipts.push(self.recover_one_prepared(staged, now)?);
        }
        Ok(receipts)
    }

    fn recover_one_prepared(
        &self,
        staged: GitWireStagedObjects,
        now: u64,
    ) -> Result<GitWireReceipt> {
        let applied = GitWireReceiptDisposition::Applied;
        if self.staged_refs_already_advanced(&staged)? {
            let observed_after = self.observe_proposed(&staged)?;
            let receipt = staged_receipt(&staged, observed_after, now, applied);
            self.commit_staged_receipt(&staged, &receipt)?;
            return Ok(receipt);
        }
        let recoverable =
            self.staged_objects_available(&staged)? && self.observed_refs_unchanged(&staged)?;
        if !recoverable {
            let failed = GitWireReceiptDisposition::Failed;
            let receipt = staged_receipt(&staged, Vec::new(), now, failed);
            self.commit_staged_receipt(&staged, &receipt)?;
            return Ok(receipt);
        }
        let observed_after = self.advance_staged_refs(&staged)?;
        let receipt = staged_receipt(&staged, observed_after, now, applied);
        self.commit_staged_receipt(&staged, &receipt)?;
        Ok(receipt)
    }

    fn staged_refs_already_advanced(&self, staged: &GitWireStagedObjects) -> Result<bool> {
        if staged.proposed_refs.is_empty() {
            return Ok(false);
        }
        for (name, oid) in &staged.proposed_refs {
            if self.read_ref(&staged.repo, name)?.as_ref() != Some(oid) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn staged_objects_available(&self, staged: &GitWireStagedObjects) -> Result<bool> {
        for (_, oid) in &staged.proposed_refs {
            if !self.object_exists(&staged.repo, oid)? {
                return Ok(false);
            }
        }
        Ok(!staged.proposed_refs.is_empty())
    }

    fn observed_refs_unchanged(&self, staged: &GitWireStagedObjects) -> Result<bool> {
        for observed in &staged.observed_refs {
            if self.read_ref(&staged.repo, &observed.name)? != observed.oid {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn observe_proposed(&self, staged: &GitWireStagedObjects) -> Result<Vec<ObservedGitRef>> {
        let mut observed = Vec::with_capacity(staged.proposed_refs.len());
        for (name, _) in &staged.proposed_refs {
            observed.push(ObservedGitRef {
                name: name.clone(),
                oid: self.read_ref(&staged.repo, name)?,
            });
        }
        Ok(observed)
    }

    fn prepared_rows(&self, identity: &str) -> Result<Vec<StoredGitWirePrepared>> {
        let rtxn = self.vault.store.env.read_txn()?;
        let mut rows = Vec::new();
        for row in self
            .vault
            .store
            .vault_meta
            .prefix_iter(&rtxn, GIT_WIRE_PREPARED_KEY_PREFIX)?
        {
            let (_, bytes) = row?;
            let stored: StoredGitWirePrepared = rmp_serde::from_slice(&bytes)
                .map_err(|_| invalid("git wire prepared row is not MessagePack"))?;
            if stored.repo_identity == identity {
                rows.push(stored);
            }
        }
        Ok(rows)
    }

    fn drop_prepared(&self, staged: &GitWireStagedObjects) -> Result<()> {
        let key = prepared_key(&staged.idempotency_key);
        self.vault.with_write_txn(|txn| {
            self.vault.store.vault_meta.delete(txn, &key)?;
            Ok(())
        })
    }
}

/// BLAKE3 over the idempotency domain, the canonical repository identity, the
/// wire name, the argv hash, the stdin payload hash, the guarded ref, and the
/// observed oid. Every field is length-prefixed, so no two distinct requests
/// can collide by concatenation.
pub fn git_wire_idempotency_key(request: &GitWireRequest) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hash_field(&mut hasher, GIT_WIRE_IDEMPOTENCY_DOMAIN);
    hash_field(&mut hasher, request.repo.canonical_identity().as_bytes());
    hash_field(&mut hasher, request.argv.operation().as_str().as_bytes());
    hash_field(&mut hasher, &request.argv.argv_hash());
    hash_field(&mut hasher, &request.argv.stdin_hash());
    let guarded = request.argv.guarded_ref().map_or("", GitRefName::as_str);
    hash_field(&mut hasher, guarded.as_bytes());
    let observed = request
        .observed_ref
        .as_ref()
        .and_then(|observed| observed.oid.as_ref())
        .map_or("", GitOid::as_str);
    hash_field(&mut hasher, observed.as_bytes());
    *hasher.finalize().as_bytes()
}

struct ReceiptInputs<'r> {
    repo: &'r GitWireRepo,
    argv: &'r FrozenGitArgv,
    idempotency_key: [u8; 32],
    observed_before: Vec<ObservedGitRef>,
    observed_after: Vec<ObservedGitRef>,
    started_at: u64,
    finished_at: u64,
}

fn receipt_for(inputs: ReceiptInputs<'_>, output: &GitWireProcessOutput) -> GitWireReceipt {
    let disposition = if output.success {
        GitWireReceiptDisposition::Applied
    } else {
        GitWireReceiptDisposition::Failed
    };
    GitWireReceipt {
        receipt_id: receipt_id(&inputs.idempotency_key, inputs.started_at, disposition),
        idempotency_key: inputs.idempotency_key,
        operation: inputs.argv.operation(),
        repo_ref: inputs.repo.repo_ref.clone(),
        argv_hash: inputs.argv.argv_hash(),
        observed_before: inputs.observed_before,
        observed_after: inputs.observed_after,
        disposition,
        exit_code: output.exit_code,
        stdout_hash: *blake3::hash(&output.stdout).as_bytes(),
        stderr_hash: *blake3::hash(&output.stderr).as_bytes(),
        started_at: inputs.started_at,
        finished_at: inputs.finished_at,
    }
}

fn staged_receipt(
    staged: &GitWireStagedObjects,
    observed_after: Vec<ObservedGitRef>,
    now: u64,
    disposition: GitWireReceiptDisposition,
) -> GitWireReceipt {
    GitWireReceipt {
        receipt_id: receipt_id(&staged.idempotency_key, staged.staged_at, disposition),
        idempotency_key: staged.idempotency_key,
        operation: GitWireOperation::StageObjects,
        repo_ref: staged.repo.repo_ref.clone(),
        argv_hash: staged.object_set_hash,
        observed_before: staged.observed_refs.clone(),
        observed_after,
        disposition,
        exit_code: Some(0),
        stdout_hash: staged.object_set_hash,
        stderr_hash: *blake3::hash(&[]).as_bytes(),
        started_at: staged.staged_at,
        finished_at: now,
    }
}

fn receipt_id(
    idempotency_key: &[u8; 32],
    started_at: u64,
    disposition: GitWireReceiptDisposition,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hash_field(&mut hasher, GIT_WIRE_IDEMPOTENCY_DOMAIN);
    hash_field(&mut hasher, b"receipt");
    hash_field(&mut hasher, idempotency_key);
    hash_field(&mut hasher, &started_at.to_be_bytes());
    hash_field(&mut hasher, disposition.as_str().as_bytes());
    *hasher.finalize().as_bytes()
}

fn stored_receipt_row(receipt: &GitWireReceipt, value: &[u8]) -> StoredGitWireReceipt {
    let value = if value.len() > GIT_WIRE_MAX_RECEIPT_VALUE_BYTES {
        Vec::new()
    } else {
        value.to_vec()
    };
    StoredGitWireReceipt {
        schema_version: GIT_WIRE_SCHEMA_VERSION,
        receipt_id: receipt.receipt_id,
        idempotency_key: receipt.idempotency_key,
        operation: receipt.operation.as_str().to_owned(),
        repo_ref: receipt.repo_ref.canonical(),
        argv_hash: receipt.argv_hash,
        observed_before: receipt
            .observed_before
            .iter()
            .map(stored_observed)
            .collect(),
        observed_after: receipt.observed_after.iter().map(stored_observed).collect(),
        disposition: receipt.disposition.as_str().to_owned(),
        exit_code: receipt.exit_code,
        stdout_hash: receipt.stdout_hash,
        stderr_hash: receipt.stderr_hash,
        started_at: receipt.started_at,
        finished_at: receipt.finished_at,
        value,
    }
}

fn receipt_from_stored(stored: &StoredGitWireReceipt) -> Result<GitWireReceipt> {
    if stored.schema_version != GIT_WIRE_SCHEMA_VERSION {
        return Err(invalid("unsupported git wire receipt schema version"));
    }
    Ok(GitWireReceipt {
        receipt_id: stored.receipt_id,
        idempotency_key: stored.idempotency_key,
        operation: GitWireOperation::parse(&stored.operation)?,
        repo_ref: RepoRef::parse(&stored.repo_ref)?,
        argv_hash: stored.argv_hash,
        observed_before: observed_from_stored(&stored.observed_before)?,
        observed_after: observed_from_stored(&stored.observed_after)?,
        disposition: GitWireReceiptDisposition::parse(&stored.disposition)?,
        exit_code: stored.exit_code,
        stdout_hash: stored.stdout_hash,
        stderr_hash: stored.stderr_hash,
        started_at: stored.started_at,
        finished_at: stored.finished_at,
    })
}

fn staged_from_stored(
    stored: &StoredGitWirePrepared,
    repo: &GitWireRepo,
) -> Result<GitWireStagedObjects> {
    if stored.schema_version != GIT_WIRE_SCHEMA_VERSION {
        return Err(invalid("unsupported git wire prepared schema version"));
    }
    let mut proposed_refs = Vec::with_capacity(stored.proposed_refs.len());
    for (name, oid) in &stored.proposed_refs {
        let name = GitRefName::parse_full(name.clone())?;
        let oid = GitOid::parse_hex(oid.clone())?;
        proposed_refs.push((name, oid));
    }
    Ok(GitWireStagedObjects {
        idempotency_key: stored.idempotency_key,
        repo: repo.clone(),
        quarantine_path: PathBuf::from(&stored.quarantine_path),
        object_set_hash: stored.object_set_hash,
        observed_refs: observed_from_stored(&stored.observed_refs)?,
        proposed_refs,
        staged_at: stored.staged_at,
    })
}

fn stored_observed(observed: &ObservedGitRef) -> StoredObservedRef {
    StoredObservedRef {
        name: observed.name.as_str().to_owned(),
        oid: observed.oid.as_ref().map(|oid| oid.as_str().to_owned()),
    }
}

fn observed_from_stored(rows: &[StoredObservedRef]) -> Result<Vec<ObservedGitRef>> {
    let mut observed = Vec::with_capacity(rows.len());
    for row in rows {
        observed.push(ObservedGitRef {
            name: GitRefName::parse_full(row.name.clone())?,
            oid: row
                .oid
                .as_ref()
                .map(|oid| GitOid::parse_hex(oid.clone()))
                .transpose()?,
        });
    }
    Ok(observed)
}

fn encode_receipt(stored: &StoredGitWireReceipt) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(stored)
        .map_err(|_| Error::InvariantViolation("git wire receipt encode failed"))
}

fn decode_receipt(bytes: &[u8]) -> Result<StoredGitWireReceipt> {
    rmp_serde::from_slice(bytes).map_err(|_| invalid("git wire receipt row is not MessagePack"))
}

fn receipt_key(idempotency_key: &[u8; 32]) -> Vec<u8> {
    prefixed_key(GIT_WIRE_RECEIPT_KEY_PREFIX, idempotency_key)
}

fn prepared_key(idempotency_key: &[u8; 32]) -> Vec<u8> {
    prefixed_key(GIT_WIRE_PREPARED_KEY_PREFIX, idempotency_key)
}

fn prefixed_key(prefix: &[u8], idempotency_key: &[u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(prefix.len() + idempotency_key.len() * 2);
    key.extend_from_slice(prefix);
    key.extend_from_slice(hex_lower(idempotency_key).as_bytes());
    key
}

fn keep_ref_name(oid: &GitOid) -> Result<GitRefName> {
    GitRefName::parse_full(format!("{GIT_WIRE_KEEP_REF_PREFIX}{}", oid.as_str()))
}

/// The refs a staged object set proposes: an object-producing effect that
/// guards a ref and printed an object id proposes exactly that advance.
fn proposed_refs_for(
    request: &GitWireRequest,
    output: &GitWireProcessOutput,
) -> Vec<(GitRefName, GitOid)> {
    let Some(name) = request.argv.guarded_ref() else {
        return Vec::new();
    };
    let Ok(oid) = parse_oid_output(&output.stdout) else {
        return Vec::new();
    };
    vec![(name.clone(), oid)]
}

fn parse_oid_output(stdout: &[u8]) -> Result<GitOid> {
    let text = String::from_utf8_lossy(stdout);
    let field = text
        .split_whitespace()
        .next()
        .ok_or_else(|| invalid("git did not print an object id"))?;
    GitOid::parse_hex(field)
}

fn hash_field(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    let length = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    hasher.update(&length.to_be_bytes());
    hasher.update(bytes);
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0F) as usize] as char);
    }
    out
}

fn format_git_wire_failure(argv: &FrozenGitArgv, output: &GitWireProcessOutput) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stderr = stderr.trim();
    let operation = argv.operation().as_str();
    let code = output.exit_code;
    truncate_git_wire_failure(&format!("git {operation} exited with {code:?}: {stderr}"))
}

fn truncate_git_wire_failure(message: &str) -> String {
    if message.len() <= GIT_WIRE_MAX_FAILURE_BYTES {
        return message.to_owned();
    }
    let mut end = GIT_WIRE_MAX_FAILURE_BYTES;
    while !message.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = message[..end].to_owned();
    out.push_str("...");
    out
}

/// The worktree path the checkout port materializes for a lease.
pub fn checkout_worktree_path(lease: &CheckoutLeaseAct) -> PathBuf {
    std::env::temp_dir().join(format!(
        "{GIT_WIRE_CHECKOUT_WORKTREE_PREFIX}{}",
        lease.checkout_id
    ))
}

fn checkout_repo(lease: &CheckoutLeaseAct) -> CheckoutResult<GitWireRepo> {
    let RepoRef::LocalFolder { path, .. } = &lease.repo_ref else {
        return Err(CheckoutError::Invalid(
            "checkout repo must be a local folder",
        ));
    };
    Ok(GitWireRepo::new(
        lease.repo_ref.clone(),
        PathBuf::from(path),
    ))
}

/// ONE-1901's repo port, served by the same frozen seam as every other git
/// effect, so neither ONE-1904 dispatch nor ORIGIN ever constructs a
/// subprocess of its own.
impl CheckoutRepoOps for GitWire<'_> {
    fn materialize(&self, lease: &CheckoutLeaseAct) -> CheckoutResult<()> {
        let repo = checkout_repo(lease)?;
        let path = checkout_worktree_path(lease);
        if path.exists() {
            return Ok(());
        }
        let base = GitRefName::parse_full("HEAD")?;
        let argv = FrozenGitArgv::worktree_add(path, base)?;
        self.run(&repo, &argv)?;
        Ok(())
    }

    fn inspect_teardown(
        &self,
        lease: &CheckoutLeaseAct,
        receipt: &PushedHeadReceipt,
    ) -> CheckoutResult<CheckoutTeardownInspection> {
        let repo = checkout_repo(lease)?;
        let path = checkout_worktree_path(lease);
        if !path.exists() {
            return Ok(uncertain_inspection());
        }
        let worktree = GitWireRepo::new(repo.repo_ref, path);
        let head = self.run(&worktree, &FrozenGitArgv::rev_parse("HEAD")?)?;
        if !head.success {
            return Ok(uncertain_inspection());
        }
        let observed = LeaseGitOid::parse(String::from_utf8_lossy(&head.stdout).trim())?;
        let status = self.run(&worktree, &FrozenGitArgv::status_porcelain())?;
        let receipt_match = if observed.to_string() == receipt.pushed_head {
            TeardownReceiptMatch::Match
        } else {
            TeardownReceiptMatch::Mismatch
        };
        Ok(CheckoutTeardownInspection {
            observed_head: Some(observed),
            dirty: !status.stdout.is_empty(),
            receipt_match,
            occupant: None,
        })
    }

    fn collect(&self, lease: &CheckoutLeaseAct) -> CheckoutResult<()> {
        let repo = checkout_repo(lease)?;
        let path = checkout_worktree_path(lease);
        if !path.exists() {
            return Ok(());
        }
        let argv = FrozenGitArgv::worktree_drop(path.clone())?;
        self.run(&repo, &argv)?;
        if path.exists() {
            let _ = std::fs::remove_dir_all(&path);
        }
        if path.exists() {
            return Err(CheckoutError::RepoOps(
                "checkout worktree survived collection".to_owned(),
            ));
        }
        Ok(())
    }
}

fn uncertain_inspection() -> CheckoutTeardownInspection {
    CheckoutTeardownInspection {
        observed_head: None,
        dirty: false,
        receipt_match: TeardownReceiptMatch::Uncertain,
        occupant: None,
    }
}
