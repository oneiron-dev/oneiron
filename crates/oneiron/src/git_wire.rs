//! Engine-owned typed git subprocess boundary (ONE-1903, RC6/ARCH-0068).
//!
//! Every engine-initiated git call is a GitWire-class effect. The module holds
//! four load-bearing invariants:
//!
//! 1. **Identity is the object store.** A [`GitWireRepo`] is only obtainable by
//!    proving, through git, that a `RepoRef`, a working root, and a pinned
//!    commit all name one verified canonical git common directory. Durable rows
//!    are keyed by that store, never by a rendered path.
//! 2. **Stored claims are current claims.** A durable record replays only while
//!    the ref postcondition it recorded still holds, so an `A -> B -> A` ref
//!    cycle can never be answered from the first receipt.
//! 3. **One transactional publication path.** Every ref move — direct, staged,
//!    or recovered — is published by a single `update-ref --stdin` transaction
//!    whose durable intent was written first, so a crash is always recoverable
//!    and a partial multi-ref result is never certified.
//! 4. **The boundary is closed.** [`spawn_git`] is the crate's only production
//!    git process constructor: a pinned executable, a cleared environment, a
//!    fixed config policy that disables every repository-configured program,
//!    bounded runtime and output, and redacted failures.
//!
//! Absence is always read from a positive signal (`for-each-ref` output,
//! `cat-file --batch-check` `missing`, `rev-list --missing=print`), never from
//! an exit code, so an expected absence can never be confused with a fatal git
//! failure.

use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::OsString;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Condvar, LazyLock, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::checkout::lease::{
    CheckoutError, CheckoutLeaseAct, CheckoutRepoOps, CheckoutResult, CheckoutTeardownInspection,
    GitOid as LeaseGitOid, PushedHeadReceipt, TeardownReceiptMatch,
};
use crate::codebase::RepoRef;
use crate::error::{Error, Result};

#[cfg(test)]
mod tests;

/// Schema version of the durable GitWire record.
pub const GIT_WIRE_SCHEMA_VERSION: u8 = 2;
/// Domain separator of every GitWire derived key.
pub const GIT_WIRE_DOMAIN: &[u8] = b"oneiron:git-wire:v2";
/// `vault_meta` keyspace of GitWire records. Rows are repo-scoped
/// (`<prefix><repo-identity>:<record-key>`) so one unreadable row can only
/// affect the repository that wrote it.
pub const GIT_WIRE_RECORD_KEY_PREFIX: &[u8] = b"git_wire:record:v2:";
/// Namespace of the protected keep-refs that hold engine object sets alive.
pub const GIT_WIRE_KEEP_REF_PREFIX: &str = "refs/oneiron/keep/";
/// Directory name of the private, repository-scoped checkout root.
pub const GIT_WIRE_CHECKOUT_ROOT_NAME: &str = "oneiron-checkout";
/// Advisory lock file, in the canonical git common directory, that serializes
/// every engine ref/worktree effect across threads and processes.
pub const GIT_WIRE_REPO_LOCK_FILE_NAME: &str = "oneiron-repo-mutation.lock";

/// The process baseline a git child may inherit. `GIT_CONFIG_*`,
/// `GIT_TERMINAL_PROMPT`, and the other pinned keys are deliberately absent:
/// GitWire assigns them fixed values after `env_clear`, so an ambient value can
/// never reach a child.
pub const GIT_WIRE_INHERITED_ENV_KEYS: [&str; 4] = ["PATH", "TMPDIR", "LANG", "LC_ALL"];

/// Environment pairs forced on every child regardless of the ambient
/// environment. `GIT_NO_LAZY_FETCH` keeps a partial-clone read from becoming a
/// network fetch and an object write; `GIT_OPTIONAL_LOCKS` keeps inspection
/// from taking or refreshing an index lock.
pub const GIT_WIRE_FIXED_ENV: [(&str, &str); 8] = [
    ("GIT_CONFIG_NOSYSTEM", "1"),
    ("GIT_CONFIG_SYSTEM", "/dev/null"),
    ("GIT_CONFIG_GLOBAL", "/dev/null"),
    ("GIT_TERMINAL_PROMPT", "0"),
    ("GIT_OPTIONAL_LOCKS", "0"),
    ("GIT_NO_LAZY_FETCH", "1"),
    ("GIT_ATTR_NOSYSTEM", "1"),
    ("GIT_PAGER", "cat"),
];

/// The closed configuration policy. It is delivered through
/// `GIT_CONFIG_COUNT`/`GIT_CONFIG_KEY_<n>`/`GIT_CONFIG_VALUE_<n>`, which git
/// treats with command-line precedence, so no repository-local or system
/// setting can reintroduce an executable hook, filter, helper, or signer — and
/// the policy also reaches any git child a git child spawns.
pub const GIT_WIRE_CONFIG_POLICY: [(&str, &str); 18] = [
    ("core.hooksPath", "/dev/null"),
    ("core.fsmonitor", ""),
    ("core.askPass", ""),
    ("core.editor", "false"),
    ("core.pager", "cat"),
    ("core.sshCommand", "false"),
    ("core.attributesFile", "/dev/null"),
    ("core.autocrlf", "false"),
    ("credential.helper", ""),
    ("diff.external", ""),
    ("gc.auto", "0"),
    ("maintenance.auto", "false"),
    ("gpg.program", "false"),
    ("gpg.ssh.program", "false"),
    ("gpg.x509.program", "false"),
    ("commit.gpgSign", "false"),
    ("uploadpack.packObjectsHook", ""),
    ("protocol.allow", "never"),
];

const GIT_WIRE_DEFAULT_BINARY: &str = "git";
const GIT_WIRE_DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);
const GIT_WIRE_DEFAULT_MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
const GIT_WIRE_MAX_ARG_BYTES: usize = 65_536;
const GIT_WIRE_MAX_ARGS: usize = 64;
const GIT_WIRE_MAX_REF_BYTES: usize = 200;
const GIT_WIRE_MAX_PLAN_OBJECTS: usize = 256;
const GIT_WIRE_MAX_PUBLICATIONS: usize = 64;
const GIT_WIRE_OID_HEX_LEN: usize = 40;
const GIT_WIRE_READ_CHUNK_BYTES: usize = 8192;
const GIT_WIRE_POLL_INTERVAL: Duration = Duration::from_millis(2);

/// The only `-c <key>=<value>` pairs the migration bridge accepts ahead of the
/// verb; the closed policy itself is applied by GitWire, not by callers.
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

fn uncertain(message: String) -> Error {
    Error::RepoMutationFailed(message)
}

// ---------------------------------------------------------------------------
// Failure classification and redaction
// ---------------------------------------------------------------------------

/// The classified cause of a git failure.
///
/// A class is the *only* thing a git child's diagnostics contribute to a
/// durable row or a propagated error: the raw text, which can carry a remote
/// URL, a credential, or an absolute path, never leaves this module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitWireFailureClass {
    /// A ref could not be locked, or its lock file already existed.
    RefLocked,
    /// A compare-and-set saw a value other than the expected one.
    RefMismatch,
    /// A named object, ref, or revision does not exist.
    Missing,
    /// The object store or a ref store is damaged.
    Corrupt,
    /// The filesystem refused the operation.
    Permission,
    /// The working root is not a repository GitWire may drive.
    NotARepository,
    /// The child exceeded its runtime bound and was killed.
    Timeout,
    /// The child exceeded its output bound.
    OutputOverflow,
    /// The child was terminated by a signal.
    Signalled,
    /// Anything else. Always treated as uncertainty, never as absence.
    Unknown,
}

impl GitWireFailureClass {
    /// Stable wire name recorded on durable rows.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RefLocked => "ref_locked",
            Self::RefMismatch => "ref_mismatch",
            Self::Missing => "missing",
            Self::Corrupt => "corrupt",
            Self::Permission => "permission",
            Self::NotARepository => "not_a_repository",
            Self::Timeout => "timeout",
            Self::OutputOverflow => "output_overflow",
            Self::Signalled => "signalled",
            Self::Unknown => "unknown",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        const ALL: [GitWireFailureClass; 10] = [
            GitWireFailureClass::RefLocked,
            GitWireFailureClass::RefMismatch,
            GitWireFailureClass::Missing,
            GitWireFailureClass::Corrupt,
            GitWireFailureClass::Permission,
            GitWireFailureClass::NotARepository,
            GitWireFailureClass::Timeout,
            GitWireFailureClass::OutputOverflow,
            GitWireFailureClass::Signalled,
            GitWireFailureClass::Unknown,
        ];
        ALL.into_iter()
            .find(|class| class.as_str() == value)
            .ok_or_else(|| invalid("unknown git wire failure class"))
    }
}

/// Needle table used to classify a child's diagnostics. Matching happens on a
/// lowercased copy that is dropped immediately afterwards.
const GIT_WIRE_FAILURE_NEEDLES: [(&str, GitWireFailureClass); 16] = [
    ("but expected", GitWireFailureClass::RefMismatch),
    ("reference already exists", GitWireFailureClass::RefMismatch),
    ("unable to create", GitWireFailureClass::RefLocked),
    ("cannot lock ref", GitWireFailureClass::RefLocked),
    ("cannot lock the ref", GitWireFailureClass::RefLocked),
    ("unable to lock", GitWireFailureClass::RefLocked),
    ("permission denied", GitWireFailureClass::Permission),
    ("operation not permitted", GitWireFailureClass::Permission),
    ("read-only file system", GitWireFailureClass::Permission),
    ("not a git repository", GitWireFailureClass::NotARepository),
    ("object file is empty", GitWireFailureClass::Corrupt),
    ("loose object", GitWireFailureClass::Corrupt),
    ("corrupt", GitWireFailureClass::Corrupt),
    ("bad object", GitWireFailureClass::Corrupt),
    ("does not exist", GitWireFailureClass::Missing),
    ("unknown revision", GitWireFailureClass::Missing),
];

/// A git failure reduced to the facts that may safely be stored or propagated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GitWireFailure {
    class: GitWireFailureClass,
    exit_code: Option<i32>,
    diagnostics_digest: [u8; 32],
    diagnostics_len: usize,
}

impl GitWireFailure {
    /// The classified cause.
    pub const fn class(&self) -> GitWireFailureClass {
        self.class
    }

    /// Whether the failure leaves the repository in an unknown state, so the
    /// caller's recovery intent must be preserved rather than discarded.
    pub const fn is_uncertain(&self) -> bool {
        !matches!(self.class, GitWireFailureClass::RefMismatch)
    }

    /// The redacted description. It carries the operation, the class, the exit
    /// code, and a digest of the child's diagnostics — never their content.
    pub fn message(&self, operation: GitWireOperation) -> String {
        let digest = hex_lower(&self.diagnostics_digest);
        let short = &digest[..16];
        let class = self.class.as_str();
        let code = self.exit_code;
        let len = self.diagnostics_len;
        let name = operation.as_str();
        format!("git {name} failed: class={class} exit={code:?} diag=blake3:{short} bytes={len}")
    }

    fn error(&self, operation: GitWireOperation) -> Error {
        uncertain(self.message(operation))
    }
}

fn classify_failure(output: &GitWireProcessOutput) -> GitWireFailure {
    let class = if output.timed_out {
        GitWireFailureClass::Timeout
    } else if output.truncated {
        GitWireFailureClass::OutputOverflow
    } else if output.exit_code.is_none() {
        GitWireFailureClass::Signalled
    } else {
        classify_diagnostics(&output.stderr)
    };
    GitWireFailure {
        class,
        exit_code: output.exit_code,
        diagnostics_digest: *blake3::hash(&output.stderr).as_bytes(),
        diagnostics_len: output.stderr.len(),
    }
}

fn classify_diagnostics(stderr: &[u8]) -> GitWireFailureClass {
    let text = String::from_utf8_lossy(stderr).to_lowercase();
    for (needle, class) in GIT_WIRE_FAILURE_NEEDLES {
        if text.contains(needle) {
            return class;
        }
    }
    GitWireFailureClass::Unknown
}

// ---------------------------------------------------------------------------
// Operations and effect classes
// ---------------------------------------------------------------------------

/// The complete, positive classification of what an operation may change.
///
/// The classification is total: every [`GitWireOperation`] names exactly one
/// class, so a new operation cannot silently inherit "harmless".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitWireEffectClass {
    /// Changes no object, ref, index, or working tree.
    Read,
    /// May add objects to the object store; moves no ref.
    ObjectWrite,
    /// May move refs; writes no object.
    RefWrite,
    /// May both add objects and move a ref in one invocation.
    ObjectAndRefWrite,
    /// May change working-tree or index state on disk.
    WorktreeWrite,
}

impl GitWireEffectClass {
    /// Whether the class changes nothing.
    pub const fn is_read(self) -> bool {
        matches!(self, Self::Read)
    }

    /// Whether the class may add objects.
    pub const fn writes_objects(self) -> bool {
        matches!(self, Self::ObjectWrite | Self::ObjectAndRefWrite)
    }

    /// Whether the class may move a ref.
    pub const fn moves_refs(self) -> bool {
        matches!(self, Self::RefWrite | Self::ObjectAndRefWrite)
    }
}

/// Typed name of a git effect. The wire name is what durable rows and derived
/// keys carry, so it is stable across releases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitWireOperation {
    ReadRefs,
    ObjectInfo,
    ReachableObjects,
    ReadTree,
    ReadObject,
    RevParse,
    MergeBase,
    WorktreeList,
    StatusPorcelain,
    NotesShow,
    GitPath,
    WriteBlob,
    WriteTree,
    WriteCommit,
    /// The mixed writer class: `notes add` writes objects *and* moves the notes
    /// ref in one invocation. GitWire classifies it so both phases can refuse
    /// it, and deliberately exposes no constructor for it.
    NotesAdd,
    PublishRefs,
    WorktreeAdd,
    WorktreeRemove,
    WorktreePrune,
}

const GIT_WIRE_ALL_OPERATIONS: [GitWireOperation; 19] = [
    GitWireOperation::ReadRefs,
    GitWireOperation::ObjectInfo,
    GitWireOperation::ReachableObjects,
    GitWireOperation::ReadTree,
    GitWireOperation::ReadObject,
    GitWireOperation::RevParse,
    GitWireOperation::MergeBase,
    GitWireOperation::WorktreeList,
    GitWireOperation::StatusPorcelain,
    GitWireOperation::NotesShow,
    GitWireOperation::GitPath,
    GitWireOperation::WriteBlob,
    GitWireOperation::WriteTree,
    GitWireOperation::WriteCommit,
    GitWireOperation::NotesAdd,
    GitWireOperation::PublishRefs,
    GitWireOperation::WorktreeAdd,
    GitWireOperation::WorktreeRemove,
    GitWireOperation::WorktreePrune,
];

impl GitWireOperation {
    /// Stable wire name recorded on durable rows and hashed into keys.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadRefs => "read_refs",
            Self::ObjectInfo => "object_info",
            Self::ReachableObjects => "reachable_objects",
            Self::ReadTree => "read_tree",
            Self::ReadObject => "read_object",
            Self::RevParse => "rev_parse",
            Self::MergeBase => "merge_base",
            Self::WorktreeList => "worktree_list",
            Self::StatusPorcelain => "status_porcelain",
            Self::NotesShow => "notes_show",
            Self::GitPath => "git_path",
            Self::WriteBlob => "write_blob",
            Self::WriteTree => "write_tree",
            Self::WriteCommit => "write_commit",
            Self::NotesAdd => "notes_add",
            Self::PublishRefs => "publish_refs",
            Self::WorktreeAdd => "worktree_add",
            Self::WorktreeRemove => "worktree_remove",
            Self::WorktreePrune => "worktree_prune",
        }
    }

    /// The single effect class of this operation.
    pub const fn effect_class(self) -> GitWireEffectClass {
        match self {
            Self::ReadRefs
            | Self::ObjectInfo
            | Self::ReachableObjects
            | Self::ReadTree
            | Self::ReadObject
            | Self::RevParse
            | Self::MergeBase
            | Self::WorktreeList
            | Self::StatusPorcelain
            | Self::NotesShow
            | Self::GitPath => GitWireEffectClass::Read,
            Self::WriteBlob | Self::WriteTree | Self::WriteCommit => {
                GitWireEffectClass::ObjectWrite
            }
            Self::NotesAdd => GitWireEffectClass::ObjectAndRefWrite,
            Self::PublishRefs => GitWireEffectClass::RefWrite,
            Self::WorktreeAdd | Self::WorktreeRemove | Self::WorktreePrune => {
                GitWireEffectClass::WorktreeWrite
            }
        }
    }

    fn parse(value: &str) -> Result<Self> {
        GIT_WIRE_ALL_OPERATIONS
            .into_iter()
            .find(|operation| operation.as_str() == value)
            .ok_or_else(|| invalid("unknown git wire operation"))
    }
}

// ---------------------------------------------------------------------------
// Ref names, object ids, observations
// ---------------------------------------------------------------------------

/// A validated full git ref name under `refs/`.
///
/// `HEAD` is deliberately not a ref name here: GitWire never compare-and-sets
/// or publishes the symbolic head, and the checkout port pins an explicit
/// commit instead. The accepted byte set is narrow enough that a name is always
/// safe as an unquoted `update-ref --stdin` field.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GitRefName(String);

impl GitRefName {
    /// Parses a full ref name. Short names, option shapes, revision syntax,
    /// lock shapes, and any byte git may later reject are refused here.
    pub fn parse_full(value: impl Into<String>) -> GitWireResult<Self> {
        let value = value.into();
        validate_full_ref_name(&value)?;
        Ok(Self(value))
    }

    /// The validated ref name.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn is_keep_ref(&self) -> bool {
        self.0.starts_with(GIT_WIRE_KEEP_REF_PREFIX)
    }
}

fn validate_full_ref_name(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > GIT_WIRE_MAX_REF_BYTES {
        return Err(invalid("git ref name must be non-empty and bounded"));
    }
    if !value.starts_with("refs/") {
        return Err(invalid("git ref name must be a full refs/ name"));
    }
    if value.ends_with('/') || value.contains("//") || value.contains("..") {
        return Err(invalid("git ref name must not use empty or relative parts"));
    }
    let shaped = value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/'));
    if !shaped {
        return Err(invalid(
            "git ref name must be [A-Za-z0-9._-/] after the refs/ prefix",
        ));
    }
    let mut parts = 0;
    for part in value.split('/') {
        if part.is_empty() || part.starts_with('.') || part.ends_with(".lock") || part == ".." {
            return Err(invalid("git ref name component is not a valid ref path"));
        }
        parts += 1;
    }
    if parts < 2 {
        return Err(invalid("git ref name must have a category and a leaf"));
    }
    Ok(())
}

/// A validated 40-character lower-hex, non-zero git object id.
///
/// `checkout::lease` owns a byte-array `GitOid` of its own; the two convert
/// through hex at the [`CheckoutRepoOps`] boundary and never alias.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
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
        if value.bytes().all(|byte| byte == b'0') {
            return Err(invalid("git oid must not be the null oid"));
        }
        Ok(Self(value))
    }

    /// The validated object id.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A ref and the value GitWire observed for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedGitRef {
    pub name: GitRefName,
    pub oid: Option<GitOid>,
}

/// What a publication requires of a ref's current value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GitRefExpectation {
    /// The ref must not exist.
    Absent,
    /// The ref must carry exactly this value.
    Value(GitOid),
    /// No requirement. Reserved for protection refs, which carry no decision.
    Any,
}

impl GitRefExpectation {
    fn from_observed(oid: Option<&GitOid>) -> Self {
        match oid {
            Some(oid) => Self::Value(oid.clone()),
            None => Self::Absent,
        }
    }

    fn holds_for(&self, observed: Option<&GitOid>) -> bool {
        match self {
            Self::Absent => observed.is_none(),
            Self::Value(expected) => observed == Some(expected),
            Self::Any => true,
        }
    }

    fn wire(&self) -> Option<String> {
        match self {
            Self::Absent => Some(String::new()),
            Self::Value(oid) => Some(oid.as_str().to_owned()),
            Self::Any => None,
        }
    }

    fn from_wire(value: Option<&String>) -> Result<Self> {
        match value {
            None => Ok(Self::Any),
            Some(text) if text.is_empty() => Ok(Self::Absent),
            Some(text) => Ok(Self::Value(GitOid::parse_hex(text.clone())?)),
        }
    }
}

/// One ref move in a publication transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitRefPublication {
    name: GitRefName,
    expected: GitRefExpectation,
    next: Option<GitOid>,
}

impl GitRefPublication {
    /// Moves `name` to `next`, requiring `expected` first.
    pub fn update(name: GitRefName, expected: GitRefExpectation, next: GitOid) -> Self {
        Self {
            name,
            expected,
            next: Some(next),
        }
    }

    /// Deletes `name`, requiring `expected` first.
    pub fn delete(name: GitRefName, expected: GitRefExpectation) -> Self {
        Self {
            name,
            expected,
            next: None,
        }
    }

    /// The published ref.
    pub fn name(&self) -> &GitRefName {
        &self.name
    }

    /// The value the decision was made against.
    pub fn expected(&self) -> &GitRefExpectation {
        &self.expected
    }

    /// The value the ref is moved to, or `None` for a deletion.
    pub fn next(&self) -> Option<&GitOid> {
        self.next.as_ref()
    }

    fn satisfied_by(&self, observed: Option<&GitOid>) -> bool {
        observed == self.next.as_ref()
    }

    fn stdin_line(&self) -> String {
        let name = self.name.as_str();
        let expectation = self.expected.wire();
        match (&self.next, expectation) {
            (Some(next), Some(expected)) => {
                let next = next.as_str();
                if expected.is_empty() {
                    format!("update {name} {next} \"\"\n")
                } else {
                    format!("update {name} {next} {expected}\n")
                }
            }
            (Some(next), None) => format!("update {name} {}\n", next.as_str()),
            (None, Some(expected)) if !expected.is_empty() => {
                format!("delete {name} {expected}\n")
            }
            (None, _) => format!("delete {name}\n"),
        }
    }
}

// ---------------------------------------------------------------------------
// Object payload types
// ---------------------------------------------------------------------------

/// One entry of a git tree object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitTreeEntry {
    pub mode: u32,
    pub name: Vec<u8>,
    pub oid: GitOid,
}

/// A validated extra commit-object header. Names are restricted to
/// `[a-z0-9-]+(:[a-z0-9-]+)*` and may never shadow a standard header; values
/// are single-line with no NUL/CR/LF. Headers ride the object body, never argv.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitCommitHeader {
    name: String,
    value: Vec<u8>,
}

impl GitCommitHeader {
    /// Parses an extra commit header.
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
        let shaped = !segment.is_empty()
            && segment
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
    /// Extra object headers after the standard set. Empty for ordinary commits.
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

fn encode_mktree_entries(entries: &[GitTreeEntry]) -> Result<Vec<u8>> {
    let mut payload = Vec::new();
    for entry in entries {
        if entry.name.is_empty() || entry.name.contains(&0) {
            return Err(invalid("tree entry name must be non-empty and NUL-free"));
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
        entries.push(parse_tree_entry(record)?);
    }
    Ok(entries)
}

fn parse_tree_entry(record: &[u8]) -> Result<GitTreeEntry> {
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
    Ok(GitTreeEntry {
        mode: u32::from_str_radix(mode, 8)
            .map_err(|_| invalid("git tree record mode must be octal"))?,
        name: record[split + 1..].to_vec(),
        oid: GitOid::parse_hex(oid)?,
    })
}

// ---------------------------------------------------------------------------
// Process baseline and the single subprocess constructor
// ---------------------------------------------------------------------------

/// The pinned executable, inherited baseline, and resource bounds every child
/// runs under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitWireProcessEnv {
    git_binary: PathBuf,
    path: OsString,
    tmpdir: PathBuf,
    timeout: Duration,
    max_output_bytes: usize,
}

/// The process baseline, resolved once. Pinning the executable at first use is
/// what keeps a later `PATH` change from redirecting a child.
static GIT_WIRE_PROCESS_ENV: LazyLock<Option<GitWireProcessEnv>> =
    LazyLock::new(GitWireProcessEnv::resolve);

impl GitWireProcessEnv {
    /// The captured baseline with the git executable pinned to one absolute
    /// path.
    pub fn capture() -> GitWireResult<Self> {
        GIT_WIRE_PROCESS_ENV
            .clone()
            .ok_or_else(|| invalid("git executable was not found on PATH"))
    }

    fn resolve() -> Option<Self> {
        let path = std::env::var_os("PATH").unwrap_or_default();
        let git_binary = resolve_git_binary(&path).ok()?;
        Some(Self {
            git_binary,
            path,
            tmpdir: std::env::temp_dir(),
            timeout: GIT_WIRE_DEFAULT_TIMEOUT,
            max_output_bytes: GIT_WIRE_DEFAULT_MAX_OUTPUT_BYTES,
        })
    }

    /// The pinned absolute git executable.
    pub fn git_binary(&self) -> &Path {
        &self.git_binary
    }

    /// The wall-clock bound on one child.
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }

    /// The captured output bound of one child.
    pub const fn max_output_bytes(&self) -> usize {
        self.max_output_bytes
    }

    /// Narrows the runtime and output bounds.
    pub fn with_limits(
        mut self,
        timeout: Duration,
        max_output_bytes: usize,
    ) -> GitWireResult<Self> {
        if timeout.is_zero() || max_output_bytes == 0 {
            return Err(invalid("git wire bounds must be positive"));
        }
        self.timeout = timeout;
        self.max_output_bytes = max_output_bytes;
        Ok(self)
    }

    /// Test-only: retargets the pinned executable so the bounded-runtime and
    /// bounded-output paths can be exercised deterministically. No production
    /// build can reach this, so the boundary keeps exactly one executable.
    #[cfg(test)]
    pub(crate) fn with_binary_for_test(mut self, binary: PathBuf) -> Self {
        self.git_binary = binary;
        self
    }
}

fn resolve_git_binary(path: &OsString) -> Result<PathBuf> {
    for directory in std::env::split_paths(path) {
        if directory.as_os_str().is_empty() {
            continue;
        }
        let candidate = directory.join(GIT_WIRE_DEFAULT_BINARY);
        if is_executable_file(&candidate) {
            return candidate
                .canonicalize()
                .map_err(|_| invalid("git executable could not be pinned"));
        }
    }
    Err(invalid("git executable was not found on PATH"))
}

#[cfg(unix)]
fn is_executable_file(candidate: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(candidate).is_ok_and(|metadata| {
        metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
    })
}

#[cfg(not(unix))]
fn is_executable_file(candidate: &Path) -> bool {
    matches!(fs::metadata(candidate), Ok(metadata) if metadata.is_file())
}

/// Captured result of one git child process.
#[derive(Debug, Clone)]
pub(crate) struct GitWireProcessOutput {
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
    pub(crate) exit_code: Option<i32>,
    pub(crate) success: bool,
    pub(crate) timed_out: bool,
    pub(crate) truncated: bool,
}

/// The single production git subprocess constructor in this crate.
///
/// Shape: `<pinned git> -C <repo_root> <frozen argv>`. The environment is
/// cleared and rebuilt from [`GIT_WIRE_INHERITED_ENV_KEYS`], the forced
/// [`GIT_WIRE_FIXED_ENV`] pairs, and the [`GIT_WIRE_CONFIG_POLICY`] override
/// block. Runtime and captured output are bounded, stdin is written on its own
/// thread so a large payload cannot deadlock against a full output pipe, and no
/// shell is ever spawned.
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
    command.stdin(if stdin_payload.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    let mut child = command.spawn()?;
    let writer = stdin_payload.map(|payload| spawn_stdin_writer(&mut child, payload));
    let cap = process_env.max_output_bytes;
    let out_reader = child.stdout.take().map(|pipe| spawn_reader(pipe, cap));
    let err_reader = child.stderr.take().map(|pipe| spawn_reader(pipe, cap));
    let status = wait_bounded(&mut child, process_env.timeout)?;
    if let Some(writer) = writer {
        let _ = writer.join();
    }
    let (stdout, stdout_over) = join_reader(out_reader);
    let (stderr, stderr_over) = join_reader(err_reader);
    let truncated = stdout_over || stderr_over;
    let (exit_code, exited_zero) = match status {
        Some(status) => (status.code(), status.success()),
        None => (None, false),
    };
    Ok(GitWireProcessOutput {
        stdout,
        stderr,
        exit_code,
        success: exited_zero && !truncated,
        timed_out: status.is_none(),
        truncated,
    })
}

type ReaderHandle = std::thread::JoinHandle<(Vec<u8>, bool)>;

fn spawn_stdin_writer(child: &mut Child, payload: &[u8]) -> std::thread::JoinHandle<()> {
    let mut sink = child.stdin.take();
    let owned = payload.to_vec();
    std::thread::spawn(move || {
        if let Some(pipe) = sink.as_mut() {
            let _ = pipe.write_all(&owned);
            let _ = pipe.flush();
        }
        drop(sink);
    })
}

fn spawn_reader<R>(pipe: R, cap: usize) -> ReaderHandle
where
    R: Read + Send + 'static,
{
    std::thread::spawn(move || read_capped(pipe, cap))
}

fn join_reader(handle: Option<ReaderHandle>) -> (Vec<u8>, bool) {
    match handle {
        Some(handle) => handle.join().unwrap_or_else(|_| (Vec::new(), true)),
        None => (Vec::new(), false),
    }
}

/// Reads a pipe to completion under a byte cap. Once the cap is exceeded the
/// remainder is drained and discarded, so a runaway child is bounded without
/// being blocked into a deadlock.
fn read_capped<R: Read>(mut pipe: R, cap: usize) -> (Vec<u8>, bool) {
    let mut collected = Vec::new();
    let mut chunk = [0_u8; GIT_WIRE_READ_CHUNK_BYTES];
    let mut overflowed = false;
    loop {
        match pipe.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(read) => {
                if overflowed || collected.len() + read > cap {
                    overflowed = true;
                } else {
                    collected.extend_from_slice(&chunk[..read]);
                }
            }
        }
    }
    (collected, overflowed)
}

/// Waits for the child under a wall-clock bound, killing and reaping it on
/// expiry. `None` means the bound was exceeded.
fn wait_bounded(child: &mut Child, timeout: Duration) -> Result<Option<ExitStatus>> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Ok(None);
        }
        std::thread::sleep(GIT_WIRE_POLL_INTERVAL);
    }
}

/// The complete environment of a GitWire child after `env_clear`.
fn child_env(process_env: &GitWireProcessEnv) -> Vec<(String, OsString)> {
    child_env_from(process_env, ambient_env)
}

/// The only ambient-environment read GitWire performs.
fn ambient_env(key: &str) -> Option<OsString> {
    std::env::var_os(key)
}

/// The environment builder with the ambient lookup injected.
///
/// Only [`GIT_WIRE_INHERITED_ENV_KEYS`] is ever asked of `ambient`. The fixed
/// pairs and the config-policy block are appended afterwards, so an ambient
/// `GIT_CONFIG_NOSYSTEM=0` cannot reach a child: those keys are never read from
/// the parent at all.
fn child_env_from<F>(process_env: &GitWireProcessEnv, ambient: F) -> Vec<(String, OsString)>
where
    F: Fn(&str) -> Option<OsString>,
{
    let mut pairs = Vec::new();
    pairs.push(("PATH".to_owned(), process_env.path.clone()));
    pairs.push((
        "TMPDIR".to_owned(),
        process_env.tmpdir.clone().into_os_string(),
    ));
    for key in ["LANG", "LC_ALL"] {
        if let Some(value) = ambient(key) {
            pairs.push((key.to_owned(), value));
        }
    }
    for (key, value) in GIT_WIRE_FIXED_ENV {
        pairs.push((key.to_owned(), OsString::from(value)));
    }
    pairs.extend(config_policy_env());
    pairs
}

/// The closed config policy rendered as git's command-line-precedence
/// environment block.
fn config_policy_env() -> Vec<(String, OsString)> {
    let mut pairs = Vec::with_capacity(GIT_WIRE_CONFIG_POLICY.len() * 2 + 1);
    pairs.push((
        "GIT_CONFIG_COUNT".to_owned(),
        OsString::from(GIT_WIRE_CONFIG_POLICY.len().to_string()),
    ));
    for (index, (key, value)) in GIT_WIRE_CONFIG_POLICY.into_iter().enumerate() {
        pairs.push((format!("GIT_CONFIG_KEY_{index}"), OsString::from(key)));
        pairs.push((format!("GIT_CONFIG_VALUE_{index}"), OsString::from(value)));
    }
    pairs
}

// ---------------------------------------------------------------------------
// Frozen argv
// ---------------------------------------------------------------------------

/// A frozen git argv: a fixed verb, validated argument positions, and an
/// optional stdin payload.
///
/// Every field is private and every constructor is typed, so no caller can
/// assemble an arbitrary vector or a shell string. Every GitWire argv requires
/// exit status zero: absence is always read from output, never from a status.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FrozenGitArgv {
    operation: GitWireOperation,
    args: Vec<OsString>,
    stdin: Option<Vec<u8>>,
}

impl FrozenGitArgv {
    fn frozen(operation: GitWireOperation, tail: Vec<OsString>) -> Self {
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
    fn read_refs(names: &[GitRefName]) -> Self {
        let mut tail = os_args(&["for-each-ref", "--format=%(objectname) %(refname)"]);
        for name in names {
            tail.push(OsString::from(name.as_str()));
        }
        Self::frozen(GitWireOperation::ReadRefs, tail)
    }

    /// `cat-file --batch-check` over oids on stdin. A missing object is
    /// reported as `<oid> missing`, so absence is a positive answer.
    fn object_info(oids: &[GitOid]) -> Self {
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
    fn reachable_objects(tip: &GitOid, exclude: &[GitOid]) -> Self {
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
    fn read_tree(tree: &GitOid) -> Self {
        let tail = os_args(&["ls-tree", "-z", tree.as_str()]);
        Self::frozen(GitWireOperation::ReadTree, tail)
    }

    /// `cat-file <type> <oid>`: the raw stored bytes of one object.
    fn read_object(kind: &str, oid: &GitOid) -> Self {
        let tail = os_args(&["cat-file", kind, oid.as_str()]);
        Self::frozen(GitWireOperation::ReadObject, tail)
    }

    /// `rev-parse --verify <revision>^{commit}`.
    fn rev_parse_commit(revision: &str) -> GitWireResult<Self> {
        validate_revision(revision)?;
        let peeled = format!("{revision}^{{commit}}");
        let tail = os_args(&["rev-parse", "--verify", "--end-of-options", &peeled]);
        Ok(Self::frozen(GitWireOperation::RevParse, tail))
    }

    /// `merge-base` over two validated revisions.
    fn merge_base(left: &str, right: &str) -> GitWireResult<Self> {
        validate_revision(left)?;
        validate_revision(right)?;
        let tail = os_args(&["merge-base", "--end-of-options", left, right]);
        Ok(Self::frozen(GitWireOperation::MergeBase, tail))
    }

    /// `rev-parse --path-format=absolute --git-common-dir`.
    fn git_common_dir() -> Self {
        let tail = os_args(&["rev-parse", "--path-format=absolute", "--git-common-dir"]);
        Self::frozen(GitWireOperation::GitPath, tail)
    }

    /// `worktree list --porcelain -z`.
    fn worktree_list() -> Self {
        let tail = os_args(&["worktree", "list", "--porcelain", "-z"]);
        Self::frozen(GitWireOperation::WorktreeList, tail)
    }

    /// `--no-optional-locks status --porcelain -z`: inspection that refreshes
    /// no index and takes no optional lock.
    fn status_porcelain() -> Self {
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
    fn notes_show(notes_ref: &GitRefName, commit: &GitOid) -> Self {
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
    fn write_blob(bytes: &[u8]) -> Self {
        let tail = os_args(&["hash-object", "-t", "blob", "-w", "--stdin"]);
        Self::frozen(GitWireOperation::WriteBlob, tail).with_stdin(bytes.to_vec())
    }

    /// `mktree -z` with NUL-terminated entry records on stdin. NUL framing
    /// makes every legal git path name expressible, newlines included.
    fn write_tree(entries: &[GitTreeEntry]) -> GitWireResult<Self> {
        let payload = encode_mktree_entries(entries)?;
        let tail = os_args(&["mktree", "-z"]);
        Ok(Self::frozen(GitWireOperation::WriteTree, tail).with_stdin(payload))
    }

    /// `hash-object -t commit -w --stdin` with the serialized commit on stdin.
    fn write_commit(request: &GitCommitRequest) -> GitWireResult<Self> {
        let payload = request.to_object_bytes()?;
        let tail = os_args(&["hash-object", "-t", "commit", "-w", "--stdin"]);
        Ok(Self::frozen(GitWireOperation::WriteCommit, tail).with_stdin(payload))
    }

    /// `update-ref --stdin --no-deref`: the one transactional publication.
    /// git applies the batch atomically, so no partial multi-ref state exists.
    fn publish_refs(publications: &[GitRefPublication]) -> Self {
        let tail = os_args(&["update-ref", "--no-deref", "--stdin"]);
        let mut payload = String::new();
        for publication in publications {
            payload.push_str(&publication.stdin_line());
        }
        Self::frozen(GitWireOperation::PublishRefs, tail).with_stdin(payload.into_bytes())
    }

    /// `worktree add --detach -- <path> <commit>`: materializes exactly one
    /// commit and never moves the repository head.
    fn worktree_add(path: &Path, commit: &GitOid) -> GitWireResult<Self> {
        validate_path_arg(path)?;
        let mut tail = os_args(&["worktree", "add", "--detach", "--"]);
        tail.push(path.as_os_str().to_owned());
        tail.push(OsString::from(commit.as_str()));
        Ok(Self::frozen(GitWireOperation::WorktreeAdd, tail))
    }

    /// `worktree remove --force -- <path>`.
    fn worktree_remove(path: &Path) -> GitWireResult<Self> {
        validate_path_arg(path)?;
        let mut tail = os_args(&["worktree", "remove", "--force", "--"]);
        tail.push(path.as_os_str().to_owned());
        Ok(Self::frozen(GitWireOperation::WorktreeRemove, tail))
    }

    /// `worktree prune`: reconciles registration with the filesystem.
    fn worktree_prune() -> Self {
        Self::frozen(
            GitWireOperation::WorktreePrune,
            os_args(&["worktree", "prune"]),
        )
    }

    const fn operation(&self) -> GitWireOperation {
        self.operation
    }

    fn args(&self) -> &[OsString] {
        &self.args
    }

    fn stdin(&self) -> Option<&[u8]> {
        self.stdin.as_deref()
    }
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
    if !path.is_absolute() {
        return Err(invalid("git path argument must be absolute"));
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

// ---------------------------------------------------------------------------
// Verified repository identity
// ---------------------------------------------------------------------------

/// The identity of one object store.
///
/// It is derived from the verified canonical git common directory, so two
/// clones that share a `RepoRef` are two identities and neither can replay the
/// other's receipts, while two spellings of one clone are one identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GitWireRepoIdentity([u8; 32]);

impl GitWireRepoIdentity {
    /// The lower-hex identity used in durable key prefixes.
    pub fn as_hex(&self) -> String {
        hex_lower(&self.0)
    }

    const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A repository whose `RepoRef`, working root, pinned commit, and object store
/// have all been proven to agree.
///
/// There is no field constructor: the only way to obtain one is
/// [`GitWire::open_repo`], which performs the proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitWireRepo {
    repo_ref: RepoRef,
    repo_root: PathBuf,
    common_dir: PathBuf,
    identity: GitWireRepoIdentity,
}

impl GitWireRepo {
    /// The repo_ref this handle was proven against.
    pub fn repo_ref(&self) -> &RepoRef {
        &self.repo_ref
    }

    /// The canonical working root git is invoked from.
    pub fn repo_root(&self) -> &Path {
        &self.repo_root
    }

    /// The canonical git common directory that backs the object and ref store.
    pub fn common_dir(&self) -> &Path {
        &self.common_dir
    }

    /// The verified object-store identity.
    pub const fn identity(&self) -> GitWireRepoIdentity {
        self.identity
    }

    /// The commit the repo_ref pins, proven present in this object store.
    pub fn pinned_commit(&self) -> GitWireResult<GitOid> {
        let commit = self
            .repo_ref
            .commit_hash()
            .ok_or_else(|| invalid("repo_ref must pin a commit"))?;
        GitOid::parse_hex(commit.to_ascii_lowercase())
    }
}

fn repo_identity_for(common_dir: &Path) -> GitWireRepoIdentity {
    let mut hasher = blake3::Hasher::new();
    hash_field(&mut hasher, GIT_WIRE_DOMAIN);
    hash_field(&mut hasher, b"repo-identity");
    hash_field(&mut hasher, common_dir.as_os_str().as_encoded_bytes());
    GitWireRepoIdentity(*hasher.finalize().as_bytes())
}

// ---------------------------------------------------------------------------
// Repository coordinator
// ---------------------------------------------------------------------------

struct GitWireRepoLockCell {
    held: Mutex<bool>,
    released: Condvar,
}

static GIT_WIRE_REPO_LOCKS: LazyLock<Mutex<HashMap<Vec<u8>, Arc<GitWireRepoLockCell>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

thread_local! {
    static GIT_WIRE_HELD_DEPTH: RefCell<HashMap<Vec<u8>, usize>> =
        RefCell::new(HashMap::new());
}

/// The exclusive hold on one repository's ref and worktree effects.
///
/// Every GitWire writer and every `repo_mutation` writer takes this guard on
/// the same canonical common directory, so the two clusters cannot interleave.
/// Acquisition is re-entrant on one thread and mutually exclusive across
/// threads and processes, because the underlying `flock` is held per open file
/// description.
pub(crate) struct GitWireRepoGuard {
    key: Vec<u8>,
    cell: Option<Arc<GitWireRepoLockCell>>,
    file: Option<fs::File>,
}

/// Serializes every engine effect on the repository behind `common_dir`.
pub(crate) fn lock_repository(common_dir: &Path) -> Result<GitWireRepoGuard> {
    let key = common_dir.as_os_str().as_encoded_bytes().to_vec();
    let depth = held_depth(&key);
    if depth > 0 {
        set_held_depth(&key, depth.saturating_add(1));
        return Ok(GitWireRepoGuard {
            key,
            cell: None,
            file: None,
        });
    }
    let cell = repo_lock_cell(&key)?;
    acquire_cell(&cell)?;
    let file = match acquire_file_lock(common_dir) {
        Ok(file) => file,
        Err(error) => {
            release_cell(&cell);
            return Err(error);
        }
    };
    set_held_depth(&key, 1);
    Ok(GitWireRepoGuard {
        key,
        cell: Some(cell),
        file,
    })
}

impl Drop for GitWireRepoGuard {
    fn drop(&mut self) {
        let depth = held_depth(&self.key);
        set_held_depth(&self.key, depth.saturating_sub(1));
        if let Some(file) = self.file.take() {
            release_file_lock(&file);
        }
        if let Some(cell) = self.cell.take() {
            release_cell(&cell);
        }
    }
}

fn held_depth(key: &[u8]) -> usize {
    GIT_WIRE_HELD_DEPTH.with(|held| held.borrow().get(key).copied().unwrap_or(0))
}

fn set_held_depth(key: &[u8], depth: usize) {
    GIT_WIRE_HELD_DEPTH.with(|held| {
        let mut held = held.borrow_mut();
        if depth == 0 {
            held.remove(key);
        } else {
            held.insert(key.to_vec(), depth);
        }
    });
}

fn repo_lock_cell(key: &[u8]) -> Result<Arc<GitWireRepoLockCell>> {
    let mut locks = GIT_WIRE_REPO_LOCKS
        .lock()
        .map_err(|_| Error::ConcurrentWrite("git wire repository lock map poisoned"))?;
    Ok(locks
        .entry(key.to_vec())
        .or_insert_with(|| {
            Arc::new(GitWireRepoLockCell {
                held: Mutex::new(false),
                released: Condvar::new(),
            })
        })
        .clone())
}

fn acquire_cell(cell: &Arc<GitWireRepoLockCell>) -> Result<()> {
    let mut held = cell
        .held
        .lock()
        .map_err(|_| Error::ConcurrentWrite("git wire repository lock poisoned"))?;
    while *held {
        held = cell
            .released
            .wait(held)
            .map_err(|_| Error::ConcurrentWrite("git wire repository lock poisoned"))?;
    }
    *held = true;
    Ok(())
}

fn release_cell(cell: &Arc<GitWireRepoLockCell>) {
    if let Ok(mut held) = cell.held.lock() {
        *held = false;
        cell.released.notify_one();
    }
}

#[cfg(unix)]
fn acquire_file_lock(common_dir: &Path) -> Result<Option<fs::File>> {
    use std::os::fd::AsRawFd;

    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(common_dir.join(GIT_WIRE_REPO_LOCK_FILE_NAME))?;
    // SAFETY: `file.as_raw_fd()` is valid for the duration of this call and
    // `flock(LOCK_EX)` blocks until the kernel grants the advisory lock.
    let granted = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
    if granted == 0 {
        Ok(Some(file))
    } else {
        Err(std::io::Error::last_os_error().into())
    }
}

#[cfg(not(unix))]
fn acquire_file_lock(_common_dir: &Path) -> Result<Option<fs::File>> {
    Ok(None)
}

#[cfg(unix)]
fn release_file_lock(file: &fs::File) {
    use std::os::fd::AsRawFd;

    // SAFETY: `file.as_raw_fd()` is a live descriptor owned by the guard, and
    // `flock(LOCK_UN)` releases the advisory lock before it is closed.
    unsafe {
        libc::flock(file.as_raw_fd(), libc::LOCK_UN);
    }
}

#[cfg(not(unix))]
fn release_file_lock(_file: &fs::File) {}

// ---------------------------------------------------------------------------
// Two-phase plan
// ---------------------------------------------------------------------------

/// One object-producing step of a plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GitWireObjectWrite {
    Blob(Vec<u8>),
    Tree(Vec<GitTreeEntry>),
    Commit(GitCommitRequest),
}

impl GitWireObjectWrite {
    fn argv(&self) -> GitWireResult<FrozenGitArgv> {
        match self {
            Self::Blob(bytes) => Ok(FrozenGitArgv::write_blob(bytes)),
            Self::Tree(entries) => FrozenGitArgv::write_tree(entries),
            Self::Commit(request) => FrozenGitArgv::write_commit(request),
        }
    }
}

/// A reference to an object a plan will publish: either one already in the
/// store, or the output of an earlier step of the same plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitWirePlannedOid {
    Existing(usize),
    Written(usize),
}

/// A publication whose target may still be unwritten.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PlannedPublication {
    name: GitRefName,
    expected: GitRefExpectation,
    next: Option<GitWirePlannedOid>,
}

/// A phase-one plan: object writes plus the ref publications they authorize.
///
/// This is the whole public two-phase entry. A caller assembles a plan with
/// typed builders, hands it to [`GitWire::stage`], and commits the returned
/// capability — no private field is ever needed, and a ref-moving operation
/// such as `notes add` cannot enter phase one because no plan step can express
/// one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GitWirePlan {
    objects: Vec<GitWireObjectWrite>,
    existing: Vec<GitOid>,
    publications: Vec<PlannedPublication>,
}

impl GitWirePlan {
    /// An empty plan.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a blob write and returns a handle to its object id.
    pub fn write_blob(&mut self, bytes: impl Into<Vec<u8>>) -> GitWireResult<GitWirePlannedOid> {
        self.push_object(GitWireObjectWrite::Blob(bytes.into()))
    }

    /// Adds a tree write and returns a handle to its object id.
    pub fn write_tree(&mut self, entries: Vec<GitTreeEntry>) -> GitWireResult<GitWirePlannedOid> {
        self.push_object(GitWireObjectWrite::Tree(entries))
    }

    /// Adds a commit write and returns a handle to its object id.
    pub fn write_commit(&mut self, request: GitCommitRequest) -> GitWireResult<GitWirePlannedOid> {
        self.push_object(GitWireObjectWrite::Commit(request))
    }

    /// Names an object that already exists in the store.
    pub fn existing_object(&mut self, oid: GitOid) -> GitWireResult<GitWirePlannedOid> {
        if self.existing.len() >= GIT_WIRE_MAX_PLAN_OBJECTS {
            return Err(invalid("git wire plan exceeds its object bound"));
        }
        self.existing.push(oid);
        Ok(GitWirePlannedOid::Existing(self.existing.len() - 1))
    }

    /// Publishes `name` at `target`, requiring the value the caller decided
    /// against.
    pub fn publish(
        &mut self,
        name: GitRefName,
        expected: GitRefExpectation,
        target: GitWirePlannedOid,
    ) -> GitWireResult<()> {
        self.push_publication(name, expected, Some(target))
    }

    /// Deletes `name`, requiring the value the caller decided against.
    pub fn unpublish(
        &mut self,
        name: GitRefName,
        expected: GitRefExpectation,
    ) -> GitWireResult<()> {
        self.push_publication(name, expected, None)
    }

    fn push_object(&mut self, write: GitWireObjectWrite) -> GitWireResult<GitWirePlannedOid> {
        if self.objects.len() >= GIT_WIRE_MAX_PLAN_OBJECTS {
            return Err(invalid("git wire plan exceeds its object bound"));
        }
        self.objects.push(write);
        Ok(GitWirePlannedOid::Written(self.objects.len() - 1))
    }

    fn push_publication(
        &mut self,
        name: GitRefName,
        expected: GitRefExpectation,
        next: Option<GitWirePlannedOid>,
    ) -> GitWireResult<()> {
        if self.publications.len() >= GIT_WIRE_MAX_PUBLICATIONS {
            return Err(invalid("git wire plan exceeds its publication bound"));
        }
        if name.is_keep_ref() {
            return Err(invalid(
                "git wire plan must not publish an engine keep-ref directly",
            ));
        }
        if matches!(expected, GitRefExpectation::Any) {
            return Err(invalid(
                "git wire publication must state the value it was decided against",
            ));
        }
        if self.publications.iter().any(|entry| entry.name == name) {
            return Err(invalid("git wire plan names one ref twice"));
        }
        self.publications.push(PlannedPublication {
            name,
            expected,
            next,
        });
        Ok(())
    }

    fn validate(&self) -> Result<()> {
        if self.publications.is_empty() {
            return Err(invalid("git wire plan must publish at least one ref"));
        }
        for publication in &self.publications {
            let Some(target) = publication.next else {
                continue;
            };
            let known = match target {
                GitWirePlannedOid::Written(index) => index < self.objects.len(),
                GitWirePlannedOid::Existing(index) => index < self.existing.len(),
            };
            if !known {
                return Err(invalid("git wire plan publishes an unknown object handle"));
            }
        }
        Ok(())
    }

    /// The stable content hash of the plan: object payload hashes plus the
    /// publications, so two textually identical plans claim one stage key and
    /// two different plans never collide.
    fn plan_hash(&self) -> GitWireResult<[u8; 32]> {
        let mut hasher = blake3::Hasher::new();
        hash_field(&mut hasher, GIT_WIRE_DOMAIN);
        hash_field(&mut hasher, b"plan");
        for write in &self.objects {
            let argv = write.argv()?;
            hash_field(&mut hasher, argv.operation().as_str().as_bytes());
            hash_field(&mut hasher, argv.stdin().unwrap_or(&[]));
        }
        for oid in &self.existing {
            hash_field(&mut hasher, oid.as_str().as_bytes());
        }
        for publication in &self.publications {
            hash_field(&mut hasher, publication.name.as_str().as_bytes());
            hash_publication_target(&mut hasher, publication);
        }
        Ok(*hasher.finalize().as_bytes())
    }
}

fn hash_publication_target(hasher: &mut blake3::Hasher, publication: &PlannedPublication) {
    match &publication.expected {
        GitRefExpectation::Absent => hash_field(hasher, b"absent"),
        GitRefExpectation::Value(oid) => hash_field(hasher, oid.as_str().as_bytes()),
        GitRefExpectation::Any => hash_field(hasher, b"any"),
    }
    match publication.next {
        Some(GitWirePlannedOid::Written(index)) => {
            hash_field(hasher, format!("written:{index}").as_bytes());
        }
        Some(GitWirePlannedOid::Existing(index)) => {
            hash_field(hasher, format!("existing:{index}").as_bytes());
        }
        None => hash_field(hasher, b"delete"),
    }
}

// ---------------------------------------------------------------------------
// Durable records
// ---------------------------------------------------------------------------

/// The lifecycle of a durable GitWire record. `Applied` and `Failed` are
/// terminal and can never be overwritten.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitWireRecordState {
    Prepared,
    Applied,
    Failed,
}

impl GitWireRecordState {
    /// Stable wire name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Applied => "applied",
            Self::Failed => "failed",
        }
    }

    /// Whether the state can no longer change.
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Applied | Self::Failed)
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "prepared" => Ok(Self::Prepared),
            "applied" => Ok(Self::Applied),
            "failed" => Ok(Self::Failed),
            _ => Err(invalid("unknown git wire record state")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredObservedRef {
    name: String,
    oid: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredPublication {
    name: String,
    expected: Option<String>,
    next: Option<String>,
}

/// The durable row of one journaled effect.
///
/// It carries only validated minimal replay values — ref names, object ids,
/// state, and a failure class. No stdout, no stderr, no payload bytes, and no
/// filesystem path ever reaches this row.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredGitWireRecord {
    schema_version: u8,
    record_key: [u8; 32],
    repo_identity: [u8; 32],
    operation: String,
    state: String,
    publications: Vec<StoredPublication>,
    observed_before: Vec<StoredObservedRef>,
    observed_after: Vec<StoredObservedRef>,
    keep_refs: Vec<String>,
    /// Hash of the worktree handle this record owns, for worktree effects.
    worktree_scope: Option<[u8; 32]>,
    failure: Option<String>,
    started_at: u64,
    finished_at: Option<u64>,
}

impl StoredGitWireRecord {
    /// The identity a capability is issued against.
    ///
    /// It covers exactly the fields that are fixed when the record is created —
    /// never the mutable state, outcome, or timing — so a handle stays valid
    /// across the record's own lifecycle while still failing closed if the row
    /// is replaced by a different intent or is gone.
    fn capability_hash(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hash_field(&mut hasher, GIT_WIRE_DOMAIN);
        hash_field(&mut hasher, b"capability");
        hash_field(&mut hasher, &self.record_key);
        hash_field(&mut hasher, &self.repo_identity);
        hash_field(&mut hasher, self.operation.as_bytes());
        for publication in &self.publications {
            hash_field(&mut hasher, publication.name.as_bytes());
            hash_field(
                &mut hasher,
                publication.expected.as_deref().unwrap_or("*").as_bytes(),
            );
            hash_field(
                &mut hasher,
                publication.next.as_deref().unwrap_or("-").as_bytes(),
            );
        }
        for observed in &self.observed_before {
            hash_field(&mut hasher, observed.name.as_bytes());
            hash_field(&mut hasher, observed.oid.as_deref().unwrap_or("-").as_bytes());
        }
        for keep in &self.keep_refs {
            hash_field(&mut hasher, keep.as_bytes());
        }
        hash_field(&mut hasher, &self.started_at.to_be_bytes());
        *hasher.finalize().as_bytes()
    }
}

/// The public view of a durable record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitWireReceipt {
    pub record_key: [u8; 32],
    pub repo_identity: GitWireRepoIdentity,
    pub operation: GitWireOperation,
    pub state: GitWireRecordState,
    pub publications: Vec<GitRefPublication>,
    pub observed_before: Vec<ObservedGitRef>,
    pub observed_after: Vec<ObservedGitRef>,
    pub failure: Option<GitWireFailureClass>,
    pub started_at: u64,
    pub finished_at: Option<u64>,
}

/// An unforgeable handle to a durable `Prepared` record.
///
/// The handle carries no effect values of its own: commit and recovery always
/// re-read the durable row and act on that. The capability hash pins the exact
/// intent the handle was issued against, so a forged handle has no record and a
/// stale one cannot commit a record that has since been replaced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitWirePrepared {
    record_key: [u8; 32],
    repo_identity: GitWireRepoIdentity,
    capability_hash: [u8; 32],
}

impl GitWirePrepared {
    /// The durable record this capability refers to.
    pub const fn record_key(&self) -> &[u8; 32] {
        &self.record_key
    }

    /// The object store this capability is bound to.
    pub const fn repo_identity(&self) -> GitWireRepoIdentity {
        self.repo_identity
    }
}

/// Why an effect did not apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitWireRejection {
    /// A guarded ref no longer carries the value the effect was decided
    /// against.
    RefMoved,
    /// A published object set is not fully present in the object store.
    ObjectsUnavailable,
    /// The effect could not be confirmed to have happened, and the record is
    /// terminally void rather than silently claimed.
    EffectUnconfirmed,
}

impl GitWireRejection {
    const fn as_failure(self) -> GitWireFailureClass {
        match self {
            Self::RefMoved => GitWireFailureClass::RefMismatch,
            Self::ObjectsUnavailable => GitWireFailureClass::Missing,
            Self::EffectUnconfirmed => GitWireFailureClass::Unknown,
        }
    }
}

/// The result of applying or replaying a journaled ref effect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GitWireCommitOutcome {
    /// The publication transaction ran now.
    Applied(GitWireReceipt),
    /// A durable terminal record answered without launching git.
    Replayed(GitWireReceipt),
    /// The effect is terminally void; no ref was moved by this call.
    Rejected {
        receipt: GitWireReceipt,
        reason: GitWireRejection,
    },
}

impl GitWireCommitOutcome {
    /// The durable record behind the outcome.
    pub fn receipt(&self) -> &GitWireReceipt {
        match self {
            Self::Applied(receipt) | Self::Replayed(receipt) => receipt,
            Self::Rejected { receipt, .. } => receipt,
        }
    }

    /// Whether the outcome came from a durable record without launching git.
    pub const fn is_replayed(&self) -> bool {
        matches!(self, Self::Replayed(_))
    }

    /// Whether the refs now carry the intended values.
    pub const fn is_applied(&self) -> bool {
        matches!(self, Self::Applied(_) | Self::Replayed(_))
    }
}

// ---------------------------------------------------------------------------
// The wire
// ---------------------------------------------------------------------------

/// The typed git seam. One handle owns the pinned process baseline and the
/// vault its durable records live in.
pub struct GitWire<'a> {
    vault: &'a Vault,
    process_env: GitWireProcessEnv,
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
    fn run_read(&self, repo: &GitWireRepo, argv: &FrozenGitArgv) -> Result<GitWireProcessOutput> {
        if !argv.operation().effect_class().is_read() {
            return Err(invalid("git wire read phase refuses a mutating operation"));
        }
        self.run_at(&repo.repo_root, argv)
    }

    /// Runs a mutation. A read is refused here in the same way, so a read can
    /// never be laundered into a durable mutation record.
    fn run_mutation(
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
    fn run_publication(
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

fn parse_oid_output(stdout: &[u8]) -> Result<GitOid> {
    let text = String::from_utf8_lossy(stdout);
    let field = text
        .split_whitespace()
        .next()
        .ok_or_else(|| invalid("git did not print an object id"))?;
    GitOid::parse_hex(field)
}

// ---------------------------------------------------------------------------
// Journaled ref publication
// ---------------------------------------------------------------------------

impl GitWire<'_> {
    /// Publishes refs through the one transactional path, under the repository
    /// coordinator and a durable intent written before git runs.
    ///
    /// A durable terminal record replays only while the postcondition it
    /// recorded still holds, so `set R=A; set R=B; set R=A` re-runs the third
    /// call instead of answering it from the first receipt.
    pub fn publish_refs(
        &self,
        repo: &GitWireRepo,
        publications: Vec<GitRefPublication>,
        now: u64,
    ) -> GitWireResult<GitWireCommitOutcome> {
        validate_publications(&publications)?;
        let _guard = lock_repository(&repo.common_dir)?;
        let key = ref_record_key(repo.identity(), &publications);
        if let Some(outcome) = self.replay_terminal(repo, &key)? {
            return Ok(outcome);
        }
        // Anything left here is a prepared row from an interrupted attempt at
        // exactly this effect: finish that intent rather than restating it.
        if let Some(prepared) = self.load_record(repo, &key)? {
            return self.finish_record(repo, prepared, now);
        }
        let names = publications
            .iter()
            .map(|publication| publication.name.clone())
            .collect::<Vec<_>>();
        let observed_before = self.read_refs(repo, &names)?;
        let record = new_record(
            repo,
            key,
            GitWireOperation::PublishRefs,
            &publications,
            &observed_before,
            now,
        );
        self.put_record(repo, &record)?;
        self.finish_record(repo, record, now)
    }

    /// Compare-and-set one ref against the value it was decided against.
    pub fn update_ref_cas(
        &self,
        repo: &GitWireRepo,
        name: &GitRefName,
        expected: Option<&GitOid>,
        next: &GitOid,
        now: u64,
    ) -> GitWireResult<GitWireCommitOutcome> {
        let publication = GitRefPublication::update(
            name.clone(),
            GitRefExpectation::from_observed(expected),
            next.clone(),
        );
        self.publish_refs(repo, vec![publication], now)
    }

    /// Writes a ref, binding the value it currently holds into the effect.
    ///
    /// The observation is taken under the coordinator and becomes part of the
    /// key and the compare-and-set, so an unconditional-looking write is still
    /// a decision against a specific state and can never replay onto a
    /// different one.
    pub fn set_ref(
        &self,
        repo: &GitWireRepo,
        name: &GitRefName,
        next: &GitOid,
        now: u64,
    ) -> GitWireResult<GitWireCommitOutcome> {
        let _guard = lock_repository(&repo.common_dir)?;
        let observed = self.read_ref(repo, name)?;
        let publication = GitRefPublication::update(
            name.clone(),
            GitRefExpectation::from_observed(observed.as_ref()),
            next.clone(),
        );
        self.publish_refs(repo, vec![publication], now)
    }

    /// Deletes a ref, compare-and-set against `expected` or against the value
    /// observed now.
    pub fn delete_ref(
        &self,
        repo: &GitWireRepo,
        name: &GitRefName,
        expected: Option<&GitOid>,
        now: u64,
    ) -> GitWireResult<GitWireCommitOutcome> {
        let _guard = lock_repository(&repo.common_dir)?;
        let expectation = match expected {
            Some(oid) => GitRefExpectation::Value(oid.clone()),
            None => GitRefExpectation::from_observed(self.read_ref(repo, name)?.as_ref()),
        };
        let publication = GitRefPublication::delete(name.clone(), expectation);
        self.publish_refs(repo, vec![publication], now)
    }

    /// Pins an object with a protected keep-ref so it survives maintenance.
    pub fn write_keep_ref(
        &self,
        repo: &GitWireRepo,
        oid: &GitOid,
        now: u64,
    ) -> GitWireResult<GitWireCommitOutcome> {
        let name = object_keep_ref_name(oid)?;
        let _guard = lock_repository(&repo.common_dir)?;
        let observed = self.read_ref(repo, &name)?;
        let publication = GitRefPublication::update(
            name,
            GitRefExpectation::from_observed(observed.as_ref()),
            oid.clone(),
        );
        self.publish_refs(repo, vec![publication], now)
    }

    /// Releases an object's keep-ref.
    pub fn delete_keep_ref(
        &self,
        repo: &GitWireRepo,
        oid: &GitOid,
        now: u64,
    ) -> GitWireResult<GitWireCommitOutcome> {
        let name = object_keep_ref_name(oid)?;
        self.delete_ref(repo, &name, None, now)
    }

    // -- shared finishing path --------------------------------------------

    /// Replays a durable terminal record, but only while its recorded
    /// postcondition still holds in the repository.
    fn replay_terminal(
        &self,
        repo: &GitWireRepo,
        key: &[u8; 32],
    ) -> Result<Option<GitWireCommitOutcome>> {
        let Some(stored) = self.load_record(repo, key)? else {
            return Ok(None);
        };
        let state = GitWireRecordState::parse(&stored.state)?;
        match state {
            GitWireRecordState::Prepared => Ok(None),
            GitWireRecordState::Failed => Ok(Some(GitWireCommitOutcome::Rejected {
                receipt: receipt_from_stored(&stored)?,
                reason: rejection_from_stored(&stored)?,
            })),
            GitWireRecordState::Applied => {
                if self.postcondition_holds(repo, &stored)? {
                    return Ok(Some(GitWireCommitOutcome::Replayed(receipt_from_stored(
                        &stored,
                    )?)));
                }
                self.drop_record(repo, key)?;
                Ok(None)
            }
        }
    }

    /// Whether every ref the record claimed to have left behind still carries
    /// the claimed value. This is what makes a stored claim a current claim.
    fn postcondition_holds(
        &self,
        repo: &GitWireRepo,
        stored: &StoredGitWireRecord,
    ) -> Result<bool> {
        let recorded = observed_from_stored(&stored.observed_after)?;
        if recorded.is_empty() {
            return Ok(false);
        }
        let names = recorded
            .iter()
            .map(|entry| entry.name.clone())
            .collect::<Vec<_>>();
        let current = self.read_refs(repo, &names)?;
        Ok(current == recorded)
    }

    /// Drives one `Prepared` record to its resolution, or leaves it prepared
    /// and reports uncertainty. Shared by publication, staged commit, and
    /// recovery, so all three obey exactly one rule set.
    fn finish_record(
        &self,
        repo: &GitWireRepo,
        record: StoredGitWireRecord,
        now: u64,
    ) -> Result<GitWireCommitOutcome> {
        match GitWireOperation::parse(&record.operation)? {
            GitWireOperation::PublishRefs => self.finish_publication_record(repo, record, now),
            GitWireOperation::WorktreeAdd
            | GitWireOperation::WorktreeRemove
            | GitWireOperation::WorktreePrune => self.finish_worktree_record(repo, record, now),
            _ => Err(invalid("git wire record names a non-journaled operation")),
        }
    }

    fn finish_publication_record(
        &self,
        repo: &GitWireRepo,
        record: StoredGitWireRecord,
        now: u64,
    ) -> Result<GitWireCommitOutcome> {
        let publications = publications_from_stored(&record.publications)?;
        if publications.is_empty() {
            return Err(invalid("git wire publication record publishes no ref"));
        }
        let names = publications
            .iter()
            .map(|publication| publication.name.clone())
            .collect::<Vec<_>>();
        let observed = self.read_refs(repo, &names)?;
        if publications_satisfied(&publications, &observed) {
            return self.finish_already_published(repo, record, &publications, observed, now);
        }
        if !publications_expected(&publications, &observed) {
            return self.reject(repo, record, GitWireRejection::RefMoved, now);
        }
        if !self.publication_objects_available(repo, &publications)? {
            return self.reject(repo, record, GitWireRejection::ObjectsUnavailable, now);
        }
        self.apply_publication(repo, record, &publications, now)
    }

    /// A record whose refs already carry their targets. Availability is still
    /// verified: an already-advanced ref is never a reason to certify an object
    /// set nobody checked.
    fn finish_already_published(
        &self,
        repo: &GitWireRepo,
        record: StoredGitWireRecord,
        publications: &[GitRefPublication],
        observed: Vec<ObservedGitRef>,
        now: u64,
    ) -> Result<GitWireCommitOutcome> {
        if !self.publication_objects_available(repo, publications)? {
            return Err(uncertain(
                "git wire refs already advanced onto an incomplete object set".to_owned(),
            ));
        }
        self.release_keep_refs(repo, &record)?;
        let applied = finish_state(record, GitWireRecordState::Applied, observed, now);
        let stored = self.transition(repo, applied)?;
        Ok(GitWireCommitOutcome::Applied(receipt_from_stored(&stored)?))
    }

    fn apply_publication(
        &self,
        repo: &GitWireRepo,
        record: StoredGitWireRecord,
        publications: &[GitRefPublication],
        now: u64,
    ) -> Result<GitWireCommitOutcome> {
        let mut batch = publications.to_vec();
        batch.extend(self.keep_ref_releases(repo, &record)?);
        let argv = FrozenGitArgv::publish_refs(&batch);
        match self.run_publication(repo, &argv)? {
            Ok(_) => self.confirm_publication(repo, record, publications, now),
            Err(failure) => {
                self.classify_publication_failure(repo, record, publications, failure, now)
            }
        }
    }

    fn confirm_publication(
        &self,
        repo: &GitWireRepo,
        record: StoredGitWireRecord,
        publications: &[GitRefPublication],
        now: u64,
    ) -> Result<GitWireCommitOutcome> {
        let names = publications
            .iter()
            .map(|publication| publication.name.clone())
            .collect::<Vec<_>>();
        let observed = self.read_refs(repo, &names)?;
        if !publications_satisfied(publications, &observed) {
            return Err(uncertain(
                "git wire publication reported success but the refs disagree".to_owned(),
            ));
        }
        let applied = finish_state(record, GitWireRecordState::Applied, observed, now);
        let stored = self.transition(repo, applied)?;
        Ok(GitWireCommitOutcome::Applied(receipt_from_stored(&stored)?))
    }

    /// Separates the three outcomes a failed transaction can have: the refs
    /// moved under us, the refs are untouched but git failed, or git failed for
    /// an unknown reason. Only the first is terminal; the others keep the
    /// prepared intent so recovery can retry.
    fn classify_publication_failure(
        &self,
        repo: &GitWireRepo,
        record: StoredGitWireRecord,
        publications: &[GitRefPublication],
        failure: GitWireFailure,
        now: u64,
    ) -> Result<GitWireCommitOutcome> {
        let names = publications
            .iter()
            .map(|publication| publication.name.clone())
            .collect::<Vec<_>>();
        let observed = self.read_refs(repo, &names)?;
        if !publications_expected(publications, &observed) {
            return self.reject(repo, record, GitWireRejection::RefMoved, now);
        }
        Err(failure.error(GitWireOperation::PublishRefs))
    }

    fn reject(
        &self,
        repo: &GitWireRepo,
        record: StoredGitWireRecord,
        reason: GitWireRejection,
        now: u64,
    ) -> Result<GitWireCommitOutcome> {
        self.release_keep_refs(repo, &record)?;
        let mut failed = finish_state(record, GitWireRecordState::Failed, Vec::new(), now);
        failed.failure = Some(reason.as_failure().as_str().to_owned());
        let stored = self.transition(repo, failed)?;
        let receipt = receipt_from_stored(&stored)?;
        if receipt.state == GitWireRecordState::Applied {
            return Ok(GitWireCommitOutcome::Replayed(receipt));
        }
        Ok(GitWireCommitOutcome::Rejected {
            receipt,
            reason: rejection_from_stored(&stored)?,
        })
    }

    /// Verifies that every published object is present *with its full reachable
    /// graph*, bounded by whatever the ref already pointed at.
    fn publication_objects_available(
        &self,
        repo: &GitWireRepo,
        publications: &[GitRefPublication],
    ) -> Result<bool> {
        for publication in publications {
            let Some(next) = publication.next() else {
                continue;
            };
            let exclude = self.reachability_bound(repo, publication)?;
            if !self.reachable_objects_present(repo, next, &exclude)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// The already-verified frontier a reachability walk may stop at: the ref's
    /// previous value, when that value is itself a commit that is present.
    fn reachability_bound(
        &self,
        repo: &GitWireRepo,
        publication: &GitRefPublication,
    ) -> Result<Vec<GitOid>> {
        let GitRefExpectation::Value(expected) = publication.expected() else {
            return Ok(Vec::new());
        };
        let mut candidates = vec![expected.clone()];
        if let Some(next) = publication.next() {
            candidates.push(next.clone());
        }
        let info = self.object_info(repo, &candidates)?;
        let both_commits = candidates
            .iter()
            .all(|oid| info.get(oid).map(String::as_str) == Some("commit"));
        if both_commits {
            Ok(vec![expected.clone()])
        } else {
            Ok(Vec::new())
        }
    }

    fn keep_ref_releases(
        &self,
        repo: &GitWireRepo,
        record: &StoredGitWireRecord,
    ) -> Result<Vec<GitRefPublication>> {
        if record.keep_refs.is_empty() {
            return Ok(Vec::new());
        }
        let mut names = Vec::with_capacity(record.keep_refs.len());
        for name in &record.keep_refs {
            names.push(GitRefName::parse_full(name.clone())?);
        }
        let observed = self.read_refs(repo, &names)?;
        Ok(observed
            .into_iter()
            .filter(|entry| entry.oid.is_some())
            .map(|entry| GitRefPublication::delete(entry.name, GitRefExpectation::Any))
            .collect())
    }

    fn release_keep_refs(&self, repo: &GitWireRepo, record: &StoredGitWireRecord) -> Result<()> {
        let releases = self.keep_ref_releases(repo, record)?;
        if releases.is_empty() {
            return Ok(());
        }
        let argv = FrozenGitArgv::publish_refs(&releases);
        match self.run_publication(repo, &argv)? {
            Ok(_) => Ok(()),
            Err(failure) => Err(failure.error(GitWireOperation::PublishRefs)),
        }
    }
}

fn validate_publications(publications: &[GitRefPublication]) -> Result<()> {
    if publications.is_empty() || publications.len() > GIT_WIRE_MAX_PUBLICATIONS {
        return Err(invalid(
            "git wire publication set must be non-empty and bounded",
        ));
    }
    for (index, publication) in publications.iter().enumerate() {
        if publications[..index]
            .iter()
            .any(|earlier| earlier.name == publication.name)
        {
            return Err(invalid("git wire publication set names one ref twice"));
        }
    }
    Ok(())
}

fn publications_satisfied(publications: &[GitRefPublication], observed: &[ObservedGitRef]) -> bool {
    publications.iter().all(|publication| {
        observed
            .iter()
            .find(|entry| entry.name == publication.name)
            .is_some_and(|entry| publication.satisfied_by(entry.oid.as_ref()))
    })
}

fn publications_expected(publications: &[GitRefPublication], observed: &[ObservedGitRef]) -> bool {
    publications.iter().all(|publication| {
        observed
            .iter()
            .find(|entry| entry.name == publication.name)
            .is_some_and(|entry| publication.expected().holds_for(entry.oid.as_ref()))
    })
}

// ---------------------------------------------------------------------------
// Two-phase staging
// ---------------------------------------------------------------------------

impl GitWire<'_> {
    /// Phase one: runs every object write outside any vault write transaction,
    /// protects the result with keep-refs, and journals the prepared intent.
    ///
    /// The stage key is claimed, so re-staging an identical plan returns the
    /// existing capability instead of repeating the effect. No advertised ref
    /// moves here; only the engine's own keep-refs are written, and only after
    /// the durable intent exists.
    pub fn stage(
        &self,
        repo: &GitWireRepo,
        plan: &GitWirePlan,
        now: u64,
    ) -> GitWireResult<GitWirePrepared> {
        plan.validate()?;
        let _guard = lock_repository(&repo.common_dir)?;
        let key = stage_record_key(repo.identity(), &plan.plan_hash()?);
        if let Some(stored) = self.load_record(repo, &key)? {
            return Ok(prepared_from_stored(&stored));
        }
        let written = self.write_plan_objects(repo, plan)?;
        let publications = resolve_plan_publications(plan, &written)?;
        let names = publications
            .iter()
            .map(|publication| publication.name.clone())
            .collect::<Vec<_>>();
        let observed_before = self.read_refs(repo, &names)?;
        let keep_refs = stage_keep_ref_names(&key, &publications)?;
        let mut record = new_record(
            repo,
            key,
            GitWireOperation::PublishRefs,
            &publications,
            &observed_before,
            now,
        );
        record.keep_refs = keep_refs
            .iter()
            .map(|name| name.as_str().to_owned())
            .collect();
        self.put_record(repo, &record)?;
        self.hold_keep_refs(repo, &keep_refs, &publications)?;
        Ok(prepared_from_stored(&record))
    }

    /// Phase two: finishes the prepared record the capability names.
    ///
    /// The capability carries no values: the durable row is re-read and its
    /// capability hash must match, so a forged or stale handle publishes
    /// nothing.
    pub fn commit_prepared(
        &self,
        repo: &GitWireRepo,
        prepared: &GitWirePrepared,
        now: u64,
    ) -> GitWireResult<GitWireCommitOutcome> {
        let _guard = lock_repository(&repo.common_dir)?;
        if prepared.repo_identity != repo.identity() {
            return Err(invalid(
                "git wire prepared capability belongs to another repository",
            ));
        }
        let stored = self
            .load_record(repo, &prepared.record_key)?
            .ok_or_else(|| invalid("git wire prepared capability has no durable record"))?;
        if stored.capability_hash() != prepared.capability_hash {
            return Err(invalid("git wire prepared capability is stale or forged"));
        }
        match GitWireRecordState::parse(&stored.state)? {
            GitWireRecordState::Applied => {
                Ok(GitWireCommitOutcome::Replayed(receipt_from_stored(&stored)?))
            }
            GitWireRecordState::Failed => Ok(GitWireCommitOutcome::Rejected {
                receipt: receipt_from_stored(&stored)?,
                reason: rejection_from_stored(&stored)?,
            }),
            GitWireRecordState::Prepared => self.finish_record(repo, stored, now),
        }
    }

    fn write_plan_objects(&self, repo: &GitWireRepo, plan: &GitWirePlan) -> Result<Vec<GitOid>> {
        let mut written = Vec::with_capacity(plan.objects.len());
        for write in &plan.objects {
            let argv = write.argv()?;
            let output = self.run_mutation(repo, &argv)?;
            written.push(parse_oid_output(&output.stdout)?);
        }
        Ok(written)
    }

    fn hold_keep_refs(
        &self,
        repo: &GitWireRepo,
        keep_refs: &[GitRefName],
        publications: &[GitRefPublication],
    ) -> Result<()> {
        let mut batch = Vec::new();
        for (name, publication) in keep_refs.iter().zip(publications) {
            let Some(next) = publication.next() else {
                continue;
            };
            batch.push(GitRefPublication::update(
                name.clone(),
                GitRefExpectation::Any,
                next.clone(),
            ));
        }
        if batch.is_empty() {
            return Ok(());
        }
        let argv = FrozenGitArgv::publish_refs(&batch);
        match self.run_publication(repo, &argv)? {
            Ok(_) => Ok(()),
            Err(failure) => Err(failure.error(GitWireOperation::PublishRefs)),
        }
    }

    /// Finishes every prepared record of one repository.
    ///
    /// Recovery runs under the same coordinator as every writer, so two
    /// recoverers cannot both drive one record, and it uses exactly the same
    /// rules as a live commit: roll forward only on a complete match, reject
    /// only on a proven expectation violation, and preserve the intent on any
    /// uncertainty.
    pub fn recover(&self, repo: &GitWireRepo, now: u64) -> GitWireResult<Vec<GitWireReceipt>> {
        let _guard = lock_repository(&repo.common_dir)?;
        let mut receipts = Vec::new();
        for record in self.prepared_records(repo)? {
            let outcome = self.finish_record(repo, record, now)?;
            receipts.push(outcome.receipt().clone());
        }
        Ok(receipts)
    }
}

fn resolve_plan_publications(
    plan: &GitWirePlan,
    written: &[GitOid],
) -> Result<Vec<GitRefPublication>> {
    let mut publications = Vec::with_capacity(plan.publications.len());
    for planned in &plan.publications {
        let next = match planned.next {
            None => None,
            Some(GitWirePlannedOid::Written(index)) => Some(
                written
                    .get(index)
                    .ok_or_else(|| invalid("git wire plan handle is out of range"))?
                    .clone(),
            ),
            Some(GitWirePlannedOid::Existing(index)) => Some(
                plan.existing
                    .get(index)
                    .ok_or_else(|| invalid("git wire plan handle is out of range"))?
                    .clone(),
            ),
        };
        publications.push(GitRefPublication {
            name: planned.name.clone(),
            expected: planned.expected.clone(),
            next,
        });
    }
    Ok(publications)
}

fn stage_keep_ref_names(
    key: &[u8; 32],
    publications: &[GitRefPublication],
) -> Result<Vec<GitRefName>> {
    let scope = hex_lower(key);
    let mut names = Vec::with_capacity(publications.len());
    for index in 0..publications.len() {
        names.push(GitRefName::parse_full(format!(
            "{GIT_WIRE_KEEP_REF_PREFIX}stage/{scope}/{index}"
        ))?);
    }
    Ok(names)
}

fn object_keep_ref_name(oid: &GitOid) -> Result<GitRefName> {
    GitRefName::parse_full(format!("{GIT_WIRE_KEEP_REF_PREFIX}object/{}", oid.as_str()))
}

// ---------------------------------------------------------------------------
// Journaled worktree effects
// ---------------------------------------------------------------------------

impl GitWire<'_> {
    /// Every worktree registered in this repository.
    pub fn list_worktrees(&self, repo: &GitWireRepo) -> GitWireResult<Vec<PathBuf>> {
        let output = self.run_read(repo, &FrozenGitArgv::worktree_list())?;
        Ok(parse_worktree_listing(&output.stdout))
    }

    /// Whether `path` is registered as a worktree of this repository.
    pub fn worktree_registered(&self, repo: &GitWireRepo, path: &Path) -> GitWireResult<bool> {
        let registered = self.list_worktrees(repo)?;
        Ok(registered.iter().any(|entry| same_path(entry, path)))
    }

    /// Reconciles worktree registration with the filesystem.
    pub fn prune_worktrees(&self, repo: &GitWireRepo) -> GitWireResult<()> {
        let _guard = lock_repository(&repo.common_dir)?;
        self.run_mutation(repo, &FrozenGitArgv::worktree_prune())?;
        Ok(())
    }

    /// Registers a worktree materializing exactly `commit`, journaling the
    /// intent first so a crash between git and the record is recoverable.
    pub fn add_worktree(
        &self,
        repo: &GitWireRepo,
        path: &Path,
        commit: &GitOid,
        now: u64,
    ) -> GitWireResult<GitWireReceipt> {
        let argv = FrozenGitArgv::worktree_add(path, commit)?;
        self.run_worktree_effect(repo, GitWireOperation::WorktreeAdd, path, &argv, now)
    }

    /// Removes a registered worktree. Returns `Ok(None)` when the path is not
    /// registered, so nothing was owned and nothing was removed.
    pub fn remove_worktree(
        &self,
        repo: &GitWireRepo,
        path: &Path,
        now: u64,
    ) -> GitWireResult<Option<GitWireReceipt>> {
        let _guard = lock_repository(&repo.common_dir)?;
        if !self.worktree_registered(repo, path)? {
            return Ok(None);
        }
        let argv = FrozenGitArgv::worktree_remove(path)?;
        let receipt =
            self.run_worktree_effect(repo, GitWireOperation::WorktreeRemove, path, &argv, now)?;
        Ok(Some(receipt))
    }

    /// Journals the intent, performs the effect, reconciles registration, and
    /// then clears the record.
    ///
    /// A worktree effect has no replay value — it is a filesystem state, not a
    /// claim — so the durable row exists purely as a crash journal. A crash
    /// between git and the clear leaves a prepared row that recovery resolves
    /// by re-observing registration.
    fn run_worktree_effect(
        &self,
        repo: &GitWireRepo,
        operation: GitWireOperation,
        path: &Path,
        argv: &FrozenGitArgv,
        now: u64,
    ) -> Result<GitWireReceipt> {
        let _guard = lock_repository(&repo.common_dir)?;
        let scope = worktree_scope(path);
        let key = worktree_record_key(repo.identity(), operation, &scope);
        let mut record = new_record(repo, key, operation, &[], &[], now);
        record.worktree_scope = Some(scope);
        self.put_record(repo, &record)?;
        self.run_mutation(repo, argv)?;
        self.run_mutation(repo, &FrozenGitArgv::worktree_prune())?;
        self.drop_record(repo, &key)?;
        receipt_from_stored(&finish_state(
            record,
            GitWireRecordState::Applied,
            Vec::new(),
            now,
        ))
    }

    /// Resolves a prepared worktree record by re-observing registration. The
    /// path is never stored: the record carries a scope hash, and recovery
    /// matches it against the paths git currently reports.
    fn finish_worktree_record(
        &self,
        repo: &GitWireRepo,
        record: StoredGitWireRecord,
        now: u64,
    ) -> Result<GitWireCommitOutcome> {
        let operation = GitWireOperation::parse(&record.operation)?;
        let scope = record
            .worktree_scope
            .ok_or_else(|| invalid("git wire worktree record has no scope"))?;
        let registered = self
            .list_worktrees(repo)?
            .into_iter()
            .find(|path| worktree_scope(path) == scope);
        let resolved = match (operation, registered) {
            (GitWireOperation::WorktreeRemove, Some(path)) => {
                let argv = FrozenGitArgv::worktree_remove(&path)?;
                self.run_mutation(repo, &argv)?;
                true
            }
            (GitWireOperation::WorktreeAdd, Some(_))
            | (GitWireOperation::WorktreeRemove, None)
            | (GitWireOperation::WorktreePrune, _) => true,
            (_, _) => false,
        };
        self.settle_worktree(repo, record, resolved, now)
    }

    fn settle_worktree(
        &self,
        repo: &GitWireRepo,
        record: StoredGitWireRecord,
        resolved: bool,
        now: u64,
    ) -> Result<GitWireCommitOutcome> {
        self.run_mutation(repo, &FrozenGitArgv::worktree_prune())?;
        self.drop_record(repo, &record.record_key)?;
        let state = if resolved {
            GitWireRecordState::Applied
        } else {
            GitWireRecordState::Failed
        };
        let mut settled = finish_state(record, state, Vec::new(), now);
        if !resolved {
            settled.failure = Some(GitWireFailureClass::Unknown.as_str().to_owned());
        }
        let receipt = receipt_from_stored(&settled)?;
        if resolved {
            return Ok(GitWireCommitOutcome::Applied(receipt));
        }
        Ok(GitWireCommitOutcome::Rejected {
            receipt,
            reason: GitWireRejection::EffectUnconfirmed,
        })
    }
}

fn parse_worktree_listing(stdout: &[u8]) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for field in stdout.split(|byte| *byte == 0) {
        let Some(raw) = field.strip_prefix(b"worktree ") else {
            continue;
        };
        let Ok(text) = std::str::from_utf8(raw) else {
            continue;
        };
        paths.push(PathBuf::from(text));
    }
    paths
}

fn same_path(left: &Path, right: &Path) -> bool {
    left == right || normalized_path(left) == normalized_path(right)
}

/// A path normalized as far as the filesystem allows.
///
/// A worktree that has just been removed no longer resolves, so falling back to
/// the resolved parent keeps a removed handle comparable with the path git
/// reported for it.
fn normalized_path(path: &Path) -> PathBuf {
    if let Ok(resolved) = path.canonicalize() {
        return resolved;
    }
    match (path.parent(), path.file_name()) {
        (Some(parent), Some(name)) => match parent.canonicalize() {
            Ok(parent) => parent.join(name),
            Err(_) => path.to_path_buf(),
        },
        _ => path.to_path_buf(),
    }
}

fn worktree_scope(path: &Path) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hash_field(&mut hasher, GIT_WIRE_DOMAIN);
    hash_field(&mut hasher, b"worktree-scope");
    hash_field(
        &mut hasher,
        normalized_path(path).as_os_str().as_encoded_bytes(),
    );
    *hasher.finalize().as_bytes()
}

// ---------------------------------------------------------------------------
// Durable record storage
// ---------------------------------------------------------------------------

impl GitWire<'_> {
    /// The durable record for a key, whatever its state.
    pub fn receipt(
        &self,
        repo: &GitWireRepo,
        record_key: &[u8; 32],
    ) -> GitWireResult<Option<GitWireReceipt>> {
        let Some(stored) = self.load_record(repo, record_key)? else {
            return Ok(None);
        };
        Ok(Some(receipt_from_stored(&stored)?))
    }

    fn load_record(
        &self,
        repo: &GitWireRepo,
        key: &[u8; 32],
    ) -> Result<Option<StoredGitWireRecord>> {
        let rtxn = self.vault.store.env.read_txn()?;
        let row = record_row_key(repo.identity(), key);
        let Some(bytes) = self.vault.store.vault_meta.get(&rtxn, &row)? else {
            return Ok(None);
        };
        Ok(Some(decode_record(&bytes)?))
    }

    fn prepared_records(&self, repo: &GitWireRepo) -> Result<Vec<StoredGitWireRecord>> {
        let rtxn = self.vault.store.env.read_txn()?;
        let prefix = record_row_prefix(repo.identity());
        let mut rows = Vec::new();
        for row in self.vault.store.vault_meta.prefix_iter(&rtxn, &prefix)? {
            let (_, bytes) = row?;
            let stored = decode_record(&bytes)?;
            if stored.state == GitWireRecordState::Prepared.as_str() {
                rows.push(stored);
            }
        }
        Ok(rows)
    }

    fn put_record(&self, repo: &GitWireRepo, record: &StoredGitWireRecord) -> Result<()> {
        let encoded = encode_record(record)?;
        let row = record_row_key(repo.identity(), &record.record_key);
        self.vault.with_write_txn(|txn| {
            self.vault.store.vault_meta.put(txn, &row, &encoded)?;
            Ok(())
        })
    }

    fn drop_record(&self, repo: &GitWireRepo, key: &[u8; 32]) -> Result<()> {
        let row = record_row_key(repo.identity(), key);
        self.vault.with_write_txn(|txn| {
            self.vault.store.vault_meta.delete(txn, &row)?;
            Ok(())
        })
    }

    /// Moves a record to a terminal state exactly once.
    ///
    /// The read and the write share one vault write transaction, so a record
    /// that is already terminal wins: `Failed` can never be overwritten by a
    /// late `Applied`, and two recoverers cannot both claim a transition.
    fn transition(
        &self,
        repo: &GitWireRepo,
        next: StoredGitWireRecord,
    ) -> Result<StoredGitWireRecord> {
        let row = record_row_key(repo.identity(), &next.record_key);
        let encoded = encode_record(&next)?;
        self.vault.with_write_txn(move |txn| {
            let current = match self.vault.store.vault_meta.get(txn, &row)? {
                Some(bytes) => decode_record(&bytes)?,
                None => {
                    return Err(invalid("git wire record disappeared before its transition"));
                }
            };
            if GitWireRecordState::parse(&current.state)?.is_terminal() {
                return Ok(current);
            }
            self.vault.store.vault_meta.put(txn, &row, &encoded)?;
            Ok(next)
        })
    }
}

fn record_row_prefix(identity: GitWireRepoIdentity) -> Vec<u8> {
    let mut key = Vec::with_capacity(GIT_WIRE_RECORD_KEY_PREFIX.len() + 66);
    key.extend_from_slice(GIT_WIRE_RECORD_KEY_PREFIX);
    key.extend_from_slice(identity.as_hex().as_bytes());
    key.push(b':');
    key
}

fn record_row_key(identity: GitWireRepoIdentity, record_key: &[u8; 32]) -> Vec<u8> {
    let mut key = record_row_prefix(identity);
    key.extend_from_slice(hex_lower(record_key).as_bytes());
    key
}

fn ref_record_key(identity: GitWireRepoIdentity, publications: &[GitRefPublication]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hash_field(&mut hasher, GIT_WIRE_DOMAIN);
    hash_field(&mut hasher, b"ref-effect");
    hash_field(&mut hasher, identity.as_bytes());
    for publication in publications {
        hash_field(&mut hasher, publication.name.as_str().as_bytes());
        match publication.expected() {
            GitRefExpectation::Absent => hash_field(&mut hasher, b"absent"),
            GitRefExpectation::Value(oid) => hash_field(&mut hasher, oid.as_str().as_bytes()),
            GitRefExpectation::Any => hash_field(&mut hasher, b"any"),
        }
        match publication.next() {
            Some(oid) => hash_field(&mut hasher, oid.as_str().as_bytes()),
            None => hash_field(&mut hasher, b"delete"),
        }
    }
    *hasher.finalize().as_bytes()
}

fn stage_record_key(identity: GitWireRepoIdentity, plan_hash: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hash_field(&mut hasher, GIT_WIRE_DOMAIN);
    hash_field(&mut hasher, b"stage");
    hash_field(&mut hasher, identity.as_bytes());
    hash_field(&mut hasher, plan_hash);
    *hasher.finalize().as_bytes()
}

fn worktree_record_key(
    identity: GitWireRepoIdentity,
    operation: GitWireOperation,
    scope: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hash_field(&mut hasher, GIT_WIRE_DOMAIN);
    hash_field(&mut hasher, b"worktree");
    hash_field(&mut hasher, identity.as_bytes());
    hash_field(&mut hasher, operation.as_str().as_bytes());
    hash_field(&mut hasher, scope);
    *hasher.finalize().as_bytes()
}

fn new_record(
    repo: &GitWireRepo,
    record_key: [u8; 32],
    operation: GitWireOperation,
    publications: &[GitRefPublication],
    observed_before: &[ObservedGitRef],
    now: u64,
) -> StoredGitWireRecord {
    StoredGitWireRecord {
        schema_version: GIT_WIRE_SCHEMA_VERSION,
        record_key,
        repo_identity: *repo.identity().as_bytes(),
        operation: operation.as_str().to_owned(),
        state: GitWireRecordState::Prepared.as_str().to_owned(),
        publications: publications.iter().map(stored_publication).collect(),
        observed_before: observed_before.iter().map(stored_observed).collect(),
        observed_after: Vec::new(),
        keep_refs: Vec::new(),
        worktree_scope: None,
        failure: None,
        started_at: now,
        finished_at: None,
    }
}

fn finish_state(
    mut record: StoredGitWireRecord,
    state: GitWireRecordState,
    observed_after: Vec<ObservedGitRef>,
    now: u64,
) -> StoredGitWireRecord {
    record.state = state.as_str().to_owned();
    record.observed_after = observed_after.iter().map(stored_observed).collect();
    record.finished_at = Some(now);
    record
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

fn stored_publication(publication: &GitRefPublication) -> StoredPublication {
    StoredPublication {
        name: publication.name.as_str().to_owned(),
        expected: publication.expected.wire(),
        next: publication.next.as_ref().map(|oid| oid.as_str().to_owned()),
    }
}

fn publications_from_stored(rows: &[StoredPublication]) -> Result<Vec<GitRefPublication>> {
    let mut publications = Vec::with_capacity(rows.len());
    for row in rows {
        publications.push(GitRefPublication {
            name: GitRefName::parse_full(row.name.clone())?,
            expected: GitRefExpectation::from_wire(row.expected.as_ref())?,
            next: row
                .next
                .as_ref()
                .map(|oid| GitOid::parse_hex(oid.clone()))
                .transpose()?,
        });
    }
    Ok(publications)
}

fn receipt_from_stored(stored: &StoredGitWireRecord) -> Result<GitWireReceipt> {
    if stored.schema_version != GIT_WIRE_SCHEMA_VERSION {
        return Err(invalid("unsupported git wire record schema version"));
    }
    Ok(GitWireReceipt {
        record_key: stored.record_key,
        repo_identity: GitWireRepoIdentity(stored.repo_identity),
        operation: GitWireOperation::parse(&stored.operation)?,
        state: GitWireRecordState::parse(&stored.state)?,
        publications: publications_from_stored(&stored.publications)?,
        observed_before: observed_from_stored(&stored.observed_before)?,
        observed_after: observed_from_stored(&stored.observed_after)?,
        failure: stored
            .failure
            .as_ref()
            .map(|class| GitWireFailureClass::parse(class.as_str()))
            .transpose()?,
        started_at: stored.started_at,
        finished_at: stored.finished_at,
    })
}

fn prepared_from_stored(stored: &StoredGitWireRecord) -> GitWirePrepared {
    GitWirePrepared {
        record_key: stored.record_key,
        repo_identity: GitWireRepoIdentity(stored.repo_identity),
        capability_hash: stored.capability_hash(),
    }
}

fn rejection_from_stored(stored: &StoredGitWireRecord) -> Result<GitWireRejection> {
    let class = stored
        .failure
        .as_ref()
        .map(|value| GitWireFailureClass::parse(value.as_str()))
        .transpose()?;
    match class {
        Some(GitWireFailureClass::Missing) => Ok(GitWireRejection::ObjectsUnavailable),
        Some(GitWireFailureClass::RefMismatch) => Ok(GitWireRejection::RefMoved),
        _ => Ok(GitWireRejection::EffectUnconfirmed),
    }
}

fn encode_record(record: &StoredGitWireRecord) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(record)
        .map_err(|_| Error::InvariantViolation("git wire record encode failed"))
}

fn decode_record(bytes: &[u8]) -> Result<StoredGitWireRecord> {
    rmp_serde::from_slice(bytes).map_err(|_| invalid("git wire record row is not MessagePack"))
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

// ---------------------------------------------------------------------------
// Checkout custody
// ---------------------------------------------------------------------------

impl GitWire<'_> {
    /// The private, repository- and epoch-bound directory that owns one lease's
    /// worktree. Nothing outside this root is ever created or removed.
    pub fn checkout_handle_dir(&self, lease: &CheckoutLeaseAct) -> CheckoutResult<PathBuf> {
        let repo = self.checkout_repo(lease)?;
        Ok(checkout_handle_dir_for(&self.process_env, &repo, lease))
    }

    /// The worktree path inside the owned handle.
    pub fn checkout_worktree_path(&self, lease: &CheckoutLeaseAct) -> CheckoutResult<PathBuf> {
        Ok(self.checkout_handle_dir(lease)?.join("tree"))
    }

    fn checkout_repo(&self, lease: &CheckoutLeaseAct) -> CheckoutResult<GitWireRepo> {
        let RepoRef::LocalFolder { path, .. } = &lease.repo_ref else {
            return Err(CheckoutError::Invalid(
                "checkout repo must be a local folder",
            ));
        };
        Ok(self.open_repo(lease.repo_ref.clone(), Path::new(path))?)
    }

    /// Proves the handle is registered with git and materializes exactly the
    /// pinned commit.
    fn claim_checkout_handle(&self, repo: &GitWireRepo, handle: &Path) -> CheckoutResult<bool> {
        if let Some(parent) = handle.parent() {
            fs::create_dir_all(parent).map_err(Error::from)?;
        }
        match fs::create_dir(handle) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let tree = handle.join("tree");
                if self.worktree_registered(repo, &tree)? {
                    return Ok(false);
                }
                Err(CheckoutError::RepoOps(
                    "checkout handle path already exists and is not an owned worktree".to_owned(),
                ))
            }
            Err(error) => Err(CheckoutError::Store(Error::from(error))),
        }
    }
}

fn checkout_handle_dir_for(
    process_env: &GitWireProcessEnv,
    repo: &GitWireRepo,
    lease: &CheckoutLeaseAct,
) -> PathBuf {
    let scope = repo.identity().as_hex();
    process_env
        .tmpdir
        .join(GIT_WIRE_CHECKOUT_ROOT_NAME)
        .join(&scope[..32])
        .join(format!("{}-{}", lease.checkout_id, lease.epoch))
}

/// ONE-1901's repo port, served by the same frozen seam as every other git
/// effect, so neither ONE-1904 dispatch nor ORIGIN ever constructs a
/// subprocess of its own.
impl CheckoutRepoOps for GitWire<'_> {
    /// Materializes exactly `repo_ref.commit` into a proven owned handle.
    ///
    /// The handle directory is created exclusively, so a pre-created path is
    /// refused rather than trusted, and the repository head is never moved.
    fn materialize(&self, lease: &CheckoutLeaseAct) -> CheckoutResult<()> {
        let repo = self.checkout_repo(lease)?;
        let commit = repo.pinned_commit()?;
        let handle = checkout_handle_dir_for(&self.process_env, &repo, lease);
        let tree = handle.join("tree");
        if !self.claim_checkout_handle(&repo, &handle)? {
            return verify_checkout_head(self, &repo, &tree, &commit);
        }
        // The handle was created exclusively by this call, so it is ours to
        // withdraw if the checkout itself fails; leaving it behind would turn a
        // transient failure into a permanently poisoned path.
        if let Err(error) = self.add_worktree(&repo, &tree, &commit, lease.updated_at) {
            let _ = fs::remove_dir_all(&handle);
            return Err(CheckoutError::from(error));
        }
        verify_checkout_head(self, &repo, &tree, &commit)
    }

    /// Observes the checkout without mutating it: registration is proven, no
    /// optional lock is taken, and no index is refreshed.
    fn inspect_teardown(
        &self,
        lease: &CheckoutLeaseAct,
        receipt: &PushedHeadReceipt,
    ) -> CheckoutResult<CheckoutTeardownInspection> {
        let repo = self.checkout_repo(lease)?;
        let tree = checkout_handle_dir_for(&self.process_env, &repo, lease).join("tree");
        if !tree.exists() || !self.worktree_registered(&repo, &tree)? {
            return Ok(uncertain_inspection());
        }
        let worktree = self.open_repo(repo.repo_ref().clone(), &tree)?;
        let Ok(observed) = self.resolve_commit(&worktree, "HEAD") else {
            return Ok(uncertain_inspection());
        };
        let head = LeaseGitOid::parse(observed.as_str())?;
        let status = self.run_read(&worktree, &FrozenGitArgv::status_porcelain())?;
        let receipt_match = if observed.as_str() == receipt.pushed_head {
            TeardownReceiptMatch::Match
        } else {
            TeardownReceiptMatch::Mismatch
        };
        Ok(CheckoutTeardownInspection {
            observed_head: Some(head),
            dirty: !status.stdout.is_empty(),
            receipt_match,
            occupant: None,
        })
    }

    /// Collects only a proven owned handle, and reconciles git's worktree
    /// registration afterwards.
    fn collect(&self, lease: &CheckoutLeaseAct) -> CheckoutResult<()> {
        let repo = self.checkout_repo(lease)?;
        let handle = checkout_handle_dir_for(&self.process_env, &repo, lease);
        let tree = handle.join("tree");
        if !handle.exists() {
            self.prune_worktrees(&repo)?;
            return Ok(());
        }
        let _journal = self.remove_worktree(&repo, &tree, lease.updated_at)?;
        if handle.exists() {
            fs::remove_dir_all(&handle).map_err(Error::from)?;
        }
        self.prune_worktrees(&repo)?;
        if handle.exists() {
            return Err(CheckoutError::RepoOps(
                "checkout handle survived collection".to_owned(),
            ));
        }
        Ok(())
    }
}

fn verify_checkout_head(
    wire: &GitWire<'_>,
    repo: &GitWireRepo,
    tree: &Path,
    commit: &GitOid,
) -> CheckoutResult<()> {
    if !wire.worktree_registered(repo, tree)? {
        return Err(CheckoutError::RepoOps(
            "checkout worktree is not registered with the repository".to_owned(),
        ));
    }
    let worktree = wire.open_repo(repo.repo_ref().clone(), tree)?;
    let observed = wire.resolve_commit(&worktree, "HEAD")?;
    if &observed != commit {
        return Err(CheckoutError::RepoOps(
            "checkout worktree does not carry the pinned commit".to_owned(),
        ));
    }
    Ok(())
}

fn uncertain_inspection() -> CheckoutTeardownInspection {
    CheckoutTeardownInspection {
        observed_head: None,
        dirty: false,
        receipt_match: TeardownReceiptMatch::Uncertain,
        occupant: None,
    }
}

// ---------------------------------------------------------------------------
// repo_mutation migration bridge
// ---------------------------------------------------------------------------

/// Migration bridge for the `repo_mutation` helper cluster.
///
/// `repo_mutation`'s helpers keep their exact signatures and delegate here so
/// the crate still has exactly one spawn site, one pinned executable, and one
/// closed configuration policy. The argv is validated position by position, the
/// only pre-verb options accepted are the frozen `user.name`/`user.email`
/// identity pairs, and the forbidden repo-mutation verb shapes are rejected.
///
/// Boundary: this entry is `pub(crate)` on purpose. No public arbitrary-vector
/// or shell-string constructor exists anywhere in the module.
pub(crate) fn run_bridged_git_argv(
    repo_root: &Path,
    args: &[String],
) -> Result<GitWireProcessOutput> {
    let process_env = GitWireProcessEnv::capture()?;
    let argv = bridged_argv(args)?;
    spawn_git(&process_env, repo_root, &argv, None)
}

/// The redacted description of a bridged git failure.
///
/// `repo_mutation` persists its failures in the durable oplog, so the same rule
/// that governs GitWire's own errors governs the bridge: a class, an exit code,
/// and a digest — never the child's diagnostics and never the argv, which can
/// carry absolute paths, commit messages, and ref labels.
pub(crate) fn redact_bridged_failure(args: &[String], code: Option<i32>, stderr: &[u8]) -> String {
    let verb = bridged_verb_index(args)
        .ok()
        .and_then(|index| args.get(index))
        .map_or("unknown", String::as_str);
    let class = classify_diagnostics(stderr).as_str();
    let digest = hex_lower(blake3::hash(stderr).as_bytes());
    let short = &digest[..16];
    let len = stderr.len();
    format!("git {verb} failed: class={class} exit={code:?} diag=blake3:{short} bytes={len}")
}

fn bridged_argv(args: &[String]) -> Result<Vec<OsString>> {
    if args.is_empty() || args.len() > GIT_WIRE_MAX_ARGS {
        return Err(invalid("git argv must be non-empty and bounded"));
    }
    let verb_index = bridged_verb_index(args)?;
    validate_bridged_prefix(&args[..verb_index])?;
    validate_forbidden_shape(&args[verb_index..])?;
    let mut argv = Vec::with_capacity(args.len());
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
