use std::collections::{BTreeSet, HashMap};
use std::ffi::OsStr;
use std::fs;
#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::Vault;
use crate::codebase::{CODEBASE_FILE_PATH_MAX_BYTES, RepoRef};
use crate::error::{Error, Result};
use crate::types::EntityId;

pub type RepoForkHash = [u8; 32];

pub const REPO_MUTATION_OPLOG_SCHEMA_VERSION: u8 = 1;
pub const REPO_MUTATION_ALLOWED_OPERATION_KINDS: [&str; 4] = [
    "commit_file",
    "create_worktree",
    "remove_worktree",
    "recover_snapshot",
];
pub const REPO_MUTATION_FORBIDDEN_GIT_COMMANDS: [&str; 3] =
    ["git clean", "git reset --hard", "git checkout -- ."];

const REPO_MUTATION_SEQ_KEY_PREFIX: &[u8] = b"repo_mutation:seq:v1:";
const REPO_MUTATION_OPLOG_KEY_PREFIX: &[u8] = b"repo_mutation:oplog:v1:";
const REPO_MUTATION_SNAPSHOT_KEY_PREFIX: &[u8] = b"repo_mutation:snapshot:v1:";
const MAX_COMMIT_MESSAGE_BYTES: usize = 4096;
const MAX_BASE_REF_BYTES: usize = 256;
const MAX_REPO_MUTATION_FAILURE_BYTES: usize = 4096;
const REPO_MUTATION_LOCK_FILE_NAME: &str = "oneiron-repo-mutation.lock";

static REPO_MUTATION_LOCKS: LazyLock<Mutex<HashMap<String, Arc<Mutex<()>>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

#[cfg(unix)]
struct RepoMutationFileLock {
    file: fs::File,
}

#[cfg(not(unix))]
struct RepoMutationFileLock;

#[cfg(unix)]
impl Drop for RepoMutationFileLock {
    fn drop(&mut self) {
        // SAFETY: `file.as_raw_fd()` is a live descriptor held by this guard.
        // `flock(LOCK_UN)` releases the advisory lock before the descriptor is
        // closed; ignoring unlock errors is acceptable during drop.
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RepoMutationStatus {
    Prepared,
    Applied,
    Failed,
}

impl RepoMutationStatus {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Applied => "applied",
            Self::Failed => "failed",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "prepared" => Ok(Self::Prepared),
            "applied" => Ok(Self::Applied),
            "failed" => Ok(Self::Failed),
            _ => Err(Error::InvalidRepoMutationRecord(
                "repo mutation status must be prepared, applied, or failed",
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RepoMutationOperation {
    CommitFile {
        path: String,
        content: Vec<u8>,
        message: String,
    },
    CreateWorktree {
        worktree_path: PathBuf,
        base_ref: String,
    },
    RemoveWorktree {
        worktree_path: PathBuf,
    },
    RecoverSnapshot {
        fork_hash: RepoForkHash,
    },
}

impl RepoMutationOperation {
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::CommitFile { .. } => "commit_file",
            Self::CreateWorktree { .. } => "create_worktree",
            Self::RemoveWorktree { .. } => "remove_worktree",
            Self::RecoverSnapshot { .. } => "recover_snapshot",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RepoMutationRequest {
    pub repo_ref: RepoRef,
    pub actor_id: Option<EntityId>,
    pub session_id: Option<EntityId>,
    pub operation: RepoMutationOperation,
}

impl RepoMutationRequest {
    #[must_use]
    pub fn new(repo_ref: RepoRef, operation: RepoMutationOperation) -> Self {
        Self {
            repo_ref,
            actor_id: None,
            session_id: None,
            operation,
        }
    }

    #[must_use]
    pub fn with_actor_id(mut self, actor_id: EntityId) -> Self {
        self.actor_id = Some(actor_id);
        self
    }

    #[must_use]
    pub fn with_session_id(mut self, session_id: EntityId) -> Self {
        self.session_id = Some(session_id);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RepoMutationOplogEntry {
    pub repo_ref: RepoRef,
    pub seq: u64,
    pub operation_kind: String,
    pub operation_subject: Option<String>,
    pub actor_id: Option<EntityId>,
    pub session_id: Option<EntityId>,
    pub started_at_ms: u64,
    pub finished_at_ms: Option<u64>,
    pub pre_action_fork_hash: RepoForkHash,
    pub status: RepoMutationStatus,
    pub failure: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RepoMutationOutcome {
    pub entry: RepoMutationOplogEntry,
}

#[derive(Debug, Clone)]
struct PreparedRepoMutation {
    repo_key_hash: String,
    seq: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredRepoMutationOplogEntry {
    schema_version: u8,
    repo_ref: String,
    seq: u64,
    operation_kind: String,
    operation_subject: Option<String>,
    actor_id: Option<[u8; 16]>,
    session_id: Option<[u8; 16]>,
    started_at_ms: u64,
    finished_at_ms: Option<u64>,
    pre_action_fork_hash: RepoForkHash,
    status: String,
    failure: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredRepoSnapshot {
    schema_version: u8,
    head: Option<String>,
    entries: Vec<StoredRepoSnapshotEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredRepoSnapshotEntry {
    path: String,
    kind: StoredRepoSnapshotEntryKind,
    executable: bool,
    content: Vec<u8>,
    symlink_target: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum StoredRepoSnapshotEntryKind {
    File,
    Symlink,
}

impl Vault {
    /// Runs a named repo mutation through the single-writer queue.
    ///
    /// The queue records a content-addressed pre-action snapshot and a durable
    /// oplog row before the mutation reaches git. The queue also holds a
    /// per-repo advisory lock in Git's common directory, so independent engine
    /// processes serialize through the same repo mutation point. A process death
    /// after the pre-action row leaves the row in `prepared`; callers can
    /// remount it via [`Vault::recover_repo_snapshot`].
    pub fn apply_repo_mutation(&self, request: RepoMutationRequest) -> Result<RepoMutationOutcome> {
        validate_operation(&request.operation)?;
        let repo_root = resolve_mutable_repo_root(&request.repo_ref)?;
        let repo_ref = canonical_repo_ref_for_root(&repo_root)?;
        let repo_key = repo_ref.canonical();
        let lock = repo_mutation_lock(&repo_key)?;
        let _guard = lock
            .lock()
            .map_err(|_| Error::ConcurrentWrite("repo mutation lock poisoned"))?;
        let _file_guard = repo_mutation_file_lock(&repo_root)?;

        let prepared = self.prepare_repo_mutation(&repo_ref, &request, &repo_root)?;
        match execute_repo_mutation(self, &repo_root, &request.operation) {
            Ok(()) => {
                let entry = self.finish_repo_mutation(
                    &prepared,
                    RepoMutationStatus::Applied,
                    None,
                    now_millis(),
                )?;
                Ok(RepoMutationOutcome { entry })
            }
            Err(error) => {
                let failure = truncate_failure(&error.to_string());
                let _ = self.finish_repo_mutation(
                    &prepared,
                    RepoMutationStatus::Failed,
                    Some(failure),
                    now_millis(),
                );
                Err(error)
            }
        }
    }

    /// Restores a repo working tree from a previously recorded pre-action
    /// forkHash, through the same mutation queue and oplog invariant.
    pub fn recover_repo_snapshot(
        &self,
        repo_ref: &RepoRef,
        fork_hash: RepoForkHash,
    ) -> Result<RepoMutationOutcome> {
        self.apply_repo_mutation(RepoMutationRequest::new(
            repo_ref.clone(),
            RepoMutationOperation::RecoverSnapshot { fork_hash },
        ))
    }

    /// Reads the durable oplog for a repo in sequence order.
    pub fn repo_mutation_oplog(&self, repo_ref: &RepoRef) -> Result<Vec<RepoMutationOplogEntry>> {
        let repo_root = resolve_mutable_repo_root(repo_ref)?;
        let canonical = canonical_repo_ref_for_root(&repo_root)?;
        let repo_key_hash = repo_key_hash(&canonical.canonical());
        let prefix = repo_mutation_oplog_prefix(&repo_key_hash);
        let rtxn = self.store.env.read_txn()?;
        let mut entries = Vec::new();
        for row in self.store.vault_meta.prefix_iter(&rtxn, &prefix)? {
            let (_, bytes) = row?;
            entries.push(decode_oplog_entry(bytes)?);
        }
        entries.sort_by_key(|entry| entry.seq);
        Ok(entries)
    }

    fn prepare_repo_mutation(
        &self,
        repo_ref: &RepoRef,
        request: &RepoMutationRequest,
        repo_root: &Path,
    ) -> Result<PreparedRepoMutation> {
        let (fork_hash, snapshot_bytes) = capture_repo_snapshot(repo_root)?;
        let repo_key_hash = repo_key_hash(&repo_ref.canonical());
        let started_at_ms = now_millis();
        let mut wtxn = self.store.env.write_txn()?;
        store_snapshot_if_absent(self, &mut wtxn, fork_hash, &snapshot_bytes)?;
        let seq = allocate_next_repo_mutation_seq(self, &mut wtxn, &repo_key_hash)?;
        let stored = StoredRepoMutationOplogEntry {
            schema_version: REPO_MUTATION_OPLOG_SCHEMA_VERSION,
            repo_ref: repo_ref.canonical(),
            seq,
            operation_kind: request.operation.kind().to_owned(),
            operation_subject: Some(operation_subject(&request.operation)),
            actor_id: request.actor_id.map(|id| *id.as_bytes()),
            session_id: request.session_id.map(|id| *id.as_bytes()),
            started_at_ms,
            finished_at_ms: None,
            pre_action_fork_hash: fork_hash,
            status: RepoMutationStatus::Prepared.as_str().to_owned(),
            failure: None,
        };
        let encoded = encode_oplog_entry(&stored)?;
        self.store.vault_meta.put(
            &mut wtxn,
            &repo_mutation_oplog_key(&repo_key_hash, seq),
            &encoded,
        )?;
        wtxn.commit()?;
        Ok(PreparedRepoMutation { repo_key_hash, seq })
    }

    fn finish_repo_mutation(
        &self,
        prepared: &PreparedRepoMutation,
        status: RepoMutationStatus,
        failure: Option<String>,
        finished_at_ms: u64,
    ) -> Result<RepoMutationOplogEntry> {
        let key = repo_mutation_oplog_key(&prepared.repo_key_hash, prepared.seq);
        let mut wtxn = self.store.env.write_txn()?;
        let raw =
            self.store
                .vault_meta
                .get(&wtxn, &key)?
                .ok_or(Error::InvalidRepoMutationRecord(
                    "repo mutation oplog row disappeared before completion",
                ))?;
        let mut stored = decode_stored_oplog_entry(raw)?;
        stored.status = status.as_str().to_owned();
        stored.failure = failure;
        stored.finished_at_ms = Some(finished_at_ms);
        let encoded = encode_oplog_entry(&stored)?;
        self.store.vault_meta.put(&mut wtxn, &key, &encoded)?;
        wtxn.commit()?;
        public_oplog_entry(stored)
    }
}

fn execute_repo_mutation(
    vault: &Vault,
    repo_root: &Path,
    operation: &RepoMutationOperation,
) -> Result<()> {
    match operation {
        RepoMutationOperation::CommitFile {
            path,
            content,
            message,
        } => {
            validate_relative_repo_path(path)?;
            validate_commit_message(message)?;
            let target = repo_root.join(path);
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&target, content)?;
            run_git(
                repo_root,
                &["add".to_owned(), "--".to_owned(), path.clone()],
            )?;
            run_git(
                repo_root,
                &[
                    "-c".to_owned(),
                    "user.name=Oneiron".to_owned(),
                    "-c".to_owned(),
                    "user.email=oneiron@example.invalid".to_owned(),
                    "commit".to_owned(),
                    "-m".to_owned(),
                    message.clone(),
                ],
            )?;
            Ok(())
        }
        RepoMutationOperation::CreateWorktree {
            worktree_path,
            base_ref,
        } => {
            validate_worktree_path(worktree_path)?;
            validate_base_ref(base_ref)?;
            run_git(
                repo_root,
                &[
                    "worktree".to_owned(),
                    "add".to_owned(),
                    "--detach".to_owned(),
                    path_arg(worktree_path)?,
                    base_ref.clone(),
                ],
            )?;
            Ok(())
        }
        RepoMutationOperation::RemoveWorktree { worktree_path } => {
            validate_worktree_path(worktree_path)?;
            run_git(
                repo_root,
                &[
                    "worktree".to_owned(),
                    "remove".to_owned(),
                    "--force".to_owned(),
                    path_arg(worktree_path)?,
                ],
            )?;
            Ok(())
        }
        RepoMutationOperation::RecoverSnapshot { fork_hash } => {
            restore_repo_snapshot(vault, repo_root, *fork_hash)
        }
    }
}

fn validate_operation(operation: &RepoMutationOperation) -> Result<()> {
    match operation {
        RepoMutationOperation::CommitFile { path, message, .. } => {
            validate_relative_repo_path(path)?;
            validate_commit_message(message)
        }
        RepoMutationOperation::CreateWorktree {
            worktree_path,
            base_ref,
        } => {
            validate_worktree_path(worktree_path)?;
            validate_base_ref(base_ref)
        }
        RepoMutationOperation::RemoveWorktree { worktree_path } => {
            validate_worktree_path(worktree_path)
        }
        RepoMutationOperation::RecoverSnapshot { .. } => Ok(()),
    }
}

fn capture_repo_snapshot(repo_root: &Path) -> Result<(RepoForkHash, Vec<u8>)> {
    let head = git_output_optional(
        repo_root,
        &[
            "rev-parse".to_owned(),
            "--verify".to_owned(),
            "HEAD".to_owned(),
        ],
    )?
    .map(|bytes| utf8_trimmed(bytes, "git HEAD must be UTF-8"))
    .transpose()?;
    let mut entries = Vec::new();
    collect_snapshot_entries(repo_root, repo_root, &mut entries)?;
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    let snapshot = StoredRepoSnapshot {
        schema_version: REPO_MUTATION_OPLOG_SCHEMA_VERSION,
        head,
        entries,
    };
    let encoded = encode_snapshot(&snapshot)?;
    let hash = sha256_bytes(&encoded);
    Ok((hash, encoded))
}

fn collect_snapshot_entries(
    repo_root: &Path,
    dir: &Path,
    entries: &mut Vec<StoredRepoSnapshotEntry>,
) -> Result<()> {
    let mut children = fs::read_dir(dir)?.collect::<std::result::Result<Vec<_>, _>>()?;
    children.sort_by_key(|entry| entry.file_name());
    for child in children {
        if child.file_name() == OsStr::new(".git") {
            continue;
        }
        let path = child.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_dir() {
            collect_snapshot_entries(repo_root, &path, entries)?;
            continue;
        }
        let relative = repo_relative_path(repo_root, &path)?;
        if metadata.file_type().is_symlink() {
            let target = fs::read_link(&path)?;
            let target = path_arg(&target)?;
            entries.push(StoredRepoSnapshotEntry {
                path: relative,
                kind: StoredRepoSnapshotEntryKind::Symlink,
                executable: false,
                content: Vec::new(),
                symlink_target: Some(target),
            });
        } else if metadata.file_type().is_file() {
            entries.push(StoredRepoSnapshotEntry {
                path: relative,
                kind: StoredRepoSnapshotEntryKind::File,
                executable: is_executable(&metadata),
                content: fs::read(&path)?,
                symlink_target: None,
            });
        } else {
            return Err(Error::InvalidRepoMutationRecord(
                "repo snapshot supports only files, directories, and symlinks",
            ));
        }
    }
    Ok(())
}

fn restore_repo_snapshot(vault: &Vault, repo_root: &Path, fork_hash: RepoForkHash) -> Result<()> {
    let key = repo_mutation_snapshot_key(fork_hash);
    let rtxn = vault.store.env.read_txn()?;
    let raw = vault
        .store
        .vault_meta
        .get(&rtxn, &key)?
        .ok_or(Error::InvalidRepoMutationRecord(
            "requested repo snapshot forkHash is unknown",
        ))?
        .to_vec();
    drop(rtxn);
    if sha256_bytes(&raw) != fork_hash {
        return Err(Error::CorruptedIndex(
            "repo mutation snapshot hash mismatch",
        ));
    }
    let snapshot = decode_snapshot(&raw)?;
    let desired: BTreeSet<String> = snapshot
        .entries
        .iter()
        .map(|entry| entry.path.clone())
        .collect();
    let mut current = BTreeSet::new();
    let mut dirs = Vec::new();
    collect_restore_inventory(repo_root, repo_root, &mut current, &mut dirs)?;

    for path in current.difference(&desired) {
        remove_existing_path(&repo_root.join(path))?;
    }
    remove_empty_dirs(dirs)?;

    for entry in snapshot.entries {
        validate_relative_repo_path(&entry.path)?;
        let target = repo_root.join(&entry.path);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        if fs::symlink_metadata(&target).is_ok() {
            remove_existing_path(&target)?;
        }
        match entry.kind {
            StoredRepoSnapshotEntryKind::File => {
                fs::write(&target, &entry.content)?;
                set_executable(&target, entry.executable)?;
            }
            StoredRepoSnapshotEntryKind::Symlink => {
                let target_path = entry
                    .symlink_target
                    .ok_or(Error::InvalidRepoMutationRecord(
                        "symlink snapshot entry missing target",
                    ))?;
                create_symlink(Path::new(&target_path), &target)?;
            }
        }
    }
    Ok(())
}

fn collect_restore_inventory(
    repo_root: &Path,
    dir: &Path,
    files: &mut BTreeSet<String>,
    dirs: &mut Vec<PathBuf>,
) -> Result<()> {
    let mut children = fs::read_dir(dir)?.collect::<std::result::Result<Vec<_>, _>>()?;
    children.sort_by_key(|entry| entry.file_name());
    for child in children {
        if child.file_name() == OsStr::new(".git") {
            continue;
        }
        let path = child.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_dir() {
            dirs.push(path.clone());
            collect_restore_inventory(repo_root, &path, files, dirs)?;
        } else if metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            files.insert(repo_relative_path(repo_root, &path)?);
        } else {
            return Err(Error::InvalidRepoMutationRecord(
                "repo restore supports only files, directories, and symlinks",
            ));
        }
    }
    Ok(())
}

fn remove_empty_dirs(mut dirs: Vec<PathBuf>) -> Result<()> {
    dirs.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for dir in dirs {
        if fs::read_dir(&dir)?.next().is_none() {
            fs::remove_dir(dir)?;
        }
    }
    Ok(())
}

fn remove_existing_path(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() {
        fs::remove_dir_all(path)?;
    } else {
        fs::remove_file(path)?;
    }
    Ok(())
}

fn store_snapshot_if_absent(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    fork_hash: RepoForkHash,
    snapshot_bytes: &[u8],
) -> Result<()> {
    let key = repo_mutation_snapshot_key(fork_hash);
    if vault.store.vault_meta.get(wtxn, &key)?.is_none() {
        vault.store.vault_meta.put(wtxn, &key, snapshot_bytes)?;
    }
    Ok(())
}

fn allocate_next_repo_mutation_seq(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    repo_key_hash: &str,
) -> Result<u64> {
    let key = repo_mutation_seq_key(repo_key_hash);
    let current = match vault.store.vault_meta.get(wtxn, &key)? {
        Some(bytes) => {
            let bytes: [u8; 8] = bytes.try_into().map_err(|_| {
                Error::InvalidRepoMutationRecord("repo mutation seq row must be 8 bytes")
            })?;
            u64::from_be_bytes(bytes)
        }
        None => 0,
    };
    let next = current
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow("repo_mutation_seq"))?;
    vault
        .store
        .vault_meta
        .put(wtxn, &key, &next.to_be_bytes())?;
    Ok(next)
}

fn decode_oplog_entry(bytes: &[u8]) -> Result<RepoMutationOplogEntry> {
    public_oplog_entry(decode_stored_oplog_entry(bytes)?)
}

fn public_oplog_entry(stored: StoredRepoMutationOplogEntry) -> Result<RepoMutationOplogEntry> {
    if stored.schema_version != REPO_MUTATION_OPLOG_SCHEMA_VERSION {
        return Err(Error::InvalidRepoMutationRecord(
            "unsupported repo mutation oplog schema version",
        ));
    }
    let repo_ref = RepoRef::parse(&stored.repo_ref)?;
    Ok(RepoMutationOplogEntry {
        repo_ref,
        seq: stored.seq,
        operation_kind: stored.operation_kind,
        operation_subject: stored.operation_subject,
        actor_id: stored
            .actor_id
            .map(EntityId::from_bytes)
            .transpose()
            .map_err(|_| Error::InvalidRepoMutationRecord("invalid repo mutation actor id"))?,
        session_id: stored
            .session_id
            .map(EntityId::from_bytes)
            .transpose()
            .map_err(|_| Error::InvalidRepoMutationRecord("invalid repo mutation session id"))?,
        started_at_ms: stored.started_at_ms,
        finished_at_ms: stored.finished_at_ms,
        pre_action_fork_hash: stored.pre_action_fork_hash,
        status: RepoMutationStatus::parse(&stored.status)?,
        failure: stored.failure,
    })
}

fn encode_oplog_entry(entry: &StoredRepoMutationOplogEntry) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(entry)
        .map_err(|_| Error::InvariantViolation("repo mutation oplog encode failed"))
}

fn decode_stored_oplog_entry(bytes: &[u8]) -> Result<StoredRepoMutationOplogEntry> {
    rmp_serde::from_slice(bytes)
        .map_err(|_| Error::InvalidRepoMutationRecord("repo mutation oplog is not MessagePack"))
}

fn encode_snapshot(snapshot: &StoredRepoSnapshot) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(snapshot)
        .map_err(|_| Error::InvariantViolation("repo mutation snapshot encode failed"))
}

fn decode_snapshot(bytes: &[u8]) -> Result<StoredRepoSnapshot> {
    let snapshot: StoredRepoSnapshot = rmp_serde::from_slice(bytes).map_err(|_| {
        Error::InvalidRepoMutationRecord("repo mutation snapshot is not MessagePack")
    })?;
    if snapshot.schema_version != REPO_MUTATION_OPLOG_SCHEMA_VERSION {
        return Err(Error::InvalidRepoMutationRecord(
            "unsupported repo mutation snapshot schema version",
        ));
    }
    Ok(snapshot)
}

fn repo_mutation_lock(repo_key: &str) -> Result<Arc<Mutex<()>>> {
    let mut locks = REPO_MUTATION_LOCKS
        .lock()
        .map_err(|_| Error::ConcurrentWrite("repo mutation lock map poisoned"))?;
    Ok(locks
        .entry(repo_key.to_owned())
        .or_insert_with(|| Arc::new(Mutex::new(())))
        .clone())
}

#[cfg(unix)]
fn repo_mutation_file_lock(repo_root: &Path) -> Result<RepoMutationFileLock> {
    let lock_path = git_common_dir(repo_root)?.join(REPO_MUTATION_LOCK_FILE_NAME);
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock_path)?;
    // SAFETY: `file.as_raw_fd()` is valid for the duration of this call, and
    // `flock(LOCK_EX)` blocks until the kernel grants the advisory lock.
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
    if result == 0 {
        Ok(RepoMutationFileLock { file })
    } else {
        Err(std::io::Error::last_os_error().into())
    }
}

#[cfg(not(unix))]
fn repo_mutation_file_lock(_repo_root: &Path) -> Result<RepoMutationFileLock> {
    Ok(RepoMutationFileLock)
}

fn git_common_dir(repo_root: &Path) -> Result<PathBuf> {
    let output = run_git(
        repo_root,
        &["rev-parse".to_owned(), "--git-common-dir".to_owned()],
    )?;
    let path = PathBuf::from(utf8_trimmed(output, "git common dir must be UTF-8")?);
    let path = if path.is_absolute() {
        path
    } else {
        repo_root.join(path)
    };
    Ok(path.canonicalize()?)
}

fn resolve_mutable_repo_root(repo_ref: &RepoRef) -> Result<PathBuf> {
    let RepoRef::LocalFolder { path } = repo_ref else {
        return Err(Error::InvalidRepoMutationRecord(
            "only local repo_refs can be mutated",
        ));
    };
    let output = run_git_at_path(
        Path::new(path),
        &["rev-parse".to_owned(), "--show-toplevel".to_owned()],
    )?;
    let root = utf8_trimmed(output, "git repo root must be UTF-8")?;
    Ok(PathBuf::from(root).canonicalize()?)
}

fn canonical_repo_ref_for_root(repo_root: &Path) -> Result<RepoRef> {
    let path = repo_root
        .to_str()
        .ok_or(Error::InvalidRepoMutationRecord(
            "local repo path must be UTF-8",
        ))?
        .to_owned();
    Ok(RepoRef::LocalFolder { path })
}

fn validate_relative_repo_path(path: &str) -> Result<()> {
    if path.is_empty() || path.len() > CODEBASE_FILE_PATH_MAX_BYTES {
        return Err(Error::InvalidRepoMutationRecord(
            "repo mutation path must be non-empty and at most 4096 bytes",
        ));
    }
    if path.contains('\\') {
        return Err(Error::InvalidRepoMutationRecord(
            "repo mutation path must use forward slashes",
        ));
    }
    let parsed = Path::new(path);
    if parsed.is_absolute() {
        return Err(Error::InvalidRepoMutationRecord(
            "repo mutation path must be repository-relative",
        ));
    }
    let mut has_component = false;
    for component in parsed.components() {
        match component {
            Component::Normal(part) => {
                if part == OsStr::new(".git") {
                    return Err(Error::InvalidRepoMutationRecord(
                        "repo mutation path must not target .git",
                    ));
                }
                has_component = true;
            }
            _ => {
                return Err(Error::InvalidRepoMutationRecord(
                    "repo mutation path must not contain . or .. components",
                ));
            }
        }
    }
    if !has_component {
        return Err(Error::InvalidRepoMutationRecord(
            "repo mutation path must contain a file component",
        ));
    }
    Ok(())
}

fn validate_commit_message(message: &str) -> Result<()> {
    if message.is_empty() || message.len() > MAX_COMMIT_MESSAGE_BYTES || message.contains('\0') {
        return Err(Error::InvalidRepoMutationRecord(
            "commit message must be non-empty, bounded, and contain no NUL",
        ));
    }
    Ok(())
}

fn validate_base_ref(base_ref: &str) -> Result<()> {
    if base_ref.is_empty() || base_ref.len() > MAX_BASE_REF_BYTES || base_ref.contains('\0') {
        return Err(Error::InvalidRepoMutationRecord(
            "worktree base ref must be non-empty, bounded, and contain no NUL",
        ));
    }
    Ok(())
}

fn validate_worktree_path(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty() {
        return Err(Error::InvalidRepoMutationRecord(
            "worktree path must be non-empty",
        ));
    }
    path_arg(path)?;
    Ok(())
}

fn operation_subject(operation: &RepoMutationOperation) -> String {
    match operation {
        RepoMutationOperation::CommitFile { path, .. } => path.clone(),
        RepoMutationOperation::CreateWorktree { worktree_path, .. }
        | RepoMutationOperation::RemoveWorktree { worktree_path } => {
            worktree_path.to_string_lossy().into_owned()
        }
        RepoMutationOperation::RecoverSnapshot { fork_hash } => hex_bytes(fork_hash),
    }
}

fn repo_relative_path(repo_root: &Path, path: &Path) -> Result<String> {
    let relative = path
        .strip_prefix(repo_root)
        .map_err(|_| Error::InvariantViolation("repo path escaped root"))?;
    let mut out = String::new();
    for component in relative.components() {
        let Component::Normal(part) = component else {
            return Err(Error::InvalidRepoMutationRecord(
                "repo snapshot path must be normal",
            ));
        };
        let part = part.to_str().ok_or(Error::InvalidRepoMutationRecord(
            "repo snapshot path must be UTF-8",
        ))?;
        if !out.is_empty() {
            out.push('/');
        }
        out.push_str(part);
    }
    validate_relative_repo_path(&out)?;
    Ok(out)
}

fn run_git(repo_root: &Path, args: &[String]) -> Result<Vec<u8>> {
    run_git_at_path(repo_root, args)
}

fn run_git_at_path(path: &Path, args: &[String]) -> Result<Vec<u8>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(path)
        .args(args)
        .output()?;
    if output.status.success() {
        return Ok(output.stdout);
    }
    Err(Error::RepoMutationFailed(format_git_failure(
        args,
        output.status.code(),
        &output.stderr,
    )))
}

fn git_output_optional(repo_root: &Path, args: &[String]) -> Result<Option<Vec<u8>>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(args)
        .output()?;
    if output.status.success() {
        Ok(Some(output.stdout))
    } else {
        Ok(None)
    }
}

fn format_git_failure(args: &[String], code: Option<i32>, stderr: &[u8]) -> String {
    let stderr = String::from_utf8_lossy(stderr);
    let stderr = stderr.trim();
    let message = format!("git {} exited with {:?}: {}", args.join(" "), code, stderr);
    truncate_failure(&message)
}

fn truncate_failure(message: &str) -> String {
    if message.len() <= MAX_REPO_MUTATION_FAILURE_BYTES {
        return message.to_owned();
    }
    let mut out = message[..MAX_REPO_MUTATION_FAILURE_BYTES].to_owned();
    out.push_str("...");
    out
}

fn path_arg(path: &Path) -> Result<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or(Error::InvalidRepoMutationRecord("path must be UTF-8"))
}

fn utf8_trimmed(bytes: Vec<u8>, context: &'static str) -> Result<String> {
    let text = String::from_utf8(bytes).map_err(|_| Error::InvalidRepoMutationRecord(context))?;
    Ok(text.trim_end_matches(['\r', '\n']).to_owned())
}

fn repo_key_hash(repo_key: &str) -> String {
    hex_bytes(&sha256_bytes(repo_key.as_bytes()))
}

fn sha256_bytes(bytes: &[u8]) -> RepoForkHash {
    let digest = Sha256::digest(bytes);
    let mut out = [0_u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0F) as usize] as char);
    }
    out
}

fn repo_mutation_seq_key(repo_key_hash: &str) -> Vec<u8> {
    prefixed_key(REPO_MUTATION_SEQ_KEY_PREFIX, repo_key_hash)
}

fn repo_mutation_snapshot_key(fork_hash: RepoForkHash) -> Vec<u8> {
    prefixed_key(REPO_MUTATION_SNAPSHOT_KEY_PREFIX, &hex_bytes(&fork_hash))
}

fn repo_mutation_oplog_prefix(repo_key_hash: &str) -> Vec<u8> {
    prefixed_key(REPO_MUTATION_OPLOG_KEY_PREFIX, repo_key_hash)
}

fn repo_mutation_oplog_key(repo_key_hash: &str, seq: u64) -> Vec<u8> {
    let mut key = repo_mutation_oplog_prefix(repo_key_hash);
    key.push(b':');
    key.extend_from_slice(format!("{seq:016x}").as_bytes());
    key
}

fn prefixed_key(prefix: &[u8], suffix: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(prefix.len() + suffix.len());
    key.extend_from_slice(prefix);
    key.extend_from_slice(suffix.as_bytes());
    key
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

fn is_executable(metadata: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        false
    }
}

fn set_executable(path: &Path, executable: bool) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if executable { 0o755 } else { 0o644 };
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    {
        let _ = (path, executable);
    }
    Ok(())
}

fn create_symlink(target: &Path, link: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link)?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = (target, link);
        Err(Error::InvalidRepoMutationRecord(
            "symlink repo snapshots are unsupported on this platform",
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};
    use std::thread;

    use tempfile::TempDir;

    use super::*;
    use crate::{ErrorKind, VaultConfig};

    fn open_test_vault() -> (TempDir, Vault) {
        let dir = tempfile::tempdir().expect("vault tempdir");
        let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
        (dir, vault)
    }

    fn init_repo() -> TempDir {
        let dir = tempfile::tempdir().expect("repo tempdir");
        run_git_at_path(dir.path(), &["init".to_owned()]).expect("git init");
        fs::write(dir.path().join("README.md"), "base\n").expect("write readme");
        run_git_at_path(
            dir.path(),
            &["add".to_owned(), "--".to_owned(), "README.md".to_owned()],
        )
        .expect("git add");
        run_git_at_path(
            dir.path(),
            &[
                "-c".to_owned(),
                "user.name=Oneiron".to_owned(),
                "-c".to_owned(),
                "user.email=oneiron@example.invalid".to_owned(),
                "commit".to_owned(),
                "-m".to_owned(),
                "initial".to_owned(),
            ],
        )
        .expect("git commit");
        dir
    }

    fn repo_ref(repo: &TempDir) -> RepoRef {
        RepoRef::LocalFolder {
            path: repo.path().to_string_lossy().into_owned(),
        }
    }

    #[test]
    fn repo_mutation_queue_serializes_concurrent_commits() {
        let (_vault_dir, vault) = open_test_vault();
        let repo = init_repo();
        let vault = Arc::new(vault);
        let barrier = Arc::new(Barrier::new(3));

        let mut handles = Vec::new();
        for name in ["a", "b"] {
            let vault = Arc::clone(&vault);
            let barrier = Arc::clone(&barrier);
            let repo_ref = repo_ref(&repo);
            handles.push(thread::spawn(move || {
                barrier.wait();
                vault.apply_repo_mutation(RepoMutationRequest::new(
                    repo_ref,
                    RepoMutationOperation::CommitFile {
                        path: format!("{name}.txt"),
                        content: format!("{name}\n").into_bytes(),
                        message: format!("commit {name}"),
                    },
                ))
            }));
        }

        barrier.wait();
        let mut seqs = Vec::new();
        for handle in handles {
            let outcome = handle.join().expect("thread join").expect("commit");
            assert_eq!(outcome.entry.status, RepoMutationStatus::Applied);
            seqs.push(outcome.entry.seq);
        }
        seqs.sort_unstable();
        assert_eq!(seqs, vec![1, 2]);

        let log = vault.repo_mutation_oplog(&repo_ref(&repo)).expect("oplog");
        assert_eq!(log.len(), 2);
        assert!(log.iter().all(|entry| entry.failure.is_none()));
        assert_eq!(log[0].status, RepoMutationStatus::Applied);
        assert_eq!(log[1].status, RepoMutationStatus::Applied);

        let commits = run_git_at_path(
            repo.path(),
            &[
                "log".to_owned(),
                "--format=%s".to_owned(),
                "--".to_owned(),
                "a.txt".to_owned(),
                "b.txt".to_owned(),
            ],
        )
        .expect("git log");
        let commits = String::from_utf8(commits).expect("utf8 log");
        assert!(commits.contains("commit a"));
        assert!(commits.contains("commit b"));
    }

    #[cfg(unix)]
    #[test]
    fn repo_mutation_file_lock_uses_git_common_dir() {
        let repo = init_repo();
        let common_dir = git_common_dir(repo.path()).expect("main common dir");
        let worktree_parent = tempfile::tempdir().expect("worktree parent");
        let worktree_path = worktree_parent.path().join("linked-worktree");
        run_git_at_path(
            repo.path(),
            &[
                "worktree".to_owned(),
                "add".to_owned(),
                "--detach".to_owned(),
                worktree_path.to_string_lossy().into_owned(),
                "HEAD".to_owned(),
            ],
        )
        .expect("create linked worktree");

        assert_eq!(
            git_common_dir(&worktree_path).expect("worktree common dir"),
            common_dir
        );
        let _guard = repo_mutation_file_lock(&worktree_path).expect("lock common dir");
        assert!(common_dir.join(REPO_MUTATION_LOCK_FILE_NAME).exists());
    }

    #[test]
    fn repo_mutation_recovery_remounts_pre_action_snapshot() {
        let (_vault_dir, vault) = open_test_vault();
        let repo = init_repo();
        let tracked = repo.path().join("README.md");
        fs::write(&tracked, "dirty before\n").expect("dirty write");
        let before = fs::read_to_string(&tracked).expect("read before");

        let outcome = vault
            .apply_repo_mutation(RepoMutationRequest::new(
                repo_ref(&repo),
                RepoMutationOperation::CommitFile {
                    path: "README.md".to_owned(),
                    content: b"mutated\n".to_vec(),
                    message: "mutate readme".to_owned(),
                },
            ))
            .expect("mutate");
        assert_eq!(
            fs::read_to_string(&tracked).expect("read mutated"),
            "mutated\n"
        );

        let recovery = vault
            .recover_repo_snapshot(&repo_ref(&repo), outcome.entry.pre_action_fork_hash)
            .expect("recover");
        assert_eq!(recovery.entry.operation_kind, "recover_snapshot");
        assert_eq!(
            fs::read_to_string(&tracked).expect("read recovered"),
            before
        );
    }

    #[test]
    fn repo_mutation_api_has_no_forbidden_raw_git_operations() {
        assert_eq!(
            REPO_MUTATION_ALLOWED_OPERATION_KINDS,
            [
                "commit_file",
                "create_worktree",
                "remove_worktree",
                "recover_snapshot"
            ]
        );
        for forbidden in REPO_MUTATION_FORBIDDEN_GIT_COMMANDS {
            assert!(
                !REPO_MUTATION_ALLOWED_OPERATION_KINDS.contains(&forbidden),
                "{forbidden} must not be an allowed queue operation"
            );
        }
        let err = validate_relative_repo_path(".git/index").expect_err("reject .git path");
        assert_eq!(err.kind(), ErrorKind::InvalidRepoMutationRecord);
        let err = validate_relative_repo_path("../outside").expect_err("reject parent path");
        assert_eq!(err.kind(), ErrorKind::InvalidRepoMutationRecord);
    }

    #[test]
    fn repo_mutation_worktree_lifecycle_is_queued_and_logged() {
        let (_vault_dir, vault) = open_test_vault();
        let repo = init_repo();
        let worktree = tempfile::tempdir().expect("worktree parent");
        let worktree_path = worktree.path().join("agent-worktree");

        let created = vault
            .apply_repo_mutation(RepoMutationRequest::new(
                repo_ref(&repo),
                RepoMutationOperation::CreateWorktree {
                    worktree_path: worktree_path.clone(),
                    base_ref: "HEAD".to_owned(),
                },
            ))
            .expect("create worktree");
        assert!(worktree_path.join("README.md").exists());

        let removed = vault
            .apply_repo_mutation(RepoMutationRequest::new(
                repo_ref(&repo),
                RepoMutationOperation::RemoveWorktree {
                    worktree_path: worktree_path.clone(),
                },
            ))
            .expect("remove worktree");
        assert!(!worktree_path.exists());
        assert_eq!(created.entry.seq, 1);
        assert_eq!(removed.entry.seq, 2);
    }
}
