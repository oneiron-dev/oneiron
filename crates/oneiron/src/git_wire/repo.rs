//! Proven repository identity plus the cross-thread, cross-process repository lock.

use std::cell::RefCell;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, LazyLock, Mutex};
use std::time::{Duration, Instant};

use super::failure::invalid;
use super::record::{hash_field, hex_lower};
use super::{GIT_WIRE_DOMAIN, GIT_WIRE_REPO_LOCK_FILE_NAME, GitOid, GitWireResult};
use crate::codebase::RepoRef;
use crate::error::{Error, Result};

/// The identity of one object store.
///
/// It is derived from the verified canonical git common directory, so two
/// clones that share a `RepoRef` are two identities and neither can replay the
/// other's receipts, while two spellings of one clone are one identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GitWireRepoIdentity(pub(super) [u8; 32]);

impl GitWireRepoIdentity {
    /// The lower-hex identity used in durable key prefixes.
    pub fn as_hex(&self) -> String {
        hex_lower(&self.0)
    }

    pub(super) const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A repository whose `RepoRef`, working root, pinned commit, and object store
/// have all been proven to agree.
///
/// There is no field constructor: the only way to obtain one is
/// [`GitWire::open_repo`](crate::git_wire::GitWire::open_repo), which performs the proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitWireRepo {
    pub(super) repo_ref: RepoRef,
    pub(super) repo_root: PathBuf,
    pub(super) common_dir: PathBuf,
    pub(super) identity: GitWireRepoIdentity,
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

pub(super) fn repo_identity_for(common_dir: &Path) -> GitWireRepoIdentity {
    let mut hasher = blake3::Hasher::new();
    hash_field(&mut hasher, GIT_WIRE_DOMAIN);
    hash_field(&mut hasher, b"repo-identity");
    hash_field(&mut hasher, common_dir.as_os_str().as_encoded_bytes());
    GitWireRepoIdentity(*hasher.finalize().as_bytes())
}

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
    acquire_repository(common_dir, Until::Granted)?.ok_or(Error::ConcurrentWrite(
        "git wire repository lock not granted",
    ))
}

/// [`lock_repository`] that never waits: `None` while another thread or
/// another process holds the repository. Re-entrant on the holding thread all
/// the same.
pub(crate) fn try_lock_repository(common_dir: &Path) -> Result<Option<GitWireRepoGuard>> {
    acquire_repository(common_dir, Until::Now)
}

/// [`lock_repository`] that waits at most `wait`: `None` while another thread
/// or another process still holds the repository then.
pub(crate) fn lock_repository_within(
    common_dir: &Path,
    wait: Duration,
) -> Result<Option<GitWireRepoGuard>> {
    acquire_repository(common_dir, Until::Deadline(Instant::now() + wait))
}

/// How long an acquisition waits for a repository another holder has.
#[derive(Clone, Copy)]
enum Until {
    /// Until it is granted.
    Granted,
    /// Not at all.
    Now,
    /// Until this moment.
    Deadline(Instant),
}

impl Until {
    /// How long is left to wait, or `None` once there is nothing left.
    fn left(self) -> Option<Option<Duration>> {
        match self {
            Self::Granted => Some(None),
            Self::Now => None,
            Self::Deadline(deadline) => {
                let left = deadline.saturating_duration_since(Instant::now());
                (!left.is_zero()).then_some(Some(left))
            }
        }
    }
}

fn acquire_repository(common_dir: &Path, until: Until) -> Result<Option<GitWireRepoGuard>> {
    let key = common_dir.as_os_str().as_encoded_bytes().to_vec();
    let depth = held_depth(&key);
    if depth > 0 {
        set_held_depth(&key, depth.saturating_add(1));
        return Ok(Some(GitWireRepoGuard {
            key,
            cell: None,
            file: None,
        }));
    }
    let cell = repo_lock_cell(&key)?;
    if !acquire_cell(&cell, until)? {
        return Ok(None);
    }
    let file = match acquire_file_lock(common_dir, until) {
        Ok(FileLock::Held(file)) => file,
        Ok(FileLock::Busy) => {
            release_cell(&cell);
            return Ok(None);
        }
        Err(error) => {
            release_cell(&cell);
            return Err(error);
        }
    };
    set_held_depth(&key, 1);
    Ok(Some(GitWireRepoGuard {
        key,
        cell: Some(cell),
        file,
    }))
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

/// Takes the in-process hold, and says whether it did: `false` only when
/// another thread still holds it once `until` has run out.
fn acquire_cell(cell: &Arc<GitWireRepoLockCell>, until: Until) -> Result<bool> {
    fn poisoned<T>(_: std::sync::PoisonError<T>) -> Error {
        Error::ConcurrentWrite("git wire repository lock poisoned")
    }
    let mut held = cell.held.lock().map_err(poisoned)?;
    while *held {
        held = match until.left() {
            None => return Ok(false),
            Some(None) => cell.released.wait(held).map_err(poisoned)?,
            Some(Some(left)) => cell.released.wait_timeout(held, left).map_err(poisoned)?.0,
        };
    }
    *held = true;
    Ok(true)
}

fn release_cell(cell: &Arc<GitWireRepoLockCell>) {
    if let Ok(mut held) = cell.held.lock() {
        *held = false;
        cell.released.notify_one();
    }
}

/// What one attempt at the cross-process lock got.
enum FileLock {
    /// The lock, held through this descriptor; none where there is no file
    /// lock to take.
    Held(Option<fs::File>),
    /// Another process holds it, and the caller would not wait.
    Busy,
}

#[cfg(unix)]
fn acquire_file_lock(common_dir: &Path, until: Until) -> Result<FileLock> {
    use std::os::fd::AsRawFd;

    /// How often a bounded wait asks the kernel again. Another process
    /// holding the repository is rare: the door's own pushes queue in process.
    const RETRY: Duration = Duration::from_millis(25);

    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(common_dir.join(GIT_WIRE_REPO_LOCK_FILE_NAME))?;
    let operation = if matches!(until, Until::Granted) {
        libc::LOCK_EX
    } else {
        libc::LOCK_EX | libc::LOCK_NB
    };
    loop {
        // SAFETY: `file.as_raw_fd()` is valid for the duration of this call
        // and `flock(LOCK_EX)` blocks until the kernel grants the advisory
        // lock, or with `LOCK_NB` returns at once.
        let granted = unsafe { libc::flock(file.as_raw_fd(), operation) };
        if granted == 0 {
            return Ok(FileLock::Held(Some(file)));
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::WouldBlock {
            return Err(error.into());
        }
        match until.left() {
            Some(Some(left)) => std::thread::sleep(left.min(RETRY)),
            _ => return Ok(FileLock::Busy),
        }
    }
}

#[cfg(not(unix))]
fn acquire_file_lock(_common_dir: &Path, _until: Until) -> Result<FileLock> {
    Ok(FileLock::Held(None))
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
