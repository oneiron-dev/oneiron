//! Proven repository identity plus the cross-thread, cross-process repository lock.

use std::cell::RefCell;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, LazyLock, Mutex};

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
/// [`GitWire::open_repo`], which performs the proof.
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
