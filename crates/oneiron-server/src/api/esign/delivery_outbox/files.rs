//! The outbox directory's file custody: its lock, whole-file writes, guarded
//! removals and syncs, its privacy, and the temporaries a hard stop left.
//! An envelope may hold a live signing link (FIX 5238), so the directory is
//! the sender's and this writer's alone: created 0700, every file 0600.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use rand_core::{OsRng, RngCore as _};

use super::{ACK_SUFFIX, ENVELOPE_SUFFIX, FILE_PREFIX, LOCK_FILE};

/// `dir`'s lock, or `None` while another publisher holds it.
pub(super) fn lock(dir: &Path) -> anyhow::Result<Option<File>> {
    ensure_directory(dir).with_context(|| format!("create the outbox {}", dir.display()))?;
    let path = dir.join(LOCK_FILE);
    let mut options = OpenOptions::new();
    options.create(true).truncate(false).read(true).write(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let file = options
        .open(&path)
        .with_context(|| format!("open {}", path.display()))?;
    match file.try_lock() {
        Ok(()) => Ok(Some(file)),
        Err(fs::TryLockError::WouldBlock) => {
            tracing::debug!(
                dir = %dir.display(),
                "another publisher holds the esign delivery outbox; this tick waits"
            );
            Ok(None)
        }
        Err(fs::TryLockError::Error(error)) => {
            Err(anyhow::Error::new(error).context(format!("lock {}", path.display())))
        }
    }
}

/// Whether only this user may enter `dir`: no group or other bit on unix.
/// Elsewhere the directory carries no such mode to read, and it counts as
/// the host made it.
pub(super) fn is_private(dir: &Path) -> io::Result<bool> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        Ok(fs::metadata(dir)?.permissions().mode() & 0o077 == 0)
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(true)
    }
}

/// Removes the temporaries a stop left mid-write of an envelope or a
/// receipt: under the lock no write of this writer's is in flight, so each
/// one found is an orphan. A sender's own temporaries are not this writer's
/// and stay. `Ok(true)` when one went.
pub(super) fn remove_orphan_temps(dir: &Path) -> io::Result<bool> {
    let mut removed = false;
    for entry in fs::read_dir(dir)? {
        let name = entry?.file_name();
        if name.to_str().is_some_and(is_own_temp) {
            removed |= remove_if_present(&dir.join(&name))?;
        }
    }
    Ok(removed)
}

/// `.<envelope or receipt name>.<16 lower hex>.tmp`, as [`write_atomic`]
/// names them.
fn is_own_temp(name: &str) -> bool {
    let Some(staged) = name
        .strip_prefix('.')
        .and_then(|rest| rest.strip_suffix(".tmp"))
        .filter(|rest| rest.starts_with(FILE_PREFIX))
    else {
        return false;
    };
    let Some((file, nonce)) = staged.rsplit_once('.') else {
        return false;
    };
    nonce.len() == 16
        && nonce
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        && file.ends_with(ENVELOPE_SUFFIX)
        && !file.ends_with(ACK_SUFFIX)
}

pub(super) fn read_if_present(path: &Path) -> io::Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

pub(super) fn remove_if_present(path: &Path) -> io::Result<bool> {
    match fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

/// Removes `path` while it still holds `bytes`: a file its writer replaced
/// since it was read stays.
pub(super) fn remove_if_unchanged(path: &Path, bytes: &[u8]) -> io::Result<bool> {
    if read_if_present(path)?.as_deref() != Some(bytes) {
        return Ok(false);
    }
    remove_if_present(path)
}

/// Writes `bytes` to `path` whole: a private temporary sibling, synced,
/// renamed over `path`, then the directory synced.
pub(super) fn write_atomic(dir: &Path, path: &Path, bytes: &[u8]) -> io::Result<()> {
    let name = path
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or(FILE_PREFIX);
    let staged: PathBuf = dir.join(format!(".{name}.{:016x}.tmp", OsRng.next_u64()));
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let written = options
        .open(&staged)
        .and_then(|mut file| {
            file.write_all(bytes)?;
            file.sync_all()
        })
        .and_then(|()| fs::rename(&staged, path));
    if let Err(error) = written {
        let _ = fs::remove_file(&staged);
        return Err(error);
    }
    sync_dir(dir)
}

/// Syncs the directory's entries. A directory opens as a file only on unix;
/// elsewhere a rename is as durable as the system makes it.
pub(super) fn sync_dir(dir: &Path) -> io::Result<()> {
    if cfg!(unix) {
        File::open(dir)?.sync_all()
    } else {
        Ok(())
    }
}

fn ensure_directory(dir: &Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(dir)
}
