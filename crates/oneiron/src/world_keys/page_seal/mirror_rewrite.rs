//! The page-seal mirror's rewrite at a sealed open and after a wrap change,
//! kept off the disk when the mirror there is already the very file the
//! write would leave: no temporary file, no rename, no file or directory
//! sync (speed, finding 12).

use std::path::Path;

use super::{Mirror, mirror_beside, write_owner_only};
use crate::error::Result;
use crate::world_keys::refused;

/// Writes `mirror` beside `root` as [`super::write_mirror`] does, unless the
/// mirror there already holds its encoding byte for byte
/// ([`capture_mirror`]). Each mirror is written whole: a new file, synced,
/// renamed over the old one, then the directory synced. So one that holds
/// these bytes was synced by the write that made it, and a torn, stale,
/// missing or unreadable mirror is written as before.
pub(super) fn write_mirror_if_changed(
    root: &Path,
    mirror: &Mirror,
) -> Result<Option<CapturedMirror>> {
    let path = mirror_beside(root)?;
    let raw =
        serde_json::to_vec(mirror).map_err(|_| refused("the page-seal mirror did not encode"))?;
    if let Some(captured) = capture_mirror(&path)
        && captured.raw == raw
    {
        return Ok(Some(captured));
    }
    // FIX 2348: the mirror has no size cap.
    write_owner_only(&path, &raw)?;
    Ok(stat_identity(&path).map(|(dev, ino)| CapturedMirror::of(raw, dev, ino)))
}

/// A mirror read fused with the file identity one look saw: the bytes a
/// write compared or left behind, with the device and inode (unix) of the
/// file they came from. [`crate::Vault::check_page_custody`] parses these
/// bytes instead of re-reading the mirror once [`captured_identity_current`]
/// proves no rename-or-remove landed since
/// (FIX 12272: a managed start's settle and ready check share one
/// under-lease mirror read).
#[derive(Clone)]
pub(crate) struct CapturedMirror {
    raw: Vec<u8>,
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
}

impl CapturedMirror {
    #[cfg(unix)]
    fn of(raw: Vec<u8>, dev: u64, ino: u64) -> Self {
        Self { raw, dev, ino }
    }

    #[cfg(not(unix))]
    fn of(raw: Vec<u8>, _dev: u64, _ino: u64) -> Self {
        Self { raw }
    }

    pub(super) fn raw(&self) -> &[u8] {
        &self.raw
    }
}

/// Opens `path` with the same no-follow owner-only checks the old
/// skip-compare applied, and returns what it holds with its identity.
/// `None` says nothing: the caller writes or re-reads as before.
#[cfg(unix)]
pub(super) fn capture_mirror(path: &Path) -> Option<CapturedMirror> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    // `O_NONBLOCK` keeps a FIFO at the mirror's name from holding the open.
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.file_type().is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
    {
        return None;
    }
    let mut raw = Vec::new();
    // One byte past the file's length: a file that grew since its metadata
    // was read compares unequal at the caller's compare.
    // FIX 2348: the mirror has no size cap; the carry is consumed at the
    // first check, never held for the vault's lifetime.
    file.take(metadata.len() + 1).read_to_end(&mut raw).ok()?;
    Some(CapturedMirror {
        raw,
        dev: metadata.dev(),
        ino: metadata.ino(),
    })
}

/// Off unix no mirror content is captured: the write always runs and the
/// check re-reads as before.
#[cfg(not(unix))]
pub(super) fn capture_mirror(_path: &Path) -> Option<CapturedMirror> {
    None
}

/// The identity a post-write file carries: its device and inode (unix), for
/// a carry over bytes this process just synced. `None` (a stat that failed,
/// or off unix) tells the caller to re-read as before; the write itself
/// already succeeded.
#[cfg(unix)]
fn stat_identity(path: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.file_type().is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
    {
        return None;
    }
    Some((metadata.dev(), metadata.ino()))
}

#[cfg(not(unix))]
fn stat_identity(_path: &Path) -> Option<(u64, u64)> {
    None
}

/// Whether `captured` still names the file at `path`: the same device and
/// inode, still an owner-only single-link regular file of the captured
/// length. Every mirror content change is a rename (a new inode) or a
/// removal (the open fails), so a match means the bytes are unchanged: no
/// content read, about two syscalls (FIX 12272).
#[cfg(unix)]
pub(super) fn captured_identity_current(path: &Path, captured: &CapturedMirror) -> bool {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let Ok(file) = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
    else {
        return false;
    };
    let Ok(metadata) = file.metadata() else {
        return false;
    };
    metadata.file_type().is_file()
        && metadata.uid() == rustix::process::geteuid().as_raw()
        && metadata.mode() & 0o7777 == 0o600
        && metadata.nlink() == 1
        && metadata.dev() == captured.dev
        && metadata.ino() == captured.ino
        && metadata.len() == captured.raw.len() as u64
}

/// Off unix no capture is ever current: the check re-reads as before.
#[cfg(not(unix))]
pub(super) fn captured_identity_current(_path: &Path, _captured: &CapturedMirror) -> bool {
    false
}
