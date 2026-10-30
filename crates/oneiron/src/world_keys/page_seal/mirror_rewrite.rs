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
/// ([`holds_encoding`]). Each mirror is written whole: a new file, synced,
/// renamed over the old one, then the directory synced. So one that holds
/// these bytes was synced by the write that made it, and a torn, stale,
/// missing or unreadable mirror is written as before.
pub(super) fn write_mirror_if_changed(root: &Path, mirror: &Mirror) -> Result<()> {
    let path = mirror_beside(root)?;
    let raw =
        serde_json::to_vec(mirror).map_err(|_| refused("the page-seal mirror did not encode"))?;
    if holds_encoding(&path, &raw) {
        return Ok(());
    }
    // FIX 2348: the mirror has no size cap.
    write_owner_only(&path, &raw)
}

/// Whether the file at `path` is the one writing `raw` there would leave: a
/// private regular file of this user (one name, mode 0600, no link
/// followed) holding `raw` byte for byte. Any failure to look says no, so
/// the write runs.
#[cfg(unix)]
fn holds_encoding(path: &Path, raw: &[u8]) -> bool {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    // `O_NONBLOCK` keeps a FIFO at the mirror's name from holding the open.
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
    let expected = raw.len() as u64;
    if !metadata.file_type().is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() != expected
    {
        return false;
    }
    let mut held = Vec::with_capacity(raw.len());
    // One byte past the expected length: a file that grew since its metadata
    // was read compares unequal.
    file.take(expected + 1).read_to_end(&mut held).is_ok() && held == raw
}

/// Off unix no mirror is taken as the write's own: the write always runs.
#[cfg(not(unix))]
fn holds_encoding(_path: &Path, _raw: &[u8]) -> bool {
    false
}
