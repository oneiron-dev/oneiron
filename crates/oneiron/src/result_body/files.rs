//! Body directory work for the collector and the checkpoint prune, done
//! through the directory's descriptor: nothing here follows a link.

use std::fs::File;
use std::time::{Duration, SystemTime};

use rustix::fs::{AtFlags, Dir, Mode, OFlags, fsync, openat, unlinkat};
use rustix::io::Errno;

use super::BODY_GRACE;
use super::pins::ResultBodyPins;
use crate::store::{BodyDir, LINE_INDEX_SUFFIX, body_file_name};
use crate::{Error, Result};

fn io(error: Errno) -> Error {
    std::io::Error::from(error).into()
}

/// One body file, or its line index, in a body directory.
pub(super) struct BodyEntry {
    pub(super) digest: [u8; 32],
    /// The body's line index, not the body.
    pub(super) index: bool,
}

/// The body files and line indexes in `dir`, read as the caller pulls them.
/// Temp files and any other name are passed over.
pub(super) fn body_entries(dir: &BodyDir) -> Result<impl Iterator<Item = Result<BodyEntry>>> {
    Ok(Dir::read_from(&dir.dir)
        .map_err(io)?
        .filter_map(|entry| match entry {
            Ok(entry) => parse_entry(entry.file_name().to_bytes()).map(Ok),
            Err(error) => Some(Err(io(error))),
        }))
}

/// A body's file name is its digest in lowercase hex; its index adds
/// [`LINE_INDEX_SUFFIX`].
fn parse_entry(name: &[u8]) -> Option<BodyEntry> {
    let name = std::str::from_utf8(name).ok()?;
    let (hex, index) = match name.strip_suffix(LINE_INDEX_SUFFIX) {
        Some(hex) => (hex, true),
        None => (name, false),
    };
    let digest = *blake3::Hash::from_hex(hex).ok()?.as_bytes();
    (body_file_name(&digest) == hex).then_some(BodyEntry { digest, index })
}

/// How long ago the regular file `name` in `dir` last changed. `None` when
/// it is absent or no regular file.
fn file_age(dir: &BodyDir, name: &str, now: SystemTime) -> Result<Option<Duration>> {
    let file = match openat(
        &dir.dir,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => File::from(fd),
        Err(Errno::NOENT | Errno::LOOP) => return Ok(None),
        Err(error) => return Err(io(error)),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Ok(None);
    }
    Ok(Some(
        now.duration_since(metadata.modified()?).unwrap_or_default(),
    ))
}

/// Unlinks `name` in `dir`; one already gone is fine.
fn unlink_name(dir: &BodyDir, name: &str) -> Result<()> {
    match unlinkat(&dir.dir, name, AtFlags::empty()) {
        Ok(()) | Err(Errno::NOENT) => Ok(()),
        Err(error) => Err(io(error)),
    }
}

/// Unlinks the body `digest` and its line index; either already gone is
/// fine.
pub(super) fn unlink_body(dir: &BodyDir, digest: &[u8; 32]) -> Result<()> {
    let name = body_file_name(digest);
    unlink_name(dir, &name)?;
    unlink_name(dir, &format!("{name}{LINE_INDEX_SUFFIX}"))
}

/// Removes the body of `entry`, which nothing names, with its line index,
/// or the line index alone once its body is gone: only past [`BODY_GRACE`]
/// and while no reader in `pins` holds it. `true` when something went.
pub(super) fn remove_unnamed(
    dir: &BodyDir,
    entry: &BodyEntry,
    now: SystemTime,
    pins: Option<&ResultBodyPins>,
) -> Result<bool> {
    let body = body_file_name(&entry.digest);
    if entry.index && file_age(dir, &body, now)?.is_some() {
        // Its body is there: the body's own entry decides for both.
        return Ok(false);
    }
    let name = if entry.index {
        format!("{body}{LINE_INDEX_SUFFIX}")
    } else {
        body
    };
    if file_age(dir, &name, now)?.is_none_or(|age| age < BODY_GRACE) {
        return Ok(false);
    }
    let remove = || {
        if entry.index {
            unlink_name(dir, &name)
        } else {
            unlink_body(dir, &entry.digest)
        }
    };
    match pins {
        Some(pins) => Ok(pins
            .unless_pinned(&entry.digest, remove)
            .transpose()?
            .is_some()),
        None => remove().map(|()| true),
    }
}

/// Syncs `dir`, so the unlinks in it last.
pub(super) fn sync_dir(dir: &BodyDir) -> Result<()> {
    fsync(&dir.dir).map_err(io)
}
