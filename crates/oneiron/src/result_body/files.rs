//! Body directory work for the collector, done through the directory's
//! descriptor: nothing here follows a link.

use std::fs::File;
use std::time::{Duration, SystemTime};

use rustix::fs::{AtFlags, Dir, Mode, OFlags, fsync, openat, unlinkat};
use rustix::io::Errno;

use super::BODY_GRACE;
use super::pins::ResultBodyPins;
use crate::store::{BodyDir, LINE_INDEX_SUFFIX, body_file_name, sealed_body_file_name};
use crate::{Error, Result};

fn io(error: Errno) -> Error {
    std::io::Error::from(error).into()
}

/// One body file, or its line index, in a body directory.
pub(super) struct BodyEntry {
    pub(super) digest: [u8; 32],
    /// A sealed vault's file: its instance (FIX 5348).
    pub(super) instance: Option<[u8; 16]>,
    /// The body's line index, not the body.
    pub(super) index: bool,
}

impl BodyEntry {
    /// The name of the body file this entry is, or indexes.
    fn body_name(&self) -> String {
        match &self.instance {
            None => body_file_name(&self.digest),
            Some(instance) => sealed_body_file_name(&self.digest, instance),
        }
    }
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

/// A body's file name is its digest in lowercase hex, a sealed file's adds
/// `-` and its instance in lowercase hex; its index adds
/// [`LINE_INDEX_SUFFIX`].
fn parse_entry(name: &[u8]) -> Option<BodyEntry> {
    let name = std::str::from_utf8(name).ok()?;
    let (stem, index) = match name.strip_suffix(LINE_INDEX_SUFFIX) {
        Some(stem) => (stem, true),
        None => (name, false),
    };
    let (hex, instance) = match stem.split_once('-') {
        Some((hex, instance)) => (hex, Some(parse_instance(instance)?)),
        None => (stem, None),
    };
    let digest = *blake3::Hash::from_hex(hex).ok()?.as_bytes();
    (body_file_name(&digest) == hex).then_some(BodyEntry {
        digest,
        instance,
        index,
    })
}

/// A sealed file's instance from its lowercase hex.
fn parse_instance(hex: &str) -> Option<[u8; 16]> {
    if hex.len() != 32 {
        return None;
    }
    let mut instance = [0u8; 16];
    for (byte, pair) in instance.iter_mut().zip(hex.as_bytes().chunks_exact(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    (crate::entity_id::bytes_to_hex_lower(&instance) == hex).then_some(instance)
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

/// Unlinks the body file `name` and its line index; either already gone is
/// fine.
fn unlink_named(dir: &BodyDir, name: &str) -> Result<()> {
    unlink_name(dir, name)?;
    unlink_name(dir, &format!("{name}{LINE_INDEX_SUFFIX}"))
}

/// Unlinks the body `digest` and its line index, and the sealed file of
/// `instance` with its own when the body had one; any already gone is fine.
pub(super) fn unlink_body(
    dir: &BodyDir,
    digest: &[u8; 32],
    instance: Option<&[u8; 16]>,
) -> Result<()> {
    unlink_named(dir, &body_file_name(digest))?;
    match instance {
        Some(instance) => unlink_named(dir, &sealed_body_file_name(digest, instance)),
        None => Ok(()),
    }
}

/// Removes the body of `entry`, which nothing names, with its line index,
/// or the line index alone once its body is gone: only past [`BODY_GRACE`]
/// and while no reader in `pins` holds it. `true` when something went.
pub(super) fn remove_unnamed(
    dir: &BodyDir,
    entry: &BodyEntry,
    now: SystemTime,
    pins: &ResultBodyPins,
) -> Result<bool> {
    let body = entry.body_name();
    if entry.index && file_age(dir, &body, now)?.is_some() {
        // Its body is there: the body's own entry decides for both.
        return Ok(false);
    }
    let name = if entry.index {
        format!("{body}{LINE_INDEX_SUFFIX}")
    } else {
        body.clone()
    };
    if file_age(dir, &name, now)?.is_none_or(|age| age < BODY_GRACE) {
        return Ok(false);
    }
    let remove = || {
        if entry.index {
            unlink_name(dir, &name)
        } else {
            unlink_named(dir, &body)
        }
    };
    Ok(pins
        .unless_pinned(&entry.digest, remove)
        .transpose()?
        .is_some())
}

/// Removes the body of `entry` with its line index at once, while no reader
/// in `pins` holds it: a body its own writer found nothing names, so no
/// grace is owed (FIX 3633). `true` when it went.
pub(super) fn remove_unnamed_now(
    dir: &BodyDir,
    entry: &BodyEntry,
    pins: &ResultBodyPins,
) -> Result<bool> {
    let body = entry.body_name();
    Ok(pins
        .unless_pinned(&entry.digest, || unlink_named(dir, &body))
        .transpose()?
        .is_some())
}

/// Syncs `dir`, so the unlinks in it last.
pub(super) fn sync_dir(dir: &BodyDir) -> Result<()> {
    fsync(&dir.dir).map_err(io)
}
