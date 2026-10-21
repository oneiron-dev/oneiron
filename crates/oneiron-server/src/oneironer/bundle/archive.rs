//! The strict reader of a platform row's archive (FIX 6755, contract rev 3
//! A1), written here with no tar dependency. An archive is one POSIX ustar
//! file, uncompressed, read as a stream and never held whole. Each header's
//! magic, version and checksum are checked, and the archive must end in its
//! two zero blocks. Only regular files and directories under relative paths
//! of plain names are taken; an absolute path, a `..`, a link, any other
//! entry type, an extension header and a base-256 size are typed refusals.
//!
//! An archive is extracted beside itself, inside the staging directory,
//! into a fresh scratch tree: directories one at a time and files with
//! `create_new`, so nothing is written through a link. Modes are normalized:
//! `0755` for a directory or an entry with any exec bit, else `0644`, never
//! a setuid, setgid or sticky bit. The `.extracted` marker, the archive's
//! full SHA-256, is written last, and the tree is then renamed to the
//! archive's name less `.tar`. A marker alone proves nothing:
//! [`verify_extraction`] checks a tree against its archive entry by entry.

use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};

use super::Artifact;

mod ustar;

use ustar::Reader;

/// The file an extraction writes last: its archive's full SHA-256.
pub(crate) const MARKER: &str = ".extracted";
/// What an unfinished extraction's scratch tree is named by, beside it.
const SCRATCH_PREFIX: &str = ".extracting-";
/// How much of an entry is moved at a time.
const CHUNK: usize = 1 << 20;
const DIR_MODE: u32 = 0o755;
const EXEC_MODE: u32 = 0o755;
const FILE_MODE: u32 = 0o644;

/// Why an archive or its extraction was refused. Paths are the archive's
/// own entry names, from a pinned file.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ArchiveError {
    #[error("archive entry {path:?} is an absolute path")]
    AbsolutePath { path: String },
    #[error("archive entry {path:?} has a `..` component")]
    ParentComponent { path: String },
    #[error("archive entry {path:?} is a symlink")]
    Symlink { path: String },
    #[error("archive entry {path:?} is a hardlink")]
    Hardlink { path: String },
    #[error("archive entry {path:?} is a {kind} (type {flag:?}), not a file or directory")]
    UnsupportedEntry {
        path: String,
        flag: char,
        kind: &'static str,
    },
    #[error("archive entry {path:?} has {what}, which this reader does not take")]
    UnsupportedHeader {
        path: String,
        /// The header field it cannot read.
        what: &'static str,
    },
    #[error("archive entry {path:?} appears twice")]
    DuplicatePath { path: String },
    #[error("archive header at byte {offset}: {reason}")]
    MalformedHeader { offset: u64, reason: String },
    #[error("archive {file:?} is not one <name>.tar file")]
    NotTar { file: String },
    #[error("the archive is not its pinned {bytes} bytes with sha256 {sha256}")]
    Pin { bytes: u64, sha256: String },
    #[error("{dir} is not its archive's extraction: {reason}")]
    Installation { dir: String, reason: String },
    #[error("{action} {path}: {reason}")]
    Io {
        action: &'static str,
        path: String,
        reason: String,
    },
}

/// `<parent>/<name>`: where the archive `artifact` names is extracted, its
/// file name less `.tar`.
pub(crate) fn extraction_dir(parent: &Path, artifact: &Artifact) -> Result<PathBuf, ArchiveError> {
    Ok(parent.join(stem(artifact)?))
}

/// Extracts the archive `tar`, pinned by `artifact`, into
/// [`extraction_dir`] under `parent`, a staging directory that holds no
/// extraction of it yet. A scratch tree an earlier attempt left is this
/// staging's own and is replaced. The archive's length and digest are
/// checked as it streams, before the marker is written.
pub(crate) fn extract_verified(
    tar: &Path,
    artifact: &Artifact,
    parent: &Path,
) -> Result<PathBuf, ArchiveError> {
    let target = extraction_dir(parent, artifact)?;
    let scratch = parent.join(format!("{SCRATCH_PREFIX}{}", stem(artifact)?));
    remove_tree(&scratch)?;
    if target.symlink_metadata().is_ok() {
        return Err(io("extracting into", &target)("it already exists"));
    }
    make_dir(&scratch, DIR_MODE)?;
    let mut reader = Reader::open(tar, artifact)?;
    let mut buffer = vec![0_u8; CHUNK];
    while let Some(entry) = reader.entry()? {
        let path = scratch.join(&entry.path);
        if entry.directory {
            make_dir(&path, entry.mode)?;
            continue;
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(io("creating", &path))?;
        reader.data(entry.size, &mut buffer, |chunk| {
            file.write_all(chunk).map_err(io("writing", &path))
        })?;
        #[cfg(unix)]
        set_mode(&path, entry.mode)?;
    }
    reader.finish(&mut buffer)?;
    let marker = scratch.join(MARKER);
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&marker)
        .and_then(|mut file| file.write_all(artifact.sha256.as_bytes()))
        .map_err(io("writing", &marker))?;
    #[cfg(unix)]
    set_mode(&marker, FILE_MODE)?;
    std::fs::rename(&scratch, &target).map_err(io("placing", &scratch))?;
    Ok(target)
}

/// Checks that `dir` is the extraction of the archive `tar`, pinned by
/// `artifact`: its marker names the archive, every entry is there with the
/// archive's type, size, normalized mode and bytes, the tree holds nothing
/// else but the marker, and the archive itself is its pin. It writes
/// nothing; a fetch's reuse and a runtime's load both run it.
pub(crate) fn verify_extraction(
    tar: &Path,
    artifact: &Artifact,
    dir: &Path,
) -> Result<(), ArchiveError> {
    let differs = |reason: String| ArchiveError::Installation {
        dir: dir.display().to_string(),
        reason,
    };
    if !dir.symlink_metadata().is_ok_and(|held| held.is_dir()) {
        return Err(differs("it is not a directory".to_owned()));
    }
    let marker = dir.join(MARKER);
    let marked = marker.symlink_metadata().is_ok_and(|held| held.is_file())
        && std::fs::read(&marker).is_ok_and(|held| held == artifact.sha256.as_bytes());
    if !marked {
        return Err(differs(format!("its {MARKER} does not name the archive")));
    }
    let mut reader = Reader::open(tar, artifact)?;
    let (mut buffer, mut held) = (vec![0_u8; CHUNK], vec![0_u8; CHUNK]);
    while let Some(entry) = reader.entry()? {
        let path = dir.join(&entry.path);
        let shown = entry.path.display();
        let Ok(metadata) = path.symlink_metadata() else {
            return Err(differs(format!("{shown} is missing")));
        };
        let same = if entry.directory {
            metadata.is_dir()
        } else {
            metadata.is_file() && metadata.len() == entry.size
        };
        if !same || !has_mode(&metadata, entry.mode) {
            return Err(differs(format!("{shown} is not the archive's type, size or mode")));
        }
        if entry.directory {
            continue;
        }
        let mut file = File::open(&path).map_err(io("opening", &path))?;
        reader.data(entry.size, &mut buffer, |chunk| {
            let mine = &mut held[..chunk.len()];
            file.read_exact(mine).map_err(io("reading", &path))?;
            if mine == chunk {
                Ok(())
            } else {
                Err(differs(format!("{shown} differs from the archive")))
            }
        })?;
    }
    let entries = reader.finish(&mut buffer)?;
    match stray(dir, &entries)? {
        Some(path) => Err(differs(format!("{} is not in the archive", path.display()))),
        None => Ok(()),
    }
}

/// Removes an extraction and its scratch tree from `parent`, a staging
/// directory whose own they are. Never run on a placed bundle.
pub(crate) fn remove_extraction(parent: &Path, artifact: &Artifact) -> Result<(), ArchiveError> {
    remove_tree(&extraction_dir(parent, artifact)?)?;
    remove_tree(&parent.join(format!("{SCRATCH_PREFIX}{}", stem(artifact)?)))
}

/// The first path under `dir` that is not an archive entry, `.extracted` at
/// its top aside, walked without following a link.
fn stray(dir: &Path, entries: &BTreeSet<PathBuf>) -> Result<Option<PathBuf>, ArchiveError> {
    let mut pending = vec![PathBuf::new()];
    while let Some(relative) = pending.pop() {
        let here = dir.join(&relative);
        for item in std::fs::read_dir(&here).map_err(io("listing", &here))? {
            let item = item.map_err(io("listing", &here))?;
            if relative.as_os_str().is_empty() && item.file_name() == MARKER {
                continue;
            }
            let path = relative.join(item.file_name());
            if !entries.contains(&path) {
                return Ok(Some(path));
            }
            if item.file_type().map_err(io("listing", &here))?.is_dir() {
                pending.push(path);
            }
        }
    }
    Ok(None)
}

/// Its file name less `.tar`.
fn stem(artifact: &Artifact) -> Result<&str, ArchiveError> {
    artifact
        .file
        .strip_suffix(".tar")
        .filter(|stem| !stem.is_empty() && !stem.contains('/'))
        .ok_or_else(|| ArchiveError::NotTar {
            file: artifact.file.clone(),
        })
}

/// Creates one directory, then sets its mode whatever the umask made it.
fn make_dir(path: &Path, mode: u32) -> Result<(), ArchiveError> {
    std::fs::create_dir(path).map_err(io("creating", path))?;
    #[cfg(unix)]
    set_mode(path, mode)?;
    #[cfg(not(unix))]
    let _ = mode;
    Ok(())
}

/// Removes `path` whatever it is, never following a link.
fn remove_tree(path: &Path) -> Result<(), ArchiveError> {
    let removed = match path.symlink_metadata() {
        Ok(held) if held.is_dir() => std::fs::remove_dir_all(path),
        Ok(_) => std::fs::remove_file(path),
        Err(_) => return Ok(()),
    };
    removed.map_err(io("removing", path))
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<(), ArchiveError> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(io("setting the mode of", path))
}

/// Whether `metadata`'s permission bits are `mode`; only Unix has them.
#[cfg(unix)]
fn has_mode(metadata: &std::fs::Metadata, mode: u32) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    metadata.permissions().mode() & 0o7777 == mode
}

#[cfg(not(unix))]
fn has_mode(_: &std::fs::Metadata, _: u32) -> bool {
    true
}

fn pin(artifact: &Artifact) -> ArchiveError {
    ArchiveError::Pin {
        bytes: artifact.bytes,
        sha256: artifact.sha256.clone(),
    }
}

fn malformed(offset: u64, reason: impl Into<String>) -> ArchiveError {
    ArchiveError::MalformedHeader {
        offset,
        reason: reason.into(),
    }
}

fn io<E: std::fmt::Display>(action: &'static str, path: &Path) -> impl FnOnce(E) -> ArchiveError {
    let path = path.display().to_string();
    move |error| ArchiveError::Io {
        action,
        path,
        reason: error.to_string(),
    }
}
