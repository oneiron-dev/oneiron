//! Current-folder capture through held directories, independent of recovery.

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs::File;
use std::path::Path;

use crate::error::{CodeError, Error, Result};

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;
#[cfg(unix)]
pub(super) use unix::Directory;
#[cfg(windows)]
pub(super) use windows::Directory;

#[derive(Clone, Copy)]
pub(crate) enum EntryKind {
    Directory,
    File,
    Symlink,
    Other,
}

pub(crate) enum CaptureEntry<'a> {
    File(File),
    Symlink {
        directory: &'a Directory,
        name: &'a OsStr,
        expected: u64,
    },
}

impl CaptureEntry<'_> {
    pub(crate) fn read_link(&self, buffer: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Symlink {
                directory, name, ..
            } => directory.read_link(name, buffer),
            Self::File(_) => Err(std::io::Error::other("not a symlink")),
        }
    }
}

pub(super) fn visit_capture_entries(
    root: &Directory,
    indexed: &BTreeSet<String>,
    linked: &BTreeSet<String>,
    visit: &mut impl FnMut(String, CaptureEntry<'_>) -> Result<()>,
) -> Result<()> {
    fn walk(
        dir: &Directory,
        relative: &Path,
        indexed: &BTreeSet<String>,
        linked: &BTreeSet<String>,
        visit: &mut impl FnMut(String, CaptureEntry<'_>) -> Result<()>,
    ) -> Result<()> {
        let mut names = dir.names()?;
        names.sort();
        for name in names {
            if name == OsStr::new(".git") {
                continue;
            }
            let path = relative.join(&name);
            let relative = super::repo_relative_path(Path::new(""), &path)?;
            if indexed.contains(&relative) {
                continue;
            }
            let (kind, expected) = dir.entry_kind(&name)?;
            match kind {
                EntryKind::Directory => {
                    if linked.contains(&relative) {
                        continue;
                    }
                    let child = dir.open_dir(&name)?;
                    if child.has_git_marker()? {
                        continue;
                    }
                    walk(&child, &path, indexed, linked, visit)?;
                }
                EntryKind::File => {
                    let file = dir.open_file(&name)?;
                    if !file.metadata()?.is_file() {
                        return Err(invalid_entry());
                    }
                    visit(relative, CaptureEntry::File(file))?;
                }
                EntryKind::Symlink => visit(
                    relative,
                    CaptureEntry::Symlink {
                        directory: dir,
                        name: &name,
                        expected,
                    },
                )?,
                EntryKind::Other => return Err(invalid_entry()),
            }
        }
        Ok(())
    }
    walk(root, Path::new(""), indexed, linked, visit)
}

fn invalid_entry() -> Error {
    Error::Code(CodeError::InvalidCodebaseSnapshotBody(
        "capture supports only files, directories, and symlinks",
    ))
}
