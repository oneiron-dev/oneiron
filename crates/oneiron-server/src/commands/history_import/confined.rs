//! Reading under one folder without leaving it. Every step opens the next
//! entry relative to the folder already open and never through a symbolic
//! link, so neither a link under the folder nor an ancestor swapped for one
//! while the walk runs can lead outside the path the person gave.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use rustix::fs::{AtFlags, CWD, Dir, FileType, Mode, OFlags, openat, statat};

use super::MAX_WALK_DEPTH;

fn directory_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

/// The folder the person named; links in the path they typed are theirs to
/// follow.
fn open_root(path: &Path) -> anyhow::Result<OwnedFd> {
    openat(
        CWD,
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| anyhow::anyhow!("open {}: {error}", path.display()))
}

fn kind(dir: &OwnedFd, name: &OsStr, listed: FileType) -> anyhow::Result<FileType> {
    if listed != FileType::Unknown {
        return Ok(listed);
    }
    let stat = statat(dir, name, AtFlags::SYMLINK_NOFOLLOW)?;
    Ok(FileType::from_raw_mode(stat.st_mode))
}

/// One regular file in an open folder, never through a link.
fn open_file(dir: &OwnedFd, name: &OsStr, shown: &Path) -> anyhow::Result<File> {
    let file = File::from(
        openat(
            dir,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| {
            anyhow::anyhow!(
                "{} changed while it was being read; nothing under it was imported ({error})",
                shown.display()
            )
        })?,
    );
    anyhow::ensure!(
        file.metadata()?.is_file(),
        "{} is not a regular file",
        shown.display()
    );
    Ok(file)
}

/// `name` in the folder at `dir`, when it is a regular file there.
pub(super) fn open_in(dir: &Path, name: &str) -> anyhow::Result<Option<File>> {
    let root = open_root(dir)?;
    let name = OsStr::new(name);
    match statat(&root, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) if FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile => {
            open_file(&root, name, &dir.join(name)).map(Some)
        }
        _ => Ok(None),
    }
}

/// Visits every `.jsonl` file under `root`, or under its `history` folder when
/// it has one (the tool's whole home was given): the path shown, and the file.
pub(super) fn walk_logs(
    root: &Path,
    history: &str,
    visit: &mut dyn FnMut(&Path, File) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    let root_dir = open_root(root)?;
    let history_name = OsStr::new(history);
    match statat(&root_dir, history_name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => {
            anyhow::ensure!(
                FileType::from_raw_mode(stat.st_mode) == FileType::Directory,
                "{} is not a folder; give the folder it points to",
                root.join(history).display()
            );
            let dir = openat(&root_dir, history_name, directory_flags(), Mode::empty())?;
            walk(&dir, &root.join(history), 0, visit)
        }
        Err(_) => walk(&root_dir, root, 0, visit),
    }
}

fn walk(
    dir: &OwnedFd,
    shown: &Path,
    depth: usize,
    visit: &mut dyn FnMut(&Path, File) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    if depth > MAX_WALK_DEPTH {
        return Ok(());
    }
    let mut entries: Vec<(OsString, FileType)> = Vec::new();
    for entry in Dir::read_from(dir)? {
        let entry = entry?;
        let name = OsStr::from_bytes(entry.file_name().to_bytes());
        if name != "." && name != ".." {
            entries.push((name.to_owned(), entry.file_type()));
        }
    }
    entries.sort_by(|(left, _), (right, _)| left.cmp(right));
    for (name, listed) in entries {
        let path = shown.join(&name);
        // A symbolic link is neither a folder nor a file here.
        match kind(dir, &name, listed)? {
            FileType::Directory => {
                let child = openat(dir, name.as_os_str(), directory_flags(), Mode::empty())
                    .map_err(|error| {
                        anyhow::anyhow!(
                            "{} changed while it was being read; nothing under it was imported ({error})",
                            path.display()
                        )
                    })?;
                walk(&child, &path, depth + 1, visit)?;
            }
            FileType::RegularFile
                if Path::new(&name)
                    .extension()
                    .is_some_and(|extension| extension == "jsonl") =>
            {
                visit(&path, open_file(dir, &name, &path)?)?;
            }
            _ => {}
        }
    }
    Ok(())
}
