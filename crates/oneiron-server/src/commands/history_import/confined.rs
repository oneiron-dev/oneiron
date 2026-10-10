//! Reading under one folder without leaving it. Every step opens the next
//! entry relative to the folder already open and never through a symbolic
//! link, so neither a link under the folder nor an ancestor swapped for one
//! while the walk runs can lead outside the path the person gave.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path};

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

/// One regular file in an open folder, never through a link. The open does
/// not block, so an entry swapped for a FIFO after it was listed is refused
/// by the type check rather than waited on; reading a regular file is the
/// same either way.
pub(super) fn open_file(dir: &OwnedFd, name: &OsStr, shown: &Path) -> anyhow::Result<File> {
    let file = File::from(
        openat(
            dir,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
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
            walk(&dir, &root.join(history), LOGS, visit)
        }
        Err(_) => walk(&root_dir, root, LOGS, visit),
    }
}

/// Visits every `.md` file under `root`, passing over hidden files and
/// folders (an editor's settings, its trash, a `.git`): the path shown, and
/// the file.
pub(super) fn walk_notes(
    root: &Path,
    visit: &mut dyn FnMut(&Path, File) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    walk(&open_root(root)?, root, NOTES, visit)
}

/// The most entries a notes walk lists, every folder together. A walk holds
/// each folder's whole listing while it sorts and visits it, so neither the
/// depth cap nor the note count bounds a wide folder.
const MAX_NOTES_WALK_ENTRIES: usize = 1_000_000;

/// Why a walk is refused whole; nothing under it is imported.
#[derive(Debug, thiserror::Error)]
pub(super) enum WalkRefused {
    #[error(
        "{folder}: the walk listed more than {most} files and folders; nothing was imported. \
         Import one folder under the one given at a time"
    )]
    TooManyEntries { folder: String, most: usize },
}

/// The files a walk visits: their extension, also in other case when
/// `any_case`; whether hidden entries count; how deep it goes; and how many
/// entries it lists before it is refused. Past `depth`, a log walk passes
/// over the folder; a notes walk refuses, since a batch without those notes
/// would read as the whole folder.
#[derive(Clone, Copy)]
pub(super) struct Wanted {
    extension: &'static str,
    any_case: bool,
    hidden: bool,
    depth: usize,
    refuse_deeper: bool,
    entries: usize,
}

pub(super) const LOGS: Wanted = Wanted {
    extension: "jsonl",
    any_case: false,
    hidden: true,
    depth: MAX_WALK_DEPTH,
    refuse_deeper: false,
    entries: usize::MAX,
};

/// A note is `.md` in any case (`BETA.MD`): editors open it either way.
const NOTES: Wanted = Wanted {
    extension: "md",
    any_case: true,
    hidden: false,
    depth: 32,
    refuse_deeper: true,
    entries: MAX_NOTES_WALK_ENTRIES,
};

impl Wanted {
    /// Whether a file named `name` is one this walk visits.
    fn visits(self, name: &OsStr) -> bool {
        Path::new(name).extension().is_some_and(|extension| {
            if self.any_case {
                extension.eq_ignore_ascii_case(self.extension)
            } else {
                extension == self.extension
            }
        })
    }
}

/// The session log `relative` names below `root`, and the folder it sits in.
/// Every folder below `root` is opened relative to the one above it and never
/// through a link, so a queued path can reach nothing outside `root`; links
/// in `root` itself are the owner's, as in a path they type.
pub(super) fn open_below(root: &Path, relative: &Path) -> anyhow::Result<(OwnedFd, File)> {
    let mut dir = open_root(root)?;
    let mut shown = root.to_path_buf();
    let mut components = relative.components().peekable();
    while let Some(component) = components.next() {
        let Component::Normal(name) = component else {
            anyhow::bail!(
                "{} is not a plain path below {}",
                relative.display(),
                root.display()
            );
        };
        shown.push(name);
        if components.peek().is_none() {
            let file = open_file(&dir, name, &shown)?;
            return Ok((dir, file));
        }
        dir = openat(&dir, name, directory_flags(), Mode::empty())
            .map_err(|error| anyhow::anyhow!("open {}: {error}", shown.display()))?;
    }
    anyhow::bail!("no session log named below {}", root.display())
}

/// The folder `name` in `dir`, never through a link; `None` when there is
/// no such folder.
pub(super) fn open_dir_in(dir: &OwnedFd, name: &OsStr) -> anyhow::Result<Option<OwnedFd>> {
    match statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) if FileType::from_raw_mode(stat.st_mode) == FileType::Directory => {
            Ok(Some(openat(dir, name, directory_flags(), Mode::empty())?))
        }
        _ => Ok(None),
    }
}

/// Visits every file `wanted` names under the open folder `dir`, shown as
/// `shown`, in name order.
pub(super) fn walk(
    dir: &OwnedFd,
    shown: &Path,
    wanted: Wanted,
    visit: &mut dyn FnMut(&Path, File) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    let mut left = wanted.entries;
    walk_below(dir, shown, 0, wanted, &mut left, visit)
}

/// One folder of a walk, `depth` below where it started; `left` is how many
/// more entries the walk may list.
fn walk_below(
    dir: &OwnedFd,
    shown: &Path,
    depth: usize,
    wanted: Wanted,
    left: &mut usize,
    visit: &mut dyn FnMut(&Path, File) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    if depth > wanted.depth {
        anyhow::ensure!(
            !wanted.refuse_deeper,
            "{} is more than {} folders deep; nothing was imported",
            shown.display(),
            wanted.depth
        );
        return Ok(());
    }
    let mut entries: Vec<(OsString, FileType)> = Vec::new();
    for entry in Dir::read_from(dir)? {
        let entry = entry?;
        let name = OsStr::from_bytes(entry.file_name().to_bytes());
        if name == "." || name == ".." {
            continue;
        }
        *left = left
            .checked_sub(1)
            .ok_or_else(|| WalkRefused::TooManyEntries {
                folder: shown.display().to_string(),
                most: wanted.entries,
            })?;
        let hidden = name.as_bytes().first() == Some(&b'.');
        if wanted.hidden || !hidden {
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
                walk_below(&child, &path, depth + 1, wanted, left, visit)?;
            }
            FileType::RegularFile if wanted.visits(&name) => {
                visit(&path, open_file(dir, &name, &path)?)?;
            }
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use std::time::Duration;

    use super::*;

    /// Greptile 1310 (confined.rs:46): an entry listed as a file and swapped
    /// for a FIFO before it is opened. Opening it must not wait for a writer.
    #[test]
    fn an_entry_that_is_a_fifo_when_opened_is_refused_without_waiting() {
        let dir = tempfile::tempdir().expect("test fixture");
        let name = "rollout-2026-09-14T10-00-00-fifo.jsonl";
        let made = std::process::Command::new("mkfifo")
            .arg(dir.path().join(name))
            .status()
            .expect("mkfifo");
        assert!(made.success(), "mkfifo");
        let folder = open_root(dir.path()).expect("open the folder");
        let (opened, outcome) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = opened.send(open_file(&folder, OsStr::new(name), Path::new(name)).is_err());
        });
        let refused = outcome
            .recv_timeout(Duration::from_secs(10))
            .expect("the open returned without a writer on the FIFO");
        assert!(refused, "a FIFO is not a regular file");
    }

    /// Astra 3 (#1351, second paragraph): a walk held each folder's whole
    /// listing before it visited any of it, and nothing bounded how many
    /// entries that was. Past its entry budget a walk is refused while it
    /// lists, before it visits the folder that went past.
    #[test]
    fn a_walk_past_its_entry_budget_is_refused_while_it_lists() {
        let dir = tempfile::tempdir().expect("test fixture");
        std::fs::create_dir(dir.path().join("sub")).expect("test fixture");
        for name in ["a.md", "b.md", "sub/c.md", "sub/d.md", "sub/e.txt"] {
            std::fs::write(dir.path().join(name), "x").expect("test fixture");
        }
        let walked = |entries| {
            let mut visited = 0;
            let outcome = walk(
                &open_root(dir.path()).expect("open the folder"),
                dir.path(),
                Wanted { entries, ..NOTES },
                &mut |_, _| {
                    visited += 1;
                    Ok(())
                },
            );
            (outcome, visited)
        };
        // Six entries: `a.md`, `b.md`, `sub` and the three in it.
        let (outcome, visited) = walked(6);
        assert!(outcome.is_ok(), "{outcome:?}");
        assert_eq!(visited, 4);
        let (outcome, visited) = walked(5);
        let refused = outcome
            .err()
            .and_then(|error| error.downcast::<WalkRefused>().ok());
        assert!(
            matches!(refused, Some(WalkRefused::TooManyEntries { most: 5, .. })),
            "{refused:?}"
        );
        assert_eq!(visited, 2, "nothing in `sub` was visited");
    }
}
