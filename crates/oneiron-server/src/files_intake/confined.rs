//! Reading under one folder without leaving it. Every step opens the next
//! entry relative to the folder already open and never through a symbolic
//! link, so neither a link under the folder nor an ancestor swapped for one
//! while the walk runs can lead outside the path the person gave.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

use rustix::fs::{AtFlags, CWD, Dir, FileType, Mode, OFlags, openat, statat};

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
pub(crate) fn open_file(dir: &OwnedFd, name: &OsStr, shown: &Path) -> anyhow::Result<File> {
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
pub(crate) fn open_in(dir: &Path, name: &str) -> anyhow::Result<Option<File>> {
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
pub(crate) fn walk_logs(
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

/// Visits every `.md` and `.pdf` file under `root`, passing over hidden files and
/// folders (an editor's settings, its trash, a `.git`): the path shown, and
/// the file.
pub(crate) fn walk_notes(
    root: &Path,
    visit: &mut dyn FnMut(&Path, File) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    walk(&open_root(root)?, root, NOTES, visit)
}

/// Why a walk is refused whole; nothing under it is imported.
#[derive(Debug, thiserror::Error)]
pub(super) enum WalkRefused {
    #[error(
        "{folder}: the walk listed more than {most} files and folders; nothing was imported. \
         Import one folder under the one given at a time"
    )]
    TooManyEntries { folder: String, most: usize },
}

/// The files a walk visits: their extensions, also in other case when
/// `any_case`, or every file; whether hidden entries count; and how many
/// entries it lists before it is refused. Every walk goes down every folder
/// below where it starts, however deep (FIX 9474).
#[derive(Clone, Copy)]
pub(crate) struct Wanted {
    extensions: &'static [&'static str],
    every_file: bool,
    any_case: bool,
    hidden: bool,
    entries: usize,
}

pub(crate) const LOGS: Wanted = Wanted {
    extensions: &["jsonl"],
    every_file: false,
    any_case: false,
    hidden: true,
    entries: usize::MAX,
};

/// A note is `.md` or `.pdf` in any case (`BETA.MD`): editors open it either
/// way. A PDF's text is its note's (ARCH-0027: the first adapter reads a
/// Markdown and PDF folder).
const NOTES: Wanted = Wanted {
    extensions: &["md", "pdf"],
    every_file: false,
    any_case: true,
    hidden: false,
    // A folder of any width is read (rule 5): its notes and their text are
    // measured against the import's `[limits]` rows instead.
    entries: usize::MAX,
};

/// A Files source's walk (FIX 6942): every regular file, hidden ones too,
/// since what it passes over is the owner's exclusions, judged before any
/// entry is opened. Its width is a notes walk's.
const FILES: Wanted = Wanted {
    extensions: &[],
    every_file: true,
    hidden: true,
    ..NOTES
};

impl Wanted {
    /// Whether a file named `name` is one this walk visits.
    fn visits(self, name: &OsStr) -> bool {
        self.every_file
            || Path::new(name).extension().is_some_and(|extension| {
                self.extensions.iter().any(|wanted| {
                    if self.any_case {
                        extension.eq_ignore_ascii_case(wanted)
                    } else {
                        extension == *wanted
                    }
                })
            })
    }
}

/// The session log `relative` names below `root`, and the folder it sits in.
/// Every folder below `root` is opened relative to the one above it and never
/// through a link, so a queued path can reach nothing outside `root`; links
/// in `root` itself are the owner's, as in a path they type.
pub(crate) fn open_below(root: &Path, relative: &Path) -> anyhow::Result<(OwnedFd, File)> {
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
pub(crate) fn open_dir_in(dir: &OwnedFd, name: &OsStr) -> anyhow::Result<Option<OwnedFd>> {
    match statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) if FileType::from_raw_mode(stat.st_mode) == FileType::Directory => {
            Ok(Some(openat(dir, name, directory_flags(), Mode::empty())?))
        }
        _ => Ok(None),
    }
}

/// Visits every file `wanted` names under the open folder `dir`, shown as
/// `shown`, in name order.
pub(crate) fn walk(
    dir: &OwnedFd,
    shown: &Path,
    wanted: Wanted,
    visit: &mut dyn FnMut(&Path, File) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    let mut left = wanted.entries;
    let mut skips = Skips {
        excluded: &nothing_excluded,
        unopened: &mut nothing_unopened,
    };
    walk_below(dir.try_clone()?, shown, wanted, &mut skips, &mut left, visit)
}

/// What a walk passes over before it opens it, and whom it names a file
/// that does not open to.
struct Skips<'a> {
    excluded: &'a dyn Fn(&Path) -> bool,
    unopened: &'a mut dyn FnMut(&Path),
}

/// A walk that excludes nothing beyond its own profile.
fn nothing_excluded(_: &Path) -> bool {
    false
}

/// Any walk but a Files walk refuses at a file that does not open, so it
/// names none.
fn nothing_unopened(_: &Path) {}

/// Visits every regular file under `root` a Files source reads (FIX 6942),
/// hidden ones too: the path shown, and the file. An entry `excluded` names
/// by its shown path is passed over before it is opened, a folder before
/// anything under it is listed. A file that does not open (no read
/// permission) is named to `unopened` and the walk goes on.
pub(crate) fn walk_files(
    root: &Path,
    excluded: &dyn Fn(&Path) -> bool,
    unopened: &mut dyn FnMut(&Path),
    visit: &mut dyn FnMut(&Path, File) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    let mut left = FILES.entries;
    let mut skips = Skips { excluded, unopened };
    walk_below(open_root(root)?, root, FILES, &mut skips, &mut left, visit)
}

/// Every folder of a walk from `dir`, shown as `shown`, passing over what
/// the walk excludes; `left` is how many more entries the walk may list.
fn walk_below(
    dir: OwnedFd,
    shown: &Path,
    wanted: Wanted,
    skips: &mut Skips<'_>,
    left: &mut usize,
    visit: &mut dyn FnMut(&Path, File) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    let mut traversal = Traversal { open: Vec::new() };
    traversal.enter(dir, shown.to_path_buf(), wanted, left)?;
    while traversal.step(wanted, skips, left, visit)? {}
    Ok(())
}

/// The folders a walk holds open, deepest last, each with the entries of it
/// still to visit, in name order (FIX 9474). The walk is this explicit stack,
/// never a recursion, so it reaches every folder below where it started
/// however deep the tree goes: no folder is passed over or refused for its
/// depth. Each step visits one entry, so a walk can stop after any step and
/// go on from there.
struct Traversal {
    open: Vec<OpenFolder>,
}

/// One folder a [`Traversal`] holds open: the folder, its path as shown, and
/// its entries not visited yet.
struct OpenFolder {
    dir: OwnedFd,
    shown: PathBuf,
    entries: std::vec::IntoIter<(OsString, FileType)>,
}

impl Traversal {
    /// Lists the open folder `dir`, shown as `shown`, and holds it open
    /// deepest; `left` is how many more entries the walk may list.
    fn enter(
        &mut self,
        dir: OwnedFd,
        shown: PathBuf,
        wanted: Wanted,
        left: &mut usize,
    ) -> anyhow::Result<()> {
        let mut entries: Vec<(OsString, FileType)> = Vec::new();
        for entry in Dir::read_from(&dir)? {
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
        self.open.push(OpenFolder {
            dir,
            shown,
            entries: entries.into_iter(),
        });
        Ok(())
    }

    /// Visits the next entry of the deepest open folder, entering it when it
    /// is a folder, or closes that folder once it has none left. `false`
    /// once no folder is open: the walk is done.
    fn step(
        &mut self,
        wanted: Wanted,
        skips: &mut Skips<'_>,
        left: &mut usize,
        visit: &mut dyn FnMut(&Path, File) -> anyhow::Result<()>,
    ) -> anyhow::Result<bool> {
        let Some(folder) = self.open.last_mut() else {
            return Ok(false);
        };
        let Some((name, listed)) = folder.entries.next() else {
            self.open.pop();
            return Ok(true);
        };
        let path = folder.shown.join(&name);
        if (skips.excluded)(&path) {
            return Ok(true);
        }
        // A symbolic link is neither a folder nor a file here.
        match kind(&folder.dir, &name, listed)? {
            FileType::Directory => {
                let child = openat(&folder.dir, name.as_os_str(), directory_flags(), Mode::empty())
                    .map_err(|error| {
                        anyhow::anyhow!(
                            "{} changed while it was being read; nothing under it was imported ({error})",
                            path.display()
                        )
                    })?;
                self.enter(child, path, wanted, left)?;
            }
            FileType::RegularFile if wanted.visits(&name) => {
                match open_file(&folder.dir, &name, &path) {
                    Ok(file) => visit(&path, file)?,
                    // A Files walk holds such a file by its name; any other
                    // walk refuses.
                    Err(_) if wanted.every_file => (skips.unopened)(&path),
                    Err(error) => return Err(error),
                }
            }
            _ => {}
        }
        Ok(true)
    }
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
        let made = oneiron_spawn::command("mkfifo")
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
