//! The mark a rehearsal's scratch copy carries when it is deleted afterwards,
//! and the start-up sweep of those a stopped process left (FIX 5677).
//!
//! A rehearsal that keeps no copy makes it in a new directory named
//! `oneiron-rehearse-<UTC time>-<id>` and marks that directory disposable
//! with a file, `.oneiron-disposable-scratch`, it holds an exclusive lock on
//! until the directory is removed. A copy kept with `--scratch` is never
//! marked. A process stopped mid-rehearsal leaves the directory, and the
//! kernel drops its lock. The next start of a server removes each directory
//! in its rehearsal directory with that name, that mark and no lock held,
//! this user's and owner-only, through the directory it holds open. Nothing
//! else is touched: no age or size decides, and no scratch vault is opened to
//! decide.

#[cfg(unix)]
use std::path::Path;

#[cfg(unix)]
use super::super::stamp::parse_file_stamp;
use super::super::stamp::{file_stamp, now_unix_ms};

/// The name every generated scratch directory starts with.
const PREFIX: &str = "oneiron-rehearse-";

/// The mark of a disposable scratch directory, a file in it: the directory
/// is a rehearsal's own, and goes once no rehearsal holds the mark's lock.
#[cfg(unix)]
const MARK: &str = ".oneiron-disposable-scratch";

/// A new scratch directory's name, `oneiron-rehearse-<UTC time>-<id>`.
pub(super) fn generated_name() -> String {
    format!(
        "{PREFIX}{}-{}",
        file_stamp(now_unix_ms()),
        oneiron::EntityId::now().to_hex()
    )
}

/// Whether `name` is exactly one [`generated_name`] makes.
#[cfg(unix)]
fn is_generated(name: &str) -> bool {
    name.strip_prefix(PREFIX)
        .and_then(|rest| rest.split_once('-'))
        .is_some_and(|(stamp, id)| {
            parse_file_stamp(stamp).is_some()
                && id.len() == 32
                && id
                    .bytes()
                    .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        })
}

/// Marks `held`, the scratch directory a rehearsal just made, disposable,
/// and returns the mark, locked while it stays open. The mark is made under a
/// partial name and locked before it takes its own, so a sweep never finds it
/// unlocked while its rehearsal lives.
#[cfg(unix)]
pub(super) fn mark(held: &std::fs::File) -> std::io::Result<std::fs::File> {
    use rustix::fs::{FlockOperation, Mode, OFlags};
    let partial = format!("{MARK}.partial");
    let flags = OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mark = std::fs::File::from(rustix::fs::openat(
        held,
        partial.as_str(),
        flags,
        Mode::RUSR | Mode::WUSR,
    )?);
    rustix::fs::flock(&mark, FlockOperation::NonBlockingLockExclusive)?;
    rustix::fs::renameat(held, partial.as_str(), held, MARK)?;
    Ok(mark)
}

/// Removes the disposable scratch directories in `parent` that no rehearsal
/// holds, those a stopped process's rehearsals left, and returns how many it
/// removed. A missing `parent` has none. One it cannot remove is logged and
/// left as it is; the error is `parent`'s own, when it does not read.
#[cfg(unix)]
pub(crate) fn sweep_rehearsals(parent: &Path) -> anyhow::Result<usize> {
    use rustix::fs::{Mode, OFlags};
    let opened = rustix::fs::open(
        parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    );
    let dir = match opened {
        Ok(dir) => dir,
        Err(rustix::io::Errno::NOENT) => return Ok(0),
        Err(error) => {
            return Err(anyhow::Error::new(std::io::Error::from(error))
                .context(format!("open {}", parent.display())));
        }
    };
    let mut names = Vec::new();
    for entry in rustix::fs::Dir::read_from(&dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy();
        if is_generated(&name) {
            names.push(name.into_owned());
        }
    }
    let mut removed = 0;
    for name in names {
        let path = parent.join(&name);
        match sweep_one(&dir, &name, &path) {
            Ok(true) => removed += 1,
            Ok(false) => {}
            Err(error) => tracing::warn!(
                reason = "rehearsal_scratch_left",
                dir = %path.display(),
                error = %format!("{error:#}"),
                "a stopped rehearsal's scratch copy was not removed; it is left as it is"
            ),
        }
    }
    Ok(removed)
}

/// Removes `name` in `parent`, at `path`, when it is a disposable scratch
/// directory no rehearsal holds, and says whether it did. A link, a directory
/// another user owns or could reach, one with no mark and one whose mark is
/// locked are left as they are.
#[cfg(unix)]
fn sweep_one(parent: &std::os::fd::OwnedFd, name: &str, path: &Path) -> anyhow::Result<bool> {
    use std::os::unix::fs::MetadataExt;

    use rustix::fs::{FlockOperation, Mode, OFlags};
    use rustix::io::Errno;
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let held = match rustix::fs::openat(parent, name, flags | OFlags::DIRECTORY, Mode::empty()) {
        Ok(held) => std::fs::File::from(held),
        Err(Errno::LOOP | Errno::NOTDIR | Errno::NOENT) => return Ok(false),
        Err(error) => return Err(std::io::Error::from(error).into()),
    };
    let metadata = held.metadata()?;
    if metadata.uid() != rustix::process::geteuid().as_raw() || metadata.mode() & 0o077 != 0 {
        return Ok(false);
    }
    // Opened without blocking, so a pipe under the mark's name never stalls
    // the start.
    let mark = match rustix::fs::openat(&held, MARK, flags | OFlags::NONBLOCK, Mode::empty()) {
        Ok(mark) => std::fs::File::from(mark),
        Err(Errno::LOOP | Errno::NOENT) => return Ok(false),
        Err(error) => return Err(std::io::Error::from(error).into()),
    };
    if !mark.metadata()?.is_file() {
        return Ok(false);
    }
    match rustix::fs::flock(&mark, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => {}
        // A rehearsal still running holds it.
        Err(Errno::WOULDBLOCK) => return Ok(false),
        Err(error) => return Err(std::io::Error::from(error).into()),
    }
    // The lock is held until the directory, mark and all, is gone.
    oneiron::store::remove_held_directory(path, &held)?;
    drop(mark);
    Ok(true)
}
