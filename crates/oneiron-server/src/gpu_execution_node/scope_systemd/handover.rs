//! The end step's hand-over (FIX EXEC-UNIT-CROSS-JOB-SAME-UID, ruling A):
//! once the unit's group is empty, every entry beneath the job's payload
//! directory that the job's uid owns becomes the engine account's, and every
//! entry of the job's group gets the engine's group. The engine can then read
//! and remove what the job left, a directory the job made 0700 included, and
//! the job's id can go to another job.
//!
//! Only the job's own ids are changed: an entry another account owns keeps its
//! owner, so a directory put in the job's place gives root nothing to change
//! but the job's own files. The walk opens each directory from the one above
//! it, follows no symbolic link (a link's own owner changes, never its
//! target's), crosses no mount, and stops at [`HANDOVER_DEPTH_MAX`],
//! [`HANDOVER_ENTRIES_MAX`] or its deadline: then the hand-over is
//! incomplete, and the end step keeps the job's id taken.

use std::ffi::{CStr, CString};
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, OwnedFd};
use std::time::{Duration, Instant};

use rustix::fs::{AtFlags, FileType, Mode, OFlags, ResolveFlags};

use super::job_ids::JobIdentity;

/// The deepest directory the walk descends to.
pub const HANDOVER_DEPTH_MAX: usize = 256;

/// The most entries one hand-over looks at.
pub const HANDOVER_ENTRIES_MAX: u64 = 1_000_000;

/// How the walk opens each directory: no symbolic link followed.
const DIR_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

/// What one hand-over did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandOver {
    /// Entries whose owner or group changed.
    pub changed: u64,
    /// Entries looked at.
    pub seen: u64,
    /// Why the walk stopped before the end; `None` when every entry beneath
    /// the payload was looked at.
    pub incomplete: Option<String>,
}

/// The owner and group an entry gets: the engine's in place of each of the
/// job's ids, `None` for an id that stays.
#[must_use]
pub fn new_ids(
    found: (u32, u32),
    job: JobIdentity,
    engine: (u32, u32),
) -> (Option<u32>, Option<u32>) {
    (
        (found.0 == job.uid).then_some(engine.0),
        (found.1 == job.gid).then_some(engine.1),
    )
}

/// Hands every entry beneath `payload` (the open payload directory, itself
/// the engine's) that `job` owns to `engine` (uid, gid), within `wait`.
#[must_use]
pub fn hand_over(
    payload: BorrowedFd<'_>,
    job: JobIdentity,
    engine: (u32, u32),
    wait: Duration,
) -> HandOver {
    let mut walk = Walk {
        device: 0,
        job,
        engine,
        until: Instant::now() + wait,
        outcome: HandOver {
            changed: 0,
            seen: 0,
            incomplete: None,
        },
        pending: Vec::new(),
    };
    let top = rustix::fs::fstat(payload).and_then(|found| {
        walk.device = found.st_dev;
        rustix::fs::openat(payload, c".", DIR_FLAGS, Mode::empty())
    });
    match top {
        Ok(top) => walk.pending.push((top, 0)),
        Err(error) => {
            walk.outcome.incomplete = Some(format!("payload: {error}"));
            return walk.outcome;
        }
    }
    while let Some((dir, depth)) = walk.pending.pop() {
        if let Err(why) = walk.dir(dir.as_fd(), depth) {
            walk.outcome.incomplete = Some(why);
            break;
        }
    }
    walk.outcome
}

/// One hand-over's walk: what it changes and the directories left to read.
struct Walk {
    device: rustix::fs::Dev,
    job: JobIdentity,
    engine: (u32, u32),
    until: Instant,
    outcome: HandOver,
    pending: Vec<(OwnedFd, usize)>,
}

impl Walk {
    /// One directory: changes each entry's ids and queues each directory
    /// beneath it on the same file system.
    fn dir(&mut self, dir: BorrowedFd<'_>, depth: usize) -> Result<(), String> {
        // Every name is read before any entry changes.
        let mut names: Vec<CString> = Vec::new();
        for entry in rustix::fs::Dir::read_from(dir).map_err(|error| error.to_string())? {
            let entry = entry.map_err(|error| error.to_string())?;
            let name = entry.file_name();
            if name != c"." && name != c".." {
                names.push(name.to_owned());
            }
        }
        for name in &names {
            self.outcome.seen += 1;
            if self.outcome.seen > HANDOVER_ENTRIES_MAX {
                return Err(format!("more than {HANDOVER_ENTRIES_MAX} entries"));
            }
            if self.outcome.seen % 256 == 0 && Instant::now() >= self.until {
                return Err(format!(
                    "the deadline came after {} entries",
                    self.outcome.seen
                ));
            }
            self.entry(dir, name, depth)?;
        }
        Ok(())
    }

    fn entry(&mut self, dir: BorrowedFd<'_>, name: &CStr, depth: usize) -> Result<(), String> {
        let found = match rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(found) => found,
            // Nothing of the job's runs any more, so only the engine could
            // have removed it: there is nothing to hand over.
            Err(rustix::io::Errno::NOENT) => return Ok(()),
            Err(error) => return Err(format!("{}: {error}", name.to_string_lossy())),
        };
        if found.st_dev != self.device {
            return Ok(());
        }
        let (uid, gid) = new_ids((found.st_uid, found.st_gid), self.job, self.engine);
        if uid.is_some() || gid.is_some() {
            change_ids(dir, name, uid, gid)?;
            self.outcome.changed += 1;
        }
        if FileType::from_raw_mode(found.st_mode) != FileType::Directory {
            return Ok(());
        }
        if depth + 1 > HANDOVER_DEPTH_MAX {
            return Err(format!(
                "{}: nested deeper than {HANDOVER_DEPTH_MAX} directories",
                name.to_string_lossy()
            ));
        }
        match rustix::fs::openat2(
            dir,
            name,
            DIR_FLAGS,
            Mode::empty(),
            ResolveFlags::NO_XDEV | ResolveFlags::NO_SYMLINKS,
        ) {
            Ok(inner) => self.pending.push((inner, depth + 1)),
            // A mount at it: what is beneath is another file system's.
            Err(rustix::io::Errno::XDEV) => {}
            Err(error) => return Err(format!("{}: {error}", name.to_string_lossy())),
        }
        Ok(())
    }
}

/// Changes `name`'s owner and group in `dir`, the link itself for a symbolic
/// link.
fn change_ids(
    dir: BorrowedFd<'_>,
    name: &CStr,
    uid: Option<u32>,
    gid: Option<u32>,
) -> Result<(), String> {
    // SAFETY: name is NUL terminated; -1 (u32::MAX) keeps an id as it is, and
    // AT_SYMLINK_NOFOLLOW changes a link itself.
    let answer = unsafe {
        libc::fchownat(
            dir.as_raw_fd(),
            name.as_ptr(),
            uid.unwrap_or(u32::MAX),
            gid.unwrap_or(u32::MAX),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if answer != 0 {
        return Err(format!(
            "{}: {}",
            name.to_string_lossy(),
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const JOB: JobIdentity = JobIdentity::of(1_879_048_192);
    const ENGINE: (u32, u32) = (970, 971);

    #[test]
    fn only_the_jobs_own_ids_become_the_engines() {
        assert_eq!(
            new_ids((JOB.uid, JOB.gid), JOB, ENGINE),
            (Some(970), Some(971))
        );
        // An engine-owned entry of the job's group (out, tmp and log are made
        // so) gets the engine's group alone.
        assert_eq!(new_ids((970, JOB.gid), JOB, ENGINE), (None, Some(971)));
        // Another account's entry keeps both.
        assert_eq!(new_ids((0, 0), JOB, ENGINE), (None, None));
        assert_eq!(new_ids((1000, 1000), JOB, ENGINE), (None, None));
    }

    #[test]
    fn a_walk_of_entries_no_job_owns_changes_nothing_and_is_complete() {
        let dir = std::env::temp_dir().join(format!("handover-test-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("a/b")).expect("tree");
        std::fs::write(dir.join("a/b/file"), b"x").expect("file");
        let fd = rustix::fs::open(&dir, DIR_FLAGS, Mode::empty()).expect("open");
        let outcome = hand_over(fd.as_fd(), JOB, ENGINE, Duration::from_secs(5));
        std::fs::remove_dir_all(&dir).expect("cleanup");
        assert_eq!(outcome.incomplete, None);
        assert_eq!(outcome.changed, 0);
        assert_eq!(outcome.seen, 3);
    }
}
