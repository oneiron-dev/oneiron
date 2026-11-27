//! The payload directory's ownership check (row R3c): the work directory's
//! path walked from `/`, each directory and symbolic link on it the engine's
//! or root's in a directory no other account renames in, before anything is
//! made, written or removed beneath it.

use std::fmt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use super::StagingRefusal;

/// The mode bits that let the group or other accounts write in a directory.
const GROUP_OTHER_WRITE: u32 = 0o022;

/// The sticky bit: in such a directory only an entry's owner renames it.
const STICKY: u32 = 0o1000;

/// The most symbolic links the work directory's path may pass through.
const WORK_PATH_LINKS_MAX: usize = 40;

/// Why a work directory or a component of its path is unsafe for staging.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkDirFault {
    /// The path does not start at `/`.
    NotAbsolute,
    /// The path component is not a directory.
    NotADirectory,
    /// A directory on the path belongs to neither root nor the engine.
    ForeignOwner {
        /// The directory owner's uid.
        uid: u32,
    },
    /// The group or other accounts can write in a non-sticky directory.
    OthersMayRename {
        /// The directory's mode bits.
        mode: u32,
    },
    /// A symbolic link belongs to neither root nor the engine.
    ForeignLink {
        /// The link owner's uid.
        uid: u32,
    },
    /// The path follows more symbolic links than staging allows.
    TooManyLinks,
    /// The resolved work directory does not belong to the engine.
    WorkDirNotEngines {
        /// The work directory owner's uid.
        uid: u32,
    },
    /// The group or other accounts can write in the resolved work directory.
    WorkDirOthersMayWrite {
        /// The work directory's mode bits.
        mode: u32,
    },
    /// The account the judgement is for may not make entries in the resolved
    /// work directory: it lacks write and search access there, so staging's
    /// mkdir of a key's payload directory fails (`checkout_failed`).
    EngineMayNotWrite,
    /// Reading a directory entry or symbolic link failed.
    Unreadable(String),
}

impl fmt::Display for WorkDirFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAbsolute => f.write_str("the path is not absolute"),
            Self::NotADirectory => f.write_str("not a directory"),
            Self::ForeignOwner { uid } => {
                write!(f, "owned by uid {uid}, neither root's nor the engine's")
            }
            Self::OthersMayRename { mode } => write!(
                f,
                "mode {mode:o}: the group or other accounts may write in it and it is not sticky"
            ),
            Self::ForeignLink { uid } => write!(
                f,
                "a symbolic link owned by uid {uid}, neither root's nor the engine's"
            ),
            Self::TooManyLinks => f.write_str("too many symbolic links"),
            Self::WorkDirNotEngines { uid } => write!(
                f,
                "the work directory is owned by uid {uid}, not the engine's"
            ),
            Self::WorkDirOthersMayWrite { mode } => write!(
                f,
                "mode {mode:o}: the group or other accounts may write in the work directory"
            ),
            Self::EngineMayNotWrite => {
                f.write_str("the engine may not make entries in it (no write and search access)")
            }
            Self::Unreadable(error) => f.write_str(error),
        }
    }
}

/// The path and reason for a work directory refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkDirUnsafe {
    /// The path at which the rule failed.
    pub path: PathBuf,
    /// Why the path failed the rule.
    pub fault: WorkDirFault,
}

/// The result of judging a work directory without making any changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkDirVerdict {
    /// The work directory passes. Holds the resolved directory.
    Passes(PathBuf),
    /// A component is missing. Everything before it passed.
    Missing {
        /// The first component that does not exist.
        first_missing: PathBuf,
        /// The judged account may write and search in `first_missing`'s parent,
        /// so staging makes the rest. False: staging's mkdir fails
        /// (`checkout_failed`) unless root makes the path first, as install does.
        engine_may_make: bool,
    },
    /// A path component or the work directory failed the rule.
    Unsafe(WorkDirUnsafe),
}

/// Judges the rule staging applies before a key's first write for the account
/// `engine_uid`, without making or changing anything, with this thread's own
/// file access, real IDs included. Check and install judge with the engine's
/// ([`work_dir_verdict_for`]).
pub fn work_dir_verdict(work_dir: &Path, engine_uid: u32) -> WorkDirVerdict {
    match walk_work_dir(work_dir, engine_uid, false) {
        Ok(Walked::Dir(dir)) if may_make_entries_in(&dir) => WorkDirVerdict::Passes(dir),
        Ok(Walked::Dir(dir)) => WorkDirVerdict::Unsafe(WorkDirUnsafe {
            path: dir,
            fault: WorkDirFault::EngineMayNotWrite,
        }),
        Ok(Walked::Missing(first_missing)) => WorkDirVerdict::Missing {
            engine_may_make: first_missing.parent().is_some_and(may_make_entries_in),
            first_missing,
        },
        Err(WalkFailed::Unsafe(unsafe_)) => WorkDirVerdict::Unsafe(unsafe_),
        Err(WalkFailed::MakeFailed) => unreachable!("the read-only walk does not make directories"),
    }
}

fn may_make_entries_in(dir: &Path) -> bool {
    use rustix::fs::{Access, access};

    // access(2) uses this thread's real uid, gid and groups. work_dir_verdict_for
    // walks only with the judged account's credentials, here or on its own thread.
    access(dir, Access::WRITE_OK | Access::EXEC_OK).is_ok()
}

/// The file access of the account a judgement is for: its uid, its primary
/// gid and its supplementary groups. For an installed unit, the groups come
/// from the group database and do not include the unit's `SupplementaryGroups=`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkDirAccess {
    /// The account's uid: the engine's.
    pub uid: u32,
    /// The account's primary gid.
    pub gid: u32,
    /// The account's supplementary groups.
    pub groups: Vec<u32>,
}

impl WorkDirAccess {
    /// Reads this process's effective uid and gid and its supplementary groups.
    ///
    /// # Errors
    ///
    /// The process's groups could not be read.
    pub fn this_process() -> Result<Self, String> {
        use rustix::process::{getegid, geteuid, getgroups};

        let mut groups: Vec<u32> = getgroups()
            .map_err(|error| format!("getgroups failed: {error}"))?
            .into_iter()
            .map(|gid| gid.as_raw())
            .collect();
        groups.sort_unstable();
        groups.dedup();
        Ok(Self {
            uid: geteuid().as_raw(),
            gid: getegid().as_raw(),
            groups,
        })
    }

    /// Compares uid, gid and group sets, counting the primary gid in each set.
    fn same_access(&self, other: &Self) -> bool {
        let group_set = |access: &Self| {
            let mut groups = access.groups.clone();
            groups.push(access.gid);
            groups.sort_unstable();
            groups.dedup();
            groups
        };
        self.uid == other.uid && self.gid == other.gid && group_set(self) == group_set(other)
    }
}

/// [`work_dir_verdict`] with `access`'s file access, the access staging has
/// in the engine. The walk runs here only if the real and effective IDs and
/// group set match `access`. The same uid alone does not imply the same file
/// access (review r2 of #10575). Otherwise, root runs the walk on a thread of
/// its own that first takes `access`'s groups, gid and uid; on Linux these are
/// the thread's own, so the rest of the process keeps root's, and the thread
/// ends with the walk.
///
/// # Errors
///
/// This process is not root and does not have `access`'s file access, its
/// groups could not be read, or the walk thread could not take that access.
pub fn work_dir_verdict_for(
    work_dir: &Path,
    access: &WorkDirAccess,
) -> Result<WorkDirVerdict, String> {
    use rustix::process::{getegid, geteuid, getgid, getuid};

    let euid = geteuid().as_raw();
    let egid = getegid().as_raw();
    let real_ids_match = getuid().as_raw() == euid && getgid().as_raw() == egid;
    if euid == 0 && (euid != access.uid || !real_ids_match) {
        return walk_with_access(work_dir, access);
    }
    if euid != access.uid {
        return Err(format!(
            "this process (uid {euid}) can take neither root's nor uid {}'s file access: \
             run it as root or as that account",
            access.uid
        ));
    }

    let mine = WorkDirAccess::this_process()?;
    if real_ids_match && mine.same_access(access) {
        return Ok(work_dir_verdict(work_dir, access.uid));
    }
    if euid == 0 {
        return walk_with_access(work_dir, access);
    }
    let ids_note = if real_ids_match {
        ""
    } else {
        "; real ids differ from effective ones"
    };
    Err(format!(
        "this process has uid {euid} but not its file access (gid {egid} and groups \
         {mine:?}, not gid {gid} and groups {theirs:?}{ids_note}): run it as root, or \
         as that account with its own groups",
        mine = mine.groups,
        gid = access.gid,
        theirs = access.groups,
    ))
}

#[cfg(target_os = "linux")]
fn walk_with_access(work_dir: &Path, access: &WorkDirAccess) -> Result<WorkDirVerdict, String> {
    use rustix::process::{Gid, Uid};

    let work_dir = work_dir.to_path_buf();
    let access = access.clone();
    std::thread::spawn(move || -> Result<WorkDirVerdict, String> {
        let groups: Vec<Gid> = access
            .groups
            .iter()
            .map(|gid| Gid::from_raw(*gid))
            .collect();
        let gid = Gid::from_raw(access.gid);
        let uid = Uid::from_raw(access.uid);
        // The uid goes last: once it is not root's, this thread can change
        // nothing else.
        rustix::thread::set_thread_groups(&groups)
            .and_then(|()| rustix::thread::set_thread_res_gid(gid, gid, gid))
            .and_then(|()| rustix::thread::set_thread_res_uid(uid, uid, uid))
            .map_err(|error| format!("could not take uid {}'s file access: {error}", access.uid))?;
        Ok(work_dir_verdict(&work_dir, access.uid))
    })
    .join()
    .map_err(|_| "the work directory judgement stopped".to_owned())?
}

#[cfg(not(target_os = "linux"))]
fn walk_with_access(_work_dir: &Path, access: &WorkDirAccess) -> Result<WorkDirVerdict, String> {
    Err(format!(
        "judging the work directory with uid {}'s file access needs Linux",
        access.uid
    ))
}

/// Whether the key's payload directory exists and is the engine's alone:
/// its work directory passes [`trusted_work_dir`], and it is a directory
/// (not a symbolic link) owned by the engine's account. With `make`, the
/// work directory's missing components and then the payload directory are
/// made (0755), each only once its parent passed. Path-based writes and
/// removals beneath it are then safe: no other account can change what the
/// path names.
pub(super) fn payload_dir_owned(payload_dir: &Path, make: bool) -> Result<bool, StagingRefusal> {
    let not_owned = |path: &Path, why: &str| {
        tracing::warn!(path = %path.display(), why, "job staging: the payload directory is not the engine's alone");
        StagingRefusal::WorkDirUnsafe
    };
    let (Some(work_dir), Some(name)) = (payload_dir.parent(), payload_dir.file_name()) else {
        return Err(not_owned(payload_dir, "it has no work directory"));
    };
    let Some(work_dir) = trusted_work_dir(work_dir, make)? else {
        return Ok(false);
    };
    let payload = work_dir.join(name);
    if make {
        match std::fs::DirBuilder::new().mode(0o755).create(&payload) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                tracing::warn!(payload_dir = %payload.display(), %error, "job staging: the payload directory was not made");
                return Err(StagingRefusal::CheckoutFailed);
            }
        }
    }
    let engine = rustix::process::geteuid().as_raw();
    match std::fs::symlink_metadata(&payload) {
        Ok(found) if found.is_dir() && found.uid() == engine => {}
        Ok(_) => {
            return Err(not_owned(
                &payload,
                "the payload directory is a link, not a directory, or not the engine's",
            ));
        }
        Err(error) if !make && error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(not_owned(&payload, &error.to_string())),
    }
    if make {
        // The job account passes through and reads; only the engine writes.
        std::fs::set_permissions(&payload, std::fs::Permissions::from_mode(0o755)).map_err(
            |error| {
                tracing::warn!(payload_dir = %payload.display(), %error, "job staging: the payload directory's mode was not set");
                StagingRefusal::CheckoutFailed
            },
        )?;
    }
    Ok(true)
}

/// Finds or makes the resolved work directory for staging, warning on refusal.
fn trusted_work_dir(work_dir: &Path, make: bool) -> Result<Option<PathBuf>, StagingRefusal> {
    match walk_work_dir(work_dir, rustix::process::geteuid().as_raw(), make) {
        Ok(Walked::Dir(dir)) => Ok(Some(dir)),
        Ok(Walked::Missing(_)) => Ok(None),
        Err(WalkFailed::Unsafe(unsafe_)) => {
            tracing::warn!(path = %unsafe_.path.display(), why = %unsafe_.fault, "job staging: the work directory is not the engine's alone");
            Err(StagingRefusal::WorkDirUnsafe)
        }
        Err(WalkFailed::MakeFailed) => Err(StagingRefusal::CheckoutFailed),
    }
}

enum Walked {
    Dir(PathBuf),
    Missing(PathBuf),
}

enum WalkFailed {
    Unsafe(WorkDirUnsafe),
    MakeFailed,
}

/// Walks `work_dir` from `/`. Each directory belongs to root or the engine
/// and is sticky or not writable by other accounts. Each symbolic link also
/// belongs to root or the engine and is followed from its checked parent.
/// With `make`, a missing component is made (0755) once its parent passed.
/// The work directory itself belongs to the engine and admits no group or
/// other writes, even if sticky.
fn walk_work_dir(work_dir: &Path, engine_uid: u32, make: bool) -> Result<Walked, WalkFailed> {
    let unsafe_at = |path: &Path, fault| {
        WalkFailed::Unsafe(WorkDirUnsafe {
            path: path.to_path_buf(),
            fault,
        })
    };
    let unreadable = |path: &Path, error: std::io::Error| {
        unsafe_at(path, WorkDirFault::Unreadable(error.to_string()))
    };
    if !work_dir.is_absolute() {
        return Err(unsafe_at(work_dir, WorkDirFault::NotAbsolute));
    }
    let owner_trusted = |found: &std::fs::Metadata| found.uid() == 0 || found.uid() == engine_uid;
    let directory_fault = |found: &std::fs::Metadata| {
        if !found.is_dir() {
            Some(WorkDirFault::NotADirectory)
        } else if !owner_trusted(found) {
            Some(WorkDirFault::ForeignOwner { uid: found.uid() })
        } else if found.mode() & GROUP_OTHER_WRITE != 0 && found.mode() & STICKY == 0 {
            Some(WorkDirFault::OthersMayRename {
                mode: found.mode() & 0o7777,
            })
        } else {
            None
        }
    };
    let mut current = PathBuf::from("/");
    let root = std::fs::symlink_metadata(&current).map_err(|error| unreadable(&current, error))?;
    if let Some(fault) = directory_fault(&root) {
        return Err(unsafe_at(&current, fault));
    }
    // The components still to walk, the next one last.
    let mut pending = Vec::new();
    push_components(&mut pending, work_dir);
    let mut links = 0;
    while let Some(name) = pending.pop() {
        let Some(name) = name else {
            // `current` was walked with no link in it, so its parent passed.
            current.pop();
            continue;
        };
        let next = current.join(&name);
        let found = match std::fs::symlink_metadata(&next) {
            Ok(found) => found,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if !make {
                    return Ok(Walked::Missing(next));
                }
                match std::fs::DirBuilder::new().mode(0o755).create(&next) {
                    // What another account made first is read below.
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => {
                        tracing::warn!(path = %next.display(), %error, "job staging: the work directory was not made");
                        return Err(WalkFailed::MakeFailed);
                    }
                }
                std::fs::symlink_metadata(&next).map_err(|error| unreadable(&next, error))?
            }
            Err(error) => return Err(unreadable(&next, error)),
        };
        if found.file_type().is_symlink() {
            links += 1;
            if !owner_trusted(&found) {
                return Err(unsafe_at(
                    &next,
                    WorkDirFault::ForeignLink { uid: found.uid() },
                ));
            }
            if links > WORK_PATH_LINKS_MAX {
                return Err(unsafe_at(&next, WorkDirFault::TooManyLinks));
            }
            let target = std::fs::read_link(&next).map_err(|error| unreadable(&next, error))?;
            if target.is_absolute() {
                current = PathBuf::from("/");
            }
            push_components(&mut pending, &target);
            continue;
        }
        if let Some(fault) = directory_fault(&found) {
            return Err(unsafe_at(&next, fault));
        }
        current = next;
    }
    let work = std::fs::symlink_metadata(&current).map_err(|error| unreadable(&current, error))?;
    if work.uid() != engine_uid {
        return Err(unsafe_at(
            &current,
            WorkDirFault::WorkDirNotEngines { uid: work.uid() },
        ));
    }
    if work.mode() & GROUP_OTHER_WRITE != 0 {
        return Err(unsafe_at(
            &current,
            WorkDirFault::WorkDirOthersMayWrite {
                mode: work.mode() & 0o7777,
            },
        ));
    }
    Ok(Walked::Dir(current))
}

/// Puts `path`'s components on `pending` so that its first is popped first:
/// a name, or `None` for `..`.
fn push_components(pending: &mut Vec<Option<std::ffi::OsString>>, path: &Path) {
    use std::path::Component;

    for component in path.components().rev() {
        match component {
            Component::Normal(name) => pending.push(Some(name.to_owned())),
            Component::ParentDir => pending.push(None),
            Component::RootDir | Component::CurDir | Component::Prefix(_) => {}
        }
    }
}
