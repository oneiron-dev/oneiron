//! Files a job unit's tasks hold after their last name is gone (review r12
//! R12-01 and r13 R13-01..R13-04, R13-10 of #10512): a job may open a file
//! in its payload, remove its name and go on writing to it. No walk of the
//! payload's names sees such a file, yet it holds blocks on the payload's
//! filesystem until its last holder lets it go. Root's measure (`usage`)
//! adds them after the walk.
//!
//! For each task (thread) in the unit's control group (`cgroup.threads`, so
//! a thread with its own descriptor table, or one whose thread-group leader
//! has ended, is read too), the scan follows each open descriptor
//! (`/proc/<tid>/fd`), each mapped file (`/proc/<tid>/map_files`), the
//! executable its address space runs (`/proc/<tid>/exe`, r14 R14-02), and
//! the task's working and root directories. It reads a descriptor table or
//! an address space that another task of the scan shares only once
//! (`kcmp`), and trusts that comparison only while the task it compared
//! with is the same one (its start time, r14 R14-13). A link counts when it
//! names an inode with no name left, on a device the payload's walk met,
//! owned by the job's own uid: a shared host file that is replaced while a
//! job still maps it is not the job's (R13-03). A removed directory that a
//! task still holds counts too. Each inode counts once, across the walk and
//! this scan (R13-01, R14-01). A task of the unit's group whose tables the
//! handler cannot find, though the group still lists it (procfs `hidepid`,
//! a handler without `CAP_SYS_PTRACE`), makes the scan an error, not a
//! smaller count (r14 R14-07).
//!
//! The scan is a lower bound, not complete accounting: a reference the
//! kernel holds outside every task's tables (a descriptor in flight in a
//! socket message) is not seen, nor a held file on a device the walk did
//! not meet (an overlay layer's, with `xino=off`, under a payload that
//! names no file there, r14 R14-08). A filesystem quota per payload is the
//! complete mechanism (FIX EXEC-NODE-PAYLOAD-QUOTA).

use std::collections::HashSet;
use std::io;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::time::Instant;

use super::super::jobs::PayloadUsage;

/// The cgroup file system's mount point.
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// The deepest child control group read beneath the unit's own: the job
/// unit delegates none, so its tasks sit in its own group.
const CHILD_GROUP_DEPTH_MAX: usize = 8;

/// The unit of `st_blocks`.
const BLOCK_BYTES: u64 = 512;

/// The most distinct descriptor tables (and address spaces) the scan
/// compares a task's with. Past it a task's table is read without the
/// comparison: the count stays right (each inode once), only slower.
const SHARED_TABLES_COMPARED_MAX: usize = 64;

/// `kcmp`'s kinds (`linux/kcmp.h`).
const KCMP_VM: libc::c_int = 1;
const KCMP_FILES: libc::c_int = 2;

/// What one scan looks at, and within what.
#[derive(Debug, Clone)]
pub struct HeldScan<'a> {
    /// The unit's control group as `systemctl show` names it, from the
    /// cgroup root; empty when the unit runs no task.
    pub control_group: &'a str,
    /// The devices the payload's walk met (the payload's own, a btrfs
    /// subvolume's, an overlay layer's): only inodes on one of them count
    /// (review r14 R14-08).
    pub payload_devices: &'a HashSet<u64>,
    /// The job's own uid: only inodes it owns count.
    pub job_uid: u32,
    /// The measure's deadline, the walk's included.
    pub deadline: Instant,
    /// The most links the scan follows, a bound of its own beside the
    /// walk's entry bound (review r14 R14-10). A unit whose tasks hold more
    /// is unmeasurable, as a payload with more entries than the walk's
    /// bound.
    pub links_max: u64,
}

/// Adds to `walked` (the walk's bytes, whose non-directory inodes are in
/// `counted`) the bytes the unit's tasks hold in inodes with no name left,
/// and answers as the walk does: [`PayloadUsage::Past`] once the sum passes
/// `stop_past`, even when that is found after the deadline (a known excess
/// is never thrown away, R13-04); [`PayloadUsage::Unmeasurable`] past
/// [`HeldScan::links_max`]; else [`PayloadUsage::Measured`], only within
/// the deadline.
///
/// # Errors
///
/// The control group, a task's table or a link could not be read for a
/// reason other than a task or a descriptor that has just gone (a denied
/// read is no measure, R13-10), a task the group still lists had no tables
/// to read (R14-07), or the deadline passed first.
pub fn add_unlinked_held(
    scan: &HeldScan<'_>,
    counted: &mut HashSet<(u64, u64)>,
    walked: u64,
    stop_past: u64,
) -> Result<PayloadUsage, String> {
    let mut held = HeldCount {
        scan,
        counted,
        bytes: walked,
        stop_past,
        links: 0,
    };
    if let Some(done) = held.scan_tasks()? {
        return Ok(done);
    }
    held.in_time()?;
    Ok(PayloadUsage::Measured { bytes: held.bytes })
}

struct HeldCount<'scan, 'set> {
    scan: &'scan HeldScan<'scan>,
    counted: &'set mut HashSet<(u64, u64)>,
    bytes: u64,
    stop_past: u64,
    links: u64,
}

impl HeldCount<'_, '_> {
    fn in_time(&self) -> Result<(), String> {
        if Instant::now() > self.scan.deadline {
            Err(format!(
                "held files not counted in time ({} links read)",
                self.links
            ))
        } else {
            Ok(())
        }
    }

    /// Every task's tables; `Some` once the answer is known early.
    fn scan_tasks(&mut self) -> Result<Option<PayloadUsage>, String> {
        let group = self.scan.control_group.trim_start_matches('/');
        if group.is_empty() {
            return Ok(None);
        }
        let group_dir = Path::new(CGROUP_ROOT).join(group);
        let mut tasks = Vec::new();
        group_tasks(&group_dir, 0, self.scan.deadline, &mut tasks)?;
        let mut files_tables: Vec<Representative> = Vec::new();
        let mut address_spaces: Vec<Representative> = Vec::new();
        // Tasks with a table not found: gone, or hidden from the handler.
        let mut not_found: Vec<u32> = Vec::new();
        for task in tasks {
            self.in_time()?;
            if first_of_its_kind(task, &mut files_tables, KCMP_FILES) {
                match self.read_links(&format!("/proc/{task}/fd"))? {
                    Links::Done(done) => return Ok(Some(done)),
                    Links::NotFound => not_found.push(task),
                    Links::Read => {}
                }
            }
            if first_of_its_kind(task, &mut address_spaces, KCMP_VM) {
                match self.read_links(&format!("/proc/{task}/map_files"))? {
                    Links::Done(done) => return Ok(Some(done)),
                    Links::NotFound => not_found.push(task),
                    Links::Read => {}
                }
                // The executable the address space runs is held by it
                // (`mm->exe_file`) even with no mapping of it left (review
                // r14 R14-02).
                if let Some(done) = self.follow(&PathBuf::from(format!("/proc/{task}/exe")))? {
                    return Ok(Some(done));
                }
            }
            // A removed directory a task still works in, or roots at.
            for link in ["cwd", "root"] {
                if let Some(done) = self.follow(&PathBuf::from(format!("/proc/{task}/{link}")))? {
                    return Ok(Some(done));
                }
            }
        }
        // A task that ended has left its group; one the group still lists
        // is hidden from the handler, and its files are not counted (review
        // r14 R14-07).
        if !not_found.is_empty() {
            let mut listed = Vec::new();
            group_tasks(&group_dir, 0, self.scan.deadline, &mut listed)?;
            if let Some(hidden) = not_found.iter().find(|task| listed.contains(task)) {
                return Err(format!(
                    "task {hidden} is in the unit's group, but the handler finds no tables of it in /proc (hidepid, or no CAP_SYS_PTRACE)"
                ));
            }
        }
        Ok(None)
    }

    /// Every link in the table directory `dir`.
    fn read_links(&mut self, dir: &str) -> Result<Links, String> {
        let entries = match std::fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(error) if gone(&error) => return Ok(Links::NotFound),
            Err(error) => return Err(format!("{dir}: {error}")),
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) if gone(&error) => return Ok(Links::NotFound),
                Err(error) => return Err(format!("{dir}: {error}")),
            };
            if let Some(done) = self.follow(&entry.path())? {
                return Ok(Links::Done(done));
            }
        }
        Ok(Links::Read)
    }

    /// Charges one link and counts the inode it names when it is the job's
    /// and has no name left.
    fn follow(&mut self, link: &Path) -> Result<Option<PayloadUsage>, String> {
        self.links = self.links.saturating_add(1);
        if self.links > self.scan.links_max {
            return Ok(Some(PayloadUsage::Unmeasurable {
                why: format!(
                    "more than {} open files, mappings and directories held",
                    self.scan.links_max
                ),
            }));
        }
        self.in_time()?;
        // The link names the open file; its stat follows it, also to an
        // inode with no name left. A pipe or a socket is on no payload
        // device.
        let file = match std::fs::metadata(link) {
            Ok(file) => file,
            Err(error) if gone(&error) => return Ok(None),
            Err(error) => return Err(format!("{}: {error}", link.display())),
        };
        if file.nlink() != 0
            || !self.scan.payload_devices.contains(&file.dev())
            || file.uid() != self.scan.job_uid
        {
            return Ok(None);
        }
        if self.counted.insert((file.dev(), file.ino())) {
            self.bytes = self
                .bytes
                .saturating_add(file.blocks().saturating_mul(BLOCK_BYTES));
        }
        Ok((self.bytes > self.stop_past).then_some(PayloadUsage::Past { bytes: self.bytes }))
    }
}

/// What reading one table directory found.
enum Links {
    /// Every link in it was followed.
    Read,
    /// The directory was not found: its task ended, or is hidden.
    NotFound,
    /// The answer is known early.
    Done(PayloadUsage),
}

/// A task whose table the scan read, by its id and its start time: a
/// comparison with it is trusted only while that same task lives, since an
/// ended task's id can be given to a new one (review r14 R14-13).
#[derive(Debug, Clone, Copy)]
struct Representative {
    task: u32,
    started: u64,
}

/// Whether `error` says the task or the descriptor has just gone.
fn gone(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::NotFound || error.raw_os_error() == Some(libc::ESRCH)
}

/// Whether `task`'s table of `kind` is shared with none in `seen`; a first
/// one joins `seen`. A comparison the kernel does not answer, or one with a
/// task that has since ended (its start time is not the one seen), counts
/// as not shared: the table is read, and each inode still counts once.
fn first_of_its_kind(task: u32, seen: &mut Vec<Representative>, kind: libc::c_int) -> bool {
    // The start time is read after `kcmp`: the same task still living then
    // was the one compared, since a living task's id is its own.
    let shared = seen.iter().any(|other| {
        same_table(other.task, task, kind) && task_started(other.task) == Some(other.started)
    });
    if !shared
        && seen.len() < SHARED_TABLES_COMPARED_MAX
        && let Some(started) = task_started(task)
    {
        seen.push(Representative { task, started });
    }
    !shared
}

/// The start time of `task` (`/proc/<task>/stat`, field 22, in clock ticks
/// since boot); `None` once it is gone.
fn task_started(task: u32) -> Option<u64> {
    // Bytes, not text: the task's name, in parentheses before the fields,
    // may hold any byte a job gives it. The fields are counted from its
    // last `)`, the state (field 3) first.
    let stat = std::fs::read(format!("/proc/{task}/stat")).ok()?;
    let after_name = stat.get(stat.iter().rposition(|&byte| byte == b')')? + 1..)?;
    std::str::from_utf8(after_name)
        .ok()?
        .split_ascii_whitespace()
        .nth(19)?
        .parse()
        .ok()
}

/// Whether tasks `a` and `b` share their table of `kind` (`kcmp(2)`).
fn same_table(a: u32, b: u32, kind: libc::c_int) -> bool {
    let (Ok(a), Ok(b)) = (libc::pid_t::try_from(a), libc::pid_t::try_from(b)) else {
        return false;
    };
    let none: libc::c_ulong = 0;
    // SAFETY: kcmp reads only its integer arguments; for these kinds the
    // last two are unused.
    let answer = unsafe { libc::syscall(libc::SYS_kcmp, a, b, kind, none, none) };
    answer == 0
}

/// The task ids of the control group at `dir` and of its children, to
/// [`CHILD_GROUP_DEPTH_MAX`] levels, read until `deadline`.
fn group_tasks(
    dir: &Path,
    depth: usize,
    deadline: Instant,
    tasks: &mut Vec<u32>,
) -> Result<(), String> {
    if Instant::now() > deadline {
        return Err("the unit's tasks not listed in time".to_owned());
    }
    let threads = dir.join("cgroup.threads");
    let text = match std::fs::read_to_string(&threads) {
        Ok(text) => text,
        // The unit's group went with its last task.
        Err(error) if error.kind() == io::ErrorKind::NotFound && depth == 0 => return Ok(()),
        Err(error) => return Err(format!("{}: {error}", threads.display())),
    };
    tasks.extend(
        text.lines()
            .filter_map(|line| line.trim().parse::<u32>().ok()),
    );
    if depth >= CHILD_GROUP_DEPTH_MAX {
        return Ok(());
    }
    let children = match std::fs::read_dir(dir) {
        Ok(children) => children,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("{}: {error}", dir.display())),
    };
    for child in children {
        let child = child.map_err(|error| format!("{}: {error}", dir.display()))?;
        if child.file_type().is_ok_and(|kind| kind.is_dir()) {
            group_tasks(&child.path(), depth + 1, deadline, tasks)?;
        }
    }
    Ok(())
}
