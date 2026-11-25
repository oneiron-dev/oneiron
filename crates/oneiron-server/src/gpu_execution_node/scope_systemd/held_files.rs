//! Files a job unit's processes hold after their last name is gone (review
//! r12 R12-01 of #10512): a job may open a file in its payload, remove its
//! name and go on writing to it. No walk of the payload's names sees such a
//! file, yet it holds blocks on the payload's filesystem until its last
//! holder closes it. Root's measure (`usage`) adds them: for each process in
//! the unit's control group, each open descriptor (`/proc/<pid>/fd`) and
//! each mapped file (`/proc/<pid>/map_files`) that is a regular file on the
//! payload's device with no name left, each file once.

use std::collections::HashSet;
use std::io;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::time::Instant;

/// The cgroup file system's mount point.
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// The deepest child control group read beneath the unit's own: the job
/// unit delegates none, so its processes sit in its own group.
const CHILD_GROUP_DEPTH_MAX: usize = 8;

/// The unit of `st_blocks`.
const BLOCK_BYTES: u64 = 512;

/// The bytes on device `payload_device` that files with no name left hold
/// for the processes of control group `control_group` (as `systemctl show`
/// names it, from the cgroup root; empty when the unit runs none), counted
/// until `deadline`.
///
/// # Errors
///
/// The control group or a process's descriptor table could not be read
/// (other than a process that has just ended), or the deadline passed.
pub fn unlinked_held_bytes(
    control_group: &str,
    payload_device: u64,
    deadline: Instant,
) -> Result<u64, String> {
    let control_group = control_group.trim_start_matches('/');
    if control_group.is_empty() {
        return Ok(0);
    }
    let mut pids = Vec::new();
    group_processes(&Path::new(CGROUP_ROOT).join(control_group), 0, &mut pids)?;
    let mut counted = HashSet::new();
    let mut bytes: u64 = 0;
    for pid in pids {
        for table in ["fd", "map_files"] {
            let dir = PathBuf::from(format!("/proc/{pid}/{table}"));
            let entries = match std::fs::read_dir(&dir) {
                Ok(entries) => entries,
                // The process ended since the control group was read.
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(format!("{}: {error}", dir.display())),
            };
            for entry in entries {
                if Instant::now() > deadline {
                    return Err("held files not counted in time".to_owned());
                }
                let Ok(entry) = entry else {
                    continue;
                };
                // The link names the open file; its stat follows it, also
                // to a file with no name left. A descriptor closed since
                // the listing, a pipe or a socket counts nothing.
                let Ok(file) = std::fs::metadata(entry.path()) else {
                    continue;
                };
                if !file.is_file() || file.nlink() != 0 || file.dev() != payload_device {
                    continue;
                }
                if counted.insert((file.dev(), file.ino())) {
                    bytes = bytes.saturating_add(file.blocks().saturating_mul(BLOCK_BYTES));
                }
            }
        }
    }
    Ok(bytes)
}

/// The process ids of the control group at `dir` and of its children, to
/// [`CHILD_GROUP_DEPTH_MAX`] levels.
fn group_processes(dir: &Path, depth: usize, pids: &mut Vec<u32>) -> Result<(), String> {
    let procs = dir.join("cgroup.procs");
    let text = match std::fs::read_to_string(&procs) {
        Ok(text) => text,
        // The unit's group went with its last process.
        Err(error) if error.kind() == io::ErrorKind::NotFound && depth == 0 => return Ok(()),
        Err(error) => return Err(format!("{}: {error}", procs.display())),
    };
    pids.extend(
        text.lines()
            .filter_map(|line| line.trim().parse::<u32>().ok()),
    );
    if depth >= CHILD_GROUP_DEPTH_MAX {
        return Ok(());
    }
    let children = std::fs::read_dir(dir).map_err(|error| format!("{}: {error}", dir.display()))?;
    for child in children.flatten() {
        if child.file_type().is_ok_and(|kind| kind.is_dir()) {
            group_processes(&child.path(), depth + 1, pids)?;
        }
    }
    Ok(())
}
