//! The launcher's inventory of the socket inodes its guest still holds
//! (FIX 5978). The supervisor keeps a host entry, and for a datagram socket
//! a writer thread, for each socket it brokered; it drops them once no
//! guest process holds the socket any more. Only the launcher can see that:
//! it reads every descriptor table of every live guest task in `/proc`.
//!
//! A guest process runs as the launcher's own uid and cannot leave it (it
//! holds no capability, and no new privileges keeps a setuid file from
//! granting one), so every live
//! process of that uid but the launcher is the guest: forks, orphans and
//! threads with descriptor tables of their own included, and the trusted
//! host or microVM supervisor, which holds its own end of each socket,
//! excluded. A duplicate or an inherited descriptor keeps its socket alive
//! wherever it sits. A scan that cannot read a table, or that sees a table
//! change under it or a task start during it, is incomplete: it is an
//! error, never an empty inventory.

use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// How often the launcher takes an inventory, once it brokered a socket.
pub(crate) const SOCKET_INVENTORY_EVERY: Duration = Duration::from_secs(1);

/// Every socket inode a live guest task holds now.
///
/// # Errors
///
/// An incomplete scan: a table it may not read, a descriptor that closed
/// while its task lived, or a task that started while it ran.
pub(crate) fn collect_guest_socket_inodes(launcher: u32) -> io::Result<BTreeSet<u64>> {
    let before = guest_tasks(launcher)?;
    let mut inodes = BTreeSet::new();
    for task in &before {
        task_sockets(task, &mut inodes)?;
    }
    // A task that began during the scan may hold a descriptor it inherited
    // from a parent that closed its own copy since.
    if !guest_tasks(launcher)?.is_subset(&before) {
        return Err(incomplete());
    }
    Ok(inodes)
}

/// The inode a `/proc/<pid>/fd/<n>` link names, when it is a socket.
pub(crate) fn socket_link_inode(target: &Path) -> Option<u64> {
    target
        .to_str()?
        .strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

/// Every task directory of every live guest process.
fn guest_tasks(launcher: u32) -> io::Result<BTreeSet<PathBuf>> {
    // SAFETY: getuid only reads this process's own credentials.
    let uid = unsafe { libc::getuid() };
    let mut tasks = BTreeSet::new();
    for entry in std::fs::read_dir("/proc")? {
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        if pid == launcher {
            continue;
        }
        let process = entry.path();
        let Some(status) = live(std::fs::read_to_string(process.join("status")))? else {
            continue;
        };
        if !guest_process(&status, uid) {
            continue;
        }
        let Some(listing) = live(std::fs::read_dir(process.join("task")))? else {
            continue;
        };
        for task in listing {
            tasks.insert(task?.path());
        }
    }
    Ok(tasks)
}

/// Whether a process status names a live process of `uid`. A zombie holds
/// no descriptor.
fn guest_process(status: &str, uid: u32) -> bool {
    let real_uid = status_field(status, "Uid:")
        .and_then(|ids| ids.split_whitespace().next())
        .and_then(|id| id.parse::<u32>().ok());
    let state = status_field(status, "State:").and_then(|state| state.chars().next());
    real_uid == Some(uid) && !matches!(state, Some('Z' | 'X'))
}

/// The value of one `name:` line of a process status.
fn status_field<'s>(status: &'s str, name: &str) -> Option<&'s str> {
    status
        .lines()
        .find_map(|line| line.strip_prefix(name))
        .map(str::trim)
}

/// Adds the socket inodes `task`'s descriptor table holds. A task that ended
/// holds nothing.
fn task_sockets(task: &Path, inodes: &mut BTreeSet<u64>) -> io::Result<()> {
    let Some(descriptors) = live(std::fs::read_dir(task.join("fd")))? else {
        return Ok(());
    };
    for descriptor in descriptors {
        match std::fs::read_link(descriptor?.path()) {
            Ok(target) => {
                if let Some(inode) = socket_link_inode(&target) {
                    inodes.insert(inode);
                }
            }
            // A descriptor that closed while its task lives may live on
            // under a number this listing did not see.
            Err(error) if gone(&error) && task.exists() => return Err(incomplete()),
            Err(error) if gone(&error) => return Ok(()),
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// `None` for what an exiting task no longer has.
fn live<T>(read: io::Result<T>) -> io::Result<Option<T>> {
    match read {
        Ok(value) => Ok(Some(value)),
        Err(error) if gone(&error) => Ok(None),
        Err(error) => Err(error),
    }
}

fn gone(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::NotFound || error.raw_os_error() == Some(libc::ESRCH)
}

fn incomplete() -> io::Error {
    io::Error::other("guest socket inventory incomplete")
}
