//! The opt-in Linux scratch mount and file-content write fence.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use super::Source;
use crate::machine::DiskFloor;

pub(super) fn directory(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

/// The engine retains the descriptor; an exec'd renderer need not retain it.
pub(super) fn pinned_path(directory: &File) -> PathBuf {
    PathBuf::from(format!(
        "/proc/{}/fd/{}",
        std::process::id(),
        directory.as_raw_fd()
    ))
}

pub(super) fn source(path: &Path, disk: &DiskFloor) -> io::Result<Source> {
    let pin = Arc::new(directory(path)?);
    let fs = rustix::fs::fstatfs(&*pin)?;
    let space = rustix::fs::fstatvfs(&*pin)?;
    let capacity = space
        .f_blocks
        .checked_mul(space.f_frsize)
        .filter(|bytes| *bytes > 0);
    if fs.f_type as u64 != libc::TMPFS_MAGIC as u64 || capacity.is_none() {
        return Err(io::Error::other(
            "renderer scratch must be a finite tmpfs mount",
        ));
    }
    let mount = mount_id(&pin)?;
    let inventory = std::fs::read_to_string("/proc/self/mountinfo")?;
    let noswap = inventory.lines().any(|line| {
        let Some((location, filesystem)) = line.split_once(" - ") else {
            return false;
        };
        if location
            .split_ascii_whitespace()
            .next()
            .and_then(|value| value.parse::<u64>().ok())
            != Some(mount)
        {
            return false;
        }
        let mut fields = filesystem.split_ascii_whitespace();
        fields.next() == Some("tmpfs")
            && fields
                .nth(1)
                .is_some_and(|options| options.split(',').any(|option| option == "noswap"))
    });
    if !noswap || mount_id(&pin)? != mount {
        return Err(io::Error::other(
            "renderer scratch mount does not report noswap",
        ));
    }
    if oneiron_container::landlock_abi() < 3 {
        return Err(io::Error::other(
            "configured renderer scratch requires Landlock ABI 3",
        ));
    }
    let spool = pinned_path(&pin);
    Ok(Source {
        disk: disk.on_shared_disk_of(spool.clone())?,
        spool,
        pin: Some(pin),
    })
}

fn mount_id(directory: &File) -> io::Result<u64> {
    let information =
        std::fs::read_to_string(format!("/proc/self/fdinfo/{}", directory.as_raw_fd()))?;
    information
        .lines()
        .find_map(|line| {
            line.strip_prefix("mnt_id:")
                .and_then(|value| value.trim().parse().ok())
        })
        .ok_or_else(|| io::Error::other("renderer scratch descriptor has no mount identity"))
}

pub(super) fn command(program: &Path, scratch: &Path) -> io::Result<Command> {
    // Keep the renderer's existing system/font/config reads. Only file-content
    // writes are fenced; unmediated metadata operations are not a quota proof.
    let ruleset =
        oneiron_container::landlock_ruleset(&[Path::new("/")], &[scratch, Path::new("/dev/null")])?;
    let program = std::fs::canonicalize(program)?;
    let mut command = oneiron_spawn::command(&program);
    command
        .current_dir(scratch)
        .env("TMPDIR", scratch)
        .env("TMP", scratch)
        .env("TEMP", scratch)
        .env("XDG_CACHE_HOME", scratch);
    // SAFETY: the native restrict helper makes only prctl/restrict_self calls
    // on the prebuilt descriptor. The earlier spawn hook marks inherited
    // nonstdio descriptors CLOEXEC; restriction happens before exec closes them.
    unsafe {
        command.pre_exec(move || oneiron_container::landlock_restrict(ruleset.as_fd()));
    }
    Ok(command)
}
