//! An inherited descriptor proven the pipe end a flag promises, before the
//! command reads or writes it: a cold restore's input and result pipes
//! (FIX 6580) and the custody anchor door's owner credential (FIX 11068).
//!
//! A named FIFO has a pipe's type, so its type alone passes it; on Linux
//! `fstatfs` tells the pipe the kernel made, on pipefs, from a node standing
//! on the filesystem that holds it. Elsewhere the type and the access mode
//! are the whole proof.

use std::os::fd::{BorrowedFd, RawFd};

/// The filesystem magic `fstatfs` reads for a pipe the kernel made, on
/// pipefs; a named FIFO reads the magic of the filesystem its node is on.
#[cfg(target_os = "linux")]
const PIPEFS_MAGIC: u64 = 0x5049_5045;

/// Whether `fd` is the read end (`write` false) or the write end of a pipe,
/// told from its type, on Linux its pipefs (FIX 6580), and its access mode
/// before it is read or written; why not otherwise. A file, socket or tty is
/// neither end, and on Linux neither is a named FIFO.
pub(crate) fn pipe_end(fd: RawFd, write: bool) -> Result<(), &'static str> {
    use rustix::fs::{FileType, OFlags};
    if fd < 0 {
        return Err("it is not a file descriptor");
    }
    // SAFETY: `fd` is an open descriptor this process holds, handed on argv
    // or owned by a `File` that outlives this call: nothing closes or reuses
    // the number while it is borrowed here.
    let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
    let stat = rustix::fs::fstat(borrowed).map_err(|_| "it is not an open descriptor")?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Fifo {
        return Err("it is not a pipe");
    }
    #[cfg(target_os = "linux")]
    if !rustix::fs::fstatfs(borrowed).is_ok_and(|fs| u64::try_from(fs.f_type) == Ok(PIPEFS_MAGIC)) {
        return Err("it is not an anonymous pipe");
    }
    let mode = rustix::fs::fcntl_getfl(borrowed).map_err(|_| "its access mode did not read")?
        & OFlags::ACCMODE;
    match (write, mode == OFlags::WRONLY, mode == OFlags::RDONLY) {
        (true, true, _) | (false, _, true) => Ok(()),
        (true, ..) => Err("it is not a pipe's write end"),
        (false, ..) => Err("it is not a pipe's read end"),
    }
}
