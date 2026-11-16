//! The syscall recorder, for a trace run only (`--cfg oneiron_test_support`,
//! never a cargo feature; FIX [ORGAN-SECCOMP-ALLOW-LIST]). With
//! `ONEIRON_SYSCALL_TRACE` naming a file, every organ this process starts
//! runs under a recording filter in place of its allow-list: a call
//! [`super::syscall_filter`] denies still kills it, and every other call
//! waits at the filter until this process's recorder answers it. The
//! recorder appends `SYSCALL <organ> <number>` to the file the first time it
//! sees an organ make a call, and lets the call go on
//! (`SECCOMP_USER_NOTIF_FLAG_CONTINUE`). The organs' allow-lists are traced
//! this way on the fleet, through each organ's own suites: the calls of the
//! exec, the loader and the runtime start are in the trace, since the child
//! installs the filter before it execs.
//!
//! The child installs the recording filter with a new listener and sends the
//! listener over a socket made before the fork, the bootstrap socket. That
//! one `sendmsg` is the only call the filter lets through unrecorded, and
//! the socket closes at exec. The recorder's thread starts before the
//! spawn: every call after the install, the exec itself included, waits for
//! its answer.

use std::collections::HashSet;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock, PoisonError};

/// The environment variable that makes this process a trace run: the file
/// its organs' calls are appended to.
const TRACE_FILE_ENV: &str = "ONEIRON_SYSCALL_TRACE";

/// The file this process's organs' calls are appended to, when it is a
/// trace run.
pub(super) fn trace_file() -> Option<PathBuf> {
    std::env::var_os(TRACE_FILE_ENV)
        .filter(|file| !file.is_empty())
        .map(PathBuf::from)
}

/// Starts the recorder of the organ `organ` is about to start, appending to
/// `file`. Returns the child's end of the bootstrap socket: the start holds
/// it until the child has exec'd, and the recorder ends when the listener
/// never comes.
///
/// # Errors
/// The bootstrap socket or the recorder's thread could not be made.
pub(super) fn start(organ: &str, file: PathBuf) -> io::Result<UnixStream> {
    let (ours, theirs) = UnixStream::pair()?;
    let organ = organ.to_owned();
    std::thread::Builder::new()
        .name(format!("syscall-trace-{organ}"))
        .spawn(move || {
            let listener = received_listener(&ours);
            drop(ours);
            if let Ok(listener) = listener {
                record(&organ, &file, &listener);
            }
        })?;
    Ok(theirs)
}

/// The listener the child sends over the bootstrap socket.
fn received_listener(stream: &UnixStream) -> io::Result<OwnedFd> {
    let mut byte = [0_u8];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let mut control = [0_usize; 8];
    // SAFETY: recvmsg writes only into the live buffers given here; a
    // descriptor it receives (SCM_RIGHTS) is this process's own.
    unsafe {
        let mut message: libc::msghdr = std::mem::zeroed();
        message.msg_iov = &raw mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = std::mem::size_of_val(&control);
        if libc::recvmsg(stream.as_raw_fd(), &raw mut message, libc::MSG_CMSG_CLOEXEC) != 1
            || message.msg_flags & libc::MSG_CTRUNC != 0
        {
            return Err(io::Error::other("the child sent no seccomp listener"));
        }
        let header = libc::CMSG_FIRSTHDR(&raw const message);
        if header.is_null()
            || (*header).cmsg_level != libc::SOL_SOCKET
            || (*header).cmsg_type != libc::SCM_RIGHTS
            || (*header).cmsg_len
                != libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as u32) as usize
        {
            return Err(io::Error::other("the child sent no seccomp listener"));
        }
        Ok(OwnedFd::from_raw_fd(std::ptr::read_unaligned(
            libc::CMSG_DATA(header).cast::<libc::c_int>(),
        )))
    }
}

/// Answers every call of the organ's processes on `listener` with
/// "continue", noting each, until no process under the filter is left.
fn record(organ: &str, file: &Path, listener: &OwnedFd) {
    let fd = listener.as_raw_fd();
    loop {
        let mut ready = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll(2) over one pollfd on this stack.
        if unsafe { libc::poll(&raw mut ready, 1, -1) } < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return;
        }
        if ready.revents & libc::POLLIN == 0 {
            // POLLHUP: every process under the filter has ended.
            return;
        }
        // SAFETY: an all-zero seccomp_notif is what the kernel takes.
        let mut call: libc::seccomp_notif = unsafe { std::mem::zeroed() };
        // SAFETY: the ioctl fills the seccomp_notif on this stack.
        if unsafe { libc::ioctl(fd, libc::SECCOMP_IOCTL_NOTIF_RECV, &raw mut call) } < 0 {
            // The caller died before its call was read, or a signal came.
            continue;
        }
        note(organ, file, call.data.nr);
        let answer = libc::seccomp_notif_resp {
            id: call.id,
            val: 0,
            error: 0,
            flags: libc::SECCOMP_USER_NOTIF_FLAG_CONTINUE as u32,
        };
        // SAFETY: the ioctl reads the seccomp_notif_resp on this stack. A
        // caller that died meanwhile fails it, which changes nothing.
        unsafe {
            libc::ioctl(fd, libc::SECCOMP_IOCTL_NOTIF_SEND, &raw const answer);
        }
    }
}

/// Appends `SYSCALL <organ> <number>` to `file` the first time this
/// process sees `organ` make call `number`.
fn note(organ: &str, file: &Path, number: libc::c_int) {
    static SEEN: OnceLock<Mutex<HashSet<(String, libc::c_int)>>> = OnceLock::new();
    let mut seen = SEEN
        .get_or_init(Mutex::default)
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    if seen.insert((organ.to_owned(), number))
        && let Ok(mut out) = OpenOptions::new().create(true).append(true).open(file)
    {
        let _ = writeln!(out, "SYSCALL {organ} {number}");
    }
}
