//! Descriptor and kernel-event operations before the child has a runtime.
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;

pub(crate) fn socket_pair() -> io::Result<(UnixStream, UnixStream)> {
    let (a, b) = UnixStream::pair()?;
    Ok((socket(a)?, socket(b)?))
}

fn socket(stream: UnixStream) -> io::Result<UnixStream> {
    let stream = if stream.as_raw_fd() < 3 {
        // SAFETY: duplicates our socket above stdio; the original closes on drop.
        let fd = unsafe { libc::fcntl(stream.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fcntl returned this new, exclusively owned socket descriptor.
        unsafe { UnixStream::from_raw_fd(fd) }
    } else {
        stream
    };
    let enabled: libc::c_int = 1;
    // SAFETY: the socket and the integer option buffer are valid for this call.
    let rc = unsafe {
        libc::setsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_NOSIGPIPE,
            (&enabled as *const libc::c_int).cast(),
            std::mem::size_of_val(&enabled) as _,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    cloexec(stream.as_raw_fd())?;
    Ok(stream)
}

pub(crate) fn cloexec(fd: RawFd) -> io::Result<()> {
    // SAFETY: only reads and changes this owned descriptor's exec flag.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd was checked above and is retained by the caller.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(crate) fn placements(ours: &[RawFd]) -> Vec<(RawFd, RawFd)> {
    let mut next = 3;
    ours.iter()
        .map(|&source| {
            while ours.contains(&next) {
                next += 1;
            }
            let pair = (source, next);
            next += 1;
            pair
        })
        .collect()
}

/// Waits for readable data, EOF or an error. Interrupted waits are retried.
pub(crate) fn readable(fds: &[RawFd]) -> io::Result<Vec<bool>> {
    let mut polls: Vec<_> = fds
        .iter()
        .map(|&fd| libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        })
        .collect();
    loop {
        // SAFETY: polls is writable for its stated length; -1 has no timeout.
        let rc = unsafe { libc::poll(polls.as_mut_ptr(), polls.len() as _, -1) };
        if rc >= 0 {
            return Ok(polls.iter().map(|p| p.revents != 0).collect());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

pub(crate) struct ProcessEvent(OwnedFd);

impl ProcessEvent {
    /// The caller still owns the unreaped process while attaching this event.
    pub(crate) fn attach(pid: libc::pid_t) -> io::Result<Self> {
        // SAFETY: creates a fresh kernel event queue.
        let fd = unsafe { libc::kqueue() };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: kqueue returned an exclusively owned descriptor.
        let queue = Self(unsafe { OwnedFd::from_raw_fd(fd) });
        cloexec(fd)?;
        let change = libc::kevent {
            ident: pid as _,
            filter: libc::EVFILT_PROC,
            flags: libc::EV_ADD | libc::EV_ONESHOT | libc::EV_RECEIPT,
            fflags: libc::NOTE_EXIT,
            data: 0,
            udata: std::ptr::null_mut(),
        };
        let mut receipt = change;
        let zero = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        loop {
            // SAFETY: both event buffers contain one initialized kevent.
            let rc = unsafe { libc::kevent(fd, &change, 1, &mut receipt, 1, &zero) };
            if rc < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if rc != 1 {
                return Err(io::Error::other("missing process-event receipt"));
            }
            if receipt.flags & libc::EV_ERROR != 0 && receipt.data != 0 {
                return Err(io::Error::from_raw_os_error(receipt.data as _));
            }
            return Ok(queue);
        }
    }

    pub(crate) fn fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }

    pub(crate) fn exited(&self) -> io::Result<bool> {
        let mut event = libc::kevent {
            ident: 0,
            filter: 0,
            flags: 0,
            fflags: 0,
            data: 0,
            udata: std::ptr::null_mut(),
        };
        let zero = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        loop {
            // SAFETY: one initialized output event, no input changes.
            let rc = unsafe { libc::kevent(self.fd(), std::ptr::null(), 0, &mut event, 1, &zero) };
            if rc < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if rc == 0 {
                return Ok(false);
            }
            if event.flags & libc::EV_ERROR != 0 {
                return Err(io::Error::from_raw_os_error(event.data as _));
            }
            return Ok(event.filter == libc::EVFILT_PROC && event.fflags & libc::NOTE_EXIT != 0);
        }
    }
}

pub(crate) struct ParentEvent {
    event: Option<ProcessEvent>,
    dead: bool,
}

impl ParentEvent {
    pub(crate) fn attach(original: libc::pid_t) -> io::Result<Self> {
        // SAFETY: getppid has no arguments and never fails.
        if unsafe { libc::getppid() } != original {
            return Ok(Self {
                event: None,
                dead: true,
            });
        }
        let event = ProcessEvent::attach(original);
        // Do not attach a recycled original pid if our actual parent changed.
        // SAFETY: the same always-successful parent identity query.
        if unsafe { libc::getppid() } != original {
            return Ok(Self {
                event: None,
                dead: true,
            });
        }
        Ok(Self {
            event: Some(event?),
            dead: false,
        })
    }

    pub(crate) fn dead(&mut self) -> io::Result<bool> {
        if let Some(event) = &self.event {
            self.dead |= event.exited()?;
        }
        Ok(self.dead)
    }

    pub(crate) fn fd(&self) -> RawFd {
        self.event.as_ref().map_or(-1, ProcessEvent::fd)
    }
}

pub(crate) fn term_own_group() -> io::Result<()> {
    // SAFETY: zero means this process's own, membership-anchored group.
    if unsafe { libc::kill(0, libc::SIGTERM) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
