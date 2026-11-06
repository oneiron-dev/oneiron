use std::{
    io::{self, Read, Write},
    os::fd::AsRawFd,
};

pub(super) struct SocketIo<'a, S> {
    pub socket: &'a S,
    pub waiting: &'a dyn Fn() -> bool,
}

pub(super) fn wait(fd: i32, events: i16, waiting: &dyn Fn() -> bool) -> io::Result<()> {
    loop {
        if !waiting() {
            return Err(io::Error::from_raw_os_error(libc::EINTR));
        }
        let mut poll = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        // SAFETY: poll names one live descriptor and a writable pollfd.
        let result = unsafe { libc::poll(&mut poll, 1, super::POLL_MS) };
        if result > 0 {
            return Ok(());
        }
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }
}

pub(super) fn hung_up(fd: i32) -> bool {
    let mut poll = libc::pollfd {
        fd,
        events: 0,
        revents: 0,
    };
    // SAFETY: poll names one live descriptor and does not wait.
    unsafe { libc::poll(&mut poll, 1, 0) > 0 && poll.revents & libc::POLLHUP != 0 }
}

pub(super) fn shutdown(fd: i32, how: i32) {
    // SAFETY: this only shuts down the caller-owned connected socket.
    let _ = unsafe { libc::shutdown(fd, how) };
}

impl<S: AsRawFd> Read for SocketIo<'_, S>
where
    for<'a> &'a S: Read,
{
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        loop {
            if !(self.waiting)() {
                return Err(io::Error::from_raw_os_error(libc::EINTR));
            }
            match self.socket.read(bytes) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    wait(self.socket.as_raw_fd(), libc::POLLIN, self.waiting)?;
                }
                result => return result,
            }
        }
    }
}

impl<S: AsRawFd> Write for SocketIo<'_, S>
where
    for<'a> &'a S: Write,
{
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        loop {
            if !(self.waiting)() {
                return Err(io::Error::from_raw_os_error(libc::EINTR));
            }
            match self.socket.write(bytes) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    wait(self.socket.as_raw_fd(), libc::POLLOUT, self.waiting)?;
                }
                result => return result,
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
