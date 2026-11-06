use super::{
    bridge,
    io::{self, SocketIo},
};
use crate::{EgressRelay, HostNetPermit, LoopbackConnection};
use std::{
    fs::File,
    io::{Read, Write},
    net::SocketAddr,
    os::{
        fd::FromRawFd,
        unix::{ffi::OsStrExt, net::UnixStream},
    },
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

/// The current session's private VMM socket, token and original host floor.
pub struct HostEndpoint {
    endpoint: PathBuf,
    token: String,
    relay: Arc<dyn EgressRelay>,
    alive: Arc<AtomicBool>,
}

impl HostEndpoint {
    /// The caller retains the directory descriptor named by `endpoint` for
    /// the whole endpoint lifetime, including during this method's calls.
    pub fn new(
        endpoint: PathBuf,
        token: String,
        relay: Arc<dyn EgressRelay>,
        alive: Arc<AtomicBool>,
    ) -> Self {
        Self {
            endpoint,
            token,
            relay,
            alive,
        }
    }

    /// Opens only this session's native loopback door. Port admission is
    /// the caller's; the trusted guest applies the original fence registry.
    pub fn connect(
        &self,
        target: SocketAddr,
        waiting: &dyn Fn() -> bool,
    ) -> std::io::Result<LoopbackConnection> {
        let waiting = || self.alive.load(Ordering::Acquire) && waiting();
        let request = super::request(&self.token, target)?;
        // All three host descriptors and both workers have room before
        // creating any socket. The returned end carries its own permit.
        let returned_room = self.relay.host_net_floor().acquire(1, 0)?;
        let bridge_room = self.relay.host_net_floor().acquire(2, 2)?;
        let buffer_room = self
            .relay
            .host_net_floor()
            .acquire_bytes((2 * super::CHUNK) as u64)?;
        let bridge_room = HostNetPermit::new((bridge_room, buffer_room));
        let wire = connect_uds(&self.endpoint, &waiting)?;
        let mut channel = SocketIo {
            socket: &wire,
            waiting: &waiting,
        };
        write!(&mut channel, "CONNECT {}\n", super::PORT)?;
        // Read exactly through EOL: the next byte belongs to our protocol.
        let mut ack = [0; 32];
        let mut count = 0;
        loop {
            if count == ack.len() {
                return Err(std::io::Error::from_raw_os_error(libc::EPROTO));
            }
            channel.read_exact(&mut ack[count..count + 1])?;
            count += 1;
            if ack[count - 1] == b'\n' {
                break;
            }
        }
        let port = std::str::from_utf8(&ack[..count])
            .ok()
            .and_then(|ack| ack.strip_prefix("OK "))
            .and_then(|port| port.strip_suffix('\n'))
            .and_then(|port| port.parse::<u32>().ok());
        if port.is_none() {
            return Err(std::io::Error::from_raw_os_error(libc::EPROTO));
        }
        channel.write_all(&request)?;
        let mut reply = [0; 4];
        channel.read_exact(&mut reply)?;
        let errno = i32::from_be_bytes(reply);
        if errno != 0 {
            return Err(std::io::Error::from_raw_os_error(errno));
        }
        let (returned, local) = UnixStream::pair()?;
        bridge::spawn(local, wire, Arc::clone(&self.alive), bridge_room)?;
        Ok(LoopbackConnection::from_parts(returned, returned_room))
    }
}

fn connect_uds(path: &Path, waiting: &dyn Fn() -> bool) -> std::io::Result<File> {
    // SAFETY: socket has no pointer inputs and returns an owned descriptor.
    let fd = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: successful socket returned this new owned descriptor.
    let socket = unsafe { File::from_raw_fd(fd) };
    // SAFETY: zeroed sockaddr_un has valid padding and a NUL-filled path.
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    let path = path.as_os_str().as_bytes();
    if path.len() >= address.sun_path.len() {
        return Err(std::io::Error::from_raw_os_error(libc::ENAMETOOLONG));
    }
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (to, from) in address.sun_path.iter_mut().zip(path) {
        *to = *from as libc::c_char;
    }
    let length =
        (std::mem::offset_of!(libc::sockaddr_un, sun_path) + path.len() + 1) as libc::socklen_t;
    loop {
        if !waiting() {
            return Err(std::io::Error::from_raw_os_error(libc::EINTR));
        }
        // SAFETY: address and its length name the initialized Unix pathname.
        if unsafe { libc::connect(fd, (&raw const address).cast(), length) } == 0 {
            return Ok(socket);
        }
        let error = std::io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::EAGAIN) => std::thread::sleep(Duration::from_millis(super::POLL_MS as u64)),
            Some(libc::EINTR) => continue,
            Some(libc::EINPROGRESS) => {
                io::wait(fd, libc::POLLOUT, waiting)?;
                let mut errno: libc::c_int = 0;
                let mut length = std::mem::size_of_val(&errno) as libc::socklen_t;
                // SAFETY: errno/length are writable SO_ERROR output buffers.
                if unsafe {
                    libc::getsockopt(
                        fd,
                        libc::SOL_SOCKET,
                        libc::SO_ERROR,
                        (&raw mut errno).cast(),
                        &mut length,
                    )
                } != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                return if errno == 0 {
                    Ok(socket)
                } else {
                    Err(std::io::Error::from_raw_os_error(errno))
                };
            }
            _ => return Err(error),
        }
    }
}
