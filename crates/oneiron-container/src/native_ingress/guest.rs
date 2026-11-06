use super::{bridge, io::SocketIo};
use crate::NativeFenceGuard;
use std::{
    fs::File,
    io::{self, Read, Write},
    os::fd::{AsRawFd, FromRawFd},
    sync::{Arc, atomic::AtomicBool},
};

/// Binds before the untrusted child starts. Only host CID 2 is served.
pub fn bind() -> io::Result<File> {
    // SAFETY: socket has no pointer inputs and returns an owned descriptor.
    let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: socket returned this fresh owned descriptor.
    let socket = unsafe { File::from_raw_fd(fd) };
    // SAFETY: zero is valid padding/reserved initialization for sockaddr_vm.
    let mut address: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
    address.svm_family = libc::AF_VSOCK as libc::sa_family_t;
    address.svm_cid = libc::VMADDR_CID_ANY;
    address.svm_port = super::PORT;
    // SAFETY: address is initialized and length exactly matches its layout.
    if unsafe {
        libc::bind(
            fd,
            (&raw const address).cast(),
            std::mem::size_of_val(&address) as libc::socklen_t,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd is this bound, owned stream socket; SOMAXCONN is kernel policy.
    if unsafe { libc::listen(fd, libc::SOMAXCONN) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(socket)
}

/// Trusted PID 1 holds the same fence until the host tears down the VM.
/// This creates no host listener and serves no guest-to-host relay command.
pub fn serve(listener: File, fence: Arc<NativeFenceGuard>, token: &str) -> io::Result<()> {
    if token.len() != 32 {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    let token = token.to_owned();
    std::thread::Builder::new().spawn(move || {
        loop {
            // SAFETY: zero is valid padding and accept4 fills this address.
            let mut peer: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
            let mut length = std::mem::size_of_val(&peer) as libc::socklen_t;
            // SAFETY: listener and output buffers are live; accept4 returns
            // a new socket with independent ownership and no exec inheritance.
            let fd = unsafe {
                libc::accept4(
                    listener.as_raw_fd(),
                    (&raw mut peer).cast(),
                    &mut length,
                    libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                )
            };
            if fd < 0 {
                if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return;
            }
            // SAFETY: accept4 returned this new owned descriptor.
            let stream = unsafe { File::from_raw_fd(fd) };
            if length as usize != std::mem::size_of_val(&peer)
                || peer.svm_family != libc::AF_VSOCK as libc::sa_family_t
                || peer.svm_cid != libc::VMADDR_CID_HOST
            {
                continue;
            }
            let fence = Arc::clone(&fence);
            let token = token.clone();
            let _ = std::thread::Builder::new().spawn(move || {
                let _ = connect(stream, fence, &token);
            });
        }
    })?;
    Ok(())
}

fn connect(stream: File, fence: Arc<NativeFenceGuard>, token: &str) -> io::Result<()> {
    let mut channel = SocketIo {
        socket: &stream,
        waiting: &|| true,
    };
    let mut request = [0; 51];
    channel.read_exact(&mut request)?;
    let connection = super::target(&request, token)
        .and_then(|target| fence.connect_loopback(target, || peer_waiting(stream.as_raw_fd())));
    match connection {
        Ok(connection) => {
            channel.write_all(&0_i32.to_be_bytes())?;
            let (local, room) = connection.into_parts();
            // The local peer and its permit stay together through both pumps.
            bridge::spawn(local, stream, Arc::new(AtomicBool::new(true)), room)
        }
        Err(error) => channel.write_all(&error.raw_os_error().unwrap_or(libc::EIO).to_be_bytes()),
    }
}

fn peer_waiting(fd: i32) -> bool {
    let mut byte = [0];
    // SAFETY: recv only peeks into this connected owned socket and never waits.
    let result = unsafe {
        libc::recv(
            fd,
            byte.as_mut_ptr().cast(),
            1,
            libc::MSG_PEEK | libc::MSG_DONTWAIT,
        )
    };
    result > 0 || (result < 0 && io::Error::last_os_error().kind() == io::ErrorKind::WouldBlock)
}
