//! Unprivileged in-container launcher and syscall-argument broker.

use crate::{linux, socket_lifetime, wire};
use std::collections::{BTreeSet, HashMap};
use std::ffi::OsString;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock, mpsc};
use std::time::{Duration, Instant};

struct Pending {
    request: Vec<u8>,
    sender: mpsc::Sender<wire::Reply>,
}
struct Bridge {
    next: AtomicU64,
    writer: Mutex<Option<UnixStream>>,
    pending: Mutex<HashMap<u64, Pending>>,
    /// A socket call holds it shared until its reply; an inventory scan
    /// holds it alone, so no socket the supervisor is still creating can be
    /// missing from a scan (FIX 5978).
    sockets: RwLock<()>,
    /// Whether a socket was brokered: until then there is nothing to scan.
    brokered: AtomicBool,
}
impl Bridge {
    fn call(&self, id: u64, op: wire::Operation) -> io::Result<wire::Reply> {
        let notification = id;
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let mut bytes = Vec::new();
        wire::write(
            &mut bytes,
            &wire::Frame::Request(wire::Request {
                id,
                notification,
                op,
            }),
        )?;
        let (sender, rx) = mpsc::channel();
        self.pending
            .lock()
            .map_err(|_| io::Error::other("fence state poisoned"))?
            .insert(
                id,
                Pending {
                    request: bytes.clone(),
                    sender,
                },
            );
        if let Some(writer) = self
            .writer
            .lock()
            .map_err(|_| io::Error::other("fence state poisoned"))?
            .as_mut()
        {
            use std::io::Write;
            let _ = writer.write_all(&bytes);
        }
        rx.recv().map_err(io::Error::other)
    }

    /// Sends one complete scan, in chunks, while the bridge is connected. A
    /// scan the bridge lost on the way is superseded by the next one.
    fn send_inventory(&self, generation: u64, inodes: &BTreeSet<u64>) -> io::Result<()> {
        use std::io::Write;
        let inodes: Vec<u64> = inodes.iter().copied().collect();
        let mut chunks = inodes.chunks(wire::INVENTORY_CHUNK).peekable();
        let mut frames = Vec::new();
        if chunks.peek().is_none() {
            frames.push(Vec::new());
        }
        frames.extend(chunks.map(<[u64]>::to_vec));
        let count = frames.len();
        for (index, inodes) in frames.into_iter().enumerate() {
            let mut bytes = Vec::new();
            wire::write(
                &mut bytes,
                &wire::Frame::Inventory(wire::SocketInventory {
                    generation,
                    inodes,
                    last: index + 1 == count,
                }),
            )?;
            let mut writer = self
                .writer
                .lock()
                .map_err(|_| io::Error::other("fence state poisoned"))?;
            let writer = writer
                .as_mut()
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotConnected))?;
            writer.write_all(&bytes)?;
        }
        Ok(())
    }
}

/// Takes the guest's socket inventory every [`socket_lifetime::SOCKET_INVENTORY_EVERY`]
/// once a socket was brokered, and sends each complete one to the supervisor
/// (FIX 5978). An incomplete scan is not sent; the next one tries again.
fn inventory(bridge: &Bridge, launcher: u32) {
    let mut generation = 0_u64;
    loop {
        std::thread::sleep(socket_lifetime::SOCKET_INVENTORY_EVERY);
        if !bridge.brokered.load(Ordering::Acquire) {
            continue;
        }
        let Ok(_alone) = bridge.sockets.write() else {
            return;
        };
        let Ok(inodes) = socket_lifetime::collect_guest_socket_inodes(launcher) else {
            continue;
        };
        generation += 1;
        let _ = bridge.send_inventory(generation, &inodes);
    }
}

/// Entry point for the engine-mounted launcher, inside a network-none guest.
pub fn launch(
    socket: &Path,
    generation: String,
    reconnect: Duration,
    command: &[OsString],
) -> io::Result<i32> {
    if command.is_empty() {
        return Err(io::Error::other("missing fenced command"));
    }
    // SAFETY: get*id only inspect this process.
    if unsafe { libc::geteuid() } == 0 || unsafe { libc::getegid() } == 0 {
        return Err(io::Error::other("fence launcher refuses root"));
    }
    let status = std::fs::read_to_string("/proc/self/status")?;
    let caps = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:\t"))
        .unwrap_or("")
        .trim()
        .to_owned();
    if caps.is_empty() || caps.bytes().any(|b| b != b'0') {
        return Err(io::Error::other("fence launcher requires no capabilities"));
    }
    // SAFETY: protects supervisor memory from same-uid descendants.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: getpid only reads the trusted supervisor identity.
    let parent_pid = unsafe { libc::getpid() } as u32;
    let inherit_group = std::env::var_os("ONEIRON_FENCE_INHERIT_GROUP").is_some();
    let (parent, child_channel) = UnixStream::pair()?;
    // SAFETY: the launcher is single-threaded at fork; no inherited worker
    // or locked Rust mutex exists. The child installs its fence then execs.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    if pid == 0 {
        drop(parent);
        if let Err(error) = child(&child_channel, command, parent_pid, inherit_group) {
            eprintln!("oneiron fence: {error}");
        }
        // SAFETY: exit the fork child without parent destructors.
        unsafe { libc::_exit(126) }
    }
    drop(child_channel);
    let listener = wire::receive_fd(&parent)?;
    let (abi, bootstrap_fd): (i32, i32) = wire::read(&mut &parent)?;
    let hello = wire::Hello {
        generation,
        bootstrap_fd,
        parent_pid,
        ruleset_hash: linux::ruleset_hash(),
        seccomp_hash: linux::filter_hash(parent_pid, bootstrap_fd),
        landlock_abi: abi,
        no_new_privs: true,
        capabilities: caps,
        routes: ["/proc/net/route", "/proc/net/ipv6_route"]
            .iter()
            .map(|path| std::fs::read_to_string(path).unwrap_or_default())
            .collect(),
    };
    let bridge = Arc::new(Bridge {
        next: AtomicU64::new(1),
        writer: Mutex::new(None),
        pending: Mutex::new(HashMap::new()),
        sockets: RwLock::new(()),
        brokered: AtomicBool::new(false),
    });
    let stream = connect(socket, &hello, &listener)?;
    *bridge
        .writer
        .lock()
        .map_err(|_| io::Error::other("fence state poisoned"))? = Some(stream.try_clone()?);
    let monitor_bridge = Arc::clone(&bridge);
    let inventory_bridge = Arc::clone(&bridge);
    std::thread::spawn(move || inventory(&inventory_bridge, std::process::id()));
    let socket = socket.to_owned();
    let listener = Arc::new(listener);
    let monitor_listener = Arc::clone(&listener);
    std::thread::spawn(move || {
        monitor(
            stream,
            socket,
            hello,
            monitor_listener,
            monitor_bridge,
            pid,
            reconnect,
            inherit_group,
        )
    });
    std::thread::spawn(move || {
        loop {
            match linux::receive(listener.as_raw_fd()) {
                Ok(notification) => {
                    let listener = Arc::clone(&listener);
                    let bridge = Arc::clone(&bridge);
                    std::thread::spawn(move || {
                        if let Err(error) = dispatch(&listener, &bridge, notification) {
                            let _ = linux::respond(
                                listener.as_raw_fd(),
                                notification.id,
                                0,
                                error.raw_os_error().unwrap_or(libc::EIO),
                                0,
                            );
                        }
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => return,
            }
        }
    });
    let mut status = 0;
    // SAFETY: waits for the launcher's own child.
    while unsafe { libc::waitpid(pid, &mut status, 0) } < 0 {
        if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        128 + libc::WTERMSIG(status)
    })
}

fn child(
    channel: &UnixStream,
    command: &[OsString],
    parent_pid: u32,
    inherit_group: bool,
) -> io::Result<()> {
    // SAFETY: creates an owned process group and makes the child inspectable
    // by its parent. Neither syscall adds privileges.
    if (!inherit_group && unsafe { libc::setpgid(0, 0) } != 0)
        || unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0) } != 0
    {
        return Err(io::Error::last_os_error());
    }
    let abi = linux::landlock()?;
    let listener = linux::install(parent_pid, channel.as_raw_fd())?;
    wire::send_fd(channel, listener.as_raw_fd())?;
    wire::write(&mut &*channel, &(abi, channel.as_raw_fd()))?;
    drop(listener);
    Err(Command::new(&command[0]).args(&command[1..]).exec())
}
fn connect(socket: &Path, hello: &wire::Hello, listener: &OwnedFd) -> io::Result<UnixStream> {
    let mut stream = UnixStream::connect(socket)?;
    wire::write(&mut stream, hello)?;
    wire::send_fd(&stream, listener.as_raw_fd())?;
    let accepted: bool = wire::read(&mut stream)?;
    if !accepted {
        return Err(io::Error::other("host refused fence proof"));
    }
    Ok(stream)
}
fn monitor(
    mut stream: UnixStream,
    socket: std::path::PathBuf,
    hello: wire::Hello,
    listener: Arc<OwnedFd>,
    bridge: Arc<Bridge>,
    pid: i32,
    window: Duration,
    inherit_group: bool,
) {
    loop {
        while let Ok(reply) = wire::read::<wire::Reply>(&mut stream) {
            if let Ok(mut pending) = bridge.pending.lock()
                && let Some(request) = pending.remove(&reply.id)
            {
                let _ = request.sender.send(reply);
            }
        }
        if let Ok(mut writer) = bridge.writer.lock() {
            writer.take();
        }
        if inherit_group {
            // The microVM PID1 owns bridge recovery for this entire group.
            // Loss of its local trusted supervisor is a terminal agent fault.
            // SAFETY: kill only this launcher's own child.
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
            return;
        }
        // SAFETY: only the owned child group is stopped, resumed or killed.
        unsafe {
            libc::kill(-pid, libc::SIGSTOP);
        }
        let deadline = Instant::now() + window;
        loop {
            if Instant::now() >= deadline {
                eprintln!("oneiron fence: bridge abandoned");
                // SAFETY: only this launcher's child group is killed.
                unsafe {
                    libc::kill(-pid, libc::SIGKILL);
                }
                if let Ok(mut pending) = bridge.pending.lock() {
                    pending.clear();
                }
                return;
            }
            match connect(&socket, &hello, &listener) {
                Ok(next) => {
                    use std::io::Write;
                    if let (Ok(mut writer), Ok(pending), Ok(copy)) = (
                        bridge.writer.lock(),
                        bridge.pending.lock(),
                        next.try_clone(),
                    ) {
                        *writer = Some(copy);
                        if let Some(writer) = writer.as_mut() {
                            for request in pending.values() {
                                let _ = writer.write_all(&request.request);
                            }
                        }
                    }
                    stream = next;
                    // SAFETY: resumes the same owned group.
                    unsafe {
                        libc::kill(-pid, libc::SIGCONT);
                    }
                    break;
                }
                Err(_) => std::thread::sleep(Duration::from_millis(100)),
            }
        }
    }
}
fn socket_inode(pid: u32, fd: u64) -> Option<u64> {
    socket_lifetime::socket_link_inode(&std::fs::read_link(format!("/proc/{pid}/fd/{fd}")).ok()?)
}
fn remote(pid: u32, address: u64, bytes: &mut [u8], write: bool) -> io::Result<()> {
    let local = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    let other = libc::iovec {
        iov_base: address as usize as *mut _,
        iov_len: bytes.len(),
    };
    // SAFETY: local references live storage. The kernel validates every
    // remote pointer and permission; Rust never dereferences those pointers.
    let n = unsafe {
        if write {
            libc::process_vm_writev(pid as i32, &local, 1, &other, 1, 0)
        } else {
            libc::process_vm_readv(pid as i32, &local, 1, &other, 1, 0)
        }
    };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    if n as usize != bytes.len() {
        return Err(io::Error::from_raw_os_error(libc::EFAULT));
    }
    Ok(())
}
fn load<T: Copy>(pid: u32, address: u64) -> io::Result<T> {
    let mut value = std::mem::MaybeUninit::<T>::uninit();
    // SAFETY: callers use C structs/integers with no invalid bit patterns;
    // every byte is filled by the kernel before assume_init.
    unsafe {
        let bytes =
            std::slice::from_raw_parts_mut(value.as_mut_ptr().cast(), std::mem::size_of::<T>());
        remote(pid, address, bytes, false)?;
        Ok(value.assume_init())
    }
}
fn store<T: Copy>(pid: u32, address: u64, mut value: T) -> io::Result<()> {
    // SAFETY: copies only the initialized object representation.
    let bytes = unsafe {
        std::slice::from_raw_parts_mut((&mut value as *mut T).cast(), std::mem::size_of::<T>())
    };
    remote(pid, address, bytes, true)
}
fn address(pid: u32, pointer: u64, len: u64) -> io::Result<Option<SocketAddr>> {
    if pointer == 0 {
        return Ok(None);
    }
    if len < 2 {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    match load::<u16>(pid, pointer)? as i32 {
        libc::AF_INET if len >= 16 => {
            let a: libc::sockaddr_in = load(pid, pointer)?;
            Ok(Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(a.sin_addr.s_addr.to_ne_bytes())),
                u16::from_be(a.sin_port),
            )))
        }
        libc::AF_INET6 if len >= 28 => {
            let a: libc::sockaddr_in6 = load(pid, pointer)?;
            Ok(Some(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(a.sin6_addr.s6_addr)),
                u16::from_be(a.sin6_port),
            )))
        }
        libc::AF_UNIX | libc::AF_NETLINK => Ok(None),
        _ => Err(io::Error::from_raw_os_error(libc::EAFNOSUPPORT)),
    }
}
fn put_address(pid: u32, ptr: u64, length: u64, addr: SocketAddr) -> io::Result<()> {
    if ptr == 0 || length == 0 {
        return Ok(());
    }
    let max: u32 = load(pid, length)?;
    // SAFETY: zeroed sockaddr_storage is a valid byte container.
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let actual = match addr {
        SocketAddr::V4(a) => {
            let value = libc::sockaddr_in {
                sin_family: libc::AF_INET as u16,
                sin_port: a.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(a.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            // SAFETY: storage is aligned and large enough for sockaddr_in.
            unsafe {
                std::ptr::write(
                    (&mut storage as *mut libc::sockaddr_storage).cast::<libc::sockaddr_in>(),
                    value,
                );
            }
            std::mem::size_of::<libc::sockaddr_in>()
        }
        SocketAddr::V6(a) => {
            let value = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as u16,
                sin6_port: a.port().to_be(),
                sin6_flowinfo: 0,
                sin6_addr: libc::in6_addr {
                    s6_addr: a.ip().octets(),
                },
                sin6_scope_id: a.scope_id(),
            };
            // SAFETY: storage is aligned and large enough for sockaddr_in6.
            unsafe {
                std::ptr::write(
                    (&mut storage as *mut libc::sockaddr_storage).cast::<libc::sockaddr_in6>(),
                    value,
                );
            }
            std::mem::size_of::<libc::sockaddr_in6>()
        }
    };
    // SAFETY: copy only initialized sockaddr storage bytes.
    let bytes = unsafe {
        std::slice::from_raw_parts_mut(
            (&mut storage as *mut libc::sockaddr_storage).cast(),
            actual.min(max as usize),
        )
    };
    remote(pid, ptr, bytes, true)?;
    store(pid, length, actual as u32)
}
fn dispatch(listener: &OwnedFd, bridge: &Bridge, n: linux::Notification) -> io::Result<()> {
    let fd = listener.as_raw_fd();
    linux::valid(fd, n.id)?;
    let a = n.data.args;
    let nr = i64::from(n.data.nr);
    if nr == libc::SYS_socket {
        let family = a[0] as i32;
        if matches!(family, libc::AF_UNIX | libc::AF_NETLINK) {
            return linux::respond(fd, n.id, 0, 0, linux::CONTINUE);
        }
        let reply = {
            let _shared = bridge
                .sockets
                .read()
                .map_err(|_| io::Error::other("fence state poisoned"))?;
            bridge.call(
                n.id,
                wire::Operation::Socket {
                    family,
                    kind: a[1] as i32,
                    protocol: a[2] as i32,
                },
            )?
        };
        // The successful socket syscall was completed by the host's ADDFD.
        return if reply.errno == 0 {
            bridge.brokered.store(true, Ordering::Release);
            Ok(())
        } else {
            linux::respond(fd, n.id, 0, reply.errno, 0)
        };
    }
    let Some(socket) = socket_inode(n.pid, a[0]) else {
        return linux::respond(fd, n.id, 0, 0, linux::CONTINUE);
    };
    let describe = bridge.call(n.id, wire::Operation::Describe { socket })?;
    if describe.errno == libc::ENOENT {
        return linux::respond(fd, n.id, 0, 0, linux::CONTINUE);
    }
    if describe.errno != 0 {
        return linux::respond(fd, n.id, 0, describe.errno, 0);
    }
    let datagram = describe.value == libc::SOCK_DGRAM as i64;
    let reply = if nr == libc::SYS_connect {
        match address(n.pid, a[1], a[2])? {
            Some(target) => bridge.call(n.id, wire::Operation::Connect { socket, target })?,
            None => return linux::respond(fd, n.id, 0, libc::EAFNOSUPPORT, 0),
        }
    } else if nr == libc::SYS_getpeername || nr == libc::SYS_getsockname {
        let reply = bridge.call(
            n.id,
            wire::Operation::Peer {
                socket,
                local: nr == libc::SYS_getsockname,
            },
        )?;
        linux::valid(fd, n.id)?;
        if let Some(addr) = reply.address {
            put_address(n.pid, a[1], a[2], addr)?;
        }
        reply
    } else if nr == libc::SYS_setsockopt || nr == libc::SYS_getsockopt {
        if a[1] as i32 == libc::SOL_SOCKET && a[2] as i32 != libc::SO_DOMAIN {
            return linux::respond(fd, n.id, 0, 0, linux::CONTINUE);
        }
        if nr == libc::SYS_getsockopt {
            let value = if a[2] as i32 == libc::SO_DOMAIN {
                describe.bytes.first().copied().unwrap_or(2) as i32
            } else {
                0_i32
            };
            linux::valid(fd, n.id)?;
            let size: u32 = load(n.pid, a[4])?;
            if size < 4 {
                return linux::respond(fd, n.id, 0, libc::EINVAL, 0);
            }
            store(n.pid, a[3], value)?;
            store(n.pid, a[4], 4_u32)?;
        }
        wire::Reply {
            id: n.id,
            ..Default::default()
        }
    } else if !datagram {
        return linux::respond(fd, n.id, 0, 0, linux::CONTINUE);
    } else if nr == libc::SYS_sendto {
        let mut bytes = vec![0; (a[2] as usize).min(65536)];
        if bytes.len() != a[2] as usize {
            return linux::respond(fd, n.id, 0, libc::EMSGSIZE, 0);
        }
        remote(n.pid, a[1], &mut bytes, false)?;
        let target = address(n.pid, a[4], a[5])?;
        bridge.call(
            n.id,
            wire::Operation::Send {
                socket,
                target,
                bytes,
                dontwait: a[3] as i32 & libc::MSG_DONTWAIT != 0,
            },
        )?
    } else if nr == libc::SYS_recvfrom {
        let reply = bridge.call(
            n.id,
            wire::Operation::Receive {
                socket,
                max: (a[2] as usize).min(65536),
                flags: a[3] as i32,
            },
        )?;
        linux::valid(fd, n.id)?;
        remote(n.pid, a[1], &mut reply.bytes.clone(), true)?;
        if let Some(addr) = reply.address {
            put_address(n.pid, a[4], a[5], addr)?;
        }
        reply
    } else if nr == libc::SYS_sendmsg || nr == libc::SYS_recvmsg {
        message(
            listener,
            bridge,
            n,
            socket,
            a[1],
            nr == libc::SYS_sendmsg,
            a[2] as i32,
        )?
    } else if nr == libc::SYS_sendmmsg || nr == libc::SYS_recvmmsg {
        let sending = nr == libc::SYS_sendmmsg;
        let mut completed = 0;
        for index in 0..(a[2] as usize).min(1024) {
            let ptr = a[1] + (index * std::mem::size_of::<libc::mmsghdr>()) as u64;
            let reply = message(listener, bridge, n, socket, ptr, sending, a[3] as i32)?;
            if reply.errno != 0 {
                if completed == 0 {
                    return linux::respond(fd, n.id, 0, reply.errno, 0);
                }
                break;
            }
            linux::valid(fd, n.id)?;
            store(
                n.pid,
                ptr + std::mem::size_of::<libc::msghdr>() as u64,
                reply.value as u32,
            )?;
            completed += 1;
        }
        wire::Reply {
            id: n.id,
            value: completed,
            ..Default::default()
        }
    } else {
        return linux::respond(fd, n.id, 0, libc::ENOSYS, 0);
    };
    linux::respond(fd, n.id, reply.value, reply.errno, 0)
}
fn message(
    listener: &OwnedFd,
    bridge: &Bridge,
    n: linux::Notification,
    socket: u64,
    pointer: u64,
    sending: bool,
    flags: i32,
) -> io::Result<wire::Reply> {
    let mut msg: libc::msghdr = load(n.pid, pointer)?;
    if msg.msg_iovlen > 1024 {
        return Err(io::Error::from_raw_os_error(libc::EMSGSIZE));
    }
    let mut vectors = Vec::new();
    let mut length = 0_usize;
    for i in 0..msg.msg_iovlen {
        let vector: libc::iovec = load(
            n.pid,
            msg.msg_iov as u64 + (i * std::mem::size_of::<libc::iovec>()) as u64,
        )?;
        length = length
            .checked_add(vector.iov_len)
            .filter(|n| *n <= 65536)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EMSGSIZE))?;
        vectors.push(vector);
    }
    let reply = if sending {
        let mut bytes = vec![0; length];
        let mut at = 0;
        for vector in &vectors {
            remote(
                n.pid,
                vector.iov_base as u64,
                &mut bytes[at..at + vector.iov_len],
                false,
            )?;
            at += vector.iov_len;
        }
        let target = address(n.pid, msg.msg_name as u64, msg.msg_namelen as u64)?;
        bridge.call(
            n.id,
            wire::Operation::Send {
                socket,
                target,
                bytes,
                dontwait: flags & libc::MSG_DONTWAIT != 0,
            },
        )?
    } else {
        bridge.call(
            n.id,
            wire::Operation::Receive {
                socket,
                max: length,
                flags,
            },
        )?
    };
    if !sending && reply.errno == 0 {
        linux::valid(listener.as_raw_fd(), n.id)?;
        let mut at = 0;
        for vector in vectors {
            let take = vector.iov_len.min(reply.bytes.len() - at);
            remote(
                n.pid,
                vector.iov_base as u64,
                &mut reply.bytes[at..at + take].to_vec(),
                true,
            )?;
            at += take;
        }
        if let Some(addr) = reply.address {
            let length_ptr = pointer + std::mem::offset_of!(libc::msghdr, msg_namelen) as u64;
            put_address(n.pid, msg.msg_name as u64, length_ptr, addr)?;
            msg.msg_namelen = load(n.pid, length_ptr)?;
        }
        msg.msg_flags = 0;
        msg.msg_controllen = 0;
        store(n.pid, pointer, msg)?;
    }
    Ok(reply)
}
