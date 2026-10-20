//! Host custody of the seccomp listener and all network transports.

use crate::{EgressRelay, Error, FenceConfig, FenceProof, Result, linux, wire};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixDatagram, UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// A socket's host entry ends with the guest's last hold on it (FIX 5978).
mod lifetime;
// A relayed datagram's worker holds its room on the host floor (FIX 5979).
mod relay_workers;

pub(crate) struct Supervisor {
    listener: UnixListener,
    directory: tempfile::TempDir,
    generation: String,
    launcher_digest: String,
    config: FenceConfig,
}
struct Socket {
    family: i32,
    kind: i32,
    target: Mutex<Option<SocketAddr>>,
    stream: Mutex<Option<UnixStream>>,
    datagram: Option<(UnixDatagram, UnixDatagram)>,
    /// No guest task holds the socket any more: its writer stops.
    closed: AtomicBool,
    /// Its room on the host floor, given back with its descriptors.
    _charge: crate::HostNetPermit,
}
#[derive(Default)]
struct Completion {
    notification: u64,
    result: Mutex<Option<wire::Reply>>,
}
struct State {
    sockets: Mutex<HashMap<u64, Arc<Socket>>>,
    requests: Mutex<HashMap<u64, Arc<Completion>>>,
    relay: Arc<dyn EgressRelay>,
    alive: Arc<AtomicBool>,
    inventory: Mutex<lifetime::Inventory>,
}

pub(crate) struct Guard {
    alive: Arc<AtomicBool>,
    directory: Option<tempfile::TempDir>,
}
impl Guard {
    pub(crate) fn abandoned(&self) -> bool {
        !self.alive.load(Ordering::Acquire)
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        self.alive.store(false, Ordering::Release);
        self.directory.take();
    }
}
impl Supervisor {
    pub(crate) fn bind(config: &FenceConfig, generation: String) -> Result<Self> {
        let directory = tempfile::Builder::new()
            .prefix("oneiron-fence-")
            .tempdir()
            .map_err(Error::Fence)?;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o711))
            .map_err(Error::Fence)?;
        let listener =
            UnixListener::bind(directory.path().join("bridge.sock")).map_err(Error::Fence)?;
        std::fs::set_permissions(
            directory.path().join("bridge.sock"),
            std::fs::Permissions::from_mode(0o666),
        )
        .map_err(Error::Fence)?;
        listener.set_nonblocking(true).map_err(Error::Fence)?;
        let mut launcher = std::fs::File::open(&config.launcher).map_err(Error::Fence)?;
        let mut digest = blake3::Hasher::new();
        digest.update_reader(&mut launcher).map_err(Error::Fence)?;
        Ok(Self {
            listener,
            directory,
            generation,
            launcher_digest: digest.finalize().to_hex().to_string(),
            config: config.clone(),
        })
    }
    pub(crate) fn directory(&self) -> &Path {
        self.directory.path()
    }
    pub(crate) fn activate(
        self,
        runtime: PathBuf,
        name: String,
        child: &mut std::process::Child,
        relay: Arc<dyn EgressRelay>,
    ) -> Result<(FenceProof, Guard)> {
        let deadline = Instant::now() + self.config.startup_timeout;
        let (mut stream, _) = loop {
            match self.listener.accept() {
                Ok(pair) => break pair,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if child.try_wait().map_err(Error::Fence)?.is_some()
                        || Instant::now() >= deadline
                    {
                        return Err(Error::Fence(io::Error::other(
                            "fence launcher did not prove readiness",
                        )));
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => return Err(Error::Fence(e)),
            }
        };
        stream
            .set_read_timeout(Some(self.config.startup_timeout))
            .map_err(Error::Fence)?;
        let hello: wire::Hello = wire::read(&mut stream).map_err(Error::Fence)?;
        let listener = wire::receive_fd(&stream).map_err(Error::Fence)?;
        let evidence = inspect(&runtime, &name).map_err(Error::Fence)?;
        let peer = peer_pid(&stream).map_err(Error::Fence)?;
        let expected = evidence[0]["State"]["Pid"].as_u64().unwrap_or(0);
        if peer == 0 || peer as u64 != expected || !self.proved(&hello) || !network_none(&evidence)
        {
            let _ = wire::write(&mut stream, &false);
            return Err(Error::Fence(io::Error::other(
                "container fence evidence mismatch",
            )));
        }
        let evidence_bytes = serde_json::to_vec(&(&evidence, &hello.routes))
            .map_err(|e| Error::Fence(io::Error::other(e)))?;
        let proof = FenceProof {
            ruleset_hash: hello.ruleset_hash.clone(),
            seccomp_hash: hello.seccomp_hash.clone(),
            network_routes: hello.routes.clone(),
            network_evidence_digest: blake3::hash(&evidence_bytes).to_hex().to_string(),
            sandbox_generation: self.generation.clone(),
            launcher_digest: self.launcher_digest.clone(),
        };
        wire::write(&mut stream, &true).map_err(Error::Fence)?;
        stream.set_read_timeout(None).map_err(Error::Fence)?;
        let alive = Arc::new(AtomicBool::new(true));
        let state = Arc::new(State {
            sockets: Mutex::new(HashMap::new()),
            requests: Mutex::new(HashMap::new()),
            relay,
            alive: Arc::clone(&alive),
            inventory: Mutex::default(),
        });
        let directory = self.directory;
        let guard = Guard {
            alive,
            directory: Some(directory),
        };
        let config = self.config;
        let generation = self.generation;
        let host_listener = self.listener;
        std::thread::spawn(move || {
            let notify = Arc::new(listener);
            loop {
                let _ = serve(stream, Arc::clone(&notify), Arc::clone(&state));
                if !state.alive.load(Ordering::Acquire) {
                    break;
                }
                let until = Instant::now() + config.reconnect_window;
                let reconnected = loop {
                    if !state.alive.load(Ordering::Acquire) || Instant::now() >= until {
                        break None;
                    }
                    match host_listener.accept() {
                        Ok((mut next, _)) => {
                            let _ = next.set_read_timeout(Some(config.startup_timeout));
                            let hello = wire::read::<wire::Hello>(&mut next);
                            let fd = wire::receive_fd(&next);
                            if peer_pid(&next).ok() == Some(peer)
                                && hello.as_ref().is_ok_and(|h| h.generation == generation)
                                && fd.is_ok()
                            {
                                let _ = wire::write(&mut next, &true);
                                let _ = next.set_read_timeout(None);
                                break Some(next);
                            }
                            let _ = wire::write(&mut next, &false);
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(20))
                        }
                        Err(_) => break None,
                    }
                };
                match reconnected {
                    Some(next) => stream = next,
                    None => {
                        state.alive.store(false, Ordering::Release);
                        remove(&runtime, &name);
                        break;
                    }
                }
            }
        });
        Ok((proof, guard))
    }
    fn proved(&self, hello: &wire::Hello) -> bool {
        hello.generation == self.generation
            && hello.landlock_abi >= 3
            && hello.ruleset_hash == linux::ruleset_hash()
            && hello.seccomp_hash == linux::filter_hash(hello.parent_pid, hello.bootstrap_fd)
            && hello.no_new_privs
            && !hello.capabilities.is_empty()
            && hello.capabilities.bytes().all(|b| b == b'0')
    }
}
fn inspect(runtime: &Path, name: &str) -> io::Result<serde_json::Value> {
    let result = oneiron_spawn::command(runtime)
        .args(["inspect", name])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .output()?;
    if !result.status.success() {
        return Err(io::Error::other("container inspect failed"));
    }
    serde_json::from_slice(&result.stdout).map_err(io::Error::other)
}
fn network_none(e: &serde_json::Value) -> bool {
    let host = &e[0]["HostConfig"];
    host["NetworkMode"] == "none"
        && host["Privileged"] == false
        && host["ReadonlyRootfs"] == true
        && host["CapDrop"]
            .as_array()
            .is_some_and(|a| a.iter().any(|v| v == "ALL"))
        && host["SecurityOpt"].as_array().is_some_and(|a| {
            a.iter().any(|v| {
                v.as_str()
                    .is_some_and(|s| s.starts_with("no-new-privileges"))
            })
        })
        && e[0]["Config"]["User"]
            .as_str()
            .is_some_and(|s| !s.is_empty() && !s.starts_with("0:"))
}
fn peer_pid(stream: &UnixStream) -> io::Result<i32> {
    // SAFETY: ucred is a plain C value filled by getsockopt with its exact size.
    unsafe {
        let mut cred: libc::ucred = std::mem::zeroed();
        let mut size = std::mem::size_of_val(&cred) as libc::socklen_t;
        if libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut size,
        ) < 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(cred.pid)
    }
}
fn remove(runtime: &Path, name: &str) {
    let _ = oneiron_spawn::command(runtime)
        .args(["rm", "--force", name])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}
fn serve(mut reader: UnixStream, listener: Arc<OwnedFd>, state: Arc<State>) -> io::Result<()> {
    let writer = Arc::new(Mutex::new(reader.try_clone()?));
    loop {
        let request = match wire::read::<wire::Frame>(&mut reader)? {
            wire::Frame::Request(request) => request,
            wire::Frame::Inventory(chunk) => {
                lifetime::receive(&state, chunk)?;
                continue;
            }
        };
        if !state.alive.load(Ordering::Acquire) {
            return Ok(());
        }
        let completion = {
            let mut requests = state
                .requests
                .lock()
                .map_err(|_| io::Error::other("fence state poisoned"))?;
            requests.retain(|_, cached| {
                linux::valid(listener.as_raw_fd(), cached.notification).is_ok()
            });
            Arc::clone(requests.entry(request.id).or_insert_with(|| {
                Arc::new(Completion {
                    notification: request.notification,
                    result: Mutex::new(None),
                })
            }))
        };
        let writer = Arc::clone(&writer);
        let listener = Arc::clone(&listener);
        let state = Arc::clone(&state);
        std::thread::spawn(move || {
            if let Ok(mut result) = completion.result.lock() {
                let reply = result.get_or_insert_with(|| {
                    let outcome = linux::valid(listener.as_raw_fd(), request.notification)
                        .and_then(|()| operate(&request, &listener, &state));
                    match outcome {
                        Ok(mut reply) => {
                            reply.id = request.id;
                            reply
                        }
                        Err(e) => relay_workers::failed(request.id, &e),
                    }
                });
                if let Ok(mut writer) = writer.lock() {
                    let _ = wire::write(&mut *writer, reply);
                }
            }
        });
    }
}
fn inode(fd: &impl AsRawFd) -> io::Result<u64> {
    // SAFETY: fstat fills a live stat value for a borrowed descriptor.
    unsafe {
        let mut stat: libc::stat = std::mem::zeroed();
        if libc::fstat(fd.as_raw_fd(), &mut stat) != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(stat.st_ino)
    }
}
fn get(state: &State, id: u64) -> io::Result<Arc<Socket>> {
    state
        .sockets
        .lock()
        .map_err(|_| io::Error::other("fence state poisoned"))?
        .get(&id)
        .cloned()
        .ok_or_else(|| io::Error::from_raw_os_error(libc::ENOENT))
}
fn operate(
    request: &wire::Request,
    listener: &OwnedFd,
    state: &Arc<State>,
) -> io::Result<wire::Reply> {
    use wire::Operation;
    let mut reply = wire::Reply::default();
    match &request.op {
        Operation::Socket {
            family,
            kind,
            protocol,
        } => {
            let base = kind & 0xf;
            if !matches!(*family, libc::AF_INET | libc::AF_INET6)
                || !matches!(base, libc::SOCK_STREAM | libc::SOCK_DGRAM)
                || !matches!(*protocol, 0 | libc::IPPROTO_TCP | libc::IPPROTO_UDP)
            {
                return Err(io::Error::from_raw_os_error(libc::EAFNOSUPPORT));
            }
            // The entry's descriptors and writer take their room on the host
            // floor first; a full floor is EAGAIN (FIX 5978).
            let (fds, workers) = if base == libc::SOCK_STREAM {
                lifetime::STREAM_ENTRY
            } else {
                lifetime::DATAGRAM_ENTRY
            };
            let charge = state.relay.host_net_floor().acquire(fds, workers)?;
            let (socket, id, guest): (Arc<Socket>, u64, OwnedFd) = if base == libc::SOCK_STREAM {
                let (guest, host) = UnixStream::pair()?;
                guest.set_nonblocking(kind & libc::SOCK_NONBLOCK != 0)?;
                let id = inode(&guest)?;
                (
                    Arc::new(Socket {
                        family: *family,
                        kind: base,
                        target: Mutex::new(None),
                        stream: Mutex::new(Some(host)),
                        datagram: None,
                        closed: AtomicBool::new(false),
                        _charge: charge,
                    }),
                    id,
                    guest.into(),
                )
            } else {
                let (guest, host) = UnixDatagram::pair()?;
                guest.set_nonblocking(kind & libc::SOCK_NONBLOCK != 0)?;
                let id = inode(&guest)?;
                let copy = guest.try_clone()?;
                (
                    Arc::new(Socket {
                        family: *family,
                        kind: base,
                        target: Mutex::new(None),
                        stream: Mutex::new(None),
                        datagram: Some((copy, host)),
                        closed: AtomicBool::new(false),
                        _charge: charge,
                    }),
                    id,
                    guest.into(),
                )
            };
            state
                .sockets
                .lock()
                .map_err(|_| io::Error::other("fence state poisoned"))?
                .insert(id, Arc::clone(&socket));
            let injected = linux::inject(
                listener.as_raw_fd(),
                request.notification,
                guest.as_raw_fd(),
                kind & libc::SOCK_CLOEXEC != 0,
            );
            // A socket the guest never received has no entry (FIX 5978).
            reply.value = i64::from(injected.inspect_err(|_| {
                if let Ok(mut sockets) = state.sockets.lock()
                    && sockets
                        .get(&id)
                        .is_some_and(|held| Arc::ptr_eq(held, &socket))
                {
                    sockets.remove(&id);
                }
            })?);
            if base == libc::SOCK_DGRAM {
                datagram_writer(socket, Arc::clone(state));
            }
        }
        Operation::Describe { socket } => {
            let socket = get(state, *socket)?;
            reply.value = socket.kind as i64;
            reply.bytes.push(socket.family as u8);
        }
        Operation::Connect { socket, target } => {
            let socket = get(state, *socket)?;
            if socket.kind == libc::SOCK_DGRAM {
                state.relay.authorize_datagram(*target)?;
                *socket
                    .target
                    .lock()
                    .map_err(|_| io::Error::other("fence state poisoned"))? = Some(*target);
            } else {
                let mut peer = socket
                    .stream
                    .lock()
                    .map_err(|_| io::Error::other("fence state poisoned"))?;
                if peer.is_none() {
                    return Err(io::Error::from_raw_os_error(libc::EISCONN));
                }
                if target.port() == 53 {
                    state.relay.authorize_datagram(*target)?;
                    let peer = peer
                        .take()
                        .ok_or_else(|| io::Error::from_raw_os_error(libc::EISCONN))?;
                    *socket
                        .target
                        .lock()
                        .map_err(|_| io::Error::other("fence state poisoned"))? = Some(*target);
                    relay_dns(peer, *target, Arc::clone(state));
                } else {
                    let stream = state.relay.connect(*target)?;
                    let peer = peer
                        .take()
                        .ok_or_else(|| io::Error::from_raw_os_error(libc::EISCONN))?;
                    *socket
                        .target
                        .lock()
                        .map_err(|_| io::Error::other("fence state poisoned"))? = Some(*target);
                    relay_stream(peer, stream, *target, Arc::clone(state));
                }
            }
        }
        Operation::Send {
            socket,
            target,
            bytes,
            dontwait,
        } => {
            let socket = get(state, *socket)?;
            let target = target
                .or(*socket
                    .target
                    .lock()
                    .map_err(|_| io::Error::other("fence state poisoned"))?)
                .ok_or_else(|| io::Error::from_raw_os_error(libc::EDESTADDRREQ))?;
            *socket
                .target
                .lock()
                .map_err(|_| io::Error::other("fence state poisoned"))? = Some(target);
            // Acknowledged once a worker holding its room relays it (FIX 5979).
            relay_workers::send(state, &socket, target, bytes, *dontwait, || {
                linux::valid(listener.as_raw_fd(), request.notification).is_ok()
            })?;
            reply.value = bytes.len() as i64;
        }
        Operation::Receive { socket, max, flags } => {
            let socket = get(state, *socket)?;
            let (guest, _) = socket
                .datagram
                .as_ref()
                .ok_or_else(|| io::Error::from_raw_os_error(libc::ENOTSOCK))?;
            reply.bytes.resize((*max).min(65536), 0);
            // SAFETY: recv writes at most the allocated byte slice and uses
            // only supported per-call flags; no address pointers are passed.
            let n = unsafe {
                libc::recv(
                    guest.as_raw_fd(),
                    reply.bytes.as_mut_ptr().cast(),
                    reply.bytes.len(),
                    flags & (libc::MSG_PEEK | libc::MSG_DONTWAIT | libc::MSG_TRUNC),
                )
            };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            reply.bytes.truncate(n as usize);
            reply.value = n as i64;
            reply.address = *socket
                .target
                .lock()
                .map_err(|_| io::Error::other("fence state poisoned"))?;
        }
        Operation::Peer { socket, local } => {
            let socket = get(state, *socket)?;
            reply.address = if *local {
                Some(
                    if socket.family == libc::AF_INET6 {
                        "[::]:0"
                    } else {
                        "0.0.0.0:0"
                    }
                    .parse()
                    .map_err(io::Error::other)?,
                )
            } else {
                *socket
                    .target
                    .lock()
                    .map_err(|_| io::Error::other("fence state poisoned"))?
            };
            if reply.address.is_none() {
                return Err(io::Error::from_raw_os_error(libc::ENOTCONN));
            }
        }
    }
    Ok(reply)
}
fn datagram_writer(socket: Arc<Socket>, state: Arc<State>) {
    std::thread::spawn(move || {
        let Some((_, host)) = &socket.datagram else {
            return;
        };
        let _ = host.set_read_timeout(Some(Duration::from_millis(250)));
        let mut bytes = [0; 65536];
        while state.alive.load(Ordering::Acquire) && !socket.closed.load(Ordering::Acquire) {
            match host.recv(&mut bytes) {
                Ok(n) => {
                    let target = socket.target.lock().ok().and_then(|a| *a);
                    // The relay's socket waits for room on the host floor;
                    // the guest's next writes wait in its socket (FIX 5979).
                    if let Some(target) = target
                        && let Some(_room) = relay_workers::reserve(&state, &socket)
                        && let Ok(answer) = state.relay.datagram(target, &bytes[..n])
                    {
                        let _ = host.send(&answer);
                    }
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    continue;
                }
                Err(_) => return,
            }
        }
    });
}
fn relay_stream(
    mut guest: UnixStream,
    mut remote: std::net::TcpStream,
    target: SocketAddr,
    state: Arc<State>,
) {
    std::thread::spawn(move || {
        let (Ok(mut incoming), Ok(mut outgoing)) = (remote.try_clone(), guest.try_clone()) else {
            return;
        };
        let _ = incoming.set_read_timeout(Some(Duration::from_millis(250)));
        let _ = guest.set_read_timeout(Some(Duration::from_millis(250)));
        let alive = Arc::clone(&state.alive);
        let upload = std::thread::spawn(move || {
            let mut bytes = [0; 32768];
            while alive.load(Ordering::Acquire) {
                match guest.read(&mut bytes) {
                    Ok(0) => break,
                    Ok(n) => {
                        if remote.write_all(&bytes[..n]).is_err() {
                            break;
                        }
                    }
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) =>
                    {
                        continue;
                    }
                    Err(_) => break,
                }
            }
            let _ = remote.shutdown(Shutdown::Write);
        });
        let mut hash = blake3::Hasher::new();
        let mut total = 0;
        let mut bytes = [0; 32768];
        while state.alive.load(Ordering::Acquire) {
            match incoming.read(&mut bytes) {
                Ok(0) => break,
                Ok(n) => {
                    hash.update(&bytes[..n]);
                    total += n as u64;
                    if outgoing.write_all(&bytes[..n]).is_err() {
                        break;
                    }
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    continue;
                }
                Err(_) => break,
            }
        }
        let _ = incoming.shutdown(Shutdown::Both);
        let _ = outgoing.shutdown(Shutdown::Both);
        let _ = upload.join();
        state
            .relay
            .transferred(target, *hash.finalize().as_bytes(), total);
    });
}

fn relay_dns(mut guest: UnixStream, target: SocketAddr, state: Arc<State>) {
    std::thread::spawn(move || {
        while state.alive.load(Ordering::Acquire) {
            let mut len = [0; 2];
            if guest.read_exact(&mut len).is_err() {
                break;
            }
            let mut query = vec![0; u16::from_be_bytes(len) as usize];
            if guest.read_exact(&mut query).is_err() {
                break;
            }
            let Ok(answer) = state.relay.datagram(target, &query) else {
                break;
            };
            if guest
                .write_all(&(answer.len() as u16).to_be_bytes())
                .and_then(|()| guest.write_all(&answer))
                .is_err()
            {
                break;
            }
        }
        let _ = guest.shutdown(Shutdown::Both);
    });
}

/// The microVM's trusted PID1 owns a local notifier supervisor. Only network
/// transport leaves the VM, over the engine's private vsock relay.
pub fn serve_native(
    listener: UnixListener,
    pid: i32,
    generation: &str,
    relay: Arc<dyn EgressRelay>,
) -> Result<NativeFenceGuard> {
    let deadline = Instant::now() + Duration::from_secs(30);
    listener.set_nonblocking(true).map_err(Error::Fence)?;
    let mut stream = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10))
            }
            _ => return Err(Error::Fence(io::Error::other("native fence readiness"))),
        }
    };
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(Error::Fence)?;
    let hello: wire::Hello = wire::read(&mut stream).map_err(Error::Fence)?;
    let notify = wire::receive_fd(&stream).map_err(Error::Fence)?;
    if peer_pid(&stream).map_err(Error::Fence)? != pid
        || hello.parent_pid != pid as u32
        || hello.generation != generation
        || hello.landlock_abi < 3
        || hello.ruleset_hash != linux::ruleset_hash()
        || hello.seccomp_hash != linux::filter_hash(hello.parent_pid, hello.bootstrap_fd)
        || hello.capabilities.bytes().any(|c| c != b'0')
    {
        return Err(Error::Fence(io::Error::other(
            "native fence proof mismatch",
        )));
    }
    wire::write(&mut stream, &true).map_err(Error::Fence)?;
    stream.set_read_timeout(None).map_err(Error::Fence)?;
    let alive = Arc::new(AtomicBool::new(true));
    let state = Arc::new(State {
        sockets: Mutex::new(HashMap::new()),
        requests: Mutex::new(HashMap::new()),
        relay,
        alive: Arc::clone(&alive),
        inventory: Mutex::default(),
    });
    std::thread::spawn(move || {
        let _ = serve(stream, Arc::new(notify), state);
    });
    Ok(NativeFenceGuard { alive })
}
pub struct NativeFenceGuard {
    alive: Arc<AtomicBool>,
}
impl Drop for NativeFenceGuard {
    fn drop(&mut self) {
        self.alive.store(false, Ordering::Release);
    }
}
