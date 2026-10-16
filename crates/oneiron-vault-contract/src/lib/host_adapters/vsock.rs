//! The microVM adapter's guest half: AF_VSOCK sockets and the Firecracker
//! backend an engine uses when it runs as a vault VM's only process.
//!
//! The host half needs none of this. Firecracker maps every guest port onto a
//! host unix socket ([`crate::vm`]), so the VMM driver speaks unix sockets.

use super::{EdgeBackend, SandboxBackend};
use crate::host::{HostFuture, HostLimits};
use crate::vm::{
    MAX_VM_FRAME, VM_BOOT_PORT, VM_HOST_CID, VM_HTTP_PORT, VmGuestFrame, VmHostFrame,
    decode_vm_frame, encode_vm_frame,
};
use crate::{Credentials, READY_BYTE, read_credentials};
use std::{
    fs::File,
    io::{self, BufRead, BufReader, Read, Write},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, ready},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf, unix::AsyncFd};
use tokio::sync::Notify;
use zeroize::Zeroizing;

const CID_ANY: u32 = u32::MAX;
const ADDRESS_LEN: libc::socklen_t = std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t;
/// How long a guest keeps dialling the boot port after a snapshot restore.
const REJOIN_WINDOW: Duration = Duration::from_secs(10);

fn socket(flags: libc::c_int) -> io::Result<OwnedFd> {
    // SAFETY: socket takes no pointers; a non-negative result is a new fd.
    let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC | flags, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the descriptor was just created and nothing else owns it.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn address(cid: u32, port: u32) -> libc::sockaddr_vm {
    // SAFETY: all-zero is a valid sockaddr_vm; reserved bytes must be zero.
    let mut address: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
    address.svm_family = libc::AF_VSOCK as libc::sa_family_t;
    address.svm_cid = cid;
    address.svm_port = port;
    address
}

fn connect_raw(fd: &OwnedFd, cid: u32, port: u32) -> io::Result<()> {
    let address = address(cid, port);
    // SAFETY: address is initialized and ADDRESS_LEN is its exact size.
    let rc = unsafe { libc::connect(fd.as_raw_fd(), (&raw const address).cast(), ADDRESS_LEN) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// A blocking stream to the host, for the boot channel before anything serves.
pub fn connect_blocking(cid: u32, port: u32) -> io::Result<File> {
    let fd = socket(0)?;
    connect_raw(&fd, cid, port)?;
    Ok(File::from(fd))
}

/// A listening guest port. Bind inside a Tokio runtime with IO enabled.
pub struct VsockListener(AsyncFd<OwnedFd>);
impl VsockListener {
    pub fn bind(port: u32) -> io::Result<Self> {
        let fd = socket(libc::SOCK_NONBLOCK)?;
        let address = address(CID_ANY, port);
        // SAFETY: address is initialized and ADDRESS_LEN is its exact size.
        if unsafe { libc::bind(fd.as_raw_fd(), (&raw const address).cast(), ADDRESS_LEN) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fd is a bound stream socket owned here.
        if unsafe { libc::listen(fd.as_raw_fd(), 128) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(AsyncFd::new(fd)?))
    }

    /// The next connection and its peer's context id. In a Firecracker guest
    /// the only possible peer is the host.
    pub async fn accept(&self) -> io::Result<(VsockStream, u32)> {
        loop {
            let mut guard = self.0.readable().await?;
            let accepted = guard.try_io(|listener| {
                // SAFETY: all-zero is a valid sockaddr_vm to receive into.
                let mut peer: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
                let mut len = ADDRESS_LEN;
                // SAFETY: peer and len are valid for writes of the stated size.
                let fd = unsafe {
                    libc::accept4(
                        listener.as_raw_fd(),
                        (&raw mut peer).cast(),
                        &mut len,
                        libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                    )
                };
                if fd < 0 {
                    return Err(io::Error::last_os_error());
                }
                // SAFETY: accept4 returned a new descriptor nothing else owns.
                Ok((unsafe { OwnedFd::from_raw_fd(fd) }, peer.svm_cid))
            });
            match accepted {
                Ok(Ok((fd, cid))) => return Ok((VsockStream(AsyncFd::new(fd)?), cid)),
                Ok(Err(error)) => return Err(error),
                Err(_would_block) => continue,
            }
        }
    }
}

/// One connected vsock stream.
pub struct VsockStream(AsyncFd<OwnedFd>);
impl VsockStream {
    pub async fn connect(cid: u32, port: u32) -> io::Result<Self> {
        let fd = socket(libc::SOCK_NONBLOCK)?;
        if let Err(error) = connect_raw(&fd, cid, port)
            && error.raw_os_error() != Some(libc::EINPROGRESS)
        {
            return Err(error);
        }
        let stream = AsyncFd::new(fd)?;
        let writable = stream.writable().await?;
        let mut error: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: error and len are valid for writes of the stated size.
        let rc = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                (&raw mut error).cast(),
                &mut len,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        if error != 0 {
            return Err(io::Error::from_raw_os_error(error));
        }
        drop(writable);
        Ok(Self(stream))
    }
}

impl AsyncRead for VsockStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            let mut guard = ready!(self.0.poll_read_ready(cx))?;
            let unfilled = buf.initialize_unfilled();
            let read = guard.try_io(|fd| {
                // SAFETY: unfilled is valid for writes of its whole length.
                let n = unsafe { libc::read(fd.as_raw_fd(), unfilled.as_mut_ptr().cast(), unfilled.len()) };
                usize::try_from(n).map_err(|_| io::Error::last_os_error())
            });
            match read {
                Ok(Ok(n)) => {
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(error)) => return Poll::Ready(Err(error)),
                Err(_would_block) => continue,
            }
        }
    }
}

impl AsyncWrite for VsockStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            let mut guard = ready!(self.0.poll_write_ready(cx))?;
            let written = guard.try_io(|fd| {
                // SAFETY: data is valid for reads of its whole length.
                let n = unsafe {
                    libc::send(fd.as_raw_fd(), data.as_ptr().cast(), data.len(), libc::MSG_NOSIGNAL)
                };
                usize::try_from(n).map_err(|_| io::Error::last_os_error())
            });
            match written {
                Ok(result) => return Poll::Ready(result),
                Err(_would_block) => continue,
            }
        }
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // SAFETY: the descriptor is a connected socket owned by self.
        if unsafe { libc::shutdown(self.0.as_raw_fd(), libc::SHUT_WR) } != 0 {
            return Poll::Ready(Err(io::Error::last_os_error()));
        }
        Poll::Ready(Ok(()))
    }
}

/// What the host asked for on the boot channel. Each request leaves a permit,
/// so a request that lands before anyone waits is not lost.
#[derive(Default)]
struct GuestEvents {
    sleep: Notify,
    resumed: Notify,
    stop: Notify,
}

struct Channel {
    vault: String,
    writer: Mutex<File>,
    events: GuestEvents,
}
impl Channel {
    fn send(&self, frame: &VmGuestFrame) -> anyhow::Result<()> {
        let line = encode_vm_frame(frame)?;
        let mut writer = self
            .writer
            .lock()
            .map_err(|_| anyhow::anyhow!("boot channel poisoned"))?;
        writer.write_all(line.as_bytes())?;
        Ok(writer.flush()?)
    }

    /// Reads host frames until the vault ends. A lost channel is the vsock
    /// reset of a snapshot restore: dial back in, name the vault, carry on.
    fn read_frames(self: Arc<Self>, mut reader: BufReader<File>) {
        loop {
            let mut line = String::new();
            let read = (&mut reader)
                .take(MAX_VM_FRAME as u64 + 1)
                .read_line(&mut line);
            match read {
                Ok(n) if n > 0 => match decode_vm_frame::<VmHostFrame>(&line) {
                    Ok(VmHostFrame::Sleep) => self.events.sleep.notify_one(),
                    Ok(VmHostFrame::Resumed) => self.events.resumed.notify_one(),
                    Ok(VmHostFrame::Stop) => self.events.stop.notify_one(),
                    Err(_) => {}
                },
                _ => match self.rejoin() {
                    Ok(next) => reader = next,
                    Err(_) => {
                        self.events.stop.notify_one();
                        return;
                    }
                },
            }
        }
    }

    fn rejoin(&self) -> anyhow::Result<BufReader<File>> {
        let (writer, reader) = join(&self.vault)?;
        *self
            .writer
            .lock()
            .map_err(|_| anyhow::anyhow!("boot channel poisoned"))? = writer;
        Ok(reader)
    }
}

/// Opens a lifecycle connection. After a restore the host's side may still be
/// coming up, so the dial is retried for a bounded window.
fn join(vault: &str) -> anyhow::Result<(File, BufReader<File>)> {
    let deadline = std::time::Instant::now() + REJOIN_WINDOW;
    let mut stream = loop {
        match connect_blocking(VM_HOST_CID, VM_BOOT_PORT) {
            Ok(stream) => break stream,
            Err(error) if std::time::Instant::now() >= deadline => return Err(error.into()),
            Err(_) => std::thread::sleep(Duration::from_millis(50)),
        }
    };
    let line = encode_vm_frame(&VmGuestFrame::Join {
        vault: vault.to_owned(),
    })?;
    stream.write_all(line.as_bytes())?;
    stream.flush()?;
    let reader = BufReader::new(stream.try_clone()?);
    Ok((stream, reader))
}

/// The ready guest's side of the boot channel, shareable with the task that
/// answers the host's sleep and stop requests.
#[derive(Clone)]
pub struct GuestLink(Arc<Channel>);
impl GuestLink {
    /// Resolves when the host asks the vault to go idle.
    pub async fn sleep_requested(&self) {
        self.0.events.sleep.notified().await;
    }
    /// Resolves when the host asks the vault to stop, or when the boot
    /// channel is lost for good.
    pub async fn stop_requested(&self) {
        self.0.events.stop.notified().await;
    }
    /// Reports the next wake and parks until the host resumes the guest, or
    /// the wake comes due while the host left it running. The host keeps
    /// `next_wake` before it pauses or snapshots, so the wake is armed first.
    pub async fn idle(&self, next_wake: Option<SystemTime>, snapshot_ok: bool) -> anyhow::Result<()> {
        self.0.send(&VmGuestFrame::Idle {
            next_wake: next_wake
                .map(|at| at.duration_since(UNIX_EPOCH).map_or(0, |since| since.as_secs())),
            snapshot_ok,
        })?;
        let resumed = self.0.events.resumed.notified();
        match next_wake {
            Some(at) => {
                let wait = at.duration_since(SystemTime::now()).unwrap_or_default();
                tokio::select! { () = resumed => {}, () = tokio::time::sleep(wait) => {} }
            }
            None => resumed.await,
        }
        Ok(())
    }
}

/// The engine inside a Firecracker vault VM. Boot dials the credential
/// connection; secrets are the frame read there up to the host's half-close;
/// ready writes the ready byte back and joins the lifecycle connection; idle
/// reports the next wake and parks until the host resumes it.
pub struct FirecrackerGuest {
    vault: String,
    boot: Option<File>,
    link: Option<GuestLink>,
    credentials: Option<Credentials>,
    snapshot_ok: Box<dyn Fn() -> bool + Send + Sync>,
}
impl FirecrackerGuest {
    /// Until a probe is given, idle never lets the host snapshot RAM.
    pub fn new(vault: String) -> Self {
        Self {
            vault,
            boot: None,
            link: None,
            credentials: None,
            snapshot_ok: Box::new(|| false),
        }
    }
    /// `probe` answers whether the guest's RAM may reach disk right now. It
    /// must say no while an off-record stretch is open.
    #[must_use]
    pub fn with_snapshot_probe(mut self, probe: impl Fn() -> bool + Send + Sync + 'static) -> Self {
        self.snapshot_ok = Box::new(probe);
        self
    }
    /// Present once ready has been signalled.
    pub fn link(&self) -> Option<GuestLink> {
        self.link.clone()
    }
    pub fn clear_secrets(&mut self) {
        self.credentials = None;
    }
}

/// The VM's size is its limit: the host sized memory and vCPUs at boot.
fn guest_limits() -> HostLimits {
    let memory_bytes = std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|info| {
            info.lines().find_map(|line| {
                let kib = line.strip_prefix("MemTotal:")?.trim().strip_suffix("kB")?;
                kib.trim().parse::<u64>().ok()
            })
        })
        .map_or(u64::MAX, |kib| kib.saturating_mul(1024));
    let cpus = std::thread::available_parallelism()
        .map_or(1, |n| u32::try_from(n.get()).unwrap_or(u32::MAX));
    HostLimits {
        memory_bytes,
        cpu_millis_per_second: cpus.saturating_mul(1000),
    }
}

impl SandboxBackend for FirecrackerGuest {
    type Listener = VsockListener;
    fn listener(&mut self) -> anyhow::Result<VsockListener> {
        Ok(VsockListener::bind(VM_HTTP_PORT)?)
    }
    fn ready(&mut self) -> anyhow::Result<()> {
        let mut boot = self
            .boot
            .take()
            .ok_or_else(|| anyhow::anyhow!("vault VM readiness already signalled"))?;
        boot.write_all(&[READY_BYTE])?;
        boot.flush()?;
        drop(boot);
        let (writer, reader) = join(&self.vault)?;
        let channel = Arc::new(Channel {
            vault: self.vault.clone(),
            writer: Mutex::new(writer),
            events: GuestEvents::default(),
        });
        self.link = Some(GuestLink(Arc::clone(&channel)));
        std::thread::Builder::new()
            .name("vault-vm-boot".into())
            .spawn(move || channel.read_frames(reader))?;
        Ok(())
    }
    fn secret(&mut self, name: &str) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        if !matches!(name, "dek" | "spawn_token") {
            anyhow::bail!("unknown vault VM secret");
        }
        if self.credentials.is_none() {
            let boot = self
                .boot
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("vault VM secrets already consumed"))?;
            self.credentials = Some(read_credentials(boot)?);
        }
        let credentials = self.credentials.as_ref().expect("loaded");
        Ok(Zeroizing::new(if name == "dek" {
            credentials.dek.to_vec()
        } else {
            credentials.token.to_vec()
        }))
    }
    fn stop(&mut self) -> anyhow::Result<()> {
        self.credentials = None;
        match &self.link {
            Some(link) => link.0.send(&VmGuestFrame::Stopping),
            None => Ok(()),
        }
    }
    fn limits(&self) -> HostLimits {
        guest_limits()
    }
    fn sleep(&mut self, next_wake: Option<SystemTime>) -> HostFuture<'_> {
        self.suspend_until(next_wake)
    }
}

impl EdgeBackend for FirecrackerGuest {
    fn boot(&mut self) -> anyhow::Result<()> {
        if self.boot.is_none() && self.link.is_none() {
            self.boot = Some(connect_blocking(VM_HOST_CID, VM_BOOT_PORT)?);
        }
        Ok(())
    }
    fn suspend_until(&mut self, next_wake: Option<SystemTime>) -> HostFuture<'_> {
        let link = self.link.clone();
        let snapshot_ok = (self.snapshot_ok)();
        Box::pin(async move {
            link.ok_or_else(|| anyhow::anyhow!("vault VM not ready"))?
                .idle(next_wake, snapshot_ok)
                .await
        })
    }
}
