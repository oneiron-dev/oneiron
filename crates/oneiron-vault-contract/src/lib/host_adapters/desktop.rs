//! The daemon position's adapters: systemd on Linux, launchd on macOS, and a
//! plain bind when neither started the process.
//!
//! The service manager owns the socket and the secrets; the engine adopts the
//! one and reads the other. Readiness goes back as sd_notify `READY=1` under
//! systemd; launchd has no readiness protocol. While a wake pass runs on a
//! plugged-in laptop, an idle-sleep assertion keeps it awake; display sleep
//! is never blocked and a manual sleep or closed lid always wins.

use super::native::wait;
use crate::host::{Host, HostFuture, HostLimits};
use std::{
    collections::BTreeMap,
    ffi::OsStr,
    io::{self, Write},
    net::{SocketAddr, TcpListener},
    os::{
        fd::{FromRawFd, OwnedFd},
        unix::{
            ffi::OsStrExt,
            net::{UnixDatagram, UnixListener},
        },
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::SystemTime,
};
use tokio::sync::Notify;
use zeroize::Zeroizing;

mod power;

type Hook = Box<dyn FnMut() -> anyhow::Result<()> + Send>;

/// A socket the service manager bound for this process.
#[derive(Debug)]
pub enum ActivatedListener {
    Tcp(TcpListener),
    Unix(UnixListener),
}
impl From<TcpListener> for ActivatedListener {
    fn from(listener: TcpListener) -> Self {
        Self::Tcp(listener)
    }
}
impl From<UnixListener> for ActivatedListener {
    fn from(listener: UnixListener) -> Self {
        Self::Unix(listener)
    }
}
impl ActivatedListener {
    fn try_clone(&self) -> io::Result<Self> {
        Ok(match self {
            Self::Tcp(listener) => Self::Tcp(listener.try_clone()?),
            Self::Unix(listener) => Self::Unix(listener.try_clone()?),
        })
    }

    /// Reads the family back from the socket itself: std refuses a unix
    /// address on an inet socket and the reverse, so the claim is checked.
    fn adopt(fd: OwnedFd) -> anyhow::Result<Self> {
        let unix = UnixListener::from(fd);
        if unix.local_addr().is_ok() {
            return Ok(Self::Unix(unix));
        }
        let tcp = TcpListener::from(OwnedFd::from(unix));
        tcp.local_addr()
            .map_err(|_| anyhow::anyhow!("activated descriptor is not a listening socket"))?;
        Ok(Self::Tcp(tcp))
    }
}

/// Where a host's secrets live. Lookups are by exact name and never fall
/// back to the environment; values are never logged.
pub enum SecretSource {
    Map(BTreeMap<String, Zeroizing<Vec<u8>>>),
    /// systemd's `$CREDENTIALS_DIRECTORY`, one file per credential.
    Directory(PathBuf),
    /// The macOS login keychain: generic passwords under this service.
    Keychain(String),
}
impl SecretSource {
    fn get(&self, name: &str) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        let plain = !name.is_empty()
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
            && !name.starts_with('.');
        anyhow::ensure!(plain, "unknown host secret");
        match self {
            Self::Map(secrets) => secrets
                .get(name)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("unknown host secret")),
            Self::Directory(dir) => Ok(Zeroizing::new(
                std::fs::read(dir.join(name))
                    .map_err(|_| anyhow::anyhow!("unknown host secret"))?,
            )),
            Self::Keychain(service) => {
                let output = Command::new("/usr/bin/security")
                    .args(["find-generic-password", "-s", service, "-a", name, "-w"])
                    .env_clear()
                    .stdin(Stdio::null())
                    .stderr(Stdio::null())
                    .output()?;
                anyhow::ensure!(output.status.success(), "unknown host secret");
                let mut value = Zeroizing::new(output.stdout);
                if value.last() == Some(&b'\n') {
                    value.pop();
                }
                Ok(value)
            }
        }
    }
}

/// When a live wake pass may hold the machine awake (ruled 2026-10-08).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AwakePolicy {
    /// Only while on mains power. On battery normal idle sleep holds.
    #[default]
    PluggedIn,
    Always,
    Never,
}

struct AwakeState {
    program: &'static str,
    args: Vec<String>,
    policy: AwakePolicy,
    /// What a PluggedIn assertion follows the power source by (FIX 9547).
    watch: power::Watch,
    /// The host's notice that power-source changes are not observed, said
    /// at most once.
    notice: OnceLock<Box<dyn Fn() + Send + Sync>>,
    told: AtomicBool,
    held: Mutex<Held>,
}

impl AwakeState {
    /// One assertion: the child that holds the machine awake while it runs.
    fn assertion(&self) -> Option<Child> {
        Command::new(self.program)
            .args(&self.args)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .ok()
    }

    /// Says once, through the host's notice, that power-source changes are
    /// not observed here.
    fn unobserved(&self) {
        if let Some(notice) = self.notice.get()
            && !self.told.swap(true, Ordering::Relaxed)
        {
            notice();
        }
    }
}

/// The holders, the one assertion they share and, under PluggedIn, the
/// power observer their set started.
#[derive(Default)]
struct Held {
    holders: usize,
    /// Moves on at each first holder, so an ended set's observer changes
    /// nothing.
    generation: u64,
    assertion: Option<Child>,
    observer: Option<power::PowerObserver>,
}

/// One idle-sleep assertion shared by every live pass: the first holder
/// takes it and the last one out releases it. Under PluggedIn it follows the
/// power source while held: released on battery, taken again on mains.
#[derive(Clone, Default)]
pub struct KeepAwake(Option<Arc<AwakeState>>);
impl KeepAwake {
    /// A logind idle inhibitor. Suspend on lid close or by hand still wins.
    pub fn systemd(policy: AwakePolicy) -> Self {
        Self::with(
            "/usr/bin/systemd-inhibit",
            [
                "--what=idle",
                "--who=oneiron",
                "--why=a wake pass is running",
                "--mode=block",
                "sleep",
                "infinity",
            ]
            .map(String::from)
            .to_vec(),
            policy,
            power::UDEV_WATCH,
        )
    }
    /// A PreventUserIdleSystemSleep assertion; `-i` leaves display sleep be.
    pub fn launchd(policy: AwakePolicy) -> Self {
        Self::with(
            "/usr/bin/caffeinate",
            vec!["-i".to_owned()],
            policy,
            power::PMSET_WATCH,
        )
    }
    fn with(
        program: &'static str,
        args: Vec<String>,
        policy: AwakePolicy,
        watch: power::Watch,
    ) -> Self {
        Self(Some(Arc::new(AwakeState {
            program,
            args,
            policy,
            watch,
            notice: OnceLock::new(),
            told: AtomicBool::new(false),
            held: Mutex::new(Held::default()),
        })))
    }
    /// Calls `notice`, once, if this host's power-source changes cannot be
    /// observed, so a PluggedIn assertion follows only the source sampled as
    /// its holders began (FIX 9547). The first notice set stands.
    pub fn on_unobserved(&self, notice: impl Fn() + Send + Sync + 'static) {
        if let Some(state) = &self.0 {
            let _ = state.notice.set(Box::new(notice));
        }
    }
    /// Holds the machine awake until the guard drops.
    pub fn hold(&self) -> AwakeGuard {
        if let Some(state) = &self.0 {
            let mut observe = None;
            if let Ok(mut held) = state.held.lock() {
                held.holders += 1;
                if held.holders == 1 {
                    held.generation = held.generation.wrapping_add(1);
                    match state.policy {
                        AwakePolicy::Never => {}
                        AwakePolicy::Always => held.assertion = state.assertion(),
                        // The set's observer takes it on mains power.
                        AwakePolicy::PluggedIn => observe = Some(held.generation),
                    }
                }
            }
            // Started outside the lock: it samples the source and spawns.
            if let Some(generation) = observe {
                power::PowerObserver::start(state, generation);
            }
        }
        AwakeGuard(self.0.clone())
    }
}

pub struct AwakeGuard(Option<Arc<AwakeState>>);
impl Drop for AwakeGuard {
    fn drop(&mut self) {
        let Some(state) = &self.0 else {
            return;
        };
        let mut ended = (None, None);
        if let Ok(mut held) = state.held.lock() {
            held.holders = held.holders.saturating_sub(1);
            if held.holders == 0 {
                ended = (held.assertion.take(), held.observer.take());
            }
        }
        // Reaped and joined outside the lock, which the observer takes.
        release(ended.0);
        drop(ended.1);
    }
}

/// Ends an assertion or observer child: killed, then reaped.
fn release(child: Option<Child>) {
    if let Some(mut child) = child {
        let _ = child.kill();
        let _ = child.wait();
    }
}

/// The cgroup v2 ceilings systemd set for this unit, read back.
fn cgroup_limits() -> HostLimits {
    let mut limits = HostLimits::unbounded();
    let Some(dir) = std::fs::read_to_string("/proc/self/cgroup")
        .ok()
        .and_then(|text| {
            text.lines()
                .find_map(|line| line.strip_prefix("0::"))
                .map(|path| Path::new("/sys/fs/cgroup").join(path.trim_start_matches('/')))
        })
    else {
        return limits;
    };
    if let Ok(memory) = std::fs::read_to_string(dir.join("memory.max"))
        && let Ok(bytes) = memory.trim().parse::<u64>()
    {
        limits.memory_bytes = bytes;
    }
    if let Ok(cpu) = std::fs::read_to_string(dir.join("cpu.max")) {
        let mut parts = cpu.split_whitespace();
        if let (Some(Ok(quota)), Some(Ok(period))) = (
            parts.next().map(str::parse::<u64>),
            parts.next().map(str::parse::<u64>),
        ) && period > 0
        {
            limits.cpu_millis_per_second = u32::try_from(quota * 1000 / period).unwrap_or(u32::MAX);
        }
    }
    limits
}

/// The process limits launchd's resource keys set, read back.
#[cfg(target_os = "macos")]
fn rlimit_limits() -> HostLimits {
    let mut limits = HostLimits::unbounded();
    // SAFETY: all-zero is a valid rlimit to receive into.
    let mut current: libc::rlimit = unsafe { std::mem::zeroed() };
    // SAFETY: current is valid for writes of one rlimit.
    if unsafe { libc::getrlimit(libc::RLIMIT_AS, &mut current) } == 0
        && current.rlim_cur != libc::RLIM_INFINITY
    {
        limits.memory_bytes = u64::try_from(current.rlim_cur).unwrap_or(u64::MAX);
    }
    limits
}

/// Connects `NOTIFY_SOCKET`, including Linux's abstract namespace (`@`).
fn notify_socket(path: &OsStr) -> io::Result<UnixDatagram> {
    let socket = UnixDatagram::unbound()?;
    match path.as_bytes().strip_prefix(b"@") {
        #[cfg(target_os = "linux")]
        Some(name) => {
            use std::os::linux::net::SocketAddrExt;
            socket.connect_addr(&std::os::unix::net::SocketAddr::from_abstract_name(name)?)?;
        }
        #[cfg(not(target_os = "linux"))]
        Some(_) => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "abstract socket",
            ));
        }
        None => socket.connect(Path::new(path))?,
    }
    Ok(socket)
}

/// Owned activation socket, secret source, and readiness channel. OS fd
/// discovery stays at process entry; adapters never own a raw fd twice.
pub struct SystemdHost {
    listener: ActivatedListener,
    secrets: SecretSource,
    limits: HostLimits,
    ready: Hook,
    stop: Hook,
    wake: Arc<Notify>,
}
impl SystemdHost {
    pub fn new(
        listener: impl Into<ActivatedListener>,
        secrets: BTreeMap<String, Zeroizing<Vec<u8>>>,
        limits: HostLimits,
        ready: impl FnMut() -> anyhow::Result<()> + Send + 'static,
        stop: impl FnMut() -> anyhow::Result<()> + Send + 'static,
    ) -> Self {
        Self::assemble(
            listener.into(),
            SecretSource::Map(secrets),
            limits,
            Box::new(ready),
            Box::new(stop),
        )
    }
    fn assemble(
        listener: ActivatedListener,
        secrets: SecretSource,
        limits: HostLimits,
        ready: Hook,
        stop: Hook,
    ) -> Self {
        Self {
            listener,
            secrets,
            limits,
            ready,
            stop,
            wake: Arc::new(Notify::new()),
        }
    }
    pub fn wake_handle(&self) -> Arc<Notify> {
        Arc::clone(&self.wake)
    }
    /// sd_notify through an already-connected notification socket.
    pub fn with_notify_socket(
        listener: impl Into<ActivatedListener>,
        secrets: BTreeMap<String, Zeroizing<Vec<u8>>>,
        limits: HostLimits,
        notify: UnixDatagram,
        stop: impl FnMut() -> anyhow::Result<()> + Send + 'static,
    ) -> Self {
        Self::new(
            listener,
            secrets,
            limits,
            move || {
                notify.send(b"READY=1")?;
                Ok(())
            },
            stop,
        )
    }

    /// Socket activation, read once at process entry. `None` when systemd did
    /// not pass this process a socket. The first passed descriptor is the
    /// listener; credentials come from `LoadCredential=`; limits are the
    /// unit's cgroup ceilings; `READY=1` and `STOPPING=1` go to
    /// `NOTIFY_SOCKET` when the unit is `Type=notify`.
    pub fn from_env() -> anyhow::Result<Option<Self>> {
        let for_us = std::env::var("LISTEN_PID")
            .ok()
            .and_then(|pid| pid.trim().parse::<u32>().ok())
            == Some(std::process::id());
        let count = std::env::var("LISTEN_FDS")
            .ok()
            .and_then(|count| count.trim().parse::<u32>().ok())
            .unwrap_or(0);
        if !for_us || count == 0 {
            return Ok(None);
        }
        // SAFETY: systemd passed LISTEN_FDS descriptors from 3 (SD_LISTEN_FDS_START)
        // to this very pid, checked above; the first one is adopted here once.
        let listener = ActivatedListener::adopt(unsafe { OwnedFd::from_raw_fd(3) })?;
        let secrets = std::env::var_os("CREDENTIALS_DIRECTORY").map_or_else(
            || SecretSource::Map(BTreeMap::new()),
            |dir| SecretSource::Directory(dir.into()),
        );
        let (ready, stop): (Hook, Hook) = match std::env::var_os("NOTIFY_SOCKET") {
            Some(path) => {
                let ready = notify_socket(&path)?;
                let stopping = ready.try_clone()?;
                (
                    Box::new(move || {
                        ready.send(b"READY=1")?;
                        Ok(())
                    }),
                    Box::new(move || {
                        stopping.send(b"STOPPING=1")?;
                        Ok(())
                    }),
                )
            }
            None => (Box::new(|| Ok(())), Box::new(|| Ok(()))),
        };
        Ok(Some(Self::assemble(
            listener,
            secrets,
            cgroup_limits(),
            ready,
            stop,
        )))
    }
}
impl Host for SystemdHost {
    type Listener = ActivatedListener;
    fn listener(&mut self) -> anyhow::Result<Self::Listener> {
        Ok(self.listener.try_clone()?)
    }
    fn ready(&mut self) -> anyhow::Result<()> {
        (self.ready)()
    }
    fn secret(&mut self, name: &str) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        self.secrets.get(name)
    }
    fn on_stop(&mut self) -> anyhow::Result<()> {
        (self.stop)()
    }
    fn limits(&self) -> HostLimits {
        self.limits
    }
    fn idle(&mut self, next: Option<SystemTime>) -> HostFuture<'_> {
        wait(&self.wake, next)
    }
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn launch_activate_socket(
        name: *const libc::c_char,
        fds: *mut *mut libc::c_int,
        count: *mut libc::size_t,
    ) -> libc::c_int;
}

/// launchd supplies an owned activation socket; a supervisor that spawns the
/// daemon itself may hand over a readiness pipe instead.
pub struct LaunchdHost(SystemdHost);
impl LaunchdHost {
    pub fn new(
        listener: impl Into<ActivatedListener>,
        secrets: BTreeMap<String, Zeroizing<Vec<u8>>>,
        limits: HostLimits,
        mut ready: impl Write + Send + 'static,
        stop: impl FnMut() -> anyhow::Result<()> + Send + 'static,
    ) -> Self {
        Self(SystemdHost::new(
            listener,
            secrets,
            limits,
            move || {
                ready.write_all(&[crate::READY_BYTE])?;
                ready.flush()?;
                Ok(())
            },
            stop,
        ))
    }

    /// The plist's `Sockets/<socket>` entry, read once at process entry.
    /// `None` when launchd did not start this process with that socket.
    /// Secrets are keychain generic passwords under `keychain_service`.
    #[cfg(target_os = "macos")]
    pub fn activate(socket: &str, keychain_service: &str) -> anyhow::Result<Option<Self>> {
        let name = std::ffi::CString::new(socket)?;
        let mut fds: *mut libc::c_int = std::ptr::null_mut();
        let mut count: libc::size_t = 0;
        // SAFETY: name is NUL-terminated; fds and count are valid out-pointers.
        let rc = unsafe { launch_activate_socket(name.as_ptr(), &mut fds, &mut count) };
        if matches!(rc, libc::ESRCH | libc::ENOENT) {
            return Ok(None);
        }
        anyhow::ensure!(
            rc == 0,
            "launch_activate_socket: {}",
            io::Error::from_raw_os_error(rc)
        );
        // SAFETY: on success launchd returned `count` descriptors in a malloc'd
        // array this process now owns.
        let raw = unsafe { std::slice::from_raw_parts(fds, count) }.to_vec();
        // SAFETY: the array came from malloc inside launch_activate_socket.
        unsafe { libc::free(fds.cast()) };
        let mut owned: Vec<OwnedFd> = raw
            .into_iter()
            .map(|fd| {
                // SAFETY: each descriptor is distinct and owned by this process.
                unsafe { OwnedFd::from_raw_fd(fd) }
            })
            .collect();
        anyhow::ensure!(!owned.is_empty(), "launchd passed no socket");
        let listener = ActivatedListener::adopt(owned.swap_remove(0))?;
        Ok(Some(Self(SystemdHost::assemble(
            listener,
            SecretSource::Keychain(keychain_service.to_owned()),
            rlimit_limits(),
            Box::new(|| Ok(())),
            Box::new(|| Ok(())),
        ))))
    }
    pub fn wake_handle(&self) -> Arc<Notify> {
        self.0.wake_handle()
    }
}
impl Host for LaunchdHost {
    type Listener = ActivatedListener;
    fn listener(&mut self) -> anyhow::Result<Self::Listener> {
        self.0.listener()
    }
    fn ready(&mut self) -> anyhow::Result<()> {
        self.0.ready()
    }
    fn secret(&mut self, name: &str) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        self.0.secret(name)
    }
    fn on_stop(&mut self) -> anyhow::Result<()> {
        self.0.on_stop()
    }
    fn limits(&self) -> HostLimits {
        self.0.limits()
    }
    fn idle(&mut self, next: Option<SystemTime>) -> HostFuture<'_> {
        self.0.idle(next)
    }
}

/// Where the desktop daemon runs, chosen once at process entry: systemd
/// socket activation, launchd activation, or a plain bind of the configured
/// address. Each announces itself by [`DesktopHost::adapter`].
pub enum DesktopHost {
    Systemd(SystemdHost),
    Launchd(LaunchdHost),
    Plain { addr: SocketAddr, wake: Arc<Notify> },
}
impl DesktopHost {
    /// launchd's socket key and keychain service are the plist's names.
    pub fn detect(
        addr: SocketAddr,
        launchd_socket: &str,
        keychain_service: &str,
    ) -> anyhow::Result<Self> {
        if let Some(host) = SystemdHost::from_env()? {
            return Ok(Self::Systemd(host));
        }
        #[cfg(target_os = "macos")]
        if let Some(host) = LaunchdHost::activate(launchd_socket, keychain_service)? {
            return Ok(Self::Launchd(host));
        }
        let _ = (launchd_socket, keychain_service);
        Ok(Self::Plain {
            addr,
            wake: Arc::new(Notify::new()),
        })
    }
    pub fn adapter(&self) -> &'static str {
        match self {
            Self::Systemd(_) => "systemd",
            Self::Launchd(_) => "launchd",
            Self::Plain { .. } => "in_process",
        }
    }
    /// The idle-sleep assertion this host holds while a wake pass runs.
    pub fn keep_awake(&self, policy: AwakePolicy) -> KeepAwake {
        match self {
            Self::Systemd(_) => KeepAwake::systemd(policy),
            Self::Launchd(_) => KeepAwake::launchd(policy),
            Self::Plain { .. } if cfg!(target_os = "macos") => KeepAwake::launchd(policy),
            Self::Plain { .. } => KeepAwake::default(),
        }
    }
}
impl Host for DesktopHost {
    type Listener = ActivatedListener;
    fn listener(&mut self) -> anyhow::Result<Self::Listener> {
        match self {
            Self::Systemd(host) => host.listener(),
            Self::Launchd(host) => host.listener(),
            Self::Plain { addr, .. } => Ok(ActivatedListener::Tcp(TcpListener::bind(*addr)?)),
        }
    }
    fn ready(&mut self) -> anyhow::Result<()> {
        match self {
            Self::Systemd(host) => host.ready(),
            Self::Launchd(host) => host.ready(),
            Self::Plain { .. } => Ok(()),
        }
    }
    /// A plain bind has no secret store: config and environment stay the
    /// daemon's only sources there.
    fn secret(&mut self, name: &str) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        match self {
            Self::Systemd(host) => host.secret(name),
            Self::Launchd(host) => host.secret(name),
            Self::Plain { .. } => anyhow::bail!("unknown host secret"),
        }
    }
    fn on_stop(&mut self) -> anyhow::Result<()> {
        match self {
            Self::Systemd(host) => host.on_stop(),
            Self::Launchd(host) => host.on_stop(),
            Self::Plain { .. } => Ok(()),
        }
    }
    fn limits(&self) -> HostLimits {
        match self {
            Self::Systemd(host) => host.limits(),
            Self::Launchd(host) => host.limits(),
            Self::Plain { .. } => HostLimits::unbounded(),
        }
    }
    fn idle(&mut self, next: Option<SystemTime>) -> HostFuture<'_> {
        match self {
            Self::Systemd(host) => host.idle(next),
            Self::Launchd(host) => host.idle(next),
            Self::Plain { wake, .. } => wait(wake, next),
        }
    }
}
