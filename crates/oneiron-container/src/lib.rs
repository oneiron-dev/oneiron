//! Container guest sessions for hosts without KVM (OF-318, OSH p4), first slice.
//!
//! A session is one long-lived guest process started through a
//! Docker-compatible CLI. Its stdin and stdout are the only channel to it:
//! the guest gets no network device (`--network none`), a read-only root, a
//! non-root user, no capabilities, no new privileges, tmpfs scratch and the
//! memory, CPU and pid limits its spec names. Nothing is published.
//!
//! Canon's container backend also needs a Landlock ruleset and a seccomp
//! connect relay through the engine's egress proxy (`code-in-oneiron.md`
//! #sandbox). This slice installs neither, so every manifest it writes says
//! `fence_unproven`, and the code-sandbox tier selector does not route to it.

use std::collections::VecDeque;
use std::ffi::OsString;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// The bytes of guest stderr a session keeps for its error reports.
const STDERR_TAIL: usize = 4096;

static GENERATION: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("container runtime {0} is not an absolute path to a file")]
    Runtime(PathBuf),
    #[error("guest image must be pinned as name@sha256:<64 hex> or sha256:<64 hex>")]
    ImageNotPinned,
    #[error("guest user must not be root")]
    RootUser,
    #[error("guest limit {0} must be above zero")]
    ZeroLimit(&'static str),
    #[error("read-only mount {0} must join absolute paths")]
    Mount(PathBuf),
    #[error("container runtime failed to start: {0}")]
    Spawn(#[source] std::io::Error),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// An image reference that names exact bytes, never a tag alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImageRef(String);

impl ImageRef {
    /// Accepts `name@sha256:<64 hex>` or a local image id `sha256:<64 hex>`.
    pub fn pinned(reference: &str) -> Result<Self> {
        let digest = match reference.split_once('@') {
            Some((name, digest)) if !name.is_empty() => digest,
            Some(_) => return Err(Error::ImageNotPinned),
            None => reference,
        };
        let hex = digest
            .strip_prefix("sha256:")
            .ok_or(Error::ImageNotPinned)?;
        if hex.len() != 64
            || !hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::ImageNotPinned);
        }
        Ok(Self(reference.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Resource bounds for one guest. They come from the host's manifest rows.
#[derive(Clone, Copy, Debug)]
pub struct GuestLimits {
    pub memory_mib: u32,
    pub cpu_millis: u32,
    pub pids: u32,
    pub tmpfs_mib: u32,
}

/// How the guest's own system calls are filtered.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GuestSeccomp {
    /// The runtime's default profile.
    RuntimeDefault,
    /// No runtime profile, because the guest program runs its own namespace
    /// and seccomp sandbox (Chromium) and the runtime default denies the user
    /// namespace that sandbox needs.
    GuestSandbox,
}

/// What one session runs.
#[derive(Clone, Debug)]
pub struct GuestSpec {
    pub image: ImageRef,
    pub user: (u32, u32),
    pub limits: GuestLimits,
    pub seccomp: GuestSeccomp,
    /// Host directories the guest may read, as `(host, guest)` absolute paths.
    pub read_only_mounts: Vec<(PathBuf, PathBuf)>,
}

/// What the session proved about its fence, for the session-manifest receipt.
#[derive(Clone, Debug, serde::Serialize)]
pub struct SessionManifest {
    pub backend: &'static str,
    pub runtime: String,
    pub image: String,
    /// blake3 of the full runtime argument list, so a receipt names its flags.
    pub argv_digest: String,
    pub network: &'static str,
    pub seccomp: GuestSeccomp,
    pub generation: u64,
    /// True until the Landlock ruleset and the seccomp connect relay land.
    pub fence_unproven: bool,
}

/// A Docker-compatible container CLI at an absolute path.
#[derive(Clone, Debug)]
pub struct ContainerRuntime {
    program: PathBuf,
}

impl ContainerRuntime {
    pub fn new(program: PathBuf) -> Result<Self> {
        if !program.is_absolute() || !program.is_file() {
            return Err(Error::Runtime(program));
        }
        Ok(Self { program })
    }

    /// Starts one guest. The session owns it: dropping the session removes it.
    pub fn start(&self, spec: &GuestSpec) -> Result<GuestSession> {
        let name = format!("oneiron-guest-{}", uuid::Uuid::now_v7().simple());
        let args = run_args(&name, spec)?;
        let mut digest = blake3::Hasher::new();
        for arg in &args {
            digest.update(arg.as_encoded_bytes());
            digest.update(&[0]);
        }
        let mut child = oneiron_spawn::command(&self.program)
            .args(&args)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(Error::Spawn)?;
        let stderr_tail = Arc::new(Mutex::new(VecDeque::with_capacity(STDERR_TAIL)));
        if let Some(stderr) = child.stderr.take() {
            keep_tail(stderr, Arc::clone(&stderr_tail));
        }
        let manifest = SessionManifest {
            backend: "container-cli",
            runtime: self.program.display().to_string(),
            image: spec.image.as_str().to_owned(),
            argv_digest: digest.finalize().to_hex().to_string(),
            network: "none",
            seccomp: spec.seccomp,
            generation: GENERATION.fetch_add(1, Ordering::Relaxed) + 1,
            fence_unproven: true,
        };
        Ok(GuestSession {
            runtime: self.program.clone(),
            name,
            child,
            manifest,
            stderr_tail,
        })
    }
}

fn run_args(name: &str, spec: &GuestSpec) -> Result<Vec<OsString>> {
    let GuestLimits {
        memory_mib,
        cpu_millis,
        pids,
        tmpfs_mib,
    } = spec.limits;
    for (limit, value) in [
        ("memory_mib", memory_mib),
        ("cpu_millis", cpu_millis),
        ("pids", pids),
        ("tmpfs_mib", tmpfs_mib),
    ] {
        if value == 0 {
            return Err(Error::ZeroLimit(limit));
        }
    }
    if spec.user.0 == 0 || spec.user.1 == 0 {
        return Err(Error::RootUser);
    }
    let mut args: Vec<OsString> = [
        "run".to_owned(),
        "--interactive".to_owned(),
        "--rm".to_owned(),
        format!("--name={name}"),
        "--network=none".to_owned(),
        "--read-only".to_owned(),
        format!("--user={}:{}", spec.user.0, spec.user.1),
        "--cap-drop=ALL".to_owned(),
        "--security-opt=no-new-privileges".to_owned(),
        format!("--memory={memory_mib}m"),
        format!("--memory-swap={memory_mib}m"),
        format!("--cpus={}.{:03}", cpu_millis / 1000, cpu_millis % 1000),
        format!("--pids-limit={pids}"),
        format!("--tmpfs=/tmp:rw,nosuid,nodev,size={tmpfs_mib}m"),
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    if spec.seccomp == GuestSeccomp::GuestSandbox {
        args.push("--security-opt=seccomp=unconfined".into());
    }
    for (host, guest) in &spec.read_only_mounts {
        args.push(read_only_mount(host, guest)?);
    }
    args.push(spec.image.as_str().into());
    Ok(args)
}

fn read_only_mount(host: &Path, guest: &Path) -> Result<OsString> {
    let plain =
        |path: &Path| path.is_absolute() && !path.as_os_str().as_encoded_bytes().contains(&b',');
    if !plain(host) || !plain(guest) {
        return Err(Error::Mount(host.to_owned()));
    }
    let mut mount = OsString::from("--mount=type=bind,readonly,src=");
    mount.push(host);
    mount.push(",dst=");
    mount.push(guest);
    Ok(mount)
}

fn keep_tail(mut stderr: impl Read + Send + 'static, tail: Arc<Mutex<VecDeque<u8>>>) {
    std::thread::spawn(move || {
        let mut buf = [0_u8; 1024];
        while let Ok(n @ 1..) = stderr.read(&mut buf) {
            let Ok(mut tail) = tail.lock() else { return };
            tail.extend(&buf[..n]);
            let excess = tail.len().saturating_sub(STDERR_TAIL);
            tail.drain(..excess);
        }
    });
}

/// One running guest. Dropping it stops and removes the container.
pub struct GuestSession {
    runtime: PathBuf,
    name: String,
    child: Child,
    manifest: SessionManifest,
    stderr_tail: Arc<Mutex<VecDeque<u8>>>,
}

impl GuestSession {
    #[must_use]
    pub fn manifest(&self) -> &SessionManifest {
        &self.manifest
    }

    /// The guest's stdin and stdout, once.
    pub fn take_stdio(&mut self) -> Option<(ChildStdin, ChildStdout)> {
        Some((self.child.stdin.take()?, self.child.stdout.take()?))
    }

    /// The last bytes the guest wrote to stderr, for an error report.
    #[must_use]
    pub fn stderr_tail(&self) -> String {
        self.stderr_tail
            .lock()
            .map(|tail| {
                String::from_utf8_lossy(&tail.iter().copied().collect::<Vec<_>>()).into_owned()
            })
            .unwrap_or_default()
    }

    /// Whether the runtime client is still running the guest.
    pub fn is_running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }
}

impl Drop for GuestSession {
    fn drop(&mut self) {
        drop(self.child.stdin.take());
        let _ = oneiron_spawn::command(&self.runtime)
            .args(["rm", "--force", &self.name])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
