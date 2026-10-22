//! Container sessions with an engine-owned Linux Landlock/seccomp fence.
//! No guest has a network device. The host proxy relays sockets and DNS.

mod cli_env;
mod egress;
mod host_net_floor;
pub mod image_release;
mod relay_protocol;
mod transport;
pub use cli_env::set_cli_env;
pub use egress::{
    EgressRelay, HttpRequest, HttpResponse, LoopbackOperation, LoopbackRefusal,
    LoopbackRefusalReason,
};
pub use host_net_floor::{
    HOST_NET_BYTE_FLOOR, HOST_NET_FD_FLOOR, HOST_NET_WORKER_FLOOR, HostNetFloor, HostNetPermit,
    UnmeteredFloor, floor_saturated, known_floor, saturated_floor,
};
pub use relay_protocol::{RelayReply, RelayRequest, read_relay, write_relay};
pub use transport::{SessionLease, SessionTransport};
#[cfg(target_os = "linux")]
mod launcher;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
mod socket_lifetime;
#[cfg(target_os = "linux")]
mod supervisor;
#[cfg(target_os = "linux")]
mod wire;
#[cfg(target_os = "linux")]
pub use launcher::launch as launch_fenced;
#[cfg(target_os = "linux")]
pub use supervisor::{NativeFenceGuard, serve_native as serve_native_fence};

use crate::cli_env::ApplyCliEnv as _;
use std::collections::VecDeque;
use std::ffi::OsString;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Stdio};
use std::sync::{Arc, Mutex};

/// The bytes of guest stderr a session keeps for its error reports.
const STDERR_TAIL: usize = 4096;

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
    #[error("container fence unavailable: {0}")]
    Fence(#[source] std::io::Error),
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuestSeccomp {
    /// The runtime's default profile.
    RuntimeDefault,
    /// No runtime profile, because the guest program runs its own namespace
    /// and seccomp sandbox (Chromium) and the runtime default denies the user
    /// namespace that sandbox needs.
    GuestSandbox,
    /// Engine Landlock and seccomp user-notification launcher.
    EngineFence,
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
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SessionManifest {
    pub backend: String,
    pub runtime: String,
    pub image: String,
    /// blake3 of the full runtime argument list, so a receipt names its flags.
    pub argv_digest: String,
    pub network: String,
    pub seccomp: GuestSeccomp,
    pub generation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fence_proof: Option<FenceProof>,
    /// Non-Linux or explicitly unfenced sessions never claim isolation.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub fence_unproven: bool,
    /// The guest-image release this launch saw (FIX 8253): evidence only,
    /// separate from the fence evidence, and never a launch decision.
    /// Absent from a record that predates it.
    #[serde(default)]
    pub image_release: image_release::ImageReleaseObservation,
}

/// Evidence verified before a guest can make its first network call.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FenceProof {
    pub ruleset_hash: String,
    pub seccomp_hash: String,
    pub network_routes: Vec<String>,
    pub network_evidence_digest: String,
    pub sandbox_generation: String,
    pub launcher_digest: String,
}

#[derive(Clone, Debug)]
pub struct FenceConfig {
    pub launcher: PathBuf,
    pub startup_timeout: std::time::Duration,
    pub reconnect_window: std::time::Duration,
}
impl FenceConfig {
    /// The engine's companion binary is provisioned by the host, never an
    /// executable chosen from the guest image or workspace.
    pub fn from_env() -> Result<Self> {
        let launcher = std::env::var_os("ONEIRON_FENCE_LAUNCHER")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute() && p.is_file())
            .ok_or_else(|| {
                Error::Fence(std::io::Error::other(
                    "ONEIRON_FENCE_LAUNCHER must name an absolute executable",
                ))
            })?;
        Ok(Self {
            launcher,
            startup_timeout: std::time::Duration::from_secs(30),
            reconnect_window: bridge_reconnect_window()?,
        })
    }
}

/// Host manifest/config row for bridge recovery on either isolated backend.
pub fn bridge_reconnect_window() -> Result<std::time::Duration> {
    let millis = std::env::var("ONEIRON_FENCE_RECONNECT_MS")
        .ok()
        .map(|s| s.parse::<u64>())
        .transpose()
        .map_err(|e| Error::Fence(std::io::Error::other(e)))?
        .unwrap_or(30_000);
    if millis == 0 {
        return Err(Error::ZeroLimit("reconnect_window"));
    }
    Ok(std::time::Duration::from_millis(millis))
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
        let generation = uuid::Uuid::now_v7().simple().to_string();
        let name = format!("oneiron-guest-{generation}");
        let args = run_args(&name, spec)?;
        let mut digest = blake3::Hasher::new();
        for arg in &args {
            digest.update(arg.as_encoded_bytes());
            digest.update(&[0]);
        }
        let image_release = image_release::observe_release(
            None,
            &image_release::ObservedArtifacts::from_image_ref(&spec.image),
            &image_release::HostCapabilities::default(),
            &image_release::NoVerifierConfigured,
        );
        let mut child = oneiron_spawn::command(&self.program)
            .args(&args)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .apply_cli_env()
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
            backend: "container-cli".to_owned(),
            runtime: self.program.display().to_string(),
            image: spec.image.as_str().to_owned(),
            argv_digest: digest.finalize().to_hex().to_string(),
            network: "none".to_owned(),
            seccomp: spec.seccomp,
            generation,
            fence_proof: None,
            fence_unproven: true,
            image_release,
        };
        Ok(GuestSession {
            runtime: self.program.clone(),
            name,
            child,
            manifest,
            stderr_tail,
            #[cfg(target_os = "linux")]
            supervisor: None,
        })
    }
    /// A production Foreign/Untrusted session. Failure to install or prove
    /// either Linux fence is an error, never an unfenced retry.
    pub fn start_fenced(
        &self,
        spec: &GuestSpec,
        command: &[OsString],
        relay: Arc<dyn EgressRelay>,
    ) -> Result<GuestSession> {
        #[cfg(target_os = "linux")]
        {
            let config = FenceConfig::from_env()?;
            let generation = uuid::Uuid::now_v7().simple().to_string();
            let name = format!("oneiron-guest-{generation}");
            let supervisor = supervisor::Supervisor::bind(&config, generation.clone())?;
            let mut fenced = spec.clone();
            fenced.seccomp = GuestSeccomp::EngineFence;
            let mut args = run_args(&name, &fenced)?;
            args.pop();
            args.push(read_only_mount(
                supervisor.directory(),
                Path::new("/run/oneiron-fence"),
            )?);
            args.push(read_only_mount(
                &config.launcher,
                Path::new("/run/oneiron-fence-launcher"),
            )?);
            args.extend([
                OsString::from("--entrypoint=/run/oneiron-fence-launcher"),
                spec.image.as_str().into(),
                "/run/oneiron-fence/bridge.sock".into(),
                generation.clone().into(),
                config.reconnect_window.as_millis().to_string().into(),
                "--".into(),
            ]);
            args.extend_from_slice(command);
            let mut digest = blake3::Hasher::new();
            for arg in &args {
                digest.update(arg.as_encoded_bytes());
                digest.update(&[0]);
            }
            let image_release = image_release::observe_release(
                None,
                &image_release::ObservedArtifacts::from_image_ref(&spec.image),
                &image_release::HostCapabilities::default(),
                &image_release::NoVerifierConfigured,
            );
            let mut child = oneiron_spawn::command(&self.program)
                .args(&args)
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .apply_cli_env()
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
                backend: "landlock-container".into(),
                runtime: self.program.display().to_string(),
                image: spec.image.as_str().into(),
                argv_digest: digest.finalize().to_hex().to_string(),
                network: "none; engine-egress-relay".into(),
                seccomp: GuestSeccomp::EngineFence,
                generation,
                fence_proof: None,
                fence_unproven: true,
                image_release,
            };
            let mut session = GuestSession {
                runtime: self.program.clone(),
                name: name.clone(),
                child,
                manifest,
                stderr_tail,
                supervisor: None,
            };
            // A start that fails names what the guest said: the session's drop
            // removes the container, and its stderr with it.
            let (proof, guard) = supervisor
                .activate(self.program.clone(), name, &mut session.child, relay)
                .map_err(|error| with_stderr_tail(error, &session.stderr_tail()))?;
            session.manifest.fence_proof = Some(proof);
            session.manifest.fence_unproven = false;
            session.supervisor = Some(guard);
            Ok(session)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (spec, command, relay);
            Err(Error::Fence(std::io::Error::other(
                "Foreign/Untrusted containers require a proven Linux fence",
            )))
        }
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
    if matches!(
        spec.seccomp,
        GuestSeccomp::GuestSandbox | GuestSeccomp::EngineFence
    ) {
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

/// `error` with the guest's last stderr appended, when it wrote any.
#[cfg(target_os = "linux")]
fn with_stderr_tail(error: Error, tail: &str) -> Error {
    let tail = tail.trim();
    match error {
        Error::Fence(source) if !tail.is_empty() => Error::Fence(std::io::Error::new(
            source.kind(),
            format!("{source}; guest stderr: {tail}"),
        )),
        other => other,
    }
}

/// One running guest. Dropping it stops and removes the container.
pub struct GuestSession {
    runtime: PathBuf,
    name: String,
    child: Child,
    manifest: SessionManifest,
    stderr_tail: Arc<Mutex<VecDeque<u8>>>,
    #[cfg(target_os = "linux")]
    supervisor: Option<supervisor::Guard>,
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

    #[must_use]
    pub fn abandoned(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            self.supervisor
                .as_ref()
                .is_some_and(supervisor::Guard::abandoned)
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }

    /// Whether the runtime client is still running the guest.
    pub fn is_running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }
}

impl Drop for GuestSession {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        self.supervisor.take();
        drop(self.child.stdin.take());
        let _ = oneiron_spawn::command(&self.runtime)
            .args(["rm", "--force", &self.name])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .apply_cli_env()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
