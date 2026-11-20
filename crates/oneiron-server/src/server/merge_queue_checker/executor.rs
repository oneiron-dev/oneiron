//! The queue checker's executors (FIX 6868): the isolated session by
//! default, the host child only on `[merge_queue].checker_backend = "host"`.
//!
//! The isolated executor selects its backend through the engine's
//! `select_backend_for_session(Untrusted, …)`: Firecracker on a KVM host
//! with it installed, else the OCI fenced container. Never the dev process
//! backend and never the first-party tier. A host with no isolated backend
//! answers a configuration need naming `merge_queue.checker_backend`; it
//! never runs the check on the host instead. Both executors drive the same
//! trusted helper over the same framed protocol: the pinned tree in, each
//! command's actual exit status and output out. No terminal frame, an
//! ended guest or the host's stop holds the check; none is a failed test.

mod protocol;
#[cfg(all(oneiron_test_support, unix))]
mod test_door;

use std::ffi::OsString;
use std::io;
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use oneiron::code_sandbox::SandboxGuestTier;
use oneiron::code_sandbox::microvm::{MicroVmBackend, SandboxBackends, select_backend_for_session};
use oneiron::host_net_floor::ProcessDescriptorFloor;
use oneiron::merge_queue::{
    QueueCheckEnvironment, QueueCheckExecution, QueueCheckHold, QueueCheckHoldReason,
    QueueCheckHost, QueueCheckInputs, QueueCheckInvocation, QueueCheckNeed,
};
use oneiron_container::{
    EgressRelay, GuestLimits, GuestSeccomp, GuestSpec, HostNetFloor, HttpRequest, HttpResponse,
    ImageRef, SessionManifest,
};
use serde::{Deserialize, Serialize};

use self::protocol::drive;
#[cfg(all(oneiron_test_support, unix))]
pub(crate) use self::test_door::run_empty_isolated_check;
use crate::config::{CheckerBackend, MergeQueueCheckerConfig};

/// One check's executor, chosen by the operator's setting.
pub(super) struct QueueCheckExecutor {
    config: MergeQueueCheckerConfig,
    /// The isolating backends the checked vault carries (F1-6), which the
    /// isolated executor selects its backend from.
    backends: Arc<dyn SandboxBackends>,
    backend: Option<Box<dyn MicroVmBackend>>,
    /// Where each started guest is recorded until it ends (FIX 7233).
    guests: Option<PathBuf>,
}

impl QueueCheckExecutor {
    pub(super) fn new(config: MergeQueueCheckerConfig, backends: Arc<dyn SandboxBackends>) -> Self {
        Self {
            config,
            backends,
            backend: None,
            guests: None,
        }
    }

    /// Records each guest it starts under `dir` until that guest ends, so a
    /// stopped host's guest is resolved by name on the next pass (FIX 7233).
    pub(super) fn with_guest_records(mut self, dir: PathBuf) -> Self {
        self.guests = Some(dir);
        self
    }

    fn isolated_environment(&mut self) -> Result<QueueCheckEnvironment, QueueCheckNeed> {
        if !cfg!(target_os = "linux") {
            return Err(QueueCheckNeed::new(
                &["merge_queue.checker_backend"],
                "this host has no isolated check backend; run the checker on a configured Linux \
                 host, or opt in with [merge_queue].checker_backend = \"host\"",
            ));
        }
        let (Some(runtime), Some(image)) = (&self.config.runtime, &self.config.image) else {
            return Err(QueueCheckNeed::new(
                &["merge_queue.runtime", "merge_queue.image"],
                "the isolated checker needs a container runtime and a pinned checker image",
            ));
        };
        if self.config.toolchain.is_empty() {
            return Err(QueueCheckNeed::new(
                &["merge_queue.toolchain"],
                "the isolated checker needs the image's immutable toolchain identity",
            ));
        }
        let backend = select_backend_for_session(
            &*self.backends,
            SandboxGuestTier::Untrusted,
            runtime.clone(),
            image,
        )
        .map_err(|error| {
            QueueCheckNeed::new(
                &["merge_queue.checker_backend"],
                format!(
                    "no isolated check backend runs on this host ({error}); provision \
                             one, or opt in with [merge_queue].checker_backend = \"host\""
                ),
            )
        })?;
        let executor = backend.name().to_owned();
        self.backend = Some(backend);
        Ok(QueueCheckEnvironment {
            backend: "isolated".to_owned(),
            executor,
            runtime: Some(runtime.display().to_string()),
            image: Some(image.clone()),
            helper: self.config.helper_argv().unwrap_or_default(),
            toolchain: self.config.toolchain.clone(),
            limits: Some(self.config.effective_limits()),
            network: self.config.network.as_str().to_owned(),
            os: std::env::consts::OS.to_owned(),
            arch: std::env::consts::ARCH.to_owned(),
        })
    }

    fn host_environment(&self) -> Result<QueueCheckEnvironment, QueueCheckNeed> {
        let Some(helper) = self.config.helper_argv() else {
            return Err(QueueCheckNeed::new(
                &["merge_queue.helper"],
                "the host checker needs the trusted helper's absolute argv",
            ));
        };
        if self.config.toolchain.is_empty() {
            return Err(QueueCheckNeed::new(
                &["merge_queue.toolchain"],
                "the host checker needs an explicit toolchain pin",
            ));
        }
        Ok(QueueCheckEnvironment {
            backend: "host".to_owned(),
            executor: "host".to_owned(),
            runtime: None,
            image: None,
            helper,
            toolchain: self.config.toolchain.clone(),
            limits: None,
            // A host child reaches what the host reaches; the receipt says so.
            network: "host".to_owned(),
            os: std::env::consts::OS.to_owned(),
            arch: std::env::consts::ARCH.to_owned(),
        })
    }

    fn execute_isolated(
        &mut self,
        invocation: &QueueCheckInvocation<'_>,
        inputs: &QueueCheckInputs,
        stop: &dyn Fn() -> bool,
    ) -> oneiron::Result<QueueCheckExecution> {
        let (Some(backend), Some(image), Some(limits)) = (
            self.backend.take(),
            inputs.environment.image.as_deref(),
            inputs.environment.limits,
        ) else {
            return Ok(QueueCheckExecution::NeedsConfiguration(
                QueueCheckNeed::new(
                    &["merge_queue.checker_backend"],
                    "no isolated check backend was selected",
                ),
            ));
        };
        let image = match ImageRef::pinned(image) {
            Ok(image) => image,
            Err(error) => {
                return Ok(unavailable(format!(
                    "the checker image is unusable: {error}"
                )));
            }
        };
        let spec = GuestSpec {
            image,
            user: (10001, 10001),
            limits: GuestLimits {
                memory_mib: limits.memory_mib,
                cpu_millis: limits.cpu_millis,
                pids: limits.pids,
                tmpfs_mib: limits.tmpfs_mib,
            },
            seccomp: GuestSeccomp::EngineFence,
            read_only_mounts: Vec::new(),
        };
        let relay = Arc::new(QueueCheckRelay::default());
        let command: Vec<OsString> = inputs
            .environment
            .helper
            .iter()
            .map(OsString::from)
            .collect();
        // The helper leaves after its terminal frame. A held session keeps
        // its container, and so its cgroup, until the helper's input closes
        // (FIX 8013).
        let transport = match backend.start_session_until_stdin_closes(
            &spec,
            &command,
            Arc::clone(&relay) as Arc<dyn EgressRelay>,
        ) {
            Ok(transport) => transport,
            Err(error) => {
                return Ok(unavailable(format!(
                    "the checker guest did not start: {error}"
                )));
            }
        };
        let started = transport.manifest.clone();
        let record = self
            .guests
            .as_deref()
            .and_then(|dir| record_guest(dir, &started));
        let mut lease = transport.lease;
        let mut input = transport.writer;
        let driven = drive(
            transport.reader,
            input.as_mut(),
            &mut || lease.is_running() && !lease.abandoned(),
            invocation,
            inputs,
            stop,
        )?;
        // The held container outlives its helper until the helper's input
        // closes, so its cgroup still reads here: the run's manifest carries
        // the pressure its guest showed (FIX 8013). Then its input closes,
        // as it did at the drive's end, and the container ends.
        let pressure = lease.observe_pressure();
        drop(input);
        let abandoned = lease.abandoned() || relay.abandoned.load(Ordering::Acquire);
        // The guest ends with its lease, after its output is read; its
        // record goes with it.
        drop(lease);
        if let Some(record) = record {
            let _removed = std::fs::remove_file(record);
        }
        let mut manifest = relay
            .manifest
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
            .unwrap_or(started);
        if pressure.is_some() {
            manifest.guest_pressure = pressure;
        }
        let refused = relay
            .refused
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        Ok(match driven {
            QueueCheckExecution::Completed(_) if abandoned => {
                QueueCheckExecution::Held(QueueCheckHold::new(
                    QueueCheckHoldReason::Interrupted,
                    "the guest session was abandoned",
                ))
            }
            // A red run that reached off its session lacked an input the
            // image must hold offline: held naming it, not a red verdict.
            QueueCheckExecution::Completed(run)
                if refused.is_some()
                    && run.commands.iter().any(|command| !command.exited_zero()) =>
            {
                QueueCheckExecution::Held(QueueCheckHold::new(
                    QueueCheckHoldReason::MissingOfflineInput,
                    format!(
                        "a command failed after reaching for {} with the network denied; the \
                         image lacks an input it needs offline",
                        refused.unwrap_or_default()
                    ),
                ))
            }
            QueueCheckExecution::Completed(mut run) => {
                run.session = Some(manifest);
                QueueCheckExecution::Completed(run)
            }
            other => other,
        })
    }

    fn execute_host(
        invocation: &QueueCheckInvocation<'_>,
        inputs: &QueueCheckInputs,
        stop: &dyn Fn() -> bool,
    ) -> oneiron::Result<QueueCheckExecution> {
        let Some((program, args)) = inputs.environment.helper.split_first() else {
            return Ok(QueueCheckExecution::NeedsConfiguration(
                QueueCheckNeed::new(
                    &["merge_queue.helper"],
                    "the host checker needs the trusted helper's absolute argv",
                ),
            ));
        };
        let spawned = oneiron_spawn::command(program)
            .args(args)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn();
        let mut child = match spawned {
            Ok(child) => child,
            Err(error) => {
                return Ok(unavailable(format!(
                    "the check helper did not start: {error}"
                )));
            }
        };
        let (Some(mut stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
            let _ = child.kill();
            let _ = child.wait();
            return Ok(unavailable("the check helper has no pipes".to_owned()));
        };
        let driven = drive(
            Box::new(stdout),
            &mut stdin,
            &mut || matches!(child.try_wait(), Ok(None)),
            invocation,
            inputs,
            stop,
        );
        drop(stdin);
        let _ = child.kill();
        let _ = child.wait();
        driven
    }
}

impl QueueCheckHost for QueueCheckExecutor {
    fn environment(&mut self) -> Result<QueueCheckEnvironment, QueueCheckNeed> {
        match self.config.checker_backend {
            CheckerBackend::Isolated => self.isolated_environment(),
            CheckerBackend::Host => self.host_environment(),
        }
    }

    fn execute(
        &mut self,
        invocation: &QueueCheckInvocation<'_>,
        inputs: &QueueCheckInputs,
        stop: &dyn Fn() -> bool,
    ) -> oneiron::Result<QueueCheckExecution> {
        match self.config.checker_backend {
            CheckerBackend::Isolated => self.execute_isolated(invocation, inputs, stop),
            CheckerBackend::Host => Self::execute_host(invocation, inputs, stop),
        }
    }
}

/// One started guest's record: what resolves it by name if its host stops
/// before it ends (FIX 7233).
#[derive(Serialize, Deserialize)]
pub(super) struct GuestRecord {
    pub(super) backend: String,
    pub(super) runtime: String,
    pub(super) generation: String,
}

/// The container a container backend names a session's guest.
pub(super) fn guest_container_name(generation: &str) -> String {
    format!("oneiron-guest-{generation}")
}

/// Writes `manifest`'s guest record under `dir`; `None` when it could not
/// be written, and the check runs on.
fn record_guest(dir: &Path, manifest: &SessionManifest) -> Option<PathBuf> {
    let record = GuestRecord {
        backend: manifest.backend.clone(),
        runtime: manifest.runtime.clone(),
        generation: manifest.generation.clone(),
    };
    let path = dir.join(&manifest.generation);
    let written = std::fs::create_dir_all(dir).and_then(|()| {
        let bytes = serde_json::to_vec(&record).map_err(io::Error::other)?;
        std::fs::write(&path, bytes)
    });
    match written {
        Ok(()) => Some(path),
        Err(error) => {
            tracing::warn!(kind = ?error.kind(), "a queue check guest record was not written");
            None
        }
    }
}

fn unavailable(detail: String) -> QueueCheckExecution {
    QueueCheckExecution::Held(QueueCheckHold::new(
        QueueCheckHoldReason::ExecutorUnavailable,
        detail,
    ))
}

/// A check guest's relay: every off-session destination is denied
/// (`network = "deny"`), and the session's start and abandonment are kept
/// for the receipt. It borrows no run, credential or owner.
#[derive(Default)]
struct QueueCheckRelay {
    manifest: Mutex<Option<SessionManifest>>,
    abandoned: AtomicBool,
    /// The first destination the guest reached for and was refused: a red
    /// run that reached off its session lacked an offline input.
    refused: Mutex<Option<String>>,
}

impl QueueCheckRelay {
    fn deny(&self, destination: impl FnOnce() -> String) -> io::Error {
        self.refused
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get_or_insert_with(destination);
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "a queue check guest reaches nothing off its session (merge_queue.network = \"deny\")",
        )
    }
}

impl EgressRelay for QueueCheckRelay {
    fn connect(&self, target: SocketAddr) -> io::Result<TcpStream> {
        Err(self.deny(|| format!("a connection to {target}")))
    }

    fn authorize_datagram(&self, target: SocketAddr) -> io::Result<()> {
        Err(self.deny(|| format!("a datagram to {target}")))
    }

    fn record_session(&self, manifest: &SessionManifest) -> io::Result<()> {
        *self.manifest.lock().unwrap_or_else(PoisonError::into_inner) = Some(manifest.clone());
        Ok(())
    }

    fn record_abandoned(&self, _manifest: &SessionManifest) -> io::Result<()> {
        self.abandoned.store(true, Ordering::Release);
        Ok(())
    }

    fn datagram(&self, target: SocketAddr, _bytes: &[u8]) -> io::Result<Vec<u8>> {
        Err(self.deny(|| format!("a datagram to {target}")))
    }

    fn fetch(&self, _request: HttpRequest) -> io::Result<HttpResponse> {
        Err(self.deny(|| "an HTTP fetch".to_owned()))
    }

    fn transferred(&self, _target: SocketAddr, _content_hash: [u8; 32], _bytes: u64) {}

    /// Every relay is refused at once, but the guest's socket entries and
    /// session-local loopback still hold host descriptors and threads: they
    /// charge the process's descriptor line (FIX 6300).
    fn host_net_floor(&self) -> &dyn HostNetFloor {
        &ProcessDescriptorFloor
    }
}
