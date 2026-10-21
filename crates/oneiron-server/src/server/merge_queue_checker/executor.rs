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

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError, mpsc};
use std::time::Duration;

use oneiron::code_sandbox::SandboxGuestTier;
use oneiron::code_sandbox::microvm::{MicroVmBackend, select_backend_for_session};
use oneiron::merge_queue::{
    QueueCheckEnvironment, QueueCheckExecution, QueueCheckHold, QueueCheckHoldReason,
    QueueCheckHost, QueueCheckInputs, QueueCheckInvocation, QueueCheckNeed, QueueCheckRun,
    QueueCommandReceipt,
};
use oneiron_container::{
    EgressRelay, GuestLimits, GuestSeccomp, GuestSpec, HostNetFloor, HttpRequest, HttpResponse,
    ImageRef, SessionManifest, UnmeteredFloor,
};
use serde::{Deserialize, Serialize};

use super::tree::{
    FRAME_DONE, FRAME_HEADER, FRAME_INPUTS, FRAME_RESULT, FRAME_STDERR, FRAME_STDOUT, Sent,
    read_frame, send_tree, write_frame,
};
use crate::config::{CheckerBackend, MergeQueueCheckerConfig};

/// Where the helper materializes its private scratch copy, in the guest
/// and for the host child alike; the plan's environment names paths under
/// it.
const CHECK_SCRATCH: &str = "/tmp/queue-check";

/// How often a waiting executor looks at the host's stop and its guest's
/// liveness. A poll, not a deadline: nothing ends a check for taking long.
const STOP_POLL: Duration = Duration::from_millis(500);

/// One check's executor, chosen by the operator's setting.
pub(super) struct QueueCheckExecutor {
    config: MergeQueueCheckerConfig,
    backend: Option<Box<dyn MicroVmBackend>>,
}

impl QueueCheckExecutor {
    pub(super) fn new(config: MergeQueueCheckerConfig) -> Self {
        Self {
            config,
            backend: None,
        }
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
        let backend =
            select_backend_for_session(SandboxGuestTier::Untrusted, runtime.clone(), image)
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
        let transport = match backend.start_session(
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
        let mut lease = transport.lease;
        let driven = drive(
            transport.reader,
            transport.writer,
            &mut || lease.is_running() && !lease.abandoned(),
            invocation,
            inputs,
            stop,
        )?;
        let abandoned = lease.abandoned() || relay.abandoned.load(Ordering::Acquire);
        // The guest ends with its lease, after its output is read.
        drop(lease);
        let manifest = relay
            .manifest
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
            .unwrap_or(started);
        Ok(match driven {
            QueueCheckExecution::Completed(_) if abandoned => {
                QueueCheckExecution::Held(QueueCheckHold::new(
                    QueueCheckHoldReason::Interrupted,
                    "the guest session was abandoned",
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
        let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
            let _ = child.kill();
            let _ = child.wait();
            return Ok(unavailable("the check helper has no pipes".to_owned()));
        };
        let driven = drive(
            Box::new(stdout),
            Box::new(stdin),
            &mut || matches!(child.try_wait(), Ok(None)),
            invocation,
            inputs,
            stop,
        );
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

fn unavailable(detail: String) -> QueueCheckExecution {
    QueueCheckExecution::Held(QueueCheckHold::new(
        QueueCheckHoldReason::ExecutorUnavailable,
        detail,
    ))
}

fn interrupted(detail: &str) -> QueueCheckExecution {
    QueueCheckExecution::Held(QueueCheckHold::new(
        QueueCheckHoldReason::Interrupted,
        detail,
    ))
}

/// The header the helper reads first.
#[derive(Serialize)]
struct Header<'h> {
    version: u8,
    scratch: &'h str,
    commands: Vec<HeaderCommand<'h>>,
    contract_outputs: Vec<HeaderCommand<'h>>,
}

#[derive(Serialize)]
struct HeaderCommand<'h> {
    name: Option<&'h str>,
    argv: &'h [String],
    env: &'h BTreeMap<String, String>,
}

/// One command result the helper reports.
#[derive(Deserialize)]
struct ResultFrame {
    kind: String,
    #[serde(default)]
    index: Option<usize>,
    #[serde(default)]
    name: Option<String>,
    status: Option<i32>,
    signal: Option<i32>,
    #[serde(default)]
    missing: Option<String>,
}

#[derive(Deserialize)]
struct InputsFrame {
    before: String,
    after: String,
}

/// Drives the helper over `reader` and `writer`: header and tree in, then
/// its frames until the terminal one, the host's stop, or its end.
fn drive(
    mut reader: Box<dyn Read + Send>,
    mut writer: Box<dyn Write + Send>,
    alive: &mut dyn FnMut() -> bool,
    invocation: &QueueCheckInvocation<'_>,
    inputs: &QueueCheckInputs,
    stop: &dyn Fn() -> bool,
) -> oneiron::Result<QueueCheckExecution> {
    let header = Header {
        version: 1,
        scratch: CHECK_SCRATCH,
        commands: inputs
            .commands
            .iter()
            .map(|command| HeaderCommand {
                name: None,
                argv: &command.argv,
                env: &command.env_allowlist,
            })
            .collect(),
        contract_outputs: inputs
            .contract_outputs
            .iter()
            .map(|(name, command)| HeaderCommand {
                name: Some(name.as_str()),
                argv: &command.argv,
                env: &command.env_allowlist,
            })
            .collect(),
    };
    let header = serde_json::to_vec(&header).map_err(io::Error::other)?;
    if write_frame(writer.as_mut(), FRAME_HEADER, &header).is_err() {
        return Ok(interrupted("the check helper closed before its header"));
    }
    let sent = match send_tree(writer.as_mut(), invocation.tree)? {
        Sent::Tree(digest) => digest,
        Sent::Closed(_) => {
            return Ok(interrupted(
                "the check helper closed before the tree was in",
            ));
        }
    };
    let (frames, received) = mpsc::channel();
    std::thread::spawn(move || {
        loop {
            match read_frame(reader.as_mut()) {
                Ok(Some(frame)) => {
                    if frames.send(frame).is_err() {
                        return;
                    }
                }
                Ok(None) | Err(_) => return,
            }
        }
    });
    let mut collected = Collected::default();
    let mut ended = false;
    loop {
        match received.recv_timeout(STOP_POLL) {
            Ok((kind, payload)) => {
                if kind == FRAME_DONE {
                    break;
                }
                if let Err(detail) = collected.take(kind, payload) {
                    return Ok(interrupted(&detail));
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if stop() {
                    return Ok(interrupted("the host stopped during the check"));
                }
                // An ended executor's frames already read drain first; one
                // more quiet poll after its end holds the check.
                if ended {
                    return Ok(interrupted(
                        "the check executor ended before its terminal frame",
                    ));
                }
                ended = !alive();
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Ok(interrupted(
                    "the check helper ended before its terminal frame",
                ));
            }
        }
    }
    // The helper's input stays open until its terminal frame is read.
    drop(writer);
    collected.finish(&sent, inputs)
}

/// The frames read so far.
#[derive(Default)]
struct Collected {
    pending: Option<(ResultFrame, Option<Vec<u8>>)>,
    commands: Vec<QueueCommandReceipt>,
    contract_outputs: BTreeMap<String, QueueCommandReceipt>,
    missing: Option<String>,
    inputs: Option<InputsFrame>,
}

impl Collected {
    fn take(&mut self, kind: u8, payload: Vec<u8>) -> Result<(), String> {
        match kind {
            FRAME_RESULT => {
                let result: ResultFrame = serde_json::from_slice(&payload)
                    .map_err(|_| "the check helper sent an unreadable result".to_owned())?;
                self.pending = Some((result, None));
            }
            FRAME_STDOUT => {
                let Some((_, stdout)) = self.pending.as_mut() else {
                    return Err("the check helper sent output out of order".to_owned());
                };
                if stdout.is_some() {
                    return Err("the check helper sent output out of order".to_owned());
                }
                *stdout = Some(payload);
            }
            FRAME_STDERR => {
                let Some((result, Some(stdout))) = self.pending.take() else {
                    return Err("the check helper sent output out of order".to_owned());
                };
                self.push(result, stdout, payload)?;
            }
            FRAME_INPUTS => {
                self.inputs = Some(
                    serde_json::from_slice(&payload)
                        .map_err(|_| "the check helper sent unreadable digests".to_owned())?,
                );
            }
            _ => return Err("the check helper sent an unknown frame".to_owned()),
        }
        Ok(())
    }

    fn push(
        &mut self,
        result: ResultFrame,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    ) -> Result<(), String> {
        if let Some(missing) = &result.missing {
            self.missing.get_or_insert_with(|| missing.clone());
        }
        let receipt = |argv: Vec<String>| QueueCommandReceipt {
            argv,
            status: result.status,
            signal: result.signal,
            stdout,
            stderr,
        };
        match (result.kind.as_str(), result.index, &result.name) {
            ("phase", Some(index), _) if index == self.commands.len() => {
                self.commands.push(receipt(Vec::new()));
            }
            ("contract", _, Some(name)) => {
                self.contract_outputs
                    .insert(name.clone(), receipt(Vec::new()));
            }
            _ => return Err("the check helper sent a result out of order".to_owned()),
        }
        Ok(())
    }

    fn finish(self, sent: &str, inputs: &QueueCheckInputs) -> oneiron::Result<QueueCheckExecution> {
        let Some(digests) = self.inputs else {
            return Ok(interrupted("the check helper sent no input digests"));
        };
        if digests.before != sent {
            return Ok(QueueCheckExecution::Held(QueueCheckHold::new(
                QueueCheckHoldReason::UnstableInputs,
                "the executor did not receive the pinned tree",
            )));
        }
        if let Some(missing) = self.missing {
            return Ok(QueueCheckExecution::Held(QueueCheckHold::new(
                QueueCheckHoldReason::MissingOfflineInput,
                missing,
            )));
        }
        let mut commands = self.commands;
        for (receipt, command) in commands.iter_mut().zip(&inputs.commands) {
            receipt.argv.clone_from(&command.argv);
        }
        let mut contract_outputs = self.contract_outputs;
        for (name, receipt) in &mut contract_outputs {
            if let Some(command) = inputs.contract_outputs.get(name) {
                receipt.argv.clone_from(&command.argv);
            }
        }
        Ok(QueueCheckExecution::Completed(QueueCheckRun {
            commands,
            contract_outputs,
            session: None,
            input_before: digests.before,
            input_after: digests.after,
        }))
    }
}

/// A check guest's relay: every off-session destination is denied
/// (`network = "deny"`), and the session's start and abandonment are kept
/// for the receipt. It borrows no run, credential or owner.
#[derive(Default)]
struct QueueCheckRelay {
    manifest: Mutex<Option<SessionManifest>>,
    abandoned: AtomicBool,
}

fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "a queue check guest reaches nothing off its session (merge_queue.network = \"deny\")",
    )
}

impl EgressRelay for QueueCheckRelay {
    fn connect(&self, _target: SocketAddr) -> io::Result<TcpStream> {
        Err(denied())
    }

    fn authorize_datagram(&self, _target: SocketAddr) -> io::Result<()> {
        Err(denied())
    }

    fn record_session(&self, manifest: &SessionManifest) -> io::Result<()> {
        *self.manifest.lock().unwrap_or_else(PoisonError::into_inner) = Some(manifest.clone());
        Ok(())
    }

    fn record_abandoned(&self, _manifest: &SessionManifest) -> io::Result<()> {
        self.abandoned.store(true, Ordering::Release);
        Ok(())
    }

    fn datagram(&self, _target: SocketAddr, _bytes: &[u8]) -> io::Result<Vec<u8>> {
        Err(denied())
    }

    fn fetch(&self, _request: HttpRequest) -> io::Result<HttpResponse> {
        Err(denied())
    }

    fn transferred(&self, _target: SocketAddr, _content_hash: [u8; 32], _bytes: u64) {}

    /// Every relay is refused at once, so nothing is charged to a floor.
    fn host_net_floor(&self) -> &dyn HostNetFloor {
        &UnmeteredFloor
    }
}
