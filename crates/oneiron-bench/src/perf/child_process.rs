//! ONE-1579 ready-child plumbing: the TCP-accept readiness probe, the child
//! programs the harness spawns, and the PARENT-OWNED lifetime that follows
//! readiness.
//!
//! Readiness boundary: a child is ready when, and only when, the parent's TCP
//! `accept` for it has completed. Children are spawned with all three standard
//! streams pointed at `/dev/null`, so there is no log text for this harness to
//! read even if someone later wanted to.
//!
//! Lifetime boundary: after readiness the PARENT owns the child. It releases
//! the child by closing the accepted stream and then waits a BOUNDED budget,
//! terminating and reaping anything still alive. The bundled `wake-child` does
//! exit on that EOF, but a caller-supplied [`ChildCommandPlan`] carries no such
//! promise — an ordinary long-lived service would connect, stay up, and hang an
//! unbounded `wait()` forever. The child's own `--hold-ms` is a safety net
//! underneath that, never the mechanism: it must be long enough to cover the
//! parent's whole spawn, accept and sample phase, which
//! [`minimum_child_hold_ms`] states and plan admission enforces.

use std::io::Read;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use oneiron::{Vault, VaultConfig};
use serde::{Deserialize, Serialize};

use super::axes::ReadinessSignal;
use super::corpus::BENCH_EMBEDDING_MODEL;

/// Environment override naming the program the ready-children probes spawn.
pub(crate) const CHILD_PROGRAM_ENV: &str = "ONEIRON_BENCH_PERF_CHILD";
/// Accept poll granularity for the wake probe, in microseconds.
pub(crate) const ACCEPT_POLL_INTERVAL_US: u64 = 100;
/// Head-room a child's hold must have OVER the accept timeout, so the earliest
/// child cannot expire while the parent is still accepting the rest of the
/// cohort and reading their RSS.
pub(crate) const READY_CHILD_SAMPLING_MARGIN_MS: u64 = 5_000;
/// How long the parent waits for a released child to exit before terminating
/// it. A caller-supplied child is not required to exit on EOF, so this bound
/// is what keeps the harness from blocking forever on `wait()`.
pub(crate) const CHILD_SHUTDOWN_BUDGET_MS: u64 = 2_000;
/// Poll granularity while waiting for a released child to exit.
const CHILD_EXIT_POLL_MS: u64 = 5;

/// The shortest child hold that still covers the parent's whole
/// spawn -> accept -> sample phase.
///
/// The parent's accept loop is bounded by the plan's `wake.timeout_ms`, and a
/// child arms its hold the moment it connects — which can be at the very start
/// of that window. A hold at or below the accept timeout therefore lets the
/// FIRST child expire before the tenth is even accepted, turning the required
/// ten-children measurement into `not_ready`.
pub(crate) const fn minimum_child_hold_ms(accept_timeout_ms: u64) -> u64 {
    accept_timeout_ms.saturating_add(READY_CHILD_SAMPLING_MARGIN_MS)
}

/// A bound loopback listener whose completed `accept` IS the readiness signal.
///
/// The probe has no API that consumes child output: there is no log reader, no
/// stdout scan and no "sleep then assume ready" path anywhere on this type.
pub(crate) struct WakeProbe {
    listener: TcpListener,
}

/// One child that reached ready. The stream is held so the parent can keep the
/// child alive and then release it by closing the socket.
pub(crate) struct ReadyChild {
    pub(crate) elapsed_ms: f64,
    pub(crate) signal: ReadinessSignal,
    pub(crate) stream: TcpStream,
}

impl WakeProbe {
    pub(crate) fn bind() -> Result<Self, String> {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .map_err(|error| format!("wake probe could not bind loopback: {error}"))?;
        listener
            .set_nonblocking(true)
            .map_err(|error| format!("wake probe could not arm its listener: {error}"))?;
        Ok(Self { listener })
    }

    pub(crate) fn addr(&self) -> Result<SocketAddr, String> {
        self.listener
            .local_addr()
            .map_err(|error| format!("wake probe has no local address: {error}"))
    }

    /// Blocks until a child connects. The elapsed time is measured from the
    /// caller's `started` instant (taken immediately before the spawn) to the
    /// completed accept — never to a log line, a sleep or a stdout token.
    pub(crate) fn wait_ready(
        &self,
        started: Instant,
        timeout: Duration,
    ) -> Result<ReadyChild, String> {
        let deadline = Instant::now() + timeout;
        loop {
            match self.listener.accept() {
                Ok((stream, _)) => {
                    let elapsed_ms = started.elapsed().as_secs_f64() * 1e3;
                    stream
                        .set_nonblocking(false)
                        .map_err(|error| format!("ready stream could not be armed: {error}"))?;
                    return Ok(ReadyChild {
                        elapsed_ms,
                        signal: ReadinessSignal::TcpAccept,
                        stream,
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Err(format!("no TCP accept within {timeout:?}"));
                    }
                    std::thread::sleep(Duration::from_micros(ACCEPT_POLL_INTERVAL_US));
                }
                Err(error) => return Err(format!("wake probe accept failed: {error}")),
            }
        }
    }
}

/// A caller-supplied child program. `{ready_addr}`, `{vault_dir}` and
/// `{hold_ms}` are substituted into each argument.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ChildCommandPlan {
    pub(crate) program: String,
    #[serde(default)]
    pub(crate) args: Vec<String>,
}

/// Sizing for the wake and ready-children probes.
pub(crate) struct ChildSettings {
    pub(crate) samples: usize,
    pub(crate) timeout_ms: u64,
    pub(crate) hold_ms: u64,
    pub(crate) child: Option<ChildCommandPlan>,
}

impl ChildSettings {
    pub(crate) const fn accept_timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms)
    }
}

/// How a released child left.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChildExit {
    /// Exited on its own inside the shutdown budget.
    Exited,
    /// Outlived the budget and was terminated and reaped by the parent.
    TerminatedAfterBudget,
    /// Could not be reaped at all; the pid is reported rather than hidden.
    Unreapable,
}

impl ChildExit {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Exited => "exited",
            Self::TerminatedAfterBudget => "terminated_after_budget",
            Self::Unreapable => "unreapable",
        }
    }
}

/// Waits at most `budget` for an already-released child to exit, then
/// terminates and reaps it.
///
/// This is the ONLY wait the harness performs on a spawned child. An
/// unconditional `wait()` would block the whole benchmark forever on a
/// caller-supplied child that stays up after readiness, which the
/// `ChildCommandPlan` contract does not forbid.
pub(crate) fn wait_bounded(child: &mut Child, budget: Duration) -> ChildExit {
    let deadline = Instant::now() + budget;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return ChildExit::Exited,
            Ok(None) => {}
            Err(_) => return ChildExit::Unreapable,
        }
        if Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(CHILD_EXIT_POLL_MS));
    }
    let _ = child.kill();
    match child.wait() {
        Ok(_) => ChildExit::TerminatedAfterBudget,
        Err(_) => ChildExit::Unreapable,
    }
}

/// The bounded shutdown budget every probe releases its children under.
pub(crate) const fn child_shutdown_budget() -> Duration {
    Duration::from_millis(CHILD_SHUTDOWN_BUDGET_MS)
}

/// Resolves the program the harness will spawn as its ready child.
pub(crate) fn resolve_child_program() -> Result<PathBuf, String> {
    if let Ok(pinned) = std::env::var(CHILD_PROGRAM_ENV)
        && !pinned.trim().is_empty()
    {
        return Ok(PathBuf::from(pinned.trim()));
    }
    let executable = std::env::current_exe()
        .map_err(|error| format!("the running executable is not resolvable: {error}"))?;
    let stem = executable
        .file_stem()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or_default()
        .to_owned();
    if stem == "oneiron-bench" {
        return Ok(executable);
    }
    Err(format!(
        "the running executable `{stem}` is not the oneiron-bench binary, so the harness has no \
         ready-child program to spawn; run the built binary or set {CHILD_PROGRAM_ENV}"
    ))
}

pub(crate) fn child_command(
    plan: Option<&ChildCommandPlan>,
    fallback: &Path,
    addr: SocketAddr,
    vault_dir: &Path,
    hold_ms: u64,
) -> (PathBuf, Vec<String>) {
    let ready_addr = addr.to_string();
    let vault = vault_dir.display().to_string();
    let hold = hold_ms.to_string();
    match plan {
        Some(plan) => {
            let args = plan
                .args
                .iter()
                .map(|argument| {
                    argument
                        .replace("{ready_addr}", &ready_addr)
                        .replace("{vault_dir}", &vault)
                        .replace("{hold_ms}", &hold)
                })
                .collect();
            (PathBuf::from(&plan.program), args)
        }
        None => (
            fallback.to_path_buf(),
            vec![
                "perf".to_owned(),
                "wake-child".to_owned(),
                "--ready-addr".to_owned(),
                ready_addr,
                "--vault".to_owned(),
                vault,
                "--hold-ms".to_owned(),
                hold,
            ],
        ),
    }
}

/// Spawns the child with every standard stream discarded. There is no pipe to
/// read, so readiness cannot accidentally become a log-text wait.
pub(crate) fn spawn_child(program: &Path, args: &[String]) -> Result<Child, String> {
    Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("could not spawn `{}`: {error}", program.display()))
}

pub(crate) fn describe_child(program: &Path, args: &[String]) -> String {
    format!("{} {}", program.display(), args.join(" "))
}

/// Best-effort resident set size for one live pid. `None` where the platform
/// exposes no per-process counter — reported as such, never guessed.
pub(crate) fn process_rss_bytes(pid: u32) -> Option<u64> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let line = status.lines().find(|line| line.starts_with("VmRSS:"))?;
    let kib: u64 = line
        .trim_start_matches("VmRSS:")
        .trim()
        .trim_end_matches("kB")
        .trim()
        .parse()
        .ok()?;
    Some(kib * 1024)
}

/// Vault config for a ready child. Small on purpose: the child exists to be a
/// real process holding a real open vault, not to hold a corpus.
pub(crate) fn child_vault_config() -> VaultConfig {
    let mut config = VaultConfig::device();
    config.dimensions = 4;
    config.embedding_model = Some(BENCH_EMBEDDING_MODEL.to_owned());
    config.map_size = 64 * 1024 * 1024;
    config.max_readers = 16;
    config
}

// ─── ready-child mode ────────────────────────────────────────────────────

/// Harness-internal child mode. Spawned by the wake and ready-children probes;
/// it opens a vault (so the child is a genuinely active vault, not an idle
/// process), announces readiness by CONNECTING to the parent's probe, and then
/// blocks until the parent closes the socket or the hold budget expires.
pub(crate) fn run_wake_child(args: &[String]) -> Result<(), String> {
    let mut ready_addr = None;
    let mut vault_dir = None;
    let mut hold_ms = 30_000_u64;
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        let value = args
            .get(index + 1)
            .ok_or_else(|| format!("wake-child flag `{flag}` needs a value"))?;
        match flag {
            "--ready-addr" => ready_addr = Some(value.clone()),
            "--vault" => vault_dir = Some(value.clone()),
            "--hold-ms" => {
                hold_ms = value
                    .parse()
                    .map_err(|_| format!("--hold-ms expects milliseconds, got `{value}`"))?;
            }
            other => return Err(format!("unknown wake-child flag `{other}`")),
        }
        index += 2;
    }
    let ready_addr = ready_addr.ok_or_else(|| "--ready-addr is required".to_owned())?;
    let ready_addr: SocketAddr = ready_addr
        .parse()
        .map_err(|_| format!("--ready-addr is not a socket address: `{ready_addr}`"))?;

    // Opening the vault BEFORE announcing readiness is the point: the child
    // only counts as ready once it is a live process holding an open vault.
    let _held_vault = match vault_dir {
        Some(dir) => Some(
            Vault::open(dir, child_vault_config())
                .map_err(|error| format!("child vault open failed: {error}"))?,
        ),
        None => None,
    };

    let mut stream = TcpStream::connect(ready_addr)
        .map_err(|error| format!("child could not reach the readiness probe: {error}"))?;
    // The hold is a SAFETY NET for an abandoned parent, not the release
    // mechanism: the parent closes the socket, which lands here as EOF.
    stream
        .set_read_timeout(Some(Duration::from_millis(hold_ms.max(1))))
        .map_err(|error| format!("child could not arm its hold timeout: {error}"))?;
    let mut scratch = [0_u8; 1];
    let _ = stream.read(&mut scratch);
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    fn first_existing(candidates: &[&str]) -> Option<PathBuf> {
        for candidate in candidates {
            let path = PathBuf::from(candidate);
            if path.exists() {
                return Some(path);
            }
        }
        None
    }

    /// A program that stays up until it is killed, for the bounded-shutdown
    /// regression. `None` only where the platform ships no such program.
    fn long_lived_program() -> Option<PathBuf> {
        first_existing(&["/bin/sleep", "/usr/bin/sleep"])
    }

    fn immediate_program() -> Option<PathBuf> {
        first_existing(&["/bin/true", "/usr/bin/true"])
    }

    /// Readiness must be the completed TCP accept and nothing else. The
    /// stand-in child emits a stream of convincing "ready" log lines well
    /// before it connects; a probe that watched log text would return early,
    /// and a probe that waited on the accept cannot.
    #[test]
    fn wake_probe_waits_for_tcp_accept_not_log_text() {
        let probe = WakeProbe::bind().expect("probe binds");
        let addr = probe.addr().expect("probe has an address");
        let log = Arc::new(Mutex::new(Vec::<String>::new()));
        let log_writer = Arc::clone(&log);
        let quiet_for = Duration::from_millis(120);

        let started = Instant::now();
        let child = std::thread::spawn(move || {
            // Everything a log-text wait would have tripped on, emitted first.
            for line in ["listening", "READY", "server ready", "startup complete"] {
                log_writer
                    .lock()
                    .expect("log lock")
                    .push(String::from(line));
                std::thread::sleep(quiet_for / 4);
            }
            TcpStream::connect(addr).expect("stand-in child connects")
        });

        let ready = probe
            .wait_ready(started, Duration::from_secs(20))
            .expect("the probe accepts the child");
        let connection = child.join().expect("stand-in child thread");

        assert_eq!(ready.signal, ReadinessSignal::TcpAccept);
        assert!(
            ready.elapsed_ms >= quiet_for.as_secs_f64() * 1e3 * 0.8,
            "readiness must not fire before the connect; got {}ms while the child spent {}ms only \
             writing log text",
            ready.elapsed_ms,
            quiet_for.as_secs_f64() * 1e3
        );
        let emitted = log.lock().expect("log lock").clone();
        assert!(
            emitted.iter().any(|line| line.contains("READY")),
            "the fixture must actually have emitted ready-looking log text"
        );
        assert_eq!(emitted.len(), 4, "all four log lines landed before ready");
        drop(connection);
        drop(ready.stream);
    }

    /// A caller-supplied child is not required to exit when the parent closes
    /// the readiness socket. An unconditional `wait()` on such a child would
    /// block the whole benchmark forever, so the parent bounds the wait and
    /// then terminates and reaps it.
    #[test]
    fn a_child_that_outlives_its_release_is_terminated_within_the_budget() {
        let Some(program) = long_lived_program() else {
            if cfg!(target_os = "linux") {
                panic!("a linux host must provide `sleep` for the bounded-shutdown regression");
            }
            return;
        };
        let mut child =
            spawn_child(&program, &["300".to_owned()]).expect("the stand-in child spawns");

        let started = Instant::now();
        let outcome = wait_bounded(&mut child, Duration::from_millis(150));
        let elapsed = started.elapsed();

        assert_eq!(
            outcome,
            ChildExit::TerminatedAfterBudget,
            "a child that ignores its release must be terminated, not waited on forever"
        );
        assert!(
            elapsed < Duration::from_secs(10),
            "the bounded wait must return promptly, took {elapsed:?}"
        );
        assert!(
            matches!(child.try_wait(), Ok(Some(_))),
            "the terminated child must be reaped, not left as a zombie"
        );
    }

    /// A child that DOES exit on its own is reported as having exited, and is
    /// never killed.
    #[test]
    fn a_child_that_exits_on_its_own_is_reported_as_exited() {
        let Some(program) = immediate_program() else {
            if cfg!(target_os = "linux") {
                panic!("a linux host must provide `true` for the shutdown regression");
            }
            return;
        };
        let mut child = spawn_child(&program, &[]).expect("the stand-in child spawns");
        assert_eq!(
            wait_bounded(&mut child, child_shutdown_budget()),
            ChildExit::Exited
        );
    }

    /// The hold a child arms at connect time must cover the parent's whole
    /// spawn, accept and sample phase — otherwise the FIRST child can expire
    /// while the parent is still accepting the tenth.
    #[test]
    fn the_minimum_child_hold_covers_the_whole_accept_and_sample_phase() {
        assert_eq!(
            minimum_child_hold_ms(20_000),
            20_000 + READY_CHILD_SAMPLING_MARGIN_MS
        );
        assert!(
            minimum_child_hold_ms(20_000) > 20_000,
            "a hold equal to the accept timeout leaves no room to sample RSS"
        );
        assert_eq!(
            minimum_child_hold_ms(u64::MAX),
            u64::MAX,
            "the floor saturates rather than wrapping to a tiny hold"
        );
    }

    /// The bundled child is described by the exact command line that was run,
    /// and a caller-supplied plan gets its placeholders substituted.
    #[test]
    fn child_commands_substitute_their_placeholders() {
        let addr: SocketAddr = "127.0.0.1:4242".parse().expect("addr");
        let fallback = Path::new("/opt/oneiron-bench");
        let vault = Path::new("/tmp/ready-3");

        let (program, args) = child_command(None, fallback, addr, vault, 25_000);
        assert_eq!(program, fallback);
        assert_eq!(args[0], "perf");
        assert_eq!(args[1], "wake-child");
        assert!(args.contains(&"127.0.0.1:4242".to_owned()));
        assert!(args.contains(&"25000".to_owned()));
        assert!(describe_child(&program, &args).contains("wake-child"));

        let plan = ChildCommandPlan {
            program: "/usr/bin/service".to_owned(),
            args: vec![
                "--listen={ready_addr}".to_owned(),
                "--data={vault_dir}".to_owned(),
                "--linger={hold_ms}".to_owned(),
            ],
        };
        let (program, args) = child_command(Some(&plan), fallback, addr, vault, 25_000);
        assert_eq!(program, Path::new("/usr/bin/service"));
        assert_eq!(
            args,
            vec![
                "--listen=127.0.0.1:4242".to_owned(),
                "--data=/tmp/ready-3".to_owned(),
                "--linger=25000".to_owned(),
            ]
        );
    }

    #[test]
    fn wake_child_arguments_are_validated() {
        assert!(run_wake_child(&["--ready-addr".to_owned()]).is_err());
        assert!(run_wake_child(&[]).is_err());
        assert!(
            run_wake_child(&["--ready-addr".to_owned(), "not-an-addr".to_owned()]).is_err()
        );
        assert!(
            run_wake_child(&["--unknown".to_owned(), "value".to_owned()]).is_err()
        );
    }
}
