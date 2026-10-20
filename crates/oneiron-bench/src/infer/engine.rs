//! An engine the bench starts itself (`--engine-cmd`), in its own process
//! group, with stdout and stderr appended to `<out>.engine.log`.
//!
//! The bench polls `--engine-health` until it answers 200 and records how
//! long that took. It stops the engine by the exact PID it spawned, never by
//! name or port, so it cannot touch another server on the machine. The house
//! recipes (`serve-llama.sh`, `serve-exl3.sh`) `exec` their server, so that
//! PID is the server itself. A SIGINT or SIGTERM to the bench sends SIGTERM
//! to every child PID it started before it exits ([`Reaper`]); a SIGKILL
//! leaves them running, and the engine's PID is in its log.

use std::fs::OpenOptions;
use std::io::Write as _;
#[cfg(unix)]
use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

#[cfg(unix)]
use tokio::signal::unix::{SignalKind, signal};

use super::args::EngineArgs;

/// How long a stopped engine gets to exit on SIGTERM before SIGKILL.
const STOP_GRACE: Duration = Duration::from_secs(60);

fn terminate(pid: u32) {
    let _ = Command::new("kill")
        .args(["-s", "TERM", &pid.to_string()])
        .stdin(Stdio::null())
        .status();
}

/// The child PIDs a SIGINT or SIGTERM to the bench stops: the engine sits in
/// its own process group, so a terminal's Ctrl-C would not reach it, and a
/// signal to the bench alone reaches neither child.
#[derive(Clone, Default)]
pub(super) struct Reaper(Arc<Mutex<Vec<u32>>>);

impl Reaper {
    pub(super) fn keep(&self, pid: u32) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(pid);
    }

    pub(super) fn forget(&self, pid: u32) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|kept| *kept != pid);
    }

    /// Listens for SIGINT and SIGTERM on a thread of its own; on either it
    /// sends SIGTERM to each kept PID and exits 130.
    #[cfg(unix)]
    pub(super) fn arm(&self) {
        let pids = Arc::clone(&self.0);
        std::thread::spawn(move || {
            let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                return;
            };
            let signalled = runtime.block_on(async {
                let (Ok(mut interrupt), Ok(mut term)) = (
                    signal(SignalKind::interrupt()),
                    signal(SignalKind::terminate()),
                ) else {
                    return false;
                };
                tokio::select! {
                    _ = interrupt.recv() => true,
                    _ = term.recv() => true,
                }
            });
            if !signalled {
                return;
            }
            let pids = pids.lock().unwrap_or_else(PoisonError::into_inner).clone();
            for pid in &pids {
                terminate(*pid);
            }
            eprintln!("infer: signalled; sent SIGTERM to {pids:?} and exiting");
            std::process::exit(130);
        });
    }

    #[cfg(not(unix))]
    pub(super) fn arm(&self) {}
}

pub(super) struct Engine {
    child: Child,
    pub(super) pid: u32,
    pub(super) load_ms: f64,
    reaper: Reaper,
}

impl Engine {
    pub(super) fn start(args: &EngineArgs, log: &Path, reaper: &Reaper) -> Result<Self, String> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(log)
            .map_err(|e| format!("engine log {}: {e}", log.display()))?;
        let err = file
            .try_clone()
            .map_err(|e| format!("engine log {}: {e}", log.display()))?;
        let mut command = Command::new(&args.cmd);
        command
            .envs(args.env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .stdin(Stdio::null())
            .stdout(file.try_clone().map_err(|e| format!("engine log: {e}"))?)
            .stderr(err);
        #[cfg(unix)]
        command.process_group(0);
        let started = Instant::now();
        let child = command
            .spawn()
            .map_err(|e| format!("start engine {}: {e}", args.cmd.display()))?;
        let pid = child.id();
        reaper.keep(pid);
        let _ = writeln!(
            file,
            "== oneiron-bench infer: engine pid {pid} started {}",
            super::rows::now_rfc3339()
        );
        eprintln!("engine pid {pid} starting: {}", args.cmd.display());
        let mut engine = Self {
            child,
            pid,
            load_ms: 0.0,
            reaper: reaper.clone(),
        };
        engine.load_ms = engine.wait_healthy(
            &args.health,
            Duration::from_secs(args.ready_timeout_secs),
            started,
        )?;
        Ok(engine)
    }

    fn wait_healthy(
        &mut self,
        url: &str,
        timeout: Duration,
        started: Instant,
    ) -> Result<f64, String> {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .map_err(|e| format!("health client: {e}"))?;
        while started.elapsed() < timeout {
            if let Ok(Some(status)) = self.child.try_wait() {
                return Err(format!("the engine exited {status} before it was healthy"));
            }
            if client
                .get(url)
                .send()
                .is_ok_and(|reply| reply.status().as_u16() == 200)
            {
                return Ok(started.elapsed().as_secs_f64() * 1000.0);
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        Err(format!(
            "the engine was not healthy at {url} within {} s",
            timeout.as_secs()
        ))
    }

    /// SIGTERM to the exact PID, then SIGKILL after [`STOP_GRACE`]; returns
    /// how it exited.
    fn halt(&mut self) -> String {
        let status = self.wait_out();
        self.reaper.forget(self.pid);
        status
    }

    fn wait_out(&mut self) -> String {
        if let Ok(Some(status)) = self.child.try_wait() {
            return format!("already exited {status}");
        }
        terminate(self.pid);
        let deadline = Instant::now() + STOP_GRACE;
        loop {
            match self.child.try_wait() {
                Ok(Some(status)) => return status.to_string(),
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(100));
                }
                _ => {
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    return format!("killed after {} s", STOP_GRACE.as_secs());
                }
            }
        }
    }

    pub(super) fn stop(mut self) -> String {
        self.halt()
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            let status = self.halt();
            eprintln!("engine pid {} stopped: {status}", self.pid);
        }
        self.reaper.forget(self.pid);
    }
}
