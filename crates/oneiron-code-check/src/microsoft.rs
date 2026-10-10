//! Microsoft's TypeScript 7 as an external process: the correctness oracle,
//! and the fallback when tsc-rs is unavailable.
//!
//! The binary is the native `tsc` of the npm platform package
//! `@typescript/typescript-<platform>` at [`MICROSOFT_TS_VERSION`]
//! (`package/lib/tsc`). It needs no Node. Each check writes its files to a
//! fresh temporary directory and runs `tsc` there with an empty environment.

use crate::{
    BackendId, CheckFailure, CheckInput, CheckReport, CodeCheck, DEFAULT_OUTPUT_BYTES,
    DEFAULT_WALL_TIME, Exited, TSC_ARGS, project_files,
};
use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// The pinned oracle: the TypeScript 7.1 preview whose diagnostics match
/// tsc-rs on the fixtures (npm `gitHead` aa8149273b23401f0a79a5f0384c42de51888693).
pub const MICROSOFT_TS_VERSION: &str = "7.1.0-dev.20261010.1";

/// How often a running check is polled for its exit.
const POLL: Duration = Duration::from_millis(1);
/// How long the reader may take to finish once the process has exited.
const DRAIN: Duration = Duration::from_millis(100);
/// `tsc --version` prints one short line.
const VERSION_BYTES: usize = 256;

pub struct MicrosoftTsc {
    tsc: PathBuf,
    wall_time: Duration,
}

impl MicrosoftTsc {
    /// The `tsc` binary at `tsc`, which must report [`MICROSOFT_TS_VERSION`]
    /// within the check's wall time. A relative path is resolved here, since
    /// each check runs in its own directory.
    ///
    /// # Errors
    ///
    /// [`CheckFailure::Unavailable`] when it is missing, does not run, does
    /// not answer in time, or reports another version.
    pub fn new(tsc: impl Into<PathBuf>) -> Result<Self, CheckFailure> {
        let tsc = std::fs::canonicalize(tsc.into()).map_err(|_| CheckFailure::Unavailable)?;
        let mut command = Command::new(&tsc);
        command.arg("--version");
        let version = run_bounded(command, Instant::now() + DEFAULT_WALL_TIME, VERSION_BYTES)
            .map_err(|_| CheckFailure::Unavailable)?;
        if version.status != 0
            || version.stderr
            || String::from_utf8_lossy(&version.stdout).trim()
                != format!("Version {MICROSOFT_TS_VERSION}")
        {
            return Err(CheckFailure::Unavailable);
        }
        Ok(Self {
            tsc,
            wall_time: DEFAULT_WALL_TIME,
        })
    }
}

impl CodeCheck for MicrosoftTsc {
    fn backend(&self) -> BackendId {
        BackendId {
            name: "microsoft",
            pin: MICROSOFT_TS_VERSION.to_owned(),
        }
    }

    fn check(&self, input: &CheckInput<'_>) -> Result<CheckReport, CheckFailure> {
        let deadline = Instant::now() + self.wall_time;
        let files = project_files(input)?;
        let directory = tempfile::tempdir().map_err(|_| CheckFailure::Unavailable)?;
        for (name, bytes) in &files {
            std::fs::write(directory.path().join(name), bytes)
                .map_err(|_| CheckFailure::Unavailable)?;
        }
        let mut command = Command::new(&self.tsc);
        command.args(TSC_ARGS).current_dir(directory.path());
        run_bounded(command, deadline, DEFAULT_OUTPUT_BYTES)?.report(self.backend(), None)
    }
}

/// Runs `command` with an empty environment until it exits, killing it at
/// `deadline` or as soon as its stdout passes `limit` bytes. No more than
/// `limit + 1` bytes of its output are ever held, and one byte of stderr.
fn run_bounded(
    mut command: Command,
    deadline: Instant,
    limit: usize,
) -> Result<Exited, CheckFailure> {
    let mut child = command
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| CheckFailure::Unavailable)?;
    let (Some(stdout), Some(stderr)) = (child.stdout.take(), child.stderr.take()) else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(CheckFailure::Unavailable);
    };
    let stdout = read_bounded(stdout, limit);
    let stderr = read_bounded(stderr, 0);
    let mut printed = None;
    let ended = loop {
        if printed.is_none()
            && let Ok(read) = stdout.try_recv()
        {
            printed = Some(read);
        }
        if let Some(Ok(bytes)) = &printed
            && bytes.len() > limit
        {
            break Err(CheckFailure::OverBudget);
        }
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(POLL),
            Ok(None) => break Err(CheckFailure::Timeout),
            Err(_) => break Err(CheckFailure::Crashed),
        }
    };
    let status = match ended {
        Ok(status) => status,
        Err(failure) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(failure);
        }
    };
    // After the exit, each reader ends at its pipe's end, unless something
    // the process left behind still holds it open.
    let drain = deadline.saturating_duration_since(Instant::now()).max(DRAIN);
    let printed = match printed {
        Some(read) => read,
        None => stdout
            .recv_timeout(drain)
            .map_err(|_| CheckFailure::Timeout)?,
    }
    .map_err(|_| CheckFailure::UnreadableOutput)?;
    if printed.len() > limit {
        return Err(CheckFailure::OverBudget);
    }
    let complained = stderr
        .recv_timeout(drain)
        .map_err(|_| CheckFailure::Timeout)?
        .map_err(|_| CheckFailure::UnreadableOutput)?;
    Ok(Exited {
        // A signal ends it with no code.
        status: status.code().unwrap_or(-1),
        stdout: printed,
        stderr: !complained.is_empty(),
    })
}

/// Reads `pipe` on its own thread, stopping one byte past `limit`: dropping
/// the pipe then ends the process's writes to it.
fn read_bounded(
    pipe: impl Read + Send + 'static,
    limit: usize,
) -> mpsc::Receiver<std::io::Result<Vec<u8>>> {
    let (sender, receiver) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut read = Vec::new();
        let result = pipe
            .take(u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1))
            .read_to_end(&mut read);
        let _ = sender.send(result.map(|_| read));
    });
    receiver
}
