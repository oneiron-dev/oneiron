//! Microsoft's TypeScript 7 as an external process: the correctness oracle,
//! and the fallback when the in-process backend (tsrs or tsc-rs) cannot check.
//!
//! The binary is the native `tsc` of the npm platform package
//! `@typescript/typescript-<platform>` at [`MICROSOFT_TS_VERSION`]
//! (`package/lib/tsc`). It needs no Node. Each check writes its files to a
//! fresh temporary directory and runs `tsc` there with an empty environment.

use crate::{
    BackendId, CheckFailure, CheckInput, CheckReport, CodeCheck, DEFAULT_INPUT_BYTES,
    DEFAULT_WALL_TIME, Exited, Stopped, TSC_ARGS, project_files,
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
/// Text through which a program can make tsc resolve a module: an import
/// (statement, call, JSDoc type or tag, JSX import source), an export from
/// another module (a program can close its envelope and write one at the top
/// level), a `require` call, a reference directive, an ambient module
/// declaration (a nested one is an augmentation, resolved even in a script),
/// or a Unicode escape that spells one of them. Matched without regard to
/// case, so a program that merely mentions one (`vault.export`) is left
/// unchecked too.
const MODULE_NAMING: [&str; 6] = ["import", "export", "require", "reference", "module", "\\u"];
/// `tsc --version` prints one short line.
const VERSION_BYTES: usize = 256;

pub struct MicrosoftTsc {
    tsc: PathBuf,
    wall_time: Duration,
    /// The most declaration and program text one check takes.
    input_bytes: usize,
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
        let mut command = oneiron_spawn::command(&tsc);
        command.arg("--version");
        let version = run_bounded(
            command,
            Instant::now() + DEFAULT_WALL_TIME,
            Some(VERSION_BYTES),
        )
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
            input_bytes: DEFAULT_INPUT_BYTES,
        })
    }

    /// The same checker, taking at most `bytes` of declaration and program
    /// text per check (`models.code_mode.check.max_input_bytes`).
    #[must_use]
    pub fn with_input_bytes(mut self, bytes: usize) -> Self {
        self.input_bytes = bytes;
        self
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
        let files = project_files(input, self.input_bytes)?;
        // tsc runs with this host's file system, and resolving a module reads
        // or probes the path it names, so a program that could name one is
        // left unchecked here. tsc-rs reads only the check's own files.
        let program = input.program.as_bytes();
        if MODULE_NAMING.iter().any(|token| {
            program
                .windows(token.len())
                .any(|window| window.eq_ignore_ascii_case(token.as_bytes()))
        }) {
            return Err(CheckFailure::Unsupported);
        }
        let directory = tempfile::tempdir().map_err(|_| CheckFailure::Unavailable)?;
        for (name, bytes) in &files {
            std::fs::write(directory.path().join(name), bytes)
                .map_err(|_| CheckFailure::Unavailable)?;
        }
        let mut command = oneiron_spawn::command(&self.tsc);
        command.args(TSC_ARGS).current_dir(directory.path());
        // Every diagnostic it prints is kept: the check's output has no bound
        // of its own (FIX 8277).
        match run_bounded(command, deadline, None) {
            Ok(exited) => exited.report(self.backend(), None),
            Err(stopped) => stopped.report(self.backend(), None),
        }
    }
}

/// Runs `command` with an empty environment until it exits, killing it and
/// its process group at `deadline`, or, with a `limit`, as soon as its stdout
/// passes `limit` bytes; then no more than `limit + 1` bytes of its output
/// are ever held. One byte of stderr is. A run that stops keeps what it had
/// printed.
fn run_bounded(
    mut command: Command,
    deadline: Instant,
    limit: Option<usize>,
) -> Result<Exited, Stopped> {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| CheckFailure::Unavailable)?;
    let (Some(stdout), Some(stderr)) = (child.stdout.take(), child.stderr.take()) else {
        stop(&mut child);
        return Err(CheckFailure::Unavailable.into());
    };
    let (Ok(stdout), Ok(stderr)) = (read_bounded(stdout, limit), read_bounded(stderr, Some(0)))
    else {
        // A reader that did start ends once the group is gone.
        stop(&mut child);
        return Err(CheckFailure::Unavailable.into());
    };
    let mut printed = None;
    let ended = loop {
        if printed.is_none()
            && let Ok(read) = stdout.try_recv()
        {
            printed = Some(read);
        }
        if let Some(Ok(bytes)) = &printed
            && limit.is_some_and(|limit| bytes.len() > limit)
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
            stop(&mut child);
            // The group is gone, so the reader ends at its pipe's end with
            // what the run printed.
            let stdout = printed
                .or_else(|| stdout.recv_timeout(DRAIN).ok())
                .and_then(Result::ok)
                .unwrap_or_default();
            return Err(Stopped { failure, stdout });
        }
    };
    // After the exit, each reader ends at its pipe's end. A process that
    // escaped the group and holds a pipe open (tsc starts none) leaves its
    // reader parked, and the check times out after a short drain.
    let drain = deadline
        .saturating_duration_since(Instant::now())
        .max(DRAIN);
    let printed = match printed {
        Some(read) => read,
        None => stdout
            .recv_timeout(drain)
            .map_err(|_| CheckFailure::Timeout)?,
    }
    .map_err(|_| CheckFailure::UnreadableOutput)?;
    if limit.is_some_and(|limit| printed.len() > limit) {
        return Err(CheckFailure::OverBudget.into());
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

/// Reads `pipe` on its own thread to its end, or with a `limit` stopping one
/// byte past it: dropping the pipe then ends the process's writes to it.
fn read_bounded(
    pipe: impl Read + Send + 'static,
    limit: Option<usize>,
) -> Result<mpsc::Receiver<std::io::Result<Vec<u8>>>, CheckFailure> {
    let (sender, receiver) = mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("tsc-output".into())
        .spawn(move || {
            let mut pipe = pipe;
            let mut read = Vec::new();
            let result = match limit {
                Some(limit) => pipe
                    .take(u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1))
                    .read_to_end(&mut read),
                None => pipe.read_to_end(&mut read),
            };
            let _ = sender.send(result.map(|_| read));
        })
        .map_err(|_| CheckFailure::Unavailable)?;
    Ok(receiver)
}

/// Kills a live child and its process group, then reaps it. Only a child not
/// yet reaped is signalled, so its group id cannot have been reused.
fn stop(child: &mut std::process::Child) {
    #[cfg(unix)]
    if let Ok(pid) = i32::try_from(child.id()) {
        // SAFETY: this live, unreaped child leads the process group it was
        // spawned into above.
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}
