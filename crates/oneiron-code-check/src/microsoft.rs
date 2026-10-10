//! Microsoft's TypeScript 7 as an external process: the correctness oracle,
//! and the fallback when tsc-rs is unavailable.
//!
//! The binary is the native `tsc` of the npm platform package
//! `@typescript/typescript-<platform>` at [`MICROSOFT_TS_VERSION`]
//! (`package/lib/tsc`). It needs no Node. Each check writes its files to a
//! fresh temporary directory and runs `tsc` there with an empty environment.

use crate::{
    BackendId, CheckFailure, CheckInput, CheckReport, CodeCheck, DEFAULT_OUTPUT_BYTES,
    DEFAULT_WALL_TIME, TSC_ARGS, output, project_files,
};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// The pinned oracle: the TypeScript 7.1 preview whose diagnostics match
/// tsc-rs on the fixtures (npm `gitHead` aa8149273b23401f0a79a5f0384c42de51888693).
pub const MICROSOFT_TS_VERSION: &str = "7.1.0-dev.20261010.1";

/// How often a running check is polled for its exit.
const POLL: Duration = Duration::from_millis(1);

pub struct MicrosoftTsc {
    tsc: PathBuf,
    wall_time: Duration,
}

impl MicrosoftTsc {
    /// The `tsc` binary at `tsc`, which must report [`MICROSOFT_TS_VERSION`].
    ///
    /// # Errors
    ///
    /// [`CheckFailure::Unavailable`] when it does not run or reports
    /// another version.
    pub fn new(tsc: impl Into<PathBuf>) -> Result<Self, CheckFailure> {
        let tsc = tsc.into();
        let version = Command::new(&tsc)
            .arg("--version")
            .env_clear()
            .stdin(Stdio::null())
            .output()
            .map_err(|_| CheckFailure::Unavailable)?;
        if String::from_utf8_lossy(&version.stdout).trim()
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
        let files = project_files(input)?;
        let directory = tempfile::tempdir().map_err(|_| CheckFailure::Unavailable)?;
        for (name, bytes) in &files {
            std::fs::write(directory.path().join(name), bytes)
                .map_err(|_| CheckFailure::Unavailable)?;
        }
        // A file, not a pipe: a full pipe cannot stall tsc before its exit.
        let stdout_path = directory.path().join("stdout");
        let stdout = std::fs::File::create(&stdout_path).map_err(|_| CheckFailure::Unavailable)?;
        let deadline = Instant::now() + self.wall_time;
        let mut child = Command::new(&self.tsc)
            .args(TSC_ARGS)
            .current_dir(directory.path())
            .env_clear()
            .stdin(Stdio::null())
            .stdout(stdout)
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| CheckFailure::Unavailable)?;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if Instant::now() < deadline => std::thread::sleep(POLL),
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(CheckFailure::Timeout);
                }
                Err(_) => return Err(CheckFailure::Crashed),
            }
        };
        if !status.code().is_some_and(|code| (0..=2).contains(&code)) {
            return Err(CheckFailure::Crashed);
        }
        let printed = std::fs::read(&stdout_path).map_err(|_| CheckFailure::UnreadableOutput)?;
        if printed.len() > DEFAULT_OUTPUT_BYTES {
            return Err(CheckFailure::OverBudget);
        }
        Ok(CheckReport {
            backend: self.backend(),
            diagnostics: output::diagnostics(&printed)?,
            peak_memory_bytes: None,
        })
    }
}
