//! The drafter trainer's process (FIX 14974), run the way the training
//! pack's connector runs its worker: `<python> -I <worker> --request
//! <job>/request.json --output <job>/output`, no shell, stdin and stdout
//! closed, stderr to `<job>/worker.stderr`. The worker inherits the host's
//! runtime environment except the server's own credentials; its inputs
//! travel through the staged files.
//!
//! It runs in a process group of its own, so its converter child stops with
//! it. The host stops the group when the job is cancelled (an erase, the off
//! switch, another recipe) and once it has run the recipe's GPU seconds.
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use oneiron::llm::WorkCancel;

use super::job::{JobDir, new_file};
use crate::config::models::DrafterTrainerSettings;

/// The server's credentials, which the worker never inherits.
const WITHHELD_ENVIRONMENT: [&str; 4] = [
    "ONEIRON_SECRET",
    "ONEIRON_BINDING_KEY",
    "ONEIRON_TOKEN",
    "ONEIRON_AUTH_SECRET",
];

/// How one run of the worker ended.
#[derive(Debug)]
pub(super) enum WorkerEnd {
    /// The worker exited on its own.
    Exited(ExitStatus),
    /// The job was cancelled and the worker stopped.
    Stopped,
    /// The worker ran the recipe's GPU seconds and was stopped.
    OverBudget,
}

/// Kills process group `group`, the worker and every child it started. A
/// group that is gone already is no fault.
pub(super) fn kill_group(group: u32) {
    #[cfg(unix)]
    if let Some(pid) = i32::try_from(group)
        .ok()
        .and_then(rustix::process::Pid::from_raw)
    {
        let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
    }
    #[cfg(not(unix))]
    let _ = group;
}

/// Runs the worker on the staged job `dir` until it exits, `cancel` fires
/// or `budget` passes, and records its process id beside the job. However it
/// ends, its process group is stopped before this returns.
///
/// # Errors
/// The worker did not start, or its files could not be made.
pub(super) async fn run_worker(
    trainer: &DrafterTrainerSettings,
    dir: &JobDir,
    budget: Duration,
    cancel: &WorkCancel,
) -> std::io::Result<WorkerEnd> {
    let stderr = new_file(&dir.stderr())?;
    let mut command = oneiron_spawn::command(&trainer.python);
    command
        .arg("-I")
        .arg(&trainer.worker)
        .arg("--request")
        .arg(dir.request())
        .arg("--output")
        .arg(dir.output())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(stderr));
    for name in WITHHELD_ENVIRONMENT {
        command.env_remove(name);
    }
    #[cfg(unix)]
    std::os::unix::process::CommandExt::process_group(&mut command, 0);
    let mut command = tokio::process::Command::from(command);
    command.kill_on_drop(true);
    let mut child = command.spawn()?;
    let group = child.id();
    if let Some(group) = group {
        use std::io::Write as _;
        // Only a recovery after a restart reads it, to stop a worker whose
        // version may no longer train.
        let written =
            new_file(&dir.pid()).and_then(|mut file| file.write_all(group.to_string().as_bytes()));
        if let Err(error) = written {
            tracing::warn!(%error, "a drafter trainer's process id was not recorded");
        }
    }
    let end = tokio::select! {
        status = child.wait() => status.map(WorkerEnd::Exited),
        () = cancel.cancelled() => Ok(WorkerEnd::Stopped),
        () = tokio::time::sleep(budget) => Ok(WorkerEnd::OverBudget),
    };
    if let Some(group) = group {
        kill_group(group);
    }
    if !matches!(end, Ok(WorkerEnd::Exited(_))) {
        let _ = child.wait().await;
    }
    end
}
