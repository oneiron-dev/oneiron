//! One running worker process in its supervisor's custody: started in a
//! process group of its own, reaped by one task, checked for liveness on its
//! health route, asked what it holds on its native socket when it has one,
//! and stopped by signals to that group alone.
use std::path::PathBuf;
use std::time::Duration;

use oneiron_driver::{LauncherFuture, RunningWorker, WorkerActivity, WorkerExit};
use rustix::process::{Pid, Signal, kill_process_group};
use tokio::sync::watch;

/// How long one liveness check may take before it counts as not live yet.
/// It only paces the next check; no worker is stopped for it.
const LIVENESS_REQUEST: Duration = Duration::from_secs(5);

/// A worker process the supervisor started.
pub(super) struct ProcessWorker {
    /// The process group: the worker's own pid.
    group: i32,
    exit: watch::Receiver<Option<WorkerExit>>,
    health: String,
    client: reqwest::Client,
    /// The worker's native socket, where its stats are read (FIX 9190).
    native: Option<PathBuf>,
}

impl ProcessWorker {
    /// Starts `command` as the leader of a new process group and takes
    /// custody of it: one task waits on and reaps it. On Linux the worker
    /// gets the terminate signal if this process dies first, so no orphan
    /// keeps its port and its device.
    pub(super) fn spawn(
        mut command: tokio::process::Command,
        health: String,
        native: Option<PathBuf>,
    ) -> std::io::Result<Self> {
        command.process_group(0).kill_on_drop(false);
        #[cfg(target_os = "linux")]
        // SAFETY: the closure runs in the child between fork and exec and
        // makes one prctl call, which is async-signal-safe; it takes no lock
        // and allocates nothing.
        unsafe {
            command.pre_exec(|| {
                rustix::process::set_parent_process_death_signal(Some(Signal::TERM))
                    .map_err(std::io::Error::from)
            });
        }
        let mut child = command.spawn()?;
        let group = child
            .id()
            .and_then(|pid| i32::try_from(pid).ok())
            .ok_or_else(|| std::io::Error::other("the worker exited before it was named"))?;
        let (sender, exit) = watch::channel(None);
        tokio::spawn(async move {
            let description = match child.wait().await {
                Ok(status) => status.to_string(),
                Err(error) => format!("its wait failed: {error}"),
            };
            sender.send_replace(Some(WorkerExit { description }));
        });
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(LIVENESS_REQUEST)
            .timeout(LIVENESS_REQUEST)
            .build()
            .map_err(std::io::Error::other)?;
        Ok(Self {
            group,
            exit,
            health,
            client,
            native,
        })
    }

    fn signal(&self, signal: Signal) {
        if let Some(group) = Pid::from_raw(self.group) {
            let _ = kill_process_group(group, signal);
        }
    }

    fn already_exited(&self) -> Option<WorkerExit> {
        self.exit.borrow().clone()
    }
}

impl RunningWorker for ProcessWorker {
    fn exited(&self) -> LauncherFuture<'_, WorkerExit> {
        let mut exit = self.exit.clone();
        Box::pin(async move {
            let seen = exit
                .wait_for(Option::is_some)
                .await
                .ok()
                .and_then(|seen| seen.clone());
            seen.unwrap_or_else(|| WorkerExit {
                description: "its reaper ended".to_owned(),
            })
        })
    }

    fn live(&self) -> LauncherFuture<'_, bool> {
        Box::pin(async move {
            self.client
                .get(&self.health)
                .send()
                .await
                .is_ok_and(|reply| reply.status().is_success())
        })
    }

    fn activity(&self) -> LauncherFuture<'_, Option<WorkerActivity>> {
        // An EXL3 worker reports its queue, its open calls and its allocator
        // reservation on its native socket (a cheap `stats`, never a walk of
        // its tensors); a worker without one reports nothing.
        Box::pin(async move {
            match &self.native {
                Some(socket) => super::super::native_exl3::activity(socket).await,
                None => None,
            }
        })
    }

    fn terminate(&self, grace: Duration) -> LauncherFuture<'_, WorkerExit> {
        Box::pin(async move {
            if let Some(exit) = self.already_exited() {
                return exit;
            }
            self.signal(Signal::TERM);
            if let Ok(exit) = tokio::time::timeout(grace, self.exited()).await {
                return exit;
            }
            self.signal(Signal::KILL);
            self.exited().await
        })
    }
}
