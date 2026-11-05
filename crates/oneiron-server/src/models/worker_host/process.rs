//! One running worker process in its supervisor's custody: started in a
//! process group of its own, reaped by one task, checked for liveness on its
//! health route, asked what it holds on its native socket when it has one
//! (a media worker on its bearer `/stats`, a llama worker on its `/metrics`),
//! asked there to drain and shut
//! down before it is stopped, and stopped by signals to that group alone.
//! An abort kills that group at once and waits for its reaper, asking the
//! worker nothing.
use std::path::PathBuf;
use std::time::Duration;

use oneiron_driver::{LauncherFuture, RunningWorker, WorkerActivity, WorkerExit};
use rustix::process::{Pid, Signal, kill_process_group};
use tokio::sync::watch;

use super::media_worker::StatsRoute;

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
    /// A media worker's stats route (FIX 8318).
    stats: Option<StatsRoute>,
    /// A llama worker's metrics route (FIX 9190): bound only for llama.
    llama_metrics: Option<super::llama_metrics::MetricsRoute>,
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
        stats: Option<StatsRoute>,
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
            stats,
            llama_metrics: None,
        })
    }

    /// Binds this worker's llama.cpp `/metrics` route, for a llama worker
    /// only: the launcher calls it right after [`Self::spawn`].
    pub(super) fn with_llama_metrics(
        mut self,
        metrics: super::llama_metrics::MetricsRoute,
    ) -> Self {
        self.llama_metrics = Some(metrics);
        self
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
        // its tensors), a media worker the same on its bearer `/stats`, a
        // llama worker on its `/metrics`; a worker with none of them reports
        // nothing.
        Box::pin(async move {
            // Only an explicit `/metrics` route is read: a (None, None)
            // worker without one is unknown, never assumed to be llama.
            if let (None, None, Some(metrics)) = (&self.native, &self.stats, &self.llama_metrics) {
                return llama_activity(&self.client, metrics).await;
            }
            match (&self.native, &self.stats) {
                (Some(socket), _) => super::super::native_exl3::activity(socket).await,
                (None, Some(stats)) => super::media_worker::activity(stats).await,
                (None, None) => None,
            }
        })
    }

    fn terminate(&self, grace: Duration) -> LauncherFuture<'_, WorkerExit> {
        Box::pin(async move {
            if let Some(exit) = self.already_exited() {
                return exit;
            }
            // An EXL3 worker with a native socket is asked to stop first: it
            // drains what it accepted, with no deadline, then shuts down
            // (FIX 9298). The signals stay for one that does not answer or
            // does not exit.
            if let Some(socket) = &self.native {
                super::super::native_exl3::drain_and_shutdown(socket).await;
                if let Ok(exit) = tokio::time::timeout(grace, self.exited()).await {
                    return exit;
                }
            }
            self.signal(Signal::TERM);
            if let Ok(exit) = tokio::time::timeout(grace, self.exited()).await {
                return exit;
            }
            self.signal(Signal::KILL);
            self.exited().await
        })
    }

    fn abort(&self) -> LauncherFuture<'_, WorkerExit> {
        // An abort asks the worker nothing: no native drain, no terminate
        // signal and no grace. The group is killed and the reaper awaited.
        Box::pin(async move {
            if let Some(exit) = self.already_exited() {
                return exit;
            }
            self.signal(Signal::KILL);
            self.exited().await
        })
    }
}

/// Reads llama.cpp's deferred and processing gauges. Both are required;
/// missing or unreadable samples mean unknown, not idle. The pinned server
/// exposes no resident-memory gauge.
async fn llama_activity(
    client: &reqwest::Client,
    metrics: &super::llama_metrics::MetricsRoute,
) -> Option<WorkerActivity> {
    let reply = metrics.request(client).send().await.ok()?;
    if !reply.status().is_success() {
        return None;
    }
    let body = reply.text().await.ok()?;
    let mut queued = None;
    let mut active = None;
    for line in body.lines() {
        let mut parts = line.split_whitespace();
        let name = match parts.next() {
            Some(name) => name,
            None => continue,
        };
        if name == "llamacpp:requests_processing" {
            let value = parts.next()?;
            active = Some(llama_count(value)?);
        } else if name == "llamacpp:requests_deferred" {
            let value = parts.next()?;
            queued = Some(llama_count(value)?);
        }
    }
    Some(WorkerActivity {
        queued: queued?,
        active: active?,
        resident_mib: None,
    })
}

/// Reads integer gauge values, including the server's scientific notation.
fn llama_count(text: &str) -> Option<u64> {
    if let Ok(value) = text.parse::<u64>() {
        return Some(value);
    }
    let value: f64 = text.parse().ok()?;
    if !value.is_finite() || value < 0.0 || value.fract() != 0.0 {
        return None;
    }
    if value >= u64::MAX as f64 {
        return None;
    }
    Some(value as u64)
}
