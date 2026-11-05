//! One running worker process in its supervisor's custody: started in a
//! process group of its own, reaped by one task, checked for liveness on its
//! health route, asked what it holds on its native socket when it has one
//! (a media worker on its bearer `/stats`, a llama worker on its `/metrics`),
//! asked there to drain and shut
//! down before it is stopped, and stopped by signals to that group alone.
//! An abort asks the worker nothing. On Mac it first waits for any private
//! guardian join to be killed and reaped; then it kills the worker group and
//! waits for the actual worker's reaper.
use std::future::{Future, poll_fn};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::Duration;

use oneiron_driver::{LauncherFuture, RunningWorker, WorkerActivity, WorkerExit};
use rustix::process::{Pid, Signal, kill_process_group};
use tokio::sync::watch;

use super::media_worker::StatsRoute;

#[cfg(target_os = "macos")]
pub(super) mod guarded;

/// How long one liveness check may take before it counts as not live yet.
/// It only paces the next check; no worker is stopped for it.
const LIVENESS_REQUEST: Duration = Duration::from_secs(5);

/// The owned leader and every signal share the reaper's short poll lock.
struct Custody {
    group: i32,
    child: tokio::process::Child,
    #[cfg(target_os = "macos")]
    pins: usize,
    #[cfg(target_os = "macos")]
    reaper_waker: Option<std::task::Waker>,
    #[cfg(target_os = "macos")]
    stopping: bool,
    #[cfg(target_os = "macos")]
    pin_released: Arc<tokio::sync::Notify>,
    #[cfg(target_os = "macos")]
    stop: Option<std::os::unix::net::UnixStream>,
}

/// A worker process the supervisor started.
pub(super) struct ProcessWorker {
    state: Arc<Mutex<Custody>>,
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
    /// custody of it: one task waits on and reaps it. On Linux it arms the
    /// existing parent-death terminate signal before exec and checks that
    /// the spawning process has not already disappeared.
    pub(super) fn spawn(
        mut command: tokio::process::Command,
        health: String,
        native: Option<PathBuf>,
        stats: Option<StatsRoute>,
    ) -> std::io::Result<Self> {
        let client = client()?;
        command.process_group(0).kill_on_drop(false);
        #[cfg(target_os = "linux")]
        let parent = rustix::process::getpid();
        #[cfg(target_os = "linux")]
        // SAFETY: between fork and exec this closure only makes raw process
        // syscalls and constructs OS-code errors, without locks or allocation.
        unsafe {
            command.pre_exec(move || {
                rustix::process::set_parent_process_death_signal(Some(Signal::TERM))
                    .map_err(std::io::Error::from)?;
                if rustix::process::getppid() != Some(parent) {
                    let _ = rustix::process::kill_process(rustix::process::getpid(), Signal::TERM);
                    // Forbid exec even if the terminate signal is masked or ignored.
                    return Err(std::io::Error::from(rustix::io::Errno::SRCH));
                }
                Ok(())
            });
        }
        let child = command.spawn()?;
        let (state, exit) = take_child(
            child,
            #[cfg(target_os = "macos")]
            None,
        )?;
        Ok(Self {
            state,
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

    #[cfg(not(target_os = "macos"))]
    fn signal(&self, signal: Signal) {
        let custody = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if self.exit.borrow().is_some() {
            return;
        }
        if let Some(group) = Pid::from_raw(custody.group) {
            let _ = kill_process_group(group, signal);
        }
    }

    #[cfg(target_os = "macos")]
    fn request_stop(&self) -> Option<Arc<tokio::sync::Notify>> {
        let mut custody = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if self.exit.borrow().is_some() {
            return None;
        }
        custody.stopping = true;
        if let Some(stop) = &custody.stop {
            let _ = stop.shutdown(std::net::Shutdown::Write);
        }
        Some(Arc::clone(&custody.pin_released))
    }

    #[cfg(target_os = "macos")]
    async fn signal(&self, signal: Signal) {
        let Some(released) = self.request_stop() else {
            return;
        };
        loop {
            let notified = released.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let custody = self
                    .state
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner());
                if self.exit.borrow().is_some() {
                    return;
                }
                if custody.pins == 0 {
                    if let Some(group) = Pid::from_raw(custody.group) {
                        let _ = kill_process_group(group, signal);
                    }
                    return;
                }
            }
            // A native G controller kills/reaps its outstanding join before
            // unpinning. This never waits on W's pin-blocked terminal watch.
            notified.await;
        }
    }

    fn already_exited(&self) -> Option<WorkerExit> {
        self.exit.borrow().clone()
    }
}

#[cfg(target_os = "macos")]
struct Notifications {
    stop: std::os::unix::net::UnixStream,
    terminal: std::os::unix::net::UnixStream,
}

fn take_child(
    child: tokio::process::Child,
    #[cfg(target_os = "macos")] notifications: Option<Notifications>,
) -> std::io::Result<(Arc<Mutex<Custody>>, watch::Receiver<Option<WorkerExit>>)> {
    let group = child
        .id()
        .and_then(|pid| i32::try_from(pid).ok())
        .ok_or_else(|| std::io::Error::other("the worker exited before it was named"))?;
    let (sender, exit) = watch::channel(None);
    #[cfg(target_os = "macos")]
    let (stop, terminal) = match notifications {
        Some(notifications) => (Some(notifications.stop), Some(notifications.terminal)),
        None => (None, None),
    };
    let state = Arc::new(Mutex::new(Custody {
        group,
        child,
        #[cfg(target_os = "macos")]
        pins: 0,
        #[cfg(target_os = "macos")]
        reaper_waker: None,
        #[cfg(target_os = "macos")]
        stopping: false,
        #[cfg(target_os = "macos")]
        pin_released: Arc::new(tokio::sync::Notify::new()),
        #[cfg(target_os = "macos")]
        stop,
    }));
    let reaper = Arc::clone(&state);
    tokio::spawn(async move {
        poll_fn(|cx| {
            let mut custody = reaper.lock().unwrap_or_else(|poison| poison.into_inner());
            #[cfg(target_os = "macos")]
            if custody.pins != 0 {
                custody.reaper_waker = Some(cx.waker().clone());
                return Poll::Pending;
            }
            let status = {
                let mut wait = std::pin::pin!(custody.child.wait());
                match wait.as_mut().poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(status) => status,
                }
            };
            let description = match status {
                Ok(status) => status.to_string(),
                Err(error) => format!("its wait failed: {error}"),
            };
            sender.send_replace(Some(WorkerExit { description }));
            Poll::Ready(())
        })
        .await;
        // The actual watch publication precedes EOF. Cancellation instead
        // closes this writer with watchNone, which the native thread keeps UNKNOWN.
        #[cfg(target_os = "macos")]
        drop(terminal);
    });
    Ok((state, exit))
}

fn client() -> std::io::Result<reqwest::Client> {
    reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(LIVENESS_REQUEST)
        .timeout(LIVENESS_REQUEST)
        .build()
        .map_err(std::io::Error::other)
}

#[cfg(target_os = "macos")]
struct GroupPin {
    state: Arc<Mutex<Custody>>,
    group: i32,
}

#[cfg(target_os = "macos")]
impl GroupPin {
    fn group(&self) -> i32 {
        self.group
    }
}

#[cfg(target_os = "macos")]
fn pin_group(
    state: &Arc<Mutex<Custody>>,
    exit: &watch::Receiver<Option<WorkerExit>>,
) -> Option<GroupPin> {
    let mut custody = state.lock().unwrap_or_else(|poison| poison.into_inner());
    if exit.borrow().is_some()
        || exit.has_changed().is_err()
        || custody.stopping
        || custody.pins != 0
    {
        return None;
    }
    custody.pins += 1;
    Some(GroupPin {
        state: Arc::clone(state),
        group: custody.group,
    })
}

#[cfg(target_os = "macos")]
impl Drop for GroupPin {
    fn drop(&mut self) {
        let (wake, released) = {
            let mut custody = self
                .state
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            custody.pins -= 1;
            (
                custody.reaper_waker.take(),
                Arc::clone(&custody.pin_released),
            )
        };
        if let Some(wake) = wake {
            wake.wake();
        }
        released.notify_waiters();
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
            #[cfg(not(target_os = "macos"))]
            self.signal(Signal::TERM);
            #[cfg(target_os = "macos")]
            self.signal(Signal::TERM).await;
            if let Ok(exit) = tokio::time::timeout(grace, self.exited()).await {
                return exit;
            }
            #[cfg(not(target_os = "macos"))]
            self.signal(Signal::KILL);
            #[cfg(target_os = "macos")]
            self.signal(Signal::KILL).await;
            self.exited().await
        })
    }

    fn abort(&self) -> LauncherFuture<'_, WorkerExit> {
        // An abort asks the worker nothing: no native drain, no terminate
        // signal and no grace. On Mac a pending private guardian join is
        // independently killed/reaped first; no W terminal wait holds its pin.
        // The group is then killed and its actual reaper awaited.
        Box::pin(async move {
            if let Some(exit) = self.already_exited() {
                return exit;
            }
            #[cfg(not(target_os = "macos"))]
            self.signal(Signal::KILL);
            #[cfg(target_os = "macos")]
            self.signal(Signal::KILL).await;
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
