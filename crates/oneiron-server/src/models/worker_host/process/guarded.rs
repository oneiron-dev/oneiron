//! The registered Mac CLI keeps W direct and delegates only parent-death watching to G.
use std::ffi::OsString;
use std::io;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use oneiron_driver::{
    LauncherFuture, RunningWorker, WORKER_STOP_GRACE, WorkerActivity, WorkerExit,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::super::media_worker::StatsRoute;
use super::{Notifications, ProcessWorker, client, take_child};
use crate::mac_worker_bootstrap::{
    sys,
    wire::{self, ExecSpec},
};

mod controller;

pub(crate) async fn spawn(
    cli: &Path,
    program: &Path,
    args: &[String],
    dir: &Path,
    env: &[(String, String)],
    health: &str,
    native: Option<PathBuf>,
    stats: Option<StatsRoute>,
    llama_metrics: Option<super::super::llama_metrics::MetricsRoute>,
    slot: &super::super::launch_manifest::LaunchSlot,
) -> io::Result<Box<dyn RunningWorker>> {
    let spec = ExecSpec {
        program: program.to_owned(),
        dir: dir.to_owned(),
        args: args.iter().map(OsString::from).collect(),
        env: env
            .iter()
            .map(|(name, value)| (OsString::from(name), OsString::from(value)))
            .collect(),
    }
    .encode()?;
    let client = client()?;
    let (control, worker_control) = sys::socket_pair()?;
    let (worker_peer, guardian_peer) = sys::socket_pair()?;
    let (status, worker_status) = sys::socket_pair()?;
    let (stop_writer, stop) = sys::socket_pair()?;
    let (terminal_writer, terminal) = sys::socket_pair()?;
    control.set_nonblocking(true)?;
    status.set_nonblocking(true)?;
    let placed = sys::placements(&[
        worker_control.as_raw_fd(),
        worker_peer.as_raw_fd(),
        worker_status.as_raw_fd(),
    ]);
    // Capture S itself before any fork. A delayed child never captures init as S.
    // SAFETY: getpid takes no arguments and never fails.
    let original = unsafe { libc::getpid() };
    let mut command: tokio::process::Command = oneiron_spawn::command_with_fds(cli, &placed).into();
    command
        .args([
            wire::MARKER,
            "worker",
            &original.to_string(),
            &placed[0].1.to_string(),
            &placed[1].1.to_string(),
            &placed[2].1.to_string(),
        ])
        .process_group(0)
        .kill_on_drop(false)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    let child = command.spawn()?;
    drop((worker_control, worker_peer, worker_status));
    let (state, exit) = take_child(
        child,
        Some(Notifications {
            stop: stop_writer,
            terminal: terminal_writer,
        }),
    )?;
    let mut startup = Startup {
        worker: Some(ProcessWorker {
            state,
            exit,
            health: health.to_owned(),
            client,
            native: None,
            stats,
            llama_metrics,
        }),
        control: Some(control),
    };
    let worker = startup.worker.as_ref().unwrap();
    let (ready, mut failed) = controller::start(
        Arc::downgrade(&worker.state),
        worker.exit.clone(),
        controller::Start {
            cli: cli.to_owned(),
            original,
            peer: guardian_peer,
            stop,
            terminal,
        },
    )?;
    let mut control =
        tokio::net::UnixStream::from_std(startup.control.as_ref().unwrap().try_clone()?)?;
    let mut status = tokio::net::UnixStream::from_std(status)?;
    // W must receive complete Spec before G can complete its initial peer ACK.
    control.write_all(&spec).await?;
    tokio::select! {
        ready = ready => ready.map_err(|_| io::Error::other("guardian controller ended before arming"))??,
        exit = startup.worker.as_ref().unwrap().exited() => return Err(io::Error::other(exit.description)),
    }
    control.write_all(&[wire::EXEC]).await?;
    let exec_status = async {
        let mut bytes = [0; 4];
        let mut got = 0;
        while got != bytes.len() {
            match status.read(&mut bytes[got..]).await? {
                0 if got == 0 => return Ok(()),
                0 => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "partial worker exec error",
                    ));
                }
                read => got += read,
            }
        }
        Err(io::Error::from_raw_os_error(i32::from_be_bytes(bytes)))
    };
    tokio::select! {
        result = exec_status => result?,
        failure = &mut failed => return Err(failure.unwrap_or_else(|_| io::Error::other("guardian controller ended during exec"))),
        exit = startup.worker.as_ref().unwrap().exited() => return Err(io::Error::other(exit.description)),
    }
    let mut worker = startup.worker.take().unwrap();
    if let Some(exit) = worker.already_exited() {
        return Err(io::Error::other(exit.description));
    }
    worker.native = native;
    if let Some(record) = slot
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .as_mut()
    {
        record.native_peer = Some(worker.native_peer());
    }
    let worker = Arc::new(worker);
    let watched = Arc::clone(&worker);
    tokio::spawn(async move {
        tokio::select! {
            _ = watched.exited() => {},
            failure = failed => {
                if failure.is_ok() {
                    // A real failed rearm, not guardian loss alone. The SAME
                    // existing managed stop/grace path produces W's real exit.
                    watched.terminate(WORKER_STOP_GRACE).await;
                }
            },
        }
    });
    Ok(Box::new(Guarded { worker }))
}

/// PreOk cancellation never drops a join pin on a Tokio future. The native
/// controller owns it and is independently woken before any W terminal await.
struct Startup {
    worker: Option<ProcessWorker>,
    control: Option<std::os::unix::net::UnixStream>,
}

impl Drop for Startup {
    fn drop(&mut self) {
        let Some(worker) = self.worker.take() else {
            return;
        };
        let _ = worker.request_stop();
        let control = self.control.take();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                worker.terminate(WORKER_STOP_GRACE).await;
                drop(control);
            });
        }
        // If the real CLI runtime is already gone, no cleanup task is assumed
        // to run. G's native controller/parent NOTE_EXIT survive until S exits.
    }
}

struct Guarded {
    worker: Arc<ProcessWorker>,
}

impl RunningWorker for Guarded {
    fn exited(&self) -> LauncherFuture<'_, WorkerExit> {
        self.worker.exited()
    }
    fn live(&self) -> LauncherFuture<'_, bool> {
        self.worker.live()
    }
    fn activity(&self) -> LauncherFuture<'_, Option<WorkerActivity>> {
        self.worker.activity()
    }
    fn terminate(&self, grace: Duration) -> LauncherFuture<'_, WorkerExit> {
        self.worker.terminate(grace)
    }
    fn abort(&self) -> LauncherFuture<'_, WorkerExit> {
        self.worker.abort()
    }
}
