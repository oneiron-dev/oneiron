//! The manager's inherited legal-copy channel and its joined blocking workers.

use std::collections::HashMap;
use std::io;
use std::net::Shutdown;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use oneiron::Vault;
use oneiron::deletion::HostLegalChannel;
use tokio::sync::oneshot;
use tokio::task::{Id, JoinError, JoinHandle, JoinSet};

use super::{ManagedArgs, ManagedShutdown};

/// Unique ownership across fallible startup, before native serving starts.
pub(super) struct HostLegalListener {
    listener: UnixListener,
    host_uid: u32,
}

impl HostLegalListener {
    pub(super) fn take(managed: &mut ManagedArgs) -> io::Result<Option<Self>> {
        let Some((fd, host_uid)) = managed.host_legal.take() else {
            return Ok(None);
        };
        // SAFETY: fcntl only reads flags from the supervisor's descriptor.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the validated managed handoff names a live inherited fd,
        // distinct from every other adopted descriptor. Taking the pair above
        // clears it before any ManagedArgs clone; this is its sole adoption.
        let listener = unsafe { UnixListener::from_raw_fd(fd) };
        // Child programs must not inherit the manager's listening authority.
        // SAFETY: the owned listener keeps this descriptor live for fcntl.
        if unsafe {
            libc::fcntl(
                listener.as_raw_fd(),
                libc::F_SETFD,
                flags | libc::FD_CLOEXEC,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Some(Self { listener, host_uid }))
    }

    pub(super) fn start(
        self,
        vault: Arc<Vault>,
        shutdown: ManagedShutdown,
    ) -> io::Result<HostLegalService> {
        let channel = HostLegalChannel::from_listener(self.listener, self.host_uid)?;
        let cancelled = Arc::new(AtomicBool::new(false));
        let (stop, stopped) = oneshot::channel();
        let worker_cancelled = Arc::clone(&cancelled);
        let task = tokio::spawn(serve(channel, vault, shutdown, stopped, worker_cancelled));
        Ok(HostLegalService {
            cancelled,
            stop,
            task,
        })
    }
}

/// Retained by managed startup until every accepted native collector joins.
pub(super) struct HostLegalService {
    cancelled: Arc<AtomicBool>,
    stop: oneshot::Sender<()>,
    task: JoinHandle<io::Result<()>>,
}

impl HostLegalService {
    pub(super) async fn stop(self) {
        self.cancelled.store(true, Ordering::Release);
        let _ = self.stop.send(());
        match self.task.await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                tracing::warn!(%error, "HOST legal channel stopped after an I/O error")
            }
            Err(error) => tracing::warn!(%error, "HOST legal channel task failed"),
        }
    }
}

async fn serve(
    channel: HostLegalChannel,
    vault: Arc<Vault>,
    shutdown: ManagedShutdown,
    mut stop: oneshot::Receiver<()>,
    cancelled: Arc<AtomicBool>,
) -> io::Result<()> {
    let mut shutdown = shutdown.triggered();
    let mut workers = JoinSet::new();
    let mut active = HashMap::new();
    let result = loop {
        tokio::select! {
            biased;
            _ = &mut stop => break Ok(()),
            _ = &mut shutdown => break Ok(()),
            completed = workers.join_next_with_id(), if !workers.is_empty() => {
                if let Some(completed) = completed {
                    finish(completed, &mut active);
                }
            }
            accepted = channel.accept() => {
                let connection = match accepted {
                    Ok(connection) => connection,
                    Err(error) if matches!(error.kind(), io::ErrorKind::PermissionDenied
                        | io::ErrorKind::ConnectionAborted | io::ErrorKind::Interrupted) => {
                        tracing::warn!(%error, "HOST legal connection was not accepted");
                        continue;
                    }
                    Err(error) => {
                        tracing::warn!(%error, "HOST legal listener stopped accepting");
                        break Err(error);
                    }
                };
                let stream = match connection.shutdown_handle() {
                    Ok(stream) => stream,
                    Err(error) => {
                        tracing::warn!(%error, "HOST legal shutdown handle failed");
                        continue;
                    }
                };
                let vault = Arc::clone(&vault);
                let cancelled = Arc::clone(&cancelled);
                let worker = workers.spawn_blocking(move || connection.run(&vault, &cancelled));
                active.insert(worker.id(), stream);
            }
        }
    };
    cancelled.store(true, Ordering::Release);
    if let Err(error) = vault.stop_pending_host_legal_captures() {
        tracing::warn!(%error, "HOST legal pending captures did not stop");
    }
    drop(channel);
    // Close every accepted socket before joining any worker: one can hold the
    // native source writer while another waits for that writer.
    for stream in active.values() {
        let _ = stream.shutdown(Shutdown::Both);
    }
    while let Some(completed) = workers.join_next_with_id().await {
        finish(completed, &mut active);
    }
    result
}

fn finish(
    completed: Result<(Id, oneiron::Result<()>), JoinError>,
    active: &mut HashMap<Id, UnixStream>,
) {
    match completed {
        Ok((id, outcome)) => {
            active.remove(&id);
            if let Err(error) = outcome {
                tracing::warn!(%error, "HOST legal capture did not finish");
            }
        }
        Err(error) => {
            active.remove(&error.id());
            tracing::warn!(%error, "HOST legal capture worker failed");
        }
    }
}
