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
        let (quiesce, quiesce_asked) = oneshot::channel();
        let (finish, finish_asked) = oneshot::channel();
        let worker_cancelled = Arc::clone(&cancelled);
        let task = tokio::spawn(serve(
            channel,
            vault,
            shutdown,
            quiesce_asked,
            finish_asked,
            worker_cancelled,
        ));
        Ok(HostLegalService {
            cancelled,
            quiesce: Some(quiesce),
            finish,
            task,
        })
    }
}

/// Retained by managed startup until every accepted native collector joins.
pub(super) struct HostLegalService {
    cancelled: Arc<AtomicBool>,
    quiesce: Option<oneshot::Sender<oneshot::Sender<()>>>,
    finish: oneshot::Sender<()>,
    task: JoinHandle<io::Result<()>>,
}

impl HostLegalService {
    /// At teardown's start: stops accepting, ends every capture but a
    /// prospective order's, and waits until those have joined. Prospective
    /// connections keep draining until [`Self::finish`].
    pub(super) async fn quiesce(&mut self) {
        let Some(quiesce) = self.quiesce.take() else {
            return;
        };
        let (reply, quiesced) = oneshot::channel();
        if quiesce.send(reply).is_ok() {
            let _ = quiesced.await;
        }
    }

    /// Once every other writing worker stopped and before the Vault closes:
    /// the final prospective drain, then every connection ends and joins.
    pub(super) async fn finish(self) {
        self.cancelled.store(true, Ordering::Release);
        let _ = self.finish.send(());
        match self.task.await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                tracing::warn!(%error, "HOST legal channel stopped after an I/O error")
            }
            Err(error) => tracing::warn!(%error, "HOST legal channel task failed"),
        }
    }
}

/// Each accepted connection's shutdown handle, and whether it carries a
/// prospective order.
type Accepted = HashMap<Id, (UnixStream, Arc<AtomicBool>)>;

async fn serve(
    channel: HostLegalChannel,
    vault: Arc<Vault>,
    shutdown: ManagedShutdown,
    mut quiesce: oneshot::Receiver<oneshot::Sender<()>>,
    mut finish: oneshot::Receiver<()>,
    cancelled: Arc<AtomicBool>,
) -> io::Result<()> {
    let mut shutdown = shutdown.triggered();
    let mut workers = JoinSet::new();
    let mut active: Accepted = HashMap::new();
    // After the stop trigger or a quiesce: nothing more is accepted, and only
    // prospective connections still run.
    let mut quiet = false;
    let mut quiesce_open = true;
    let mut quiesced: Option<oneshot::Sender<()>> = None;
    let result = loop {
        if quiet && let Some(reply) = quiesced.take_if(|_| only_prospective(&active)) {
            let _ = reply.send(());
        }
        tokio::select! {
            biased;
            _ = &mut finish => break Ok(()),
            asked = &mut quiesce, if quiesce_open => {
                quiesce_open = false;
                quiesced = asked.ok();
                if !quiet {
                    quiet = true;
                    quiet_captures(&vault, &cancelled, &active);
                }
            }
            _ = &mut shutdown, if !quiet => {
                quiet = true;
                quiet_captures(&vault, &cancelled, &active);
            }
            completed = workers.join_next_with_id(), if !workers.is_empty() => {
                if let Some(completed) = completed {
                    joined(completed, &mut active);
                }
            }
            accepted = channel.accept(), if !quiet => {
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
                let prospective = connection.prospective_flag();
                let vault = Arc::clone(&vault);
                let cancelled = Arc::clone(&cancelled);
                let worker = workers.spawn_blocking(move || connection.run(&vault, &cancelled));
                active.insert(worker.id(), (stream, prospective));
            }
        }
    };
    drop(channel);
    if !quiet {
        quiet_captures(&vault, &cancelled, &active);
    }
    // Every writer of this process has stopped: each prospective order
    // drains its last entries and names its next ordinal. A listener error
    // skips it; the outboxes stay for the next start.
    if result.is_ok() {
        let drain = Arc::clone(&vault);
        if let Err(error) =
            tokio::task::spawn_blocking(move || drain.finish_host_legal_prospective()).await
        {
            tracing::warn!(%error, "HOST legal final drain task failed");
        }
    }
    if let Err(error) = vault.stop_pending_host_legal_captures() {
        tracing::warn!(%error, "HOST legal pending captures did not stop");
    }
    // Close every accepted socket before joining any worker: one can hold the
    // native source writer while another waits for that writer.
    for (stream, _) in active.values() {
        let _ = stream.shutdown(Shutdown::Both);
    }
    while let Some(completed) = workers.join_next_with_id().await {
        joined(completed, &mut active);
    }
    if let Some(reply) = quiesced.take() {
        let _ = reply.send(());
    }
    result
}

/// The stop trigger: every capture but a prospective order's ends now, and
/// its socket closes, since one can hold the native source writer the final
/// drain needs. Prospective connections keep draining.
fn quiet_captures(vault: &Vault, cancelled: &AtomicBool, active: &Accepted) {
    cancelled.store(true, Ordering::Release);
    if let Err(error) = vault.stop_live_host_legal_captures() {
        tracing::warn!(%error, "HOST legal live captures did not stop");
    }
    for (stream, prospective) in active.values() {
        if !prospective.load(Ordering::Acquire) {
            let _ = stream.shutdown(Shutdown::Both);
        }
    }
}

/// Whether every connection still running carries a prospective order.
fn only_prospective(active: &Accepted) -> bool {
    active
        .values()
        .all(|(_, prospective)| prospective.load(Ordering::Acquire))
}

fn joined(completed: Result<(Id, oneiron::Result<()>), JoinError>, active: &mut Accepted) {
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
