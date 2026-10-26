//! One serve run of an [`super::EmbeddedEngine`], from its start until it
//! returns, and the state that holds it between a stop and a wake (FIX
//! 9483, 9484): a starting run sits in that state before its app is ready,
//! and a stopping one until its drain ends, so no stop, close or wake
//! dropped midway leaves a run nobody joins.

use std::sync::Arc;

use oneiron_vault_contract::host_adapters::{AppHost, EmbeddedHost};
use tokio::io::DuplexStream;
use tokio::sync::{Notify, mpsc, oneshot};

use super::super::failure::{EngineErrorKind, cause, failure};
use super::{ENGINE_CONNECTION_BACKLOG, Readied};
use crate::config::ServeConfig;
use crate::owner::schedule::OwnerHost;

/// One run of the serve body, from its start until it returns.
pub(super) struct Serving {
    pub(super) connector: mpsc::Sender<DuplexStream>,
    /// The artifact app's own channel (`/a/`), apart from the API's.
    pub(super) artifacts: mpsc::Sender<DuplexStream>,
    pub(super) wake: Arc<Notify>,
    pub(super) stop: Arc<Notify>,
    done: oneshot::Receiver<anyhow::Result<()>>,
    /// Asked to stop: it is draining, takes no new connection, and the next
    /// stop, close or wake joins it rather than start another (FIX 9484).
    pub(super) stopping: bool,
}

impl Serving {
    /// Asks the run to stop, once; the drain goes on without a waiter.
    pub(super) fn signal_stop(&mut self) {
        if !self.stopping {
            self.stop.notify_one();
            self.stopping = true;
        }
    }

    /// The serve body returned, or is returning: it takes no connection.
    pub(super) fn ended(&self) -> bool {
        self.connector.is_closed()
    }
}

/// Asks a serve run to stop when its start is dropped before its app is
/// ready (FIX 9483, 9484); disarmed once the run is ready or has ended.
struct StartupStop<'run> {
    stop: &'run Notify,
    stopping: Option<&'run mut bool>,
}

impl StartupStop<'_> {
    /// The run is ready, or has ended: nothing is left to ask.
    fn disarm(mut self) {
        self.stopping = None;
    }
}

impl Drop for StartupStop<'_> {
    fn drop(&mut self) {
        if let Some(stopping) = self.stopping.take() {
            self.stop.notify_one();
            *stopping = true;
        }
    }
}

/// Starts the serve body over `vault` on a thread of its own, its app not
/// yet ready: on a runtime of its own capped at `serve_workers` workers, or
/// on the caller's ([`super::super::runtime::spawn_serving`]).
pub(super) fn spawn_run<A: AppHost + 'static>(
    host: EmbeddedHost<Readied<A>, DuplexStream>,
    vault: Arc<oneiron::Vault>,
    config: ServeConfig,
    owner_host: OwnerHost,
    serve_workers: Option<usize>,
) -> anyhow::Result<Serving> {
    let connector = host.connector();
    // The artifact origin's channel, served beside the API's for this run.
    let (artifacts, artifact_streams) = mpsc::channel(ENGINE_CONNECTION_BACKLOG);
    let (wake, stop) = (host.wake_handle(), host.stop_handle());
    let done = super::super::runtime::spawn_serving(serve_workers, move || {
        super::super::serve_prepared(host, vault, config, Some(artifact_streams), owner_host)
    })?;
    Ok(Serving {
        connector,
        artifacts,
        wake,
        stop,
        done,
        stopping: false,
    })
}

/// Why serving ended before the app's `ready` ran.
fn startup_failure(served: Result<anyhow::Result<()>, oneshot::error::RecvError>) -> anyhow::Error {
    match served {
        Ok(Err(error)) => error.context(cause(
            EngineErrorKind::StartFailed,
            "the embedded engine did not start",
        )),
        Ok(Ok(())) => failure(
            EngineErrorKind::StartFailed,
            "the embedded engine stopped before it was ready",
        ),
        Err(_) => failure(
            EngineErrorKind::StartFailed,
            "the embedded engine's serve thread panicked before it was ready",
        ),
    }
}

/// What serving holds between a stop and a wake.
pub(super) struct State<A> {
    pub(super) app: A,
    pub(super) serving: Option<Serving>,
}

impl<A> State<A> {
    /// Keeps `serving`, a run [`spawn_run`] started, here while it waits for
    /// its app's `ready` on `readied` (FIX 9484): a start or wake dropped
    /// meanwhile leaves it here, stopping, for the next stop, close or wake
    /// to join. A run that ends before it is ready is gone, with why.
    pub(super) async fn start_run(
        &mut self,
        serving: Serving,
        mut readied: oneshot::Receiver<()>,
    ) -> anyhow::Result<()> {
        let serving = self.serving.insert(serving);
        let startup = StartupStop {
            stop: &serving.stop,
            stopping: Some(&mut serving.stopping),
        };
        let served = tokio::select! {
            biased;
            ready = &mut readied => match ready {
                Ok(()) => {
                    startup.disarm();
                    return Ok(());
                }
                Err(_) => (&mut serving.done).await,
            },
            served = &mut serving.done => served,
        };
        startup.disarm();
        self.serving = None;
        Err(startup_failure(served))
    }

    /// Stops the serving run, if any, and waits out its ordered drain in
    /// place (FIX 9484): the run stays here, stopping, until its completion
    /// arrives, so a stop, close or wake dropped mid-drain leaves it for the
    /// next one to join, and none declares the engine stopped before it is.
    pub(super) async fn join_serving(&mut self) -> anyhow::Result<()> {
        let Some(serving) = self.serving.as_mut() else {
            return Ok(());
        };
        serving.signal_stop();
        let finished = (&mut serving.done).await;
        self.serving = None;
        finished.unwrap_or_else(|_| {
            Err(anyhow::anyhow!(
                "the embedded engine's serve thread panicked"
            ))
        })
    }
}
