//! The healer oversight receipts (ARCH-0066 §8): each vault signs three counts
//! about review work, coverage, review latency and escalation rate. The engine
//! owns no timers, so every serving host, plain and managed, signs them once
//! as it starts and then on a fixed cadence; the owner reads the latest at
//! `GET /v1/owner/healer/oversight`.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::oneshot;
use tokio::task::{JoinError, JoinHandle};

use super::core::SyncServer;

/// How often the host signs the receipts again.
pub(crate) const HEALER_OVERSIGHT_EVERY: Duration = Duration::from_secs(60 * 60);

/// Why a host could not sign its first receipts. A vault carries them from
/// its first serve (ARCH-0066 §9), so the host stops here instead of
/// reporting ready.
#[derive(Debug, thiserror::Error)]
pub enum OversightStartError {
    /// The host's write gate refused the first emission.
    #[error("the host refused the first healer oversight emission")]
    NotAdmitted,
    /// The vault refused the write.
    #[error("the first healer oversight receipts were not signed: {0}")]
    Refused(oneiron::Error),
    /// The write's blocking task panicked or was cancelled.
    #[error("the first healer oversight emission did not finish: {0}")]
    Interrupted(JoinError),
}

/// The running cadence. Dropping it stops future ticks; [`Self::stop`] also
/// waits for a write already admitted.
pub(crate) struct HealerOversight {
    stop: oneshot::Sender<()>,
    task: JoinHandle<()>,
}

impl HealerOversight {
    /// Stops future ticks, then waits for an emission already admitted to end
    /// its write. That write runs on a blocking thread, which no abort
    /// reaches, so shutdown goes on only once it is done.
    pub(crate) async fn stop(self) {
        let _ = self.stop.send(());
        if let Err(error) = self.task.await {
            tracing::warn!(%error, "healer oversight task failed");
        }
    }
}

impl SyncServer {
    /// Signs the receipts once, then starts the cadence. Awaited before the
    /// host reports ready, and a first emission that is refused or fails is
    /// returned, so a vault carries its receipts from its first serve. Later
    /// failures are logged and the next tick tries again.
    ///
    /// `admit` is the host's write gate. Each emission holds what it returns
    /// until the write finishes, so the host can see the write in flight. On
    /// a later tick `None` skips that tick: a managed vault frozen for reap
    /// signs nothing.
    pub(crate) async fn start_healer_oversight<A: Send + 'static>(
        self: &Arc<Self>,
        every: Duration,
        admit: impl Fn() -> Option<A> + Send + 'static,
    ) -> Result<HealerOversight, OversightStartError> {
        let admission = admit().ok_or(OversightStartError::NotAdmitted)?;
        match self.emit_healer_oversight_admitted(admission).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => return Err(OversightStartError::Refused(error)),
            Err(error) => return Err(OversightStartError::Interrupted(error)),
        }
        let (stop, mut stopped) = oneshot::channel();
        let server = Arc::clone(self);
        let task = tokio::spawn(async move {
            let mut interval = tokio::time::interval_at(tokio::time::Instant::now() + every, every);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                // A stop, or a dropped handle, ends the cadence between
                // emissions, never during one.
                tokio::select! {
                    biased;
                    _ = &mut stopped => return,
                    _ = interval.tick() => {}
                }
                let Some(admission) = admit() else {
                    continue;
                };
                match server.emit_healer_oversight_admitted(admission).await {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => tracing::warn!(%error, "healer oversight emission failed"),
                    Err(error) => tracing::warn!(%error, "healer oversight task failed"),
                }
            }
        });
        Ok(HealerOversight { stop, task })
    }

    async fn emit_healer_oversight_admitted<A: Send + 'static>(
        self: &Arc<Self>,
        admission: A,
    ) -> Result<Result<(), oneiron::Error>, JoinError> {
        let server = Arc::clone(self);
        tokio::task::spawn_blocking(move || {
            let _admission = admission;
            server.emit_healer_oversight_once()
        })
        .await
    }

    /// Signs and stores the three receipts as of the vault's clock.
    pub(crate) fn emit_healer_oversight_once(&self) -> Result<(), oneiron::Error> {
        let vault = self.vault();
        vault.emit_healer_oversight(vault.now_recorded_at())?;
        Ok(())
    }
}
