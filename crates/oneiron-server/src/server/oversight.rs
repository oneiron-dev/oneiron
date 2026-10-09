//! The healer oversight receipts (ARCH-0066 §8): each vault signs three counts
//! about review work, coverage, review latency and escalation rate. The engine
//! owns no timers, so every serving host, plain and managed, signs them once
//! as it starts and then on a fixed cadence; the owner reads the latest at
//! `GET /v1/owner/healer/oversight`.

use std::sync::Arc;
use std::time::Duration;

use super::core::SyncServer;

/// How often the host signs the receipts again.
pub(crate) const HEALER_OVERSIGHT_EVERY: Duration = Duration::from_secs(60 * 60);

impl SyncServer {
    /// Signs the receipts once, then starts the cadence. Awaited before the
    /// host reports ready, so a vault carries its receipts from its first
    /// serve.
    ///
    /// `admit` is the host's write gate. Each emission holds what it returns
    /// until the write finishes, so the host can see the write in flight, and
    /// `None` skips that tick: a managed vault frozen for reap signs nothing.
    pub(crate) async fn start_healer_oversight<A: Send + 'static>(
        self: &Arc<Self>,
        every: Duration,
        admit: impl Fn() -> Option<A> + Send + 'static,
    ) -> tokio::task::JoinHandle<()> {
        let first = admit();
        self.emit_healer_oversight_admitted(first).await;
        let server = Arc::clone(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval_at(tokio::time::Instant::now() + every, every);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                let admission = admit();
                server.emit_healer_oversight_admitted(admission).await;
            }
        })
    }

    async fn emit_healer_oversight_admitted<A: Send + 'static>(
        self: &Arc<Self>,
        admission: Option<A>,
    ) {
        let Some(admission) = admission else {
            return;
        };
        let server = Arc::clone(self);
        let emitted = tokio::task::spawn_blocking(move || {
            let _admission = admission;
            server.emit_healer_oversight_once()
        })
        .await;
        match emitted {
            Ok(Ok(())) => {}
            Ok(Err(error)) => tracing::warn!(%error, "healer oversight emission failed"),
            Err(error) => tracing::warn!(%error, "healer oversight task failed"),
        }
    }

    /// Signs and stores the three receipts as of the vault's clock.
    pub(crate) fn emit_healer_oversight_once(&self) -> Result<(), oneiron::Error> {
        let vault = self.vault();
        vault.emit_healer_oversight(vault.now_recorded_at())?;
        Ok(())
    }
}
