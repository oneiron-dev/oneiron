//! The healer oversight receipts (ARCH-0066 §8): each vault signs three counts
//! about review work, coverage, review latency and escalation rate. The engine
//! owns no timers, so the host emits them once at start and then on a fixed
//! cadence; the owner reads the latest at `GET /v1/owner/healer/oversight`.

use std::sync::Arc;
use std::time::Duration;

use super::core::SyncServer;

/// How often the host signs the receipts again.
pub(crate) const HEALER_OVERSIGHT_EVERY: Duration = Duration::from_secs(60 * 60);

impl SyncServer {
    /// Starts the oversight emission. The first tick fires at once, so a
    /// vault carries its receipts from its first serve.
    pub(crate) fn spawn_healer_oversight(
        self: &Arc<Self>,
        every: Duration,
    ) -> tokio::task::JoinHandle<()> {
        let server = Arc::clone(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(every);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                let server = Arc::clone(&server);
                match tokio::task::spawn_blocking(move || server.emit_healer_oversight_once()).await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        tracing::warn!(%error, "healer oversight emission failed");
                    }
                    Err(error) => tracing::warn!(%error, "healer oversight task failed"),
                }
            }
        })
    }

    /// Signs and stores the three receipts as of the vault's clock.
    pub(crate) fn emit_healer_oversight_once(&self) -> Result<(), oneiron::Error> {
        let vault = self.vault();
        vault.emit_healer_oversight(vault.now_recorded_at())?;
        Ok(())
    }
}
