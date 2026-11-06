//! Physical obligations left by terminal bundle work; pending work is untouched.
use super::SyncServer;
use oneiron::sync::residence::{cleanup_sealed_bundle_work, sealed_bundle_work_memory_bytes};
use std::sync::Arc;
use std::time::{Duration, Instant};

impl SyncServer {
    pub(crate) fn residence_work_stopping(&self) -> bool {
        self.housekeeping_passes.stopping()
    }

    pub(super) async fn cleanup_residence_work(self: &Arc<Self>, budget: Duration) {
        let until = Instant::now() + budget;
        while !self.residence_work_stopping() && Instant::now() < until {
            let bytes = sealed_bundle_work_memory_bytes(0);
            let mut held = self.retained.empty();
            self.retained.charge(
                &mut held,
                usize::try_from(bytes).unwrap_or(usize::MAX),
                &self.transfers.questions,
            );
            let server = Arc::clone(self);
            let next = tokio::task::spawn_blocking(move || {
                let _held = held;
                let _memory = server
                    .memory
                    .lease_until(bytes, until, &|| server.residence_work_stopping())
                    .ok()?;
                if server.residence_work_stopping() {
                    return None;
                }
                let result = cleanup_sealed_bundle_work(server.vault());
                server.transfers.reconcile_sealed_stages(server.vault());
                server.residence_work_changed.notify_waiters();
                Some(result)
            })
            .await;
            match next {
                Ok(Some(Ok(true))) => {}
                Ok(Some(Ok(false))) | Ok(None) => break,
                Ok(Some(Err(error))) => {
                    tracing::warn!(kind = ?error.kind(), "bundle work cleanup remains pending");
                    break;
                }
                Err(error) => {
                    tracing::warn!(
                        panicked = error.is_panic(),
                        "bundle work cleanup worker ended"
                    );
                    break;
                }
            }
            tokio::task::yield_now().await;
        }
    }
}
