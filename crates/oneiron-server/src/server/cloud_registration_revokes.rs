//! One owned per-vault consumer for committed local erase revokes.

use std::sync::Arc;
use tokio::task::JoinHandle;

use super::core::SyncServer;

impl SyncServer {
    /// Attach before returning, so an erase cannot race the worker's first poll.
    pub(super) fn spawn_cloud_registration_erase_revoker(
        self: &Arc<Self>,
    ) -> Option<JoinHandle<()>> {
        let mut receiver = self.cloud_registration.attach_erase_revoker(self.vault())?;
        let server = Arc::clone(self);
        Some(tokio::spawn(async move {
            while let Some(capture) = receiver.recv().await {
                if server.housekeeping_passes.stopping() {
                    return;
                }
                let revoker = Arc::clone(&server);
                let (ended, done) = tokio::sync::oneshot::channel::<()>();
                let run = tokio::task::spawn_blocking(move || {
                    revoker.cloud_registration.revoke_after_owner_erase(capture);
                    let _ = ended.send(());
                });
                // Track the actual blocking handle before this loop can yield.
                // Parent cancellation cannot detach its in-flight HTTP work.
                server.housekeeping_passes.hold(run);
                // One family send at a time, not a task fan-out per erase.
                let _ = done.await;
            }
        }))
    }
}
