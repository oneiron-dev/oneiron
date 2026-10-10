//! The board publisher: committed TASK writes reach STREAM subscribers.
//!
//! The engine announces every committed TASK write and decides what it means
//! to the board (`oneiron::context_board::CommittedTaskBoardState`). This loop
//! is the host half: it carries each announcement into the process-local
//! stream registry the MCP gateway owns. Done deltas then ride the
//! subscriber's next tool result; wakes wait in the registry for a host-side
//! adapter. The read runs on a blocking thread, outside the registry lock.

use std::sync::Arc;

use oneiron::context_board::CommittedTaskBoardState;
use tokio::sync::broadcast::error::RecvError;

use super::core::SyncServer;

impl SyncServer {
    /// Starts the publisher. It subscribes before it returns, so no TASK
    /// committed after this call is missed.
    pub(crate) fn spawn_board_publisher(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let updates = self.vault().subscribe_task_updates();
        let server = Arc::clone(self);
        tokio::spawn(async move { server.publish_board_forever(updates).await })
    }

    async fn publish_board_forever(
        self: Arc<Self>,
        mut updates: tokio::sync::broadcast::Receiver<oneiron::EntityId>,
    ) {
        loop {
            let task = match updates.recv().await {
                Ok(task) => task,
                Err(RecvError::Lagged(missed)) => {
                    tracing::warn!(
                        missed,
                        "board publisher fell behind; those TASK changes reach subscribers at their next board refresh"
                    );
                    continue;
                }
                Err(RecvError::Closed) => return,
            };
            let vault = Arc::clone(self.vault());
            let state =
                tokio::task::spawn_blocking(move || CommittedTaskBoardState::read(&vault, task))
                    .await;
            match state {
                Ok(Ok(Some(state))) => {
                    let mut registry = self.mcp_registry.lock().await;
                    registry.streams_mut().publish_task_state(state);
                }
                Ok(Ok(None)) => {}
                Ok(Err(error)) => {
                    tracing::warn!(%error, task = %task.to_hex(), "board publisher could not read a committed TASK");
                }
                Err(error) => {
                    tracing::warn!(%error, task = %task.to_hex(), "board publisher read did not finish");
                }
            }
        }
    }
}
