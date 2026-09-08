//! WebSocket connection manager with debounced sync and reconnection.
//!
//! Implements the full connection lifecycle per ARCH-023b:
//! 1. Connect WebSocket to server (protocol-version hello is the first frame)
//! 2. Initial sync flow (root doc + default windows)
//! 3. Drain offline queue: each queued update is imported into the LOCAL
//!    window doc, then replayed to the server via WindowSync
//! 4. Convergence protocol (ARCH-0023b Fig. 2) over the replayed windows
//! 5. Steady state: read WS messages + write debounced local updates
//! 6. On disconnect: queue updates, reconnect with exponential backoff
//!
//! Convergence protocol after queue replay (ONE-1128):
//! - Per round, every unconfirmed window sends SyncStep1 (`VV_REQUEST` with
//!   our VV); the server answers with its delta + `VV_RESPONSE` (its VV),
//!   and our reverse delta goes back (bidirectional SyncStep1/SyncStep2).
//! - A window is converged only when its local doc VV is IDENTICAL to a
//!   server-witnessed VV — a server that never received the replayed
//!   updates can never produce such a witness (no lost-confirmation loss).
//! - The queue is cleared via `clear_through_confirmed` ONLY when ALL
//!   replayed windows are converged. Delete-bearing (tombstone) updates
//!   therefore survive in the queue at least until their own window
//!   converges (ONE-1135: only the CONFIRMED clear removes them + their
//!   `d:` markers).
//! - After `MAX_CONVERGENCE_ROUNDS` (5) unconfirmed rounds: force
//!   re-bootstrap — drop in-memory Docs + clear the queue (`q:`/`e:` rows
//!   only; `h:`/`m:`/`x:` families and delete-bearing rows + `d:` markers
//!   are preserved) and re-run the Phase 1-3
//!   initial sync on the live connection (without the per-connection hello).
//! - Queue overflow (`SyncQueue::is_full`) triggers the same re-bootstrap:
//!   docs dropped + queue cleared between reconnect attempts, so the next
//!   connection re-runs Phase 1-3 from scratch.

mod converge;
mod handshake;
mod session;
mod steady;

use std::sync::Arc;

use crate::sync::client::SyncClientConfig;
use crate::sync::manager::WindowManager;
use crate::sync::queue::SyncQueue;
pub use crate::sync::types::LocalUpdate;
use crate::sync::types::parse_window_key_str;

/// Configuration for the connection manager.
#[derive(Debug, Clone)]
pub struct ConnectionConfig {
    /// Sync client configuration (server URL, auth, debounce, etc.).
    pub client_config: SyncClientConfig,
    /// Whether to auto-reconnect on disconnect.
    pub auto_reconnect: bool,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            client_config: SyncClientConfig::default(),
            auto_reconnect: true,
        }
    }
}

/// Manages the WebSocket connection lifecycle, offline queue, and sync state.
pub struct SyncConnection {
    manager: Arc<WindowManager>,
    queue: SyncQueue,
    config: ConnectionConfig,
}

impl SyncConnection {
    /// Creates a new connection manager over manager-owned windows.
    pub fn new(
        manager: Arc<WindowManager>,
        config: ConnectionConfig,
    ) -> crate::error::Result<Self> {
        let queue = SyncQueue::new(Arc::clone(manager.vault()))?;
        Ok(Self {
            manager,
            queue,
            config,
        })
    }

    /// Returns a reference to the offline queue for external inspection.
    pub fn queue(&self) -> &SyncQueue {
        &self.queue
    }
}

/// Flush all buffered local updates to the persistent offline queue.
/// Logs errors but does not fail — best-effort during disconnect/shutdown.
fn flush_to_queue(queue: &SyncQueue, buffer: &mut Vec<LocalUpdate>) {
    for local_update in buffer.drain(..) {
        if parse_window_key_str(&local_update.window_key).is_none() {
            tracing::error!(
                "Rejected invalid local update window key during queue flush: {}",
                local_update.window_key
            );
            continue;
        }
        let queue_result = queue.push(&local_update.window_key, &local_update.update_bytes);
        if let Err(e) = queue_result {
            tracing::error!("Failed to persist update to offline queue: {e}");
        }
    }
}

/// Reason the steady-state loop exited.
enum LoopExit {
    /// Clean shutdown requested.
    Shutdown,
    /// WebSocket disconnected (with error description).
    Disconnected(String),
}

#[cfg(test)]
mod tests;

#[cfg(test)]
use self::session::{ConvergenceSession, MAX_CONVERGENCE_ROUNDS};
#[cfg(test)]
use crate::sync::client::{SyncClient, SyncEvent};
#[cfg(test)]
use crate::sync::queue::QueuedUpdate;
#[cfg(test)]
use crate::sync::transport::{self, TransportError, window_sub_tags};
#[cfg(test)]
use futures_util::{SinkExt, StreamExt};
#[cfg(test)]
use std::collections::BTreeSet;
#[cfg(test)]
use tokio::sync::mpsc;
#[cfg(test)]
use tokio_tungstenite::tungstenite::Message;
