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

    /// Fetch one grant-selected item into this device's observed CRDT window.
    pub async fn fetch_item(
        &self,
        window: &crate::sync::WindowKey,
        item: crate::EntityId,
    ) -> Result<(), crate::sync::TransportError> {
        let (mut client, _events) = crate::sync::SyncClient::new(
            Arc::clone(&self.manager),
            self.config.client_config.clone(),
        )
        .map_err(|e| crate::sync::TransportError::Storage(e.to_string()))?;
        client.fetch_item(window, item).await
    }

    /// Promote an opened item's whole window into the canonical Loro unit
    /// before a write. Grant checks run at the home before any full bytes ship.
    pub async fn promote_window(
        &self,
        window: &crate::sync::WindowKey,
        item: crate::EntityId,
    ) -> Result<(), crate::sync::TransportError> {
        let (mut client, _events) = crate::sync::SyncClient::new(
            Arc::clone(&self.manager),
            self.config.client_config.clone(),
        )
        .map_err(|e| crate::sync::TransportError::Storage(e.to_string()))?;
        client.promote_window(window, item).await
    }

    /// The first write to a thin item promotes its canonical window before
    /// changing the ledger. After that, the ordinary local Loro mirror and
    /// queued CRDT path carry the edit. Other write doors refuse thin IDs.
    pub async fn edit_opened_item(
        &self,
        window: &crate::sync::WindowKey,
        item: crate::EntityId,
        entity_type: u8,
        occurred: crate::TimeRange,
        learned_at: u64,
        body: &[u8],
    ) -> Result<(), crate::sync::TransportError> {
        if self.thin_item(item)?.is_some() {
            self.promote_window(window, item).await?;
        }
        if self
            .manager
            .vault()
            .sync_state_get(&format!("rp:w:{window}"))
            .map_err(|e| crate::sync::TransportError::Storage(e.to_string()))?
            .is_none()
        {
            return Err(crate::sync::TransportError::InvalidPayload(
                "item write requires causal window promotion",
            ));
        }
        if window
            .start_timestamp()
            .is_none_or(|start| learned_at < start)
            || window.end_timestamp().is_some_and(|end| learned_at >= end)
        {
            return Err(crate::sync::TransportError::InvalidWindowKey);
        }
        self.manager
            .vault()
            .put_entity(&item, entity_type, occurred, learned_at, body)
            .map_err(|e| crate::sync::TransportError::Storage(e.to_string()))?;
        let loaded = self
            .manager
            .open_window(window)
            .map_err(|e| crate::sync::TransportError::Storage(e.to_string()))?;
        let raw = self
            .manager
            .vault()
            .get_raw_unsealed(&item)
            .map_err(|e| crate::sync::TransportError::Storage(e.to_string()))?
            .ok_or(crate::sync::TransportError::InvalidPayload(
                "edited item absent",
            ))?;
        crate::sync::loro_support::map_insert_bytes(
            &loaded.doc.get_map("entities"),
            &item.to_hex(),
            &raw,
        )
        .map_err(|e| crate::sync::TransportError::Storage(e.to_string()))?;
        loaded.doc.commit();
        Ok(())
    }

    /// Read the cached item without materializing it as a writable replica.
    pub fn thin_item(
        &self,
        item: crate::EntityId,
    ) -> Result<Option<crate::sync::ThinItem>, crate::sync::TransportError> {
        let (client, _events) = crate::sync::SyncClient::new(
            Arc::clone(&self.manager),
            self.config.client_config.clone(),
        )
        .map_err(|e| crate::sync::TransportError::Storage(e.to_string()))?;
        client.thin_item(item)
    }

    /// Search on the home node when reachable, or return explicitly partial
    /// local-only results over items previously opened on this device.
    pub async fn search_resident(
        &self,
        query: &str,
        limit: usize,
    ) -> Result<crate::sync::ResidenceSearch, crate::sync::TransportError> {
        let (client, _events) = crate::sync::SyncClient::new(
            Arc::clone(&self.manager),
            self.config.client_config.clone(),
        )
        .map_err(|e| crate::sync::TransportError::Storage(e.to_string()))?;
        client.search_resident(query, limit).await
    }

    /// Clear only the contiguous queued updates whose bytes the home has
    /// durably acknowledged. A different digest or a missing earlier ACK
    /// retains the whole unconfirmed suffix, including delete markers.
    fn clear_residence_acks(&self, client: &mut crate::sync::SyncClient) -> Result<(), String> {
        let mut through = None;
        for queued in self.queue.drain_updates().map_err(|e| e.to_string())? {
            let Some(ack) = client.residence_acks.get(&queued.seq) else {
                break;
            };
            if *ack != *blake3::hash(&queued.encoded).as_bytes() {
                return Err("home residence acknowledgment digest mismatch".into());
            }
            through = Some(queued.seq);
        }
        if let Some(seq) = through {
            self.queue
                .clear_through_confirmed(seq)
                .map_err(|e| e.to_string())?;
            client.residence_acks.retain(|key, _| *key > seq);
        }
        Ok(())
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
