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
mod node_batch;
mod session;
mod steady;
mod topology;

use std::sync::Arc;

use crate::sync::client::{SyncClientConfig, SyncResidenceMode};
use crate::sync::manager::WindowManager;
use crate::sync::queue::SyncQueue;
pub use crate::sync::types::LocalUpdate;
use crate::sync::types::parse_window_key_str;
pub use topology::HomeNodeTopology;

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
    /// The residence mode this machine runs now. A change closes the live
    /// socket; the next connect negotiates the new hello.
    mode: tokio::sync::watch::Sender<SyncResidenceMode>,
}

/// What switching this machine's residence mode did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResidenceModeChange {
    /// The mode the machine runs now; the elected home always runs All.
    pub mode: SyncResidenceMode,
    /// Held windows the home granted again, kept as promoted opened windows.
    pub retained: Vec<crate::sync::WindowKey>,
    /// Held windows the home did not grant again: still on disk, unsynced.
    pub unsynced: Vec<crate::sync::WindowKey>,
    /// Opened-item read caches dropped on the way to sync-all.
    pub pruned_items: usize,
}

impl SyncConnection {
    /// Creates a new connection manager over manager-owned windows. An own
    /// device runs its persisted residence choice (the elected home runs
    /// All); the configured mode stands when the owner never chose.
    pub fn new(
        manager: Arc<WindowManager>,
        config: ConnectionConfig,
    ) -> crate::error::Result<Self> {
        let queue = SyncQueue::new(Arc::clone(manager.vault()))?;
        let mode = if config.client_config.federation_peer.is_some() {
            config.client_config.residence_mode
        } else {
            crate::sync::residence::resolve_residence_mode(
                manager.vault(),
                config.client_config.residence_mode,
            )?
        };
        Ok(Self {
            manager,
            queue,
            config,
            mode: tokio::sync::watch::channel(mode).0,
        })
    }

    /// The client configuration with the residence mode this machine runs now.
    fn client_config(&self) -> SyncClientConfig {
        let mut config = self.config.client_config.clone();
        config.residence_mode = *self.mode.borrow();
        config
    }

    fn client(&self) -> Result<crate::sync::SyncClient, crate::sync::TransportError> {
        crate::sync::SyncClient::new(Arc::clone(&self.manager), self.client_config())
            .map(|(client, _events)| client)
            .map_err(|e| crate::sync::TransportError::Storage(e.to_string()))
    }

    /// The residence mode this machine runs now.
    pub fn residence_mode(&self) -> SyncResidenceMode {
        *self.mode.borrow()
    }

    /// Switch this machine between sync-all and sync-what-you-opened. The
    /// choice persists; the live socket closes and reconnects with the new
    /// hello. To sync-all, the opened read caches are dropped (full windows
    /// replace them). To opened, each window held in full is granted again
    /// by the home before it keeps syncing as a promoted window; that needs
    /// the home reachable, and an offline home leaves the mode unchanged.
    /// Nothing held is erased. The elected home always stays All.
    pub async fn set_residence_mode(
        &self,
        mode: SyncResidenceMode,
    ) -> Result<ResidenceModeChange, crate::sync::TransportError> {
        let storage = |e: crate::Error| crate::sync::TransportError::Storage(e.to_string());
        if self.config.client_config.federation_peer.is_some() {
            return Err(crate::sync::TransportError::InvalidPayload(
                "a federation lane has no residence mode",
            ));
        }
        let vault = self.manager.vault();
        let effective = crate::sync::residence::effective_residence_mode(
            None,
            mode,
            crate::sync::residence::local_is_elected_home(vault).map_err(storage)?,
        );
        let mut change = ResidenceModeChange {
            mode: effective,
            retained: Vec::new(),
            unsynced: Vec::new(),
            pruned_items: 0,
        };
        if effective != *self.mode.borrow() {
            match effective {
                SyncResidenceMode::All => {
                    // A cached id refuses local writes until promoted; the
                    // full windows supersede every read cache.
                    change.pruned_items = crate::sync::residence::prune_thin_items(vault, u64::MAX)
                        .map_err(storage)?;
                }
                SyncResidenceMode::Opened => {
                    let mut config = self.client_config();
                    config.residence_mode = SyncResidenceMode::Opened;
                    let (mut client, _events) =
                        crate::sync::SyncClient::new(Arc::clone(&self.manager), config)
                            .map_err(storage)?;
                    for window in crate::sync::residence::discover_local_window_keys(vault)
                        .map_err(storage)?
                    {
                        if client.retain_window(&window).await? {
                            change.retained.push(window);
                        } else {
                            change.unsynced.push(window);
                        }
                    }
                }
            }
        }
        crate::sync::residence::set_device_sync_preference(vault, mode).map_err(storage)?;
        self.mode.send_replace(effective);
        Ok(change)
    }

    /// Open one item for a person: its read cache, its local canonical row,
    /// or a first touch at the home. See [`crate::sync::SyncClient::open_item`].
    pub async fn open_item(
        &self,
        window: &crate::sync::WindowKey,
        item: crate::EntityId,
    ) -> Result<crate::sync::OpenedItem, crate::sync::TransportError> {
        self.client()?.open_item(window, item).await
    }

    /// Fetch the current windows' thin index again and return it.
    pub async fn refresh_residence_index(
        &self,
        now_secs: u64,
    ) -> Result<Vec<crate::sync::ResidenceIndexWindow>, crate::sync::TransportError> {
        self.client()?.refresh_residence_index(now_secs).await
    }

    /// Relay this machine's sealed private-world windows through the home
    /// (OF-534 G7). See [`crate::sync::SyncClient::relay_sealed_windows`].
    pub async fn relay_sealed_windows(
        &self,
    ) -> Result<crate::sync::SealedRelay, crate::sync::TransportError> {
        if self.config.client_config.federation_peer.is_some() {
            return Err(crate::sync::TransportError::InvalidPayload(
                "a federation lane relays no sealed window",
            ));
        }
        self.client()?.relay_sealed_windows().await
    }

    /// Take in the signed authority entries the home holds and this machine
    /// lacks (OF-469). See [`crate::sync::SyncClient::catch_up_authority`].
    pub async fn catch_up_authority(&self) -> Result<usize, crate::sync::TransportError> {
        if self.config.client_config.federation_peer.is_some() {
            return Err(crate::sync::TransportError::InvalidPayload(
                "a federation lane takes no home authority history",
            ));
        }
        self.client()?.catch_up_authority().await
    }

    /// The thin index this device holds.
    pub fn residence_index(
        &self,
    ) -> Result<Vec<crate::sync::ResidenceIndexWindow>, crate::sync::TransportError> {
        self.client()?.residence_index()
    }

    /// Drop read caches of opened items last touched before `before`
    /// (recorded-clock seconds). Promoted and sync-all windows are not
    /// pruned here: [`Self::demote_window`] demotes a promoted one.
    pub fn prune_opened_items(&self, before: u64) -> Result<usize, crate::sync::TransportError> {
        crate::sync::residence::prune_thin_items(self.manager.vault(), before)
            .map_err(|e| crate::sync::TransportError::Storage(e.to_string()))
    }

    /// Demote a promoted window back to thin once the home holds every op of
    /// it (OF-534). See [`crate::sync::SyncClient::demote_window`]. When it
    /// completes, the live socket reconnects without the window.
    pub async fn demote_window(
        &self,
        window: &crate::sync::WindowKey,
    ) -> Result<crate::sync::residence::WindowDemotion, crate::sync::TransportError> {
        if self.config.client_config.federation_peer.is_some() {
            return Err(crate::sync::TransportError::InvalidPayload(
                "a federation lane has no residence mode",
            ));
        }
        let demotion = self.client()?.demote_window(window).await?;
        if demotion.complete {
            // The steady socket still follows the window: a fresh hello
            // drops it.
            let mode = *self.mode.borrow();
            self.mode.send_replace(mode);
        }
        Ok(demotion)
    }

    /// Fetch one grant-selected item into this device's observed CRDT window.
    pub async fn fetch_item(
        &self,
        window: &crate::sync::WindowKey,
        item: crate::EntityId,
    ) -> Result<(), crate::sync::TransportError> {
        let mut client = self.client()?;
        client.fetch_item(window, item).await
    }

    /// Promote an opened item's whole window into the canonical Loro unit
    /// before a write. Grant checks run at the home before any full bytes ship.
    pub async fn promote_window(
        &self,
        window: &crate::sync::WindowKey,
        item: crate::EntityId,
    ) -> Result<(), crate::sync::TransportError> {
        let mut client = self.client()?;
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
        let already_promoted = self
            .manager
            .vault()
            .sync_state_get(&format!("rp:w:{window}"))
            .map_err(|e| crate::sync::TransportError::Storage(e.to_string()))?
            .is_some();
        if !already_promoted && self.thin_item(item)?.is_some() {
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
        // Open the canonical window before the write: opening rematerializes
        // its current rows, which must never land over this edit.
        let loaded = self
            .manager
            .open_window(window)
            .map_err(|e| crate::sync::TransportError::Storage(e.to_string()))?;
        self.manager
            .vault()
            .put_entity(&item, entity_type, occurred, learned_at, body)
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
        let client = self.client()?;
        client.thin_item(item)
    }

    /// Search on the home node when reachable, or return explicitly partial
    /// local-only results over items previously opened on this device.
    pub async fn search_resident(
        &self,
        query: &str,
        limit: usize,
    ) -> Result<crate::sync::ResidenceSearch, crate::sync::TransportError> {
        let client = self.client()?;
        client.search_resident(query, limit).await
    }

    /// Clear only the contiguous queued updates whose bytes the home has
    /// durably acknowledged. A different digest or a missing earlier ACK
    /// retains the whole unconfirmed suffix, including delete markers. A row
    /// a device-only world keeps here is never sent, so never acknowledged:
    /// it clears with its neighbours, and its operations stay in the window's
    /// durable doc for the promoted vector exchange once the flag clears. A
    /// row that cannot be judged is retained like an unacknowledged one.
    fn clear_residence_acks(&self, client: &mut crate::sync::SyncClient) -> Result<(), String> {
        let mut through = None;
        for queued in self.queue.drain_updates().map_err(|e| e.to_string())? {
            let Some(ack) = client.residence_acks.get(&queued.seq) else {
                if client.update_verdict(&queued.window_key, &queued.encoded)
                    == crate::sync::window::UpdateVerdict::Withheld
                {
                    through = Some(queued.seq);
                    continue;
                }
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
use crate::sync::transport::{self, window_sub_tags};
#[cfg(test)]
use futures_util::{SinkExt, StreamExt};
#[cfg(test)]
use std::collections::BTreeSet;
#[cfg(test)]
use tokio::sync::mpsc;
#[cfg(test)]
use tokio_tungstenite::tungstenite::Message;
