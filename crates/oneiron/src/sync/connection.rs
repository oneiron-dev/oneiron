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

use std::collections::BTreeSet;
use std::sync::Arc;

use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tokio::time::{Duration, Instant};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

use crate::sync::client::{SyncClient, SyncClientConfig, SyncEvent, SyncStatus, next_backoff};
use crate::sync::loro_support::doc_version_vector;
use crate::sync::manager::WindowManager;
use crate::sync::queue::{QueuedUpdate, SyncQueue};
use crate::sync::transport::{self, TransportError, window_sub_tags};
pub use crate::sync::types::LocalUpdate;
use crate::sync::types::parse_window_key_str;

/// Maximum convergence rounds before forcing re-bootstrap
/// (ARCH-0023b Fig. 2: "Max 5 rounds before force re-bootstrap").
const MAX_CONVERGENCE_ROUNDS: u32 = 5;
const FULL_RESYNC_MARKER_PREFIX: &str = "fr:w:";

type WsStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;
type WsSink = SplitSink<WsStream, Message>;
type WsSource = SplitStream<WsStream>;

/// Read-budget for one server-frame pump: how long to wait for the first
/// frame, how long a quiet gap ends the pump, and a frame cap.
struct PumpBudget {
    first_frame: Duration,
    quiet: Duration,
    max_frames: usize,
}

impl PumpBudget {
    /// Matches the initial-sync loop: 30 s for the first frame, 200 ms quiet
    /// window, 100-frame cap.
    fn standard() -> Self {
        Self {
            first_frame: Duration::from_secs(30),
            quiet: Duration::from_millis(200),
            max_frames: 100,
        }
    }
}

/// Tracks which replayed windows still need VV-confirmed convergence and
/// enforces the round budget (ARCH-0023b Fig. 2, ONE-1128).
struct ConvergenceSession {
    /// Replayed windows not yet VV-confirmed by the server.
    pending: BTreeSet<String>,
    /// Windows with `fr:w:` markers. VV equality cannot prove these safe, so
    /// they intentionally remain pending until the round budget forces
    /// re-bootstrap.
    force_resync: BTreeSet<String>,
    /// Highest queue sequence covered by this replay — the
    /// `clear_through_confirmed` bound once ALL windows are confirmed.
    max_seq: u64,
    /// Rounds started so far.
    rounds_started: u32,
}

impl ConvergenceSession {
    fn from_queued(queued: &[QueuedUpdate]) -> Self {
        Self::from_queued_with_force(queued, &BTreeSet::new())
    }

    fn from_queued_with_force(queued: &[QueuedUpdate], force_resync: &BTreeSet<String>) -> Self {
        let mut pending: BTreeSet<String> = queued.iter().map(|u| u.window_key.clone()).collect();
        pending.extend(force_resync.iter().cloned());
        let max_seq = queued.iter().map(|u| u.seq).max().unwrap_or(0);
        Self {
            pending,
            force_resync: force_resync.clone(),
            max_seq,
            rounds_started: 0,
        }
    }

    /// Starts the next convergence round: returns SyncStep1 `VV_REQUEST`
    /// frames (carrying our VV) for every pending window, or `None` once the
    /// `MAX_CONVERGENCE_ROUNDS` budget is exhausted (→ force re-bootstrap).
    fn begin_round(
        &mut self,
        client: &mut SyncClient,
    ) -> Result<Option<Vec<Vec<u8>>>, TransportError> {
        if self.rounds_started >= MAX_CONVERGENCE_ROUNDS {
            return Ok(None);
        }
        self.rounds_started += 1;
        let mut frames = Vec::with_capacity(self.pending.len());
        for key in &self.pending {
            let window = client.ensure_window(key)?;
            frames.push(
                transport::encode_window_sync(
                    key,
                    window_sub_tags::VV_REQUEST,
                    &doc_version_vector(&window.doc),
                )
                .into_result()?,
            );
        }
        Ok(Some(frames))
    }

    /// Drops every pending window whose local doc is now VV-identical to a
    /// server-witnessed VV. `None` (no witness yet) is fail-closed: NOT
    /// converged.
    fn note_progress(&mut self, client: &SyncClient) {
        let force_resync = &self.force_resync;
        self.pending
            .retain(|key| force_resync.contains(key) || client.window_converged(key) != Some(true));
    }

    fn all_converged(&self) -> bool {
        self.pending.is_empty()
    }
}

#[derive(Debug, Clone)]
struct FullResyncMarker {
    key: String,
    window_key: String,
}

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

    /// Queue-overflow check, run between reconnect attempts.
    ///
    /// Overflow triggers a REAL re-bootstrap (ONE-1128): the queue is
    /// cleared (`q:`/`e:` rows only — the `h:`/`m:`/`x:` families and
    /// delete-bearing rows + `d:` markers survive)
    /// and the in-memory Docs are dropped, so the next `connect_and_sync`
    /// re-runs the Phase 1-3 initial sync from scratch. Docs are dropped
    /// only AFTER the queue clear succeeds — on failure both queue and docs
    /// stay intact and the check retries next cycle.
    fn handle_queue_overflow_check(
        &self,
        client: &mut SyncClient,
        event_tx: &mpsc::UnboundedSender<SyncEvent>,
        is_full: crate::error::Result<bool>,
    ) {
        match is_full {
            Ok(true) => {
                let _ = event_tx.send(SyncEvent::Error(
                    "Queue overflow — performing re-bootstrap".to_string(),
                ));
                match self.queue.clear_all() {
                    Ok(()) => client.reset_for_re_bootstrap(),
                    Err(e) => {
                        let _ = event_tx.send(SyncEvent::Error(format!("Clear queue failed: {e}")));
                    }
                }
            }
            Ok(false) => {}
            Err(e) => {
                let _ = event_tx.send(SyncEvent::Error(format!("Queue inspection failed: {e}")));
            }
        }
    }

    /// Main event loop. Runs until the shutdown signal is received.
    ///
    /// Creates the local-update channel itself and attaches it to the
    /// window manager's [`crate::sync::bridge::OutboundSink`], so every
    /// Observer A update (persisted local commit) flows into the debounce →
    /// wire path without host plumbing (ONE-1126). On exit the sink is
    /// detached and later updates fall back to the durable `SyncQueue`.
    ///
    /// # Arguments
    ///
    /// * `shutdown_rx` — Oneshot channel to signal clean shutdown
    ///
    /// # Returns
    ///
    /// Returns the event receiver that emits `SyncEvent`s for the application.
    pub async fn run(
        &self,
        mut shutdown_rx: tokio::sync::oneshot::Receiver<()>,
    ) -> crate::error::Result<mpsc::UnboundedReceiver<SyncEvent>> {
        let (client, event_rx) =
            SyncClient::new(Arc::clone(&self.manager), self.config.client_config.clone())?;
        let event_tx = client.event_tx.clone();
        let mut client = client;

        // Observer A → outbound wiring: while attached, persisted local
        // updates arrive on `local_rx` below.
        let (local_tx, mut local_rx) = mpsc::unbounded_channel::<LocalUpdate>();
        self.manager.outbound().attach(local_tx);

        let mut backoff_ms = self.config.client_config.reconnect_initial_ms;

        loop {
            // Attempt connection
            let _ = event_tx.send(SyncEvent::StatusChanged(SyncStatus::Connecting));

            match self.connect_and_sync(&mut client, &event_tx).await {
                Ok(ws_stream) => {
                    // Reset backoff on successful connect
                    // Note: connect_and_sync already emits Synced, so we don't emit Connected here
                    // to avoid regressing status for observers.
                    backoff_ms = self.config.client_config.reconnect_initial_ms;

                    // Run steady state until disconnect or shutdown
                    let reason = self
                        .steady_state(
                            ws_stream,
                            &mut client,
                            &event_tx,
                            &mut local_rx,
                            &mut shutdown_rx,
                        )
                        .await;

                    match reason {
                        LoopExit::Shutdown => {
                            let _ =
                                event_tx.send(SyncEvent::StatusChanged(SyncStatus::Disconnected));
                            break;
                        }
                        LoopExit::Disconnected(err) => {
                            let _ = event_tx
                                .send(SyncEvent::Error(format!("WebSocket disconnected: {err}")));
                            let _ =
                                event_tx.send(SyncEvent::StatusChanged(SyncStatus::Disconnected));
                        }
                    }
                }
                Err(e) => {
                    let _ = event_tx.send(SyncEvent::Error(format!("Connection failed: {e}")));
                    let _ = event_tx.send(SyncEvent::StatusChanged(SyncStatus::Disconnected));
                }
            }

            if !self.config.auto_reconnect {
                break;
            }

            // Check for queue overflow → re-bootstrap
            self.handle_queue_overflow_check(&mut client, &event_tx, self.queue.is_full());

            // Wait with backoff before reconnecting
            let delay = Duration::from_millis(backoff_ms as u64);
            tokio::select! {
                _ = tokio::time::sleep(delay) => {
                    backoff_ms = next_backoff(backoff_ms, self.config.client_config.reconnect_backoff_max_ms);
                }
                _ = &mut shutdown_rx => {
                    break;
                }
            }
        }

        self.manager.outbound().detach();
        Ok(event_rx)
    }

    /// Connects to the server and performs initial sync + queue replay.
    async fn connect_and_sync(
        &self,
        client: &mut SyncClient,
        event_tx: &mpsc::UnboundedSender<SyncEvent>,
    ) -> Result<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        String,
    > {
        // Connect WebSocket. Phase-1 auth: the shared secret
        // (SyncClientConfig.auth_token) rides as the `x-oneiron-secret`
        // header on the upgrade request — the same scheme the server HTTP
        // API uses — and the server rejects the upgrade when a secret is
        // configured and the header is missing or wrong (fail-closed).
        let url = &self.config.client_config.server_url;
        let mut request = url
            .into_client_request()
            .map_err(|e| format!("WS connect failed: {e}"))?;
        let auth_token = &self.config.client_config.auth_token;
        if !auth_token.is_empty() {
            let header_value = auth_token
                .parse()
                .map_err(|_| "Auth token is not a valid header value".to_string())?;
            request
                .headers_mut()
                .insert("x-oneiron-secret", header_value);
        }
        let (ws_stream, _response) = tokio_tungstenite::connect_async(request)
            .await
            .map_err(|e| format!("WS connect failed: {e}"))?;

        let (mut write, mut read) = ws_stream.split();

        // Phase 1-2: Initial sync (send our VVs, receive server state)
        let initial_messages = client
            .try_generate_initial_sync()
            .map_err(|e| format!("Generate initial sync failed: {e}"))?;
        for msg in initial_messages {
            write
                .send(Message::Binary(msg.into()))
                .await
                .map_err(|e| format!("Send initial sync failed: {e}"))?;
        }

        // Read server responses until we get all window states
        // The server sends: root snapshot + window VV responses/updates
        // We process a limited number of messages for initial sync
        let mut init_messages_received = 0;
        let max_init_messages = 100;

        'initial_sync: while init_messages_received < max_init_messages {
            let msg = tokio::time::timeout(Duration::from_secs(30), read.next())
                .await
                .map_err(|_| "Initial sync timeout".to_string())?;

            match msg {
                Some(Ok(Message::Binary(data))) => {
                    let responses = client
                        .handle_server_message(&data)
                        .map_err(|e| format!("Handle server message failed: {e}"))?;
                    for resp in responses {
                        write
                            .send(Message::Binary(resp.into()))
                            .await
                            .map_err(|e| format!("Send response failed: {e}"))?;
                    }
                    init_messages_received += 1;

                    // Drain the rest of the server's initial burst until the
                    // stream is quiet for 200ms, then consider initial sync
                    // done. This must LOOP on each received message: the
                    // burst (root snapshot + VV response + per-window
                    // updates) has arbitrary length, and bouncing back to
                    // the 30s outer read after a single quiet-check receive
                    // hangs the flow whenever the burst has an even number
                    // of messages (the last one is consumed here and the
                    // outer read then waits on a quiet stream).
                    loop {
                        if init_messages_received >= max_init_messages {
                            break 'initial_sync;
                        }
                        let quiet_check =
                            tokio::time::timeout(Duration::from_millis(200), read.next()).await;
                        match quiet_check {
                            Ok(Some(Ok(Message::Binary(data)))) => {
                                let responses = client
                                    .handle_server_message(&data)
                                    .map_err(|e| format!("Handle server message failed: {e}"))?;
                                for resp in responses {
                                    write
                                        .send(Message::Binary(resp.into()))
                                        .await
                                        .map_err(|e| format!("Send response failed: {e}"))?;
                                }
                                init_messages_received += 1;
                            }
                            Ok(Some(Ok(Message::Close(frame)))) => {
                                // Surface the close code/reason — a 4xxx code here
                                // is how a protocol-version mismatch shows up.
                                return Err(format!(
                                    "Server closed during initial sync: {frame:?}"
                                ));
                            }
                            Ok(Some(Ok(
                                Message::Ping(_)
                                | Message::Pong(_)
                                | Message::Text(_)
                                | Message::Frame(_),
                            ))) => {
                                // Ignore keepalive/non-binary messages during quiet check
                            }
                            Ok(Some(Err(e))) => {
                                return Err(format!("WS error during initial sync: {e}"));
                            }
                            Ok(None) => {
                                return Err("WS stream ended during initial sync".to_string());
                            }
                            // Timeout means initial sync is done
                            Err(_) => break 'initial_sync,
                        };
                    }
                }
                Some(Ok(Message::Close(frame))) => {
                    // Surface the close code/reason — a 4xxx code here is how a
                    // protocol-version mismatch shows up (ONE-1127).
                    return Err(format!("Server closed during initial sync: {frame:?}"));
                }
                None => {
                    return Err("Server closed during initial sync".to_string());
                }
                Some(Err(e)) => {
                    return Err(format!("WS error during initial sync: {e}"));
                }
                _ => continue, // Skip ping/pong/text
            }
        }

        // Phase 3: Drain offline queue
        let queued = self.queue.drain_updates().map_err(|e| format!("{e}"))?;
        let full_resync_markers = self.full_resync_markers()?;
        let force_resync: BTreeSet<String> = full_resync_markers
            .iter()
            .map(|marker| marker.window_key.clone())
            .collect();
        if !full_resync_markers.is_empty() {
            tracing::info!(
                marker_count = full_resync_markers.len(),
                "forcing full-resync marker windows through re-bootstrap"
            );
        }
        if !queued.is_empty() {
            tracing::info!(
                queued_updates = queued.len(),
                "replaying queued sync updates"
            );
            for update in &queued {
                // Mirror the queued ops into the LOCAL window doc first:
                // convergence is confirmed by VV equality with the server,
                // which only vouches for ops the local doc knows about
                // (ONE-1128). Corrupt bytes cannot be confirmed — surface
                // loudly and still replay them; the server-side import is
                // the last chance to recover the ops.
                if let Err(e) = client.import_queued_update(&update.window_key, &update.encoded) {
                    let _ = event_tx.send(SyncEvent::Error(format!(
                        "Queued update import failed (window {}, seq {}): {e}",
                        update.window_key, update.seq
                    )));
                }
                // Re-encode as WindowSync wire message
                let msg = transport::encode_window_sync(
                    &update.window_key,
                    window_sub_tags::UPDATE,
                    &update.encoded,
                )
                .into_result()
                .map_err(|e| format!("Queue replay encode failed: {e}"))?;
                write
                    .send(Message::Binary(msg.into()))
                    .await
                    .map_err(|e| format!("Queue replay failed: {e}"))?;
            }

            // ARCH-0023b Fig. 2 convergence dance. Any error here leaves the
            // queue intact (fail-closed) and surfaces as a connection failure.
            self.run_convergence(
                &mut write,
                &mut read,
                client,
                event_tx,
                &queued,
                &force_resync,
            )
            .await?;
            self.clear_full_resync_markers(&full_resync_markers)?;
        } else if !full_resync_markers.is_empty() {
            self.re_bootstrap(&mut write, &mut read, client, event_tx, &force_resync)
                .await?;
            self.clear_full_resync_markers(&full_resync_markers)?;
        } else {
            // No queue — clear stale updates but preserve embed jobs
            if let Err(e) = self.queue.clear_updates() {
                let _ = event_tx.send(SyncEvent::Error(format!(
                    "Failed to clear stale queue updates: {e}"
                )));
            }
        }

        // Reunite the stream
        let ws_stream = read.reunite(write).map_err(|e| format!("{e}"))?;

        let _ = event_tx.send(SyncEvent::StatusChanged(SyncStatus::Synced));

        // m:last_sync (ARCH-0023b key table) — last successful sync stamp.
        if let Err(e) = client.mark_synced() {
            let _ = event_tx.send(SyncEvent::Error(format!(
                "Failed to record last sync timestamp: {e}"
            )));
        }

        Ok(ws_stream)
    }

    fn full_resync_markers(&self) -> Result<Vec<FullResyncMarker>, String> {
        let keys = self
            .manager
            .vault()
            .sync_state_keys_with_prefix(FULL_RESYNC_MARKER_PREFIX)
            .map_err(|e| format!("Read full-resync markers failed: {e}"))?;
        let mut markers = Vec::with_capacity(keys.len());
        for key in keys {
            let Some(window_key) = key.strip_prefix(FULL_RESYNC_MARKER_PREFIX) else {
                continue;
            };
            if parse_window_key_str(window_key).is_none() {
                return Err(format!("Invalid full-resync marker key: {key}"));
            }
            let window_key = window_key.to_string();
            markers.push(FullResyncMarker { key, window_key });
        }
        Ok(markers)
    }

    fn clear_full_resync_markers(&self, markers: &[FullResyncMarker]) -> Result<(), String> {
        if markers.is_empty() {
            return Ok(());
        }
        let vault = self.manager.vault();
        vault
            .with_write_txn(|wtxn| {
                for marker in markers {
                    vault.store.sync_state.delete(wtxn, &marker.key)?;
                }
                Ok(())
            })
            .map_err(|e| format!("Clear full-resync markers failed: {e}"))
    }

    /// Runs the convergence protocol after queue replay (ARCH-0023b Fig. 2,
    /// ONE-1128).
    ///
    /// Per round: send SyncStep1 (`VV_REQUEST` carrying our VV) for every
    /// not-yet-confirmed window, pump the server's replies (delta `UPDATE`s
    /// and `VV_RESPONSE`s — and our reverse deltas back) through
    /// `handle_server_message`, then check VV equality per window. The queue
    /// is cleared via `clear_through_confirmed` ONLY when ALL replayed
    /// windows are confirmed converged. After `MAX_CONVERGENCE_ROUNDS` unconfirmed
    /// rounds, force a real re-bootstrap (drop Docs + queue, Phase 1-3).
    async fn run_convergence(
        &self,
        write: &mut WsSink,
        read: &mut WsSource,
        client: &mut SyncClient,
        event_tx: &mpsc::UnboundedSender<SyncEvent>,
        queued: &[QueuedUpdate],
        force_resync: &BTreeSet<String>,
    ) -> Result<(), String> {
        let mut session = if force_resync.is_empty() {
            ConvergenceSession::from_queued(queued)
        } else {
            ConvergenceSession::from_queued_with_force(queued, force_resync)
        };
        loop {
            let frames = session
                .begin_round(client)
                .map_err(|e| format!("Convergence round failed: {e}"))?;
            let Some(frames) = frames else {
                let _ = event_tx.send(SyncEvent::Error(format!(
                    "Convergence not confirmed after {MAX_CONVERGENCE_ROUNDS} rounds — \
                     forcing re-bootstrap"
                )));
                return self
                    .re_bootstrap(write, read, client, event_tx, force_resync)
                    .await;
            };
            for frame in frames {
                write
                    .send(Message::Binary(frame.into()))
                    .await
                    .map_err(|e| format!("Convergence send failed: {e}"))?;
            }
            self.pump_server_frames(read, write, client, event_tx, PumpBudget::standard())
                .await?;
            session.note_progress(client);
            if session.all_converged() {
                // The ONLY queue-clear on the convergence path. Every window
                // is VV-confirmed here, so the CONFIRMED variant applies: it
                // also removes delete-bearing rows + their `d:` markers
                // (ONE-1135). If it fails, the rows are replayed (idempotent
                // Loro import) on the next reconnect — retention is the
                // fail-closed side.
                if let Err(e) = self.queue.clear_through_confirmed(session.max_seq) {
                    let _ = event_tx.send(SyncEvent::Error(format!(
                        "Failed to clear converged queue: {e}"
                    )));
                }
                return Ok(());
            }
        }
    }

    /// Forces the ARCH-0023b Fig. 2 re-bootstrap on the live connection:
    /// drop in-memory Docs + clear the queue, then re-run the Phase 1-3
    /// initial sync (without the per-connection protocol hello).
    async fn re_bootstrap(
        &self,
        write: &mut WsSink,
        read: &mut WsSource,
        client: &mut SyncClient,
        event_tx: &mpsc::UnboundedSender<SyncEvent>,
        force_resync: &BTreeSet<String>,
    ) -> Result<(), String> {
        let frames = self
            .re_bootstrap_local_state(client, force_resync)
            .map_err(|e| format!("Re-bootstrap queue clear failed: {e}"))?;
        for frame in frames {
            write
                .send(Message::Binary(frame.into()))
                .await
                .map_err(|e| format!("Re-bootstrap send failed: {e}"))?;
        }
        let received = self
            .pump_server_frames(read, write, client, event_tx, PumpBudget::standard())
            .await?;
        if received == 0 {
            return Err("Re-bootstrap sync timeout".to_string());
        }
        Ok(())
    }

    /// Local half of the re-bootstrap, shared by the convergence and
    /// queue-overflow paths: clear the queue FIRST (`q:`/`e:` rows only —
    /// the `h:`/`m:`/`x:` families and delete-bearing rows + `d:` markers
    /// survive per ARCH-0038/ONE-1135), then drop the
    /// in-memory Docs and produce fresh Phase 1-2 sync frames. If the queue
    /// clear fails, the docs are left intact and the error propagates —
    /// nothing is half-dropped.
    fn re_bootstrap_local_state(
        &self,
        client: &mut SyncClient,
        force_resync: &BTreeSet<String>,
    ) -> crate::error::Result<Vec<Vec<u8>>> {
        self.queue.clear_all()?;
        client
            .generate_re_bootstrap_sync_for_windows(force_resync.iter().cloned())
            .map_err(|e| {
                crate::error::Error::SyncProtocolError(format!("re-bootstrap encode failed: {e}"))
            })
    }

    /// Reads server frames until the stream goes quiet (or the frame cap is
    /// hit), feeding each binary frame through `handle_server_message` and
    /// sending any produced responses. Returns the number of binary frames
    /// processed. Protocol errors are surfaced as events, not failures —
    /// fail-closed for the queue: an unconfirmed window simply stays
    /// unconfirmed.
    async fn pump_server_frames(
        &self,
        read: &mut WsSource,
        write: &mut WsSink,
        client: &mut SyncClient,
        event_tx: &mpsc::UnboundedSender<SyncEvent>,
        budget: PumpBudget,
    ) -> Result<usize, String> {
        let mut received = 0usize;
        let mut wait = budget.first_frame;
        while received < budget.max_frames {
            let msg = match tokio::time::timeout(wait, read.next()).await {
                // Quiet window elapsed — the burst is over.
                Err(_) => break,
                Ok(msg) => msg,
            };
            match msg {
                Some(Ok(Message::Binary(data))) => {
                    match client.handle_server_message(&data) {
                        Ok(responses) => {
                            for resp in responses {
                                write
                                    .send(Message::Binary(resp.into()))
                                    .await
                                    .map_err(|e| format!("Send response failed: {e}"))?;
                            }
                        }
                        Err(e) => {
                            let _ = event_tx.send(SyncEvent::Error(format!("Protocol error: {e}")));
                        }
                    }
                    received += 1;
                    wait = budget.quiet;
                }
                Some(Ok(Message::Ping(data))) => {
                    write
                        .send(Message::Pong(data))
                        .await
                        .map_err(|e| format!("Pong failed: {e}"))?;
                }
                Some(Ok(Message::Pong(_) | Message::Text(_) | Message::Frame(_))) => {}
                Some(Ok(Message::Close(frame))) => {
                    return Err(format!("Server closed connection: {frame:?}"));
                }
                Some(Err(e)) => return Err(format!("WS error: {e}")),
                None => return Err("WS stream ended".to_string()),
            }
        }
        Ok(received)
    }

    /// Steady-state event loop: multiplexes WS reads, local updates, and debounce.
    async fn steady_state(
        &self,
        ws_stream: tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        client: &mut SyncClient,
        event_tx: &mpsc::UnboundedSender<SyncEvent>,
        local_rx: &mut mpsc::UnboundedReceiver<LocalUpdate>,
        shutdown_rx: &mut tokio::sync::oneshot::Receiver<()>,
    ) -> LoopExit {
        let (mut write, mut read) = ws_stream.split();

        // Debounce state: buffer local edits and flush after 50ms of quiet
        let debounce_ms = self.config.client_config.sync_debounce_ms as u64;
        let mut debounce_buffer: Vec<LocalUpdate> = Vec::new();
        let mut debounce_deadline: Option<Instant> = None;

        loop {
            // Compute sleep future for debounce timer
            let debounce_sleep = match debounce_deadline {
                Some(deadline) => tokio::time::sleep_until(deadline),
                None => tokio::time::sleep(Duration::from_secs(86400)), // effectively never
            };

            tokio::select! {
                // WS message from server
                msg = read.next() => {
                    match msg {
                        Some(Ok(Message::Binary(data))) => {
                            match client.handle_server_message(&data) {
                                Ok(responses) => {
                                    for resp in responses {
                                        let send_result =
                                            write.send(Message::Binary(resp.into())).await;
                                        if let Err(e) = send_result {
                                            return LoopExit::Disconnected(format!("Send failed: {e}"));
                                        }
                                    }
                                }
                                Err(e) => {
                                    let _ = event_tx.send(SyncEvent::Error(format!("Protocol error: {e}")));
                                }
                            }
                        }
                        Some(Ok(Message::Ping(data))) => {
                            let pong_result = write.send(Message::Pong(data)).await;
                            if let Err(e) = pong_result {
                                return LoopExit::Disconnected(format!("Pong failed: {e}"));
                            }
                        }
                        Some(Ok(Message::Close(_))) | None => {
                            // Flush debounce buffer before disconnecting
                            flush_to_queue(&self.queue, &mut debounce_buffer);
                            return LoopExit::Disconnected("Server closed connection".to_string());
                        }
                        Some(Err(e)) => {
                            flush_to_queue(&self.queue, &mut debounce_buffer);
                            return LoopExit::Disconnected(format!("WS error: {e}"));
                        }
                        _ => {} // Text, Pong — ignore
                    }
                }

                // Local update from application
                update = local_rx.recv() => {
                    match update {
                        Some(local_update) if parse_window_key_str(&local_update.window_key).is_none() => {
                            let _ = event_tx.send(SyncEvent::Error(format!(
                                "Rejected invalid local update window key: {}",
                                local_update.window_key
                            )));
                            continue;
                        }
                        Some(local_update) => {
                            debounce_buffer.push(local_update);
                            debounce_deadline = Some(Instant::now() + Duration::from_millis(debounce_ms));
                        }
                        None => {
                            // Channel closed — application is shutting down
                            return LoopExit::Shutdown;
                        }
                    }
                }

                // Debounce timer fired — flush buffered updates
                _ = debounce_sleep, if debounce_deadline.is_some() => {
                    debounce_deadline = None;

                    // Drain the buffer — take ownership to avoid borrow conflicts
                    let mut failed_at = None;
                    let pending: Vec<LocalUpdate> = std::mem::take(&mut debounce_buffer);

                    for (i, local_update) in pending.iter().enumerate() {
                        let wire_msg = match transport::encode_window_sync(
                            &local_update.window_key,
                            window_sub_tags::UPDATE,
                            &local_update.update_bytes,
                        )
                        .into_result()
                        {
                            Ok(frame) => frame,
                            Err(e) => {
                                failed_at = Some((i, format!("Encode failed: {e}")));
                                break;
                            }
                        };

                        let send_result = write.send(Message::Binary(wire_msg.into())).await;
                        if let Err(e) = send_result {
                            failed_at = Some((i, format!("Send failed: {e}")));
                            break;
                        }
                    }

                    if let Some((fail_idx, err)) = failed_at {
                        // Queue all unsent updates (including the failed one)
                        for local_update in &pending[fail_idx..] {
                            let queue_result = self.queue.push(
                                &local_update.window_key,
                                &local_update.update_bytes,
                            );
                            if let Err(e) = queue_result {
                                tracing::error!("Failed to persist update to offline queue: {e}");
                            }
                        }
                        // Also flush any remaining debounce buffer
                        flush_to_queue(&self.queue, &mut debounce_buffer);
                        return LoopExit::Disconnected(err);
                    }
                }

                // Shutdown signal
                _ = &mut *shutdown_rx => {
                    // Flush any remaining buffered updates to queue
                    flush_to_queue(&self.queue, &mut debounce_buffer);
                    // Send close frame
                    let _ = write.send(Message::Close(None)).await;
                    return LoopExit::Shutdown;
                }
            }
        }
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
mod tests {
    use super::*;
    use crate::sync::bridge::Materializer;
    use crate::types::VaultConfig;
    use core::assert_matches;

    fn test_manager() -> Arc<WindowManager> {
        let config = VaultConfig::device();
        let (_dir, vault) = crate::test_util::open_test_vault_with(config);
        let vault = Arc::new(vault);
        Arc::new(WindowManager::new(
            vault,
            Arc::new(Materializer::new()),
            "test-user",
        ))
    }

    #[test]
    fn flush_to_queue_skips_invalid_window_keys() {
        let conn = SyncConnection::new(test_manager(), ConnectionConfig::default()).unwrap();
        let mut buffer = vec![
            LocalUpdate {
                window_key: "2026-13".to_string(),
                update_bytes: vec![1, 2, 3],
            },
            LocalUpdate {
                window_key: "2026-03".to_string(),
                update_bytes: vec![4, 5, 6],
            },
        ];

        flush_to_queue(conn.queue(), &mut buffer);

        let queued = conn.queue().drain_updates().unwrap();
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].window_key, "2026-03");
        assert_eq!(queued[0].encoded, vec![4, 5, 6]);
    }

    #[tokio::test]
    async fn queue_push_and_drain_roundtrip() {
        let conn = SyncConnection::new(
            test_manager(),
            ConnectionConfig {
                auto_reconnect: false,
                ..Default::default()
            },
        )
        .unwrap();

        // Push some updates to the queue to simulate offline state
        conn.queue().push("2026-03", &[10, 20]).unwrap();
        conn.queue().push("2026-03", &[30, 40]).unwrap();

        let updates = conn.queue().drain_updates().unwrap();
        assert_eq!(updates.len(), 2);
        assert_eq!(updates[0].encoded, vec![10, 20]);
        assert_eq!(updates[1].encoded, vec![30, 40]);
    }

    #[test]
    fn queue_inspection_error_does_not_clear_queue() {
        let manager = test_manager();
        let conn = SyncConnection::new(Arc::clone(&manager), ConnectionConfig::default()).unwrap();
        let (mut client, _client_rx) =
            SyncClient::new(manager, SyncClientConfig::default()).unwrap();
        conn.queue().push("2026-03", &[1, 2, 3]).unwrap();
        client.ensure_window("2026-03").unwrap();

        let (event_tx, mut event_rx) = mpsc::unbounded_channel();
        conn.handle_queue_overflow_check(
            &mut client,
            &event_tx,
            Err(crate::error::Error::CorruptedIndex("sync queue metadata")),
        );

        assert_eq!(conn.queue().len().unwrap(), 1);
        assert!(
            client.window("2026-03").is_some(),
            "inspection error must not drop in-memory docs"
        );
        let event = event_rx.try_recv().unwrap();
        assert_matches!(event, SyncEvent::Error(msg) if msg.contains("Queue inspection failed"));
    }

    #[test]
    fn convergence_round_propagates_invalid_window_key_without_frame() {
        let manager = test_manager();
        let (mut client, _client_rx) =
            SyncClient::new(manager, SyncClientConfig::default()).unwrap();
        let mut pending = BTreeSet::new();
        pending.insert("2026-003".to_string());
        let mut session = ConvergenceSession {
            pending,
            force_resync: BTreeSet::new(),
            max_seq: 0,
            rounds_started: 0,
        };

        assert_matches!(
            session.begin_round(&mut client),
            Err(TransportError::InvalidWindowKey)
        );
    }

    // ───────────────────────────────────────────────────────────────────────
    // ONE-1128 — convergence protocol + real re-bootstrap (socket-free)
    // ───────────────────────────────────────────────────────────────────────

    use crate::sync::loro_support::export_updates_since;
    use crate::sync::transport::{TAG_PROTOCOL_HELLO, TAG_VERSION_VECTOR, TAG_WINDOW_SYNC};
    use loro::{ExportMode, LoroDoc, VersionVector};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const FULL_RESYNC_TEST_WINDOW: &str = "1970-01";
    const DEFERRED_TOMBSTONE_KEY: &str = "0123456789abcdef0123456789abcdef";

    /// Contract literal (ARCH-0023b Fig. 2): "Max 5 rounds before force
    /// re-bootstrap". A drifted budget silently changes how long a GDPR
    /// tombstone can sit unconfirmed before the queue is dropped.
    #[test]
    fn max_convergence_rounds_is_pinned_to_five() {
        assert_eq!(MAX_CONVERGENCE_ROUNDS, 5);
    }

    fn window_doc() -> LoroDoc {
        let doc = LoroDoc::new();
        let _ = doc.get_map("entities");
        let _ = doc.get_map("edges");
        let _ = doc.get_map("tombstones");
        doc.commit();
        doc
    }

    /// Server test double for socket-free convergence tests: one Loro doc
    /// per window, answering SyncStep1/SyncStep2 the same way the production
    /// peer does. `forget_window` simulates the lost-confirmation failure
    /// mode the stub had no defense against: inbound UPDATE frames for that window
    /// are silently dropped, never imported.
    struct FakeServer {
        docs: HashMap<String, LoroDoc>,
        forget_window: Option<String>,
    }

    impl FakeServer {
        fn new() -> Self {
            Self {
                docs: HashMap::new(),
                forget_window: None,
            }
        }

        fn doc(&mut self, key: &str) -> &LoroDoc {
            self.docs.entry(key.to_string()).or_insert_with(window_doc)
        }

        fn handle(&mut self, frame: &[u8]) -> Vec<Vec<u8>> {
            match frame[0] {
                TAG_PROTOCOL_HELLO | TAG_VERSION_VECTOR => Vec::new(),
                TAG_WINDOW_SYNC => {
                    let (key, sub_tag, payload) =
                        transport::decode_window_sync(&frame[1..]).unwrap();
                    let key = key.to_string();
                    let forgets = self.forget_window.as_deref() == Some(key.as_str());
                    let doc = self.doc(&key);
                    match sub_tag {
                        window_sub_tags::UPDATE => {
                            if !forgets {
                                doc.import(payload).unwrap();
                            }
                            Vec::new()
                        }
                        window_sub_tags::VV_REQUEST => vec![
                            transport::encode_window_sync(
                                &key,
                                window_sub_tags::UPDATE,
                                &export_updates_since(doc, payload).unwrap(),
                            )
                            .into_result()
                            .unwrap(),
                            transport::encode_window_sync(
                                &key,
                                window_sub_tags::VV_RESPONSE,
                                &doc.oplog_vv().encode(),
                            )
                            .into_result()
                            .unwrap(),
                        ],
                        window_sub_tags::VV_RESPONSE => vec![
                            transport::encode_window_sync(
                                &key,
                                window_sub_tags::UPDATE,
                                &export_updates_since(doc, payload).unwrap(),
                            )
                            .into_result()
                            .unwrap(),
                        ],
                        other => panic!("unexpected sub tag {other}"),
                    }
                }
                other => panic!("unexpected tag {other}"),
            }
        }
    }

    async fn spawn_fake_sync_server(
        mut server: FakeServer,
        close_on_forced_window: Option<&'static str>,
        forced_window_requests: Arc<AtomicUsize>,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            while let Some(msg) = ws.next().await {
                let Message::Binary(data) = msg.unwrap() else {
                    continue;
                };
                let responses = match data[0] {
                    TAG_PROTOCOL_HELLO => Vec::new(),
                    transport::TAG_LEASE_REQUEST => {
                        let (client_id, _, _) =
                            transport::decode_lease_request(&data[1..]).unwrap();
                        vec![transport::encode_lease_granted(
                            transport::LEASE_STATUS_GRANTED,
                            client_id,
                            1,
                        )]
                    }
                    TAG_VERSION_VECTOR => {
                        VersionVector::decode(&data[1..]).unwrap();
                        let mut response = vec![TAG_VERSION_VECTOR];
                        response.extend_from_slice(&VersionVector::new().encode());
                        vec![response]
                    }
                    TAG_WINDOW_SYNC => {
                        let (window_key, sub_tag, _) =
                            transport::decode_window_sync(&data[1..]).unwrap();
                        if window_key == FULL_RESYNC_TEST_WINDOW
                            && sub_tag == window_sub_tags::VV_REQUEST
                        {
                            forced_window_requests.fetch_add(1, Ordering::SeqCst);
                            if close_on_forced_window == Some(window_key) {
                                let _ = ws.close(None).await;
                                break;
                            }
                        }
                        server.handle(&data)
                    }
                    other => panic!("unexpected client tag {other}"),
                };
                for response in responses {
                    ws.send(Message::Binary(response.into())).await.unwrap();
                }
            }
        });
        (format!("ws://{addr}"), handle)
    }

    /// Drives client→server frames and all transitive replies to quiescence
    /// — the socket-free equivalent of one `pump_server_frames` burst.
    fn exchange(server: &mut FakeServer, client: &mut SyncClient, frames: Vec<Vec<u8>>) {
        let mut to_server = frames;
        while !to_server.is_empty() {
            let mut to_client = Vec::new();
            for frame in &to_server {
                to_client.extend(server.handle(frame));
            }
            let mut next = Vec::new();
            for frame in &to_client {
                next.extend(client.handle_server_message(frame).unwrap());
            }
            to_server = next;
        }
    }

    /// Builds the offline-writes fixture: window A carries a DELETE-BEARING
    /// update (tombstones-map insert), window B a plain entity write. Both
    /// are pushed to the persistent queue, exactly like a disconnect flush.
    fn seed_offline_queue(conn: &SyncConnection) -> Vec<QueuedUpdate> {
        let writer_a = window_doc();
        writer_a
            .get_map("tombstones")
            .insert("victim-entity", b"t".as_slice())
            .unwrap();
        writer_a.commit();
        let writer_b = window_doc();
        writer_b
            .get_map("entities")
            .insert("new-entity", b"payload".as_slice())
            .unwrap();
        writer_b.commit();

        conn.queue()
            .push(
                "2026-03",
                &writer_a.export(ExportMode::all_updates()).unwrap(),
            )
            .unwrap();
        conn.queue()
            .push(
                "2026-04",
                &writer_b.export(ExportMode::all_updates()).unwrap(),
            )
            .unwrap();
        conn.queue().drain_updates().unwrap()
    }

    /// Replays the queue the way `connect_and_sync` does: import into the
    /// local doc, then ship the raw update to the (fake) server.
    fn replay(queued: &[QueuedUpdate], client: &mut SyncClient, server: &mut FakeServer) {
        for update in queued {
            client
                .import_queued_update(&update.window_key, &update.encoded)
                .unwrap();
            let frame = transport::encode_window_sync(
                &update.window_key,
                window_sub_tags::UPDATE,
                &update.encoded,
            );
            assert!(server.handle(&frame).is_empty());
        }
    }

    /// AC1 + AC5 (ONE-1128): offline writes → reconnect replay → one
    /// bidirectional VV round → ALL windows VV-confirmed → queue cleared via
    /// `clear_through_confirmed`. The pre-clear assertion pins that nothing
    /// is cleared before confirmation (the old stub cleared unconditionally).
    #[test]
    fn convergence_clears_queue_only_after_all_windows_vv_confirm() {
        let manager = test_manager();
        let conn = SyncConnection::new(Arc::clone(&manager), ConnectionConfig::default()).unwrap();
        let (mut client, _rx) =
            SyncClient::new(Arc::clone(&manager), SyncClientConfig::default()).unwrap();
        let mut server = FakeServer::new();

        let queued = seed_offline_queue(&conn);
        assert_eq!(queued.len(), 2);
        replay(&queued, &mut client, &mut server);

        let mut session = ConvergenceSession::from_queued(&queued);
        assert!(!session.all_converged());

        let frames = session
            .begin_round(&mut client)
            .unwrap()
            .expect("round 1 is within budget");
        assert_eq!(frames.len(), 2, "one SyncStep1 per replayed window");

        // Queue must remain intact until confirmation lands.
        assert_eq!(conn.queue().len().unwrap(), 2);

        exchange(&mut server, &mut client, frames);
        session.note_progress(&client);

        assert!(
            session.all_converged(),
            "honest server must confirm in round 1"
        );
        assert_eq!(session.rounds_started, 1);

        // ONLY now: the driver's clear_through_confirmed call (every window
        // is VV-confirmed, so delete-bearing rows are cleared too).
        conn.queue()
            .clear_through_confirmed(session.max_seq)
            .unwrap();
        assert_eq!(conn.queue().len().unwrap(), 0);

        // Deep convergence on both windows, including the tombstone.
        for key in ["2026-03", "2026-04"] {
            assert_eq!(
                client.window(key).unwrap().doc.get_deep_value(),
                server.doc(key).get_deep_value(),
                "window {key} must deep-converge"
            );
        }
        let server_tombstones = server.doc("2026-03").get_map("tombstones");
        assert!(
            server_tombstones.get("victim-entity").is_some(),
            "the delete-bearing update must have reached the server"
        );
    }

    #[test]
    fn full_resync_marker_is_never_dropped_by_vv_equality() {
        let manager = test_manager();
        let (mut client, _rx) =
            SyncClient::new(Arc::clone(&manager), SyncClientConfig::default()).unwrap();
        let mut server = FakeServer::new();
        let mut force_resync = BTreeSet::new();
        force_resync.insert(FULL_RESYNC_TEST_WINDOW.to_string());

        let mut session = ConvergenceSession::from_queued_with_force(&[], &force_resync);
        for round in 1..=MAX_CONVERGENCE_ROUNDS {
            let frames = session
                .begin_round(&mut client)
                .unwrap()
                .expect("forced rounds stay within budget");
            exchange(&mut server, &mut client, frames);
            assert_eq!(
                client.window_converged(FULL_RESYNC_TEST_WINDOW),
                Some(true),
                "fixture should prove VV equality would otherwise drop the window"
            );
            session.note_progress(&client);
            assert!(
                !session.all_converged(),
                "round {round}: fr:w window must stay pending despite VV equality"
            );
        }
        assert!(
            session.begin_round(&mut client).unwrap().is_none(),
            "forced fr:w window must exhaust into re-bootstrap"
        );
    }

    #[tokio::test]
    async fn full_resync_marker_recovers_deferred_post_delete_op() {
        let manager = test_manager();
        let vault = Arc::clone(manager.vault());
        let marker_key = format!("fr:w:{FULL_RESYNC_TEST_WINDOW}");
        vault.sync_state_put(&marker_key, &[1u8]).unwrap();

        let mut server = FakeServer::new();
        server
            .doc(FULL_RESYNC_TEST_WINDOW)
            .get_map("tombstones")
            .insert(DEFERRED_TOMBSTONE_KEY, b"t".as_slice())
            .unwrap();
        server.doc(FULL_RESYNC_TEST_WINDOW).commit();

        let forced_window_requests = Arc::new(AtomicUsize::new(0));
        let (server_url, server_task) =
            spawn_fake_sync_server(server, None, Arc::clone(&forced_window_requests)).await;
        let conn = SyncConnection::new(
            Arc::clone(&manager),
            ConnectionConfig {
                client_config: SyncClientConfig {
                    server_url,
                    ..Default::default()
                },
                auto_reconnect: false,
            },
        )
        .unwrap();
        let (mut client, _rx) =
            SyncClient::new(Arc::clone(&manager), SyncClientConfig::default()).unwrap();
        let (event_tx, _event_rx) = mpsc::unbounded_channel();

        let ws_stream = conn.connect_and_sync(&mut client, &event_tx).await.unwrap();
        drop(ws_stream);
        server_task.abort();

        assert!(
            forced_window_requests.load(Ordering::SeqCst) >= 1,
            "connect-time fr:w consumer must request the marked historical window"
        );
        let recovered = client
            .window(FULL_RESYNC_TEST_WINDOW)
            .expect("forced re-bootstrap must load the marked window");
        assert!(
            recovered
                .doc
                .get_map("tombstones")
                .get(DEFERRED_TOMBSTONE_KEY)
                .is_some(),
            "deferred post-delete op must be present locally after this connect"
        );
        assert!(
            vault.sync_state_get(&marker_key).unwrap().is_none(),
            "fr:w marker clears only after successful re-bootstrap"
        );
    }

    #[tokio::test]
    async fn full_resync_marker_retained_when_rebootstrap_errors() {
        let manager = test_manager();
        let vault = Arc::clone(manager.vault());
        let marker_key = format!("fr:w:{FULL_RESYNC_TEST_WINDOW}");
        vault.sync_state_put(&marker_key, &[1u8]).unwrap();

        let forced_window_requests = Arc::new(AtomicUsize::new(0));
        let (server_url, server_task) = spawn_fake_sync_server(
            FakeServer::new(),
            Some(FULL_RESYNC_TEST_WINDOW),
            Arc::clone(&forced_window_requests),
        )
        .await;
        let conn = SyncConnection::new(
            Arc::clone(&manager),
            ConnectionConfig {
                client_config: SyncClientConfig {
                    server_url,
                    ..Default::default()
                },
                auto_reconnect: false,
            },
        )
        .unwrap();
        let (mut client, _rx) =
            SyncClient::new(Arc::clone(&manager), SyncClientConfig::default()).unwrap();
        let (event_tx, _event_rx) = mpsc::unbounded_channel();

        let result = conn.connect_and_sync(&mut client, &event_tx).await;
        server_task.abort();

        assert!(
            result.is_err(),
            "server close during forced re-bootstrap must fail the connect"
        );
        assert_eq!(
            forced_window_requests.load(Ordering::SeqCst),
            1,
            "failure must happen during the forced fr:w request"
        );
        assert_eq!(
            vault.sync_state_get(&marker_key).unwrap().as_deref(),
            Some([1u8].as_slice()),
            "fr:w marker must remain set so the next connect retries"
        );
    }

    /// AC2 + AC4 + AC5 variant (ONE-1128): the server 'forgets' the
    /// delete-bearing update (lost confirmation). The tombstone window must
    /// NEVER confirm, the queue must NOT be cleared, the round counter must
    /// walk to 5, and round 6 must road-block into the re-bootstrap path.
    /// This test FAILS against the old stub, which cleared unconditionally.
    #[test]
    fn forgetful_server_blocks_clear_and_round_six_forces_re_bootstrap() {
        let manager = test_manager();
        let vault = Arc::clone(manager.vault());
        let conn = SyncConnection::new(Arc::clone(&manager), ConnectionConfig::default()).unwrap();
        let (mut client, _rx) =
            SyncClient::new(Arc::clone(&manager), SyncClientConfig::default()).unwrap();
        let mut server = FakeServer::new();
        server.forget_window = Some("2026-03".to_string());

        let queued = seed_offline_queue(&conn);
        replay(&queued, &mut client, &mut server);

        let mut session = ConvergenceSession::from_queued(&queued);
        for round in 1..=MAX_CONVERGENCE_ROUNDS {
            let frames = session
                .begin_round(&mut client)
                .unwrap()
                .expect("rounds 1-5 are within budget");
            if round > 1 {
                assert_eq!(
                    frames.len(),
                    1,
                    "round {round}: only the unconfirmed tombstone window re-requests"
                );
            }
            exchange(&mut server, &mut client, frames);
            session.note_progress(&client);
            assert!(
                !session.all_converged(),
                "round {round}: forgotten tombstone window must NOT confirm"
            );
            assert_eq!(session.rounds_started, round);
        }

        // AC4: the queued tombstone update survives until ITS window
        // converges — nothing was cleared.
        let remaining = conn.queue().drain_updates().unwrap();
        assert_eq!(remaining.len(), 2, "queue must be fully intact");
        assert!(
            remaining.iter().any(|u| u.window_key == "2026-03"),
            "the delete-bearing row must still be queued"
        );

        // Round 6: budget exhausted → re-bootstrap signal.
        assert!(
            session.begin_round(&mut client).unwrap().is_none(),
            "round 6 must refuse and signal re-bootstrap"
        );

        // Pre-seed the protected row families before the re-bootstrap clear.
        let sweep_key = b"h:synthetic-sweep".to_vec();
        let exemption_key = b"x:synthetic-exemption".to_vec();
        {
            let mut wtxn = vault.store.env.write_txn().unwrap();
            vault
                .store
                .sync_queue
                .put(&mut wtxn, &sweep_key, &[7u8])
                .unwrap();
            vault
                .store
                .sync_queue
                .put(&mut wtxn, &exemption_key, &[9u8])
                .unwrap();
            wtxn.commit().unwrap();
        }

        // The REAL re-bootstrap local half (same path the socket driver takes).
        let frames = conn
            .re_bootstrap_local_state(&mut client, &BTreeSet::new())
            .unwrap();

        // Docs dropped.
        assert!(
            client.window("2026-03").is_none(),
            "re-bootstrap must drop in-memory window docs"
        );
        assert!(client.window("2026-04").is_none());

        // q: rows cleared; h:/m:/x: families preserved.
        assert_eq!(conn.queue().len().unwrap(), 0);
        let rtxn = vault.store.env.read_txn().unwrap();
        assert_eq!(
            vault.store.sync_queue.get(&rtxn, &sweep_key).unwrap(),
            Some([7u8].as_slice()),
            "h:* sweep rows must survive re-bootstrap (ARCH-0038 Art.17 SLA)"
        );
        assert_eq!(
            vault.store.sync_queue.get(&rtxn, &exemption_key).unwrap(),
            Some([9u8].as_slice()),
            "x:* rows must survive re-bootstrap"
        );
        assert_eq!(
            vault
                .store
                .sync_queue
                .get(&rtxn, b"m:last_update_seq".as_slice())
                .unwrap(),
            Some(2u64.to_le_bytes().as_slice()),
            "m:* sequence cursor must survive re-bootstrap"
        );
        drop(rtxn);

        // Phase 1-3 frames: root VV (EMPTY — docs really dropped) + default
        // window VV requests, and NO per-connection hello.
        let protocol_hello = transport::encode_protocol_hello();
        assert!(
            frames.iter().all(|f| f != &protocol_hello),
            "re-bootstrap must not re-send the protocol hello"
        );
        assert_eq!(frames[0][0], TAG_VERSION_VECTOR);
        assert_eq!(
            VersionVector::decode(&frames[0][1..]).unwrap(),
            VersionVector::new(),
            "re-bootstrap root VV must be empty"
        );
        assert_eq!(frames.len(), 3, "root VV + 2 default-window VV requests");
        for frame in &frames[1..] {
            assert_eq!(frame[0], TAG_WINDOW_SYNC);
            let (k, sub_tag, payload) = transport::decode_window_sync(&frame[1..]).unwrap();
            assert_eq!(sub_tag, window_sub_tags::VV_REQUEST);
            assert!(parse_window_key_str(k).is_some());
            VersionVector::decode(payload).expect("window VV must be Loro binary encoding");
        }
    }

    /// AC3 (ONE-1128): queue overflow triggers the SAME real re-bootstrap —
    /// docs dropped + queue cleared (h:/m:/x: preserved); Phase 1-3 then
    /// re-runs naturally on the next connect.
    #[test]
    fn queue_overflow_triggers_real_re_bootstrap() {
        let manager = test_manager();
        let vault = Arc::clone(manager.vault());
        let conn = SyncConnection::new(Arc::clone(&manager), ConnectionConfig::default()).unwrap();
        let (mut client, _rx) =
            SyncClient::new(Arc::clone(&manager), SyncClientConfig::default()).unwrap();

        conn.queue().push("2026-03", &[1, 2, 3]).unwrap();
        client.ensure_window("2026-03").unwrap();
        let exemption_key = b"x:synthetic-exemption".to_vec();
        {
            let mut wtxn = vault.store.env.write_txn().unwrap();
            vault
                .store
                .sync_queue
                .put(&mut wtxn, &exemption_key, &[9u8])
                .unwrap();
            wtxn.commit().unwrap();
        }

        let (event_tx, mut event_rx) = mpsc::unbounded_channel();
        conn.handle_queue_overflow_check(&mut client, &event_tx, Ok(true));

        assert_eq!(conn.queue().len().unwrap(), 0, "q: rows must be cleared");
        assert!(
            client.window("2026-03").is_none(),
            "overflow re-bootstrap must drop in-memory docs"
        );
        let rtxn = vault.store.env.read_txn().unwrap();
        assert_eq!(
            vault.store.sync_queue.get(&rtxn, &exemption_key).unwrap(),
            Some([9u8].as_slice()),
            "x:* rows must survive the overflow re-bootstrap"
        );
        drop(rtxn);

        let event = event_rx.try_recv().unwrap();
        assert_matches!(event, SyncEvent::Error(msg) if msg.contains("re-bootstrap"));
    }
}
