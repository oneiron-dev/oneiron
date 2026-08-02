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
use tokio_tungstenite::tungstenite::http::header::AUTHORIZATION;

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
const EPHEMERAL_HOUSEKEEPING_INTERVAL_SECS: u64 = 1;

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
            client.scrub_window_before_export(&window.key, &window.doc)?;
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
        // Connect WebSocket. The credential (SyncClientConfig.auth_token)
        // rides as `Authorization: Bearer` on the upgrade request — the same
        // scheme the server HTTP API uses — and the server rejects the
        // upgrade when a secret is configured and the credential is missing
        // or wrong (fail-closed). Sync pulls the full root snapshot, so the
        // server requires an owner-grade credential here: the trust-root
        // secret or an empty-claims token, never a scoped one.
        let url = &self.config.client_config.server_url;
        let mut request = url
            .into_client_request()
            .map_err(|e| format!("WS connect failed: {e}"))?;
        let auth_token = &self.config.client_config.auth_token;
        if !auth_token.is_empty() {
            let header_value = format!("Bearer {auth_token}")
                .parse()
                .map_err(|_| "Auth token is not a valid header value".to_string())?;
            request.headers_mut().insert(AUTHORIZATION, header_value);
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
                crate::error::Error::sync_engine(
                    crate::error::SyncEngineContext::RebootstrapEncode,
                    e,
                )
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
        let mut ephemeral_housekeeping =
            tokio::time::interval(Duration::from_secs(EPHEMERAL_HOUSEKEEPING_INTERVAL_SECS));
        ephemeral_housekeeping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

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

                // Loro's Rust EphemeralStore has no internal timer.
                _ = ephemeral_housekeeping.tick() => {
                    client.remove_outdated_ephemeral();
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
mod tests;
