//! Handshake: run loop, connect_and_sync, overflow check, resync markers.

use std::collections::BTreeSet;
use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tokio::time::Duration;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header::AUTHORIZATION;

use crate::sync::client::{SyncClient, SyncEvent, SyncStatus, next_backoff};
use crate::sync::queue::QueuedUpdate;
use crate::sync::transport::{self, window_sub_tags};
use crate::sync::types::parse_window_key_str;
use crate::sync::window::UpdateVerdict;
use crate::sync::window_rows::WINDOW_FULL_RESYNC_MARKER;

use super::session::{FullResyncMarker, WsSink, WsSource, residence_update_frame};
use super::{LocalUpdate, LoopExit, SyncConnection};

impl SyncConnection {
    /// Queue-overflow check, run between reconnect attempts.
    ///
    /// Overflow triggers a REAL re-bootstrap (ONE-1128): the queue is
    /// cleared (`q:`/`e:` rows only — the `h:`/`m:`/`x:` families and
    /// delete-bearing rows + `d:` markers survive)
    /// and the in-memory Docs are dropped, so the next `connect_and_sync`
    /// re-runs the Phase 1-3 initial sync from scratch. Docs are dropped
    /// only AFTER the queue clear succeeds — on failure both queue and docs
    /// stay intact and the check retries next cycle.
    pub(super) fn handle_queue_overflow_check(
        &self,
        client: &mut SyncClient,
        event_tx: &mpsc::UnboundedSender<SyncEvent>,
        is_full: crate::error::Result<bool>,
    ) {
        match is_full {
            Ok(true) if client.config.residence_mode == crate::sync::SyncResidenceMode::Opened => {
                let _ = event_tx.send(SyncEvent::Error(
                    "Opened-item queue full — updates retained; explicit sync-all recovery required"
                        .to_owned(),
                ));
            }
            Ok(true) => {
                let _ = event_tx.send(SyncEvent::Error(
                    "Queue overflow — performing re-bootstrap".to_string(),
                ));
                match self.clear_queue_for_re_bootstrap(client) {
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
        let (client, event_rx) = SyncClient::new(Arc::clone(&self.manager), self.client_config())?;
        let event_tx = client.event_tx.clone();
        let mut client = client;

        // The host topology is authoritative even before the first socket
        // attempt, and its watcher remains active during reconnect backoff.
        // There is no fallback election on transport loss or cancellation.
        let _topology_watcher = self
            .config
            .client_config
            .home_node_topology
            .as_ref()
            .map(|source| {
                super::topology::watch_topology(
                    Arc::clone(self.manager.vault()),
                    source,
                    event_tx.clone(),
                )
            })
            .transpose()?;

        // Observer A → outbound wiring: while attached, persisted local
        // updates arrive on `local_rx` below.
        let (local_tx, mut local_rx) = mpsc::unbounded_channel::<LocalUpdate>();
        self.manager.outbound().attach(local_tx);

        let mut backoff_ms = self.config.client_config.reconnect_initial_ms;
        let mut promotion_rx = self.manager.subscribe_promotions();
        let mut left_rx = self.left.subscribe();
        self.running.send_replace(true);

        loop {
            // A member who left the shared vault this env holds never
            // reconnects (OF-158).
            if *left_rx.borrow_and_update() {
                break;
            }
            // A residence-mode switch takes effect at this connect's hello.
            client.config.residence_mode = *self.mode.borrow();
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
                            &mut promotion_rx,
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
                _ = left_rx.wait_for(|left| *left) => {
                    break;
                }
            }
        }

        self.manager.outbound().detach();
        self.running.send_replace(false);
        Ok(event_rx)
    }

    /// Connects to the server and performs initial sync + queue replay.
    pub(super) async fn connect_and_sync(
        &self,
        client: &mut SyncClient,
        event_tx: &mpsc::UnboundedSender<SyncEvent>,
    ) -> Result<crate::sync::carrier::SyncSocket, String> {
        client.note_session_bound = false;
        client.artifact_publication_resend.clear();
        client.home_peer = crate::authority::PeerMachine::Unknown;
        // Sync pulls the full root snapshot. The upgrade therefore proves an
        // unattenuated logged slip with a fresh holder signature; a device-key
        // lease or an issuer secret never grants this read. Each reconnect has
        // its own nonce, so it cannot replay a previous upgrade's proof. It
        // is signed on the wall clock, as every holder signs: the recording
        // clock may still hold a floor a host clock that ran ahead left.
        let url = &self.config.client_config.server_url;
        let mut request = url
            .into_client_request()
            .map_err(|e| format!("WS connect failed: {e}"))?;
        let mut binding = None;
        if let Some(credential) = &self.config.client_config.transport_credential {
            binding = Some(
                credential
                    .sign_upgrade(
                        self.manager.vault(),
                        self.manager.vault().store.clock.wall_now(),
                        &mut request,
                    )
                    .map_err(str::to_owned)?,
            );
        } else if !self.config.client_config.auth_token.is_empty() {
            let header_value = format!("Bearer {}", self.config.client_config.auth_token)
                .parse()
                .map_err(|_| "Auth token is not a valid header value".to_string())?;
            request.headers_mut().insert(AUTHORIZATION, header_value);
        }
        let (ws_stream, response) = crate::sync::carrier::connect_sync_socket(
            request,
            self.config.client_config.mesh_dialer.as_deref(),
        )
        .await
        .map_err(|e| format!("WS connect failed: {e}"))?;
        // Every send on this socket is judged for the machine the home
        // proved over this upgrade's own proof (OF-534 G6), before the first.
        client.home_peer =
            crate::sync::home_proof::home_peer(self.manager.vault(), &response, binding.as_ref());

        let (mut write, mut read) = ws_stream.split();

        // Phase 1-2: this socket needs fresh window subscriptions even if
        // the same client instance survived a prior disconnect.
        client.begin_connection_sync();
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
                    // Judged per frame: a device-only flag may turn while an
                    // earlier frame waits on the socket.
                    for resp in responses
                        .into_iter()
                        .filter(|frame| !client.frame_withheld(frame))
                    {
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
                                // Judged per frame: a device-only flag may turn while an
                                // earlier frame waits on the socket.
                                for resp in responses
                                    .into_iter()
                                    .filter(|frame| !client.frame_withheld(frame))
                                {
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

        // Opened-item enrol finishes only after the grant-filtered thin index
        // is durable. A missing actor grant/session is a failure, never an
        // excuse to fall back to full-window sync.
        if client.config.residence_mode == crate::sync::SyncResidenceMode::Opened {
            let now_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |duration| duration.as_secs());
            client
                .fetch_current_index(now_secs)
                .await
                .map_err(|e| format!("Fetch residence index failed: {e}"))?;
        }

        // Phase 3: Drain offline queue
        let queued = self.queue.drain_updates().map_err(|e| format!("{e}"))?;
        let full_resync_markers = self.full_resync_markers()?;
        let force_resync: BTreeSet<String> = full_resync_markers
            .iter()
            .map(|marker| marker.window_key.clone())
            .collect();
        if client.config.residence_mode == crate::sync::SyncResidenceMode::Opened
            && !full_resync_markers.is_empty()
        {
            return Err("opened-item full-resync requires explicit sync-all recovery".into());
        }
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
            let sent = self
                .replay_queued_updates(&mut write, client, event_tx, queued)
                .await?;

            // ARCH-0023b Fig. 2 convergence dance. Any error here leaves the
            // queue intact (fail-closed) and surfaces as a connection failure.
            if client.config.residence_mode == crate::sync::SyncResidenceMode::Opened {
                self.wait_residence_acks(&mut write, &mut read, client, &sent)
                    .await?;
            } else {
                self.run_convergence(
                    &mut write,
                    &mut read,
                    client,
                    event_tx,
                    &sent,
                    &force_resync,
                )
                .await?;
            }
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

    /// A home acknowledgment is sent only after persistence. A missing ACK
    /// leaves every unconfirmed queue row intact for the next reconnect. The
    /// wait ends once every row of `sent` is acknowledged or cleared; a row
    /// never sent is never acknowledged, and one queued before them keeps
    /// them queued for a later clear.
    async fn wait_residence_acks(
        &self,
        write: &mut WsSink,
        read: &mut WsSource,
        client: &mut SyncClient,
        sent: &[QueuedUpdate],
    ) -> Result<(), String> {
        let sent: BTreeSet<u64> = sent.iter().map(|update| update.seq).collect();
        let budgets = self
            .manager
            .vault()
            .residence_operation_budgets()
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "residence policy unavailable".to_string())?;
        // Rows a device-only world keeps here were never sent.
        self.clear_residence_acks(client)?;
        tokio::time::timeout(Duration::from_millis(budgets.ack_timeout_ms), async {
            while self
                .queue
                .drain_updates()
                .map_err(|e| e.to_string())?
                .iter()
                .any(|update| {
                    sent.contains(&update.seq) && !client.residence_acks.contains_key(&update.seq)
                })
            {
                let message = read
                    .next()
                    .await
                    .ok_or_else(|| "home closed before residence ACK".to_string())?
                    .map_err(|e| e.to_string())?;
                if let Message::Binary(data) = message {
                    for response in client
                        .handle_server_message(&data)
                        .map_err(|e| e.to_string())?
                        .into_iter()
                        .filter(|frame| !client.frame_withheld(frame))
                    {
                        write
                            .send(Message::Binary(response.into()))
                            .await
                            .map_err(|e| e.to_string())?;
                    }
                    self.clear_residence_acks(client)?;
                }
            }
            Ok::<(), String>(())
        })
        .await
        .map_err(|_| "home residence acknowledgment timed out".to_string())?
    }

    /// Sends queued rows the way Phase 3 replays them, importing each into the
    /// local window doc first. Returns the rows sent; a row the device-only
    /// verdict withholds is skipped, and nothing past an unjudged row is sent.
    pub(super) async fn replay_queued_updates(
        &self,
        write: &mut WsSink,
        client: &mut SyncClient,
        event_tx: &mpsc::UnboundedSender<SyncEvent>,
        queued: Vec<QueuedUpdate>,
    ) -> Result<Vec<QueuedUpdate>, String> {
        let mut sent = Vec::with_capacity(queued.len());
        let mut frames = Vec::new();
        let mut size = 1;
        let mut tick = tokio::time::interval(Duration::from_millis(
            u64::from(client.config.sync_debounce_ms).max(1),
        ));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        for update in queued {
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
            // Bytes queued while a world was portable stay here once it
            // is flagged device-only; the window's next export reads the
            // flag again. Bytes that cannot be read in full keep their
            // row and every later one queued: nothing past them is sent,
            // so no clear reaches them.
            match client.update_verdict(&update.window_key, &update.encoded) {
                UpdateVerdict::Portable => {}
                UpdateVerdict::Withheld => continue,
                UpdateVerdict::Uninspectable => break,
            }
            // A window the home refused to grant again keeps its rows queued,
            // unsent; they hold back no other window's clear.
            if !client.residence_granted(&update.window_key) {
                continue;
            }
            // Re-encode as WindowSync wire message
            let msg = if client.config.residence_mode == crate::sync::SyncResidenceMode::Opened {
                residence_update_frame(update.seq, &update.window_key, &update.encoded)
            } else {
                transport::encode_window_sync(
                    &update.window_key,
                    window_sub_tags::UPDATE,
                    &update.encoded,
                )
                .into_result()
            }
            .map_err(|e| format!("Queue replay encode failed: {e}"))?;
            if !super::node_batch::fits(&frames, size, &msg).map_err(|e| e.to_string())? {
                tick.tick().await;
                let batch = transport::encode_node_batch(&frames)
                    .into_result()
                    .map_err(|e| e.to_string())?;
                write
                    .send(Message::Binary(batch.into()))
                    .await
                    .map_err(|e| format!("Queue replay failed: {e}"))?;
                frames.clear();
                size = 1;
                // A single member still has to fit inside its BATCH envelope.
                super::node_batch::fits(&frames, size, &msg).map_err(|e| e.to_string())?;
            }
            size += 4 + msg.len();
            frames.push(msg);
            sent.push(update);
        }
        if !frames.is_empty() {
            tick.tick().await;
            let batch = transport::encode_node_batch(&frames)
                .into_result()
                .map_err(|e| e.to_string())?;
            write
                .send(Message::Binary(batch.into()))
                .await
                .map_err(|e| format!("Queue replay failed: {e}"))?;
        }
        Ok(sent)
    }

    fn full_resync_markers(&self) -> Result<Vec<FullResyncMarker>, String> {
        let vault = self.manager.vault();
        let rtxn = vault
            .store
            .env
            .read_txn()
            .map_err(|e| format!("Read full-resync markers failed: {e}"))?;
        let keys = WINDOW_FULL_RESYNC_MARKER
            .scan_keys(&vault.store, &rtxn, &[])
            .map_err(|e| format!("Read full-resync markers failed: {e}"))?;
        let mut markers = Vec::with_capacity(keys.len());
        for window_key in keys {
            if parse_window_key_str(&window_key).is_none() {
                return Err(format!("Invalid full-resync marker key: fr:w:{window_key}"));
            }
            markers.push(FullResyncMarker { window_key });
        }
        Ok(markers)
    }

    pub(super) fn set_full_resync_markers(
        &self,
        markers: &[FullResyncMarker],
    ) -> Result<(), String> {
        if markers.is_empty() {
            return Ok(());
        }
        let vault = self.manager.vault();
        vault
            .with_write_txn_grouped(|wtxn| {
                for marker in markers {
                    WINDOW_FULL_RESYNC_MARKER.put(
                        &vault.store,
                        wtxn,
                        &marker.window_key,
                        &[1u8],
                    )?;
                }
                Ok(())
            })
            .map_err(|e| format!("Set full-resync markers failed: {e}"))
    }

    pub(super) fn clear_full_resync_markers(
        &self,
        markers: &[FullResyncMarker],
    ) -> Result<(), String> {
        if markers.is_empty() {
            return Ok(());
        }
        let vault = self.manager.vault();
        vault
            .with_write_txn_grouped(|wtxn| {
                for marker in markers {
                    WINDOW_FULL_RESYNC_MARKER.delete(&vault.store, wtxn, &marker.window_key)?;
                }
                Ok(())
            })
            .map_err(|e| format!("Clear full-resync markers failed: {e}"))
    }
}
