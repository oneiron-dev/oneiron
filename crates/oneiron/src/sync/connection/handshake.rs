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
use crate::sync::transport::{self, window_sub_tags};
use crate::sync::types::parse_window_key_str;

use super::session::{FULL_RESYNC_MARKER_PREFIX, FullResyncMarker};
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
    pub(super) async fn connect_and_sync(
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
}
