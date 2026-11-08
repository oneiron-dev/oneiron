//! Handshake: run loop, open_sync_session, overflow check.

use std::collections::BTreeSet;
use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tokio::time::Duration;
use tokio_tungstenite::tungstenite::Message;

use crate::sync::client::{SyncClient, SyncEvent, SyncStatus, next_backoff};
use crate::sync::types::WindowKey;

use super::peer_session::HomeReach;
use super::server_close::ServerClose;
use super::session::SessionFault;
use super::{LocalUpdate, LoopExit, SyncConnection};

mod acks;
mod replay;
mod resync_markers;
mod upgrade;

pub(super) use self::upgrade::upgrade_request;

impl SyncConnection {
    /// Queue-overflow check, run between reconnect attempts.
    ///
    /// Overflow triggers a REAL re-bootstrap (ONE-1128): the queue is
    /// cleared (`q:` rows only — the `h:`/`m:`/`x:`/`e:` families and
    /// delete-bearing rows + `d:` markers survive)
    /// and the in-memory Docs are dropped, so the next `open_sync_session`
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
    /// window manager's [`crate::sync::bridge::OutboundSink`], beside any
    /// other channel there, so every Observer A update (persisted local
    /// commit) flows into the debounce → wire path without host plumbing
    /// (ONE-1126). On exit its own channel is detached; with none left,
    /// later updates fall back to the durable `SyncQueue`.
    ///
    /// # Arguments
    ///
    /// * `shutdown_rx` — Oneshot channel to signal clean shutdown, honoured
    ///   while a connect is pending too
    ///
    /// # Returns
    ///
    /// Returns the event receiver that emits `SyncEvent`s for the application.
    pub async fn run(
        &self,
        shutdown_rx: tokio::sync::oneshot::Receiver<()>,
    ) -> crate::error::Result<mpsc::UnboundedReceiver<SyncEvent>> {
        let (client, event_rx) = SyncClient::new(Arc::clone(&self.manager), self.client_config())?;
        self.drive(client, shutdown_rx).await?;
        Ok(event_rx)
    }

    /// [`Self::run`] for a host that keeps the connection for its whole
    /// life: each event reaches `on_event` as it happens, rather than piling
    /// up until the loop ends.
    pub async fn run_observed(
        &self,
        shutdown_rx: tokio::sync::oneshot::Receiver<()>,
        mut on_event: impl FnMut(SyncEvent) + Send,
    ) -> crate::error::Result<()> {
        let (client, mut event_rx) =
            SyncClient::new(Arc::clone(&self.manager), self.client_config())?;
        let drive = self.drive(client, shutdown_rx);
        tokio::pin!(drive);
        let result = loop {
            tokio::select! {
                result = &mut drive => break result,
                Some(event) = event_rx.recv() => on_event(event),
            }
        };
        while let Ok(event) = event_rx.try_recv() {
            on_event(event);
        }
        result
    }

    /// The loop [`Self::run`] and [`Self::run_observed`] drive, with the
    /// owner's residence directives naming this machine run beside it, across
    /// its reconnects, each time the residence upkeep wakes them (OF-534),
    /// and the home handoff's delivery worker beside both (FIX 5661 C2a), and
    /// the mode that follows the committed home (FIX 8869).
    async fn drive(
        &self,
        client: SyncClient,
        shutdown_rx: tokio::sync::oneshot::Receiver<()>,
    ) -> crate::error::Result<()> {
        // Under the host's admission, set by now (FIX 12036).
        self.collect_left_env_bodies();
        let directives = self.run_residence_directives(client.event_tx.clone());
        let home_handoff = self.run_home_handoff(client.event_tx.clone());
        let residence_mode = self.run_residence_mode(client.event_tx.clone());
        tokio::select! {
            result = self.drive_loop(client, shutdown_rx) => result,
            never = directives => match never {},
            never = home_handoff => match never {},
            never = residence_mode => match never {},
        }
    }

    /// The connect, sync and reconnect loop [`Self::drive`] runs.
    async fn drive_loop(
        &self,
        client: SyncClient,
        mut shutdown_rx: tokio::sync::oneshot::Receiver<()>,
    ) -> crate::error::Result<()> {
        let event_tx = client.event_tx.clone();
        let mut client = client;

        // The host topology is authoritative even before the first socket
        // attempt, and its watcher remains active during reconnect backoff.
        // There is no fallback election on transport loss or cancellation.
        // Its first election holds the host's admission (FIX 12036).
        let mut left_rx = self.left.subscribe();
        let Some(first_election) = self.admit_or_stop(&mut shutdown_rx, &mut left_rx).await else {
            return Ok(());
        };
        let _topology_watcher = self
            .config
            .client_config
            .home_node_topology
            .as_ref()
            .map(|source| {
                super::topology::watch_topology(
                    Arc::clone(self.manager.vault()),
                    source,
                    self.config.client_config.residence_home_route.clone(),
                    self.config.client_config.server_url.clone(),
                    event_tx.clone(),
                    self.batch_admission.clone(),
                )
            })
            .transpose()?;
        drop(first_election);

        // Observer A → outbound wiring: while attached, persisted local
        // updates arrive on `local_rx` below.
        let (local_tx, mut local_rx) = mpsc::unbounded_channel::<LocalUpdate>();
        let mut debounce_buffer = Vec::new();
        let attachment = self.manager.outbound().attach(local_tx);

        let mut backoff_ms = self.config.client_config.reconnect_initial_ms;
        let mut promotion_rx = self.manager.subscribe_promotions();
        let mut mode_rx = self.mode.subscribe();
        // Whether the home serves this machine's sync; while it is down,
        // sessions go to this vault's other machines (FIX 4748).
        let mut reach = HomeReach::new(self.config.client_config.peer_dialer.is_some());
        self.running.send_replace(true);
        // Every connection's upkeep, owned here across reconnects (FIX 12785).
        let mut upkeep = super::steady::UpkeepTasks::default();

        loop {
            // A member who left the shared vault this env holds never
            // reconnects (OF-158).
            if *left_rx.borrow_and_update() {
                break;
            }
            // The connect is one exchange under the host's admission; a
            // paused host is waited out before the dial (FIX 12036).
            let Some(connect_batch) = self.admit_or_stop(&mut shutdown_rx, &mut left_rx).await
            else {
                let _ = event_tx.send(SyncEvent::StatusChanged(SyncStatus::Disconnected));
                break;
            };
            // A residence-mode switch takes effect at this connect's hello.
            client.config.residence_mode = *mode_rx.borrow_and_update();
            // While the home is down this session goes to a peer (FIX 4748).
            // A server's vector witnesses for the machine that sent it alone:
            // a session with another machine than the last starts with none.
            let peer = reach.next_peer(self.config.client_config.peer_dialer.as_deref());
            if peer != client.peer_session {
                client.server_vvs.clear();
            }
            client.peer_session = peer;
            // Attempt connection
            let _ = event_tx.send(SyncEvent::StatusChanged(SyncStatus::Connecting));

            // Shutdown or a confirmed leave cancels the pending connect,
            // including its initial sync and queue replay.
            let connected = tokio::select! {
                biased;
                _ = left_rx.wait_for(|left| *left) => {
                    let _ = event_tx.send(SyncEvent::StatusChanged(SyncStatus::Disconnected));
                    break;
                }
                _ = &mut shutdown_rx => {
                    let _ = event_tx.send(SyncEvent::StatusChanged(SyncStatus::Disconnected));
                    break;
                }
                connected = self.open_sync_session(&mut client, &event_tx) => connected,
            };
            drop(connect_batch);
            let mut renegotiate = false;
            let mut home_returned = false;
            match connected {
                Ok(ws_stream) => {
                    // A home session opens once its first round completed:
                    // the home served this machine's sync (FIX 4748).
                    reach.opened(peer);
                    // Reset backoff on successful connect
                    // Note: open_sync_session already emits Synced, so we don't emit Connected here
                    // to avoid regressing status for observers.
                    backoff_ms = self.config.client_config.reconnect_initial_ms;

                    // Run steady state until disconnect or shutdown
                    let reason = self
                        .steady_state(
                            ws_stream,
                            &mut client,
                            &event_tx,
                            &mut local_rx,
                            &mut debounce_buffer,
                            &mut promotion_rx,
                            &mut shutdown_rx,
                            &mut upkeep,
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
                        // FIX 5927: a server fault reconnects as after any outage,
                        // this device's queue intact; a refusal is reported as the
                        // server's judgment of a frame this device sent.
                        LoopExit::Closed(close) => {
                            let _ = event_tx
                                .send(SyncEvent::Error(format!("WebSocket closed: {close}")));
                            let _ =
                                event_tx.send(SyncEvent::StatusChanged(SyncStatus::Disconnected));
                        }
                        // FIX 8869: a mode change is no outage.
                        LoopExit::Renegotiate => {
                            let _ =
                                event_tx.send(SyncEvent::StatusChanged(SyncStatus::Disconnected));
                            renegotiate = super::residence_mode::RENEGOTIATE_AT_ONCE;
                        }
                        // FIX 4748: the home sent a peer session's probe
                        // its root; its session follows at once, the home
                        // still down until that session's round completes.
                        LoopExit::HomeReturned => {
                            let _ =
                                event_tx.send(SyncEvent::StatusChanged(SyncStatus::Disconnected));
                            reach.home_returned();
                            home_returned = true;
                        }
                    }
                }
                Err(e) => {
                    // The first peer is dialed on the first backoff step, not
                    // the home's grown one, as is the peer after a home turn
                    // that failed (FIX 4748). A fault of this machine's own
                    // counts the home nothing (FIX 22107).
                    if reach.failed(peer, &e) {
                        backoff_ms = self.config.client_config.reconnect_initial_ms;
                    }
                    let _ = event_tx.send(SyncEvent::Error(format!("Connection failed: {e}")));
                    let _ = event_tx.send(SyncEvent::StatusChanged(SyncStatus::Disconnected));
                }
            }
            // An incomplete root image ends with its socket, before any backoff.
            client.reset_root_parts();
            // A peer session's receipt takes its end (FIX 4748).
            if let Some(receipt) = client.peer_receipt.take() {
                receipt.close(self.manager.vault());
            }

            if !renegotiate && !home_returned && !self.config.auto_reconnect {
                break;
            }

            // Check for queue overflow → re-bootstrap. Not while the home is
            // down, its probe turn included: nothing re-bootstraps then, and
            // the home session replays the queue whole (FIX 4748).
            if !reach.down() {
                self.admitted_overflow_check(&mut client, &event_tx).await;
            }
            if renegotiate || home_returned {
                continue;
            }

            // Wait with backoff before reconnecting; a mode change while it
            // waits reconnects at once with the new hello (FIX 8869).
            let delay = Duration::from_millis(backoff_ms as u64);
            tokio::select! {
                _ = tokio::time::sleep(delay) => {
                    backoff_ms = next_backoff(backoff_ms, self.config.client_config.reconnect_backoff_max_ms);
                }
                Ok(()) = mode_rx.changed(), if super::residence_mode::RENEGOTIATE_AT_ONCE => {}
                _ = &mut shutdown_rx => {
                    break;
                }
                _ = left_rx.wait_for(|left| *left) => {
                    break;
                }
            }
        }

        // The run ends its upkeep, every connection's, before anything else
        // (FIX 12037): none of its writes lands after the run.
        upkeep.end().await;
        // A peer session the run ended in takes its end too (FIX 4748).
        if let Some(receipt) = client.peer_receipt.take() {
            receipt.close(self.manager.vault());
        }
        client.reset_root_parts();
        // Detach before draining: the sink serializes sends with detach, so
        // this receiver's backlog is finite and no update can arrive later.
        self.manager.outbound().detach(attachment);
        while let Ok(update) = local_rx.try_recv() {
            debounce_buffer.push(update);
        }
        // Leave-only single try (OF-158): a confirmed leave publishes and
        // clears its remaining run buffer here too, before `running=false`.
        // This includes updates received during connect or steady cleanup.
        // Non-leave shutdown stays thaw-waiting, as before.
        if *self.left.borrow() {
            self.queue_on_exit(&mut self.batch_gate(), &mut debounce_buffer)
                .await;
            self.publish_leave_unqueued(&mut debounce_buffer);
        } else {
            let mut final_gate = self.batch_gate();
            let mut final_left = self.left.subscribe();
            tokio::select! {
                biased;
                () = async { let _ = final_left.wait_for(|left| *left).await; } => {
                    self.queue_on_exit(&mut final_gate, &mut debounce_buffer).await;
                    self.publish_leave_unqueued(&mut debounce_buffer);
                }
                _ = self.queue_on_shutdown(&mut final_gate, &mut debounce_buffer) => {}
            }
        }
        self.running.send_replace(false);
        Ok(())
    }

    /// Connects to the server and performs initial sync + queue replay. A
    /// peer session (FIX 4748, `client.peer_session`) dials its peer over
    /// the mesh and runs the same exchange, confirming nothing. A home
    /// session returns its socket only once its first round completed, so
    /// the home served this machine's sync; a fault of the far end before
    /// that, the home's refusal, fault or close included, leaves it unserved
    /// ([`HomeReach`]). A fault of this machine's own ([`SessionFault`], FIX
    /// 22107) says nothing of the home.
    pub(super) async fn open_sync_session(
        &self,
        client: &mut SyncClient,
        event_tx: &mpsc::UnboundedSender<SyncEvent>,
    ) -> Result<crate::sync::carrier::SyncSocket, SessionFault> {
        client.note_session_bound = false;
        client.artifact_publication_resend.clear();
        client.document_retries = Default::default();
        client.asset_bodies = Default::default();
        client.home_peer = crate::authority::PeerMachine::Unknown;
        client.kept_out_peer_copies.clear();
        client.residence_acks.clear();
        client.reset_window_pads();
        client.reset_root_parts();
        let (ws_stream, response, binding) = self.open_socket(client, event_tx).await?;
        self.sync_socket(client, event_tx, ws_stream, &response, binding.as_ref())
            .await
    }

    /// [`Self::open_sync_session`], its fault told as its message alone.
    #[cfg(test)]
    pub(super) async fn connect_and_sync(
        &self,
        client: &mut SyncClient,
        event_tx: &mpsc::UnboundedSender<SyncEvent>,
    ) -> Result<crate::sync::carrier::SyncSocket, String> {
        self.open_sync_session(client, event_tx)
            .await
            .map_err(|fault| fault.to_string())
    }

    /// Initial sync and queue replay on the open socket whose upgrade
    /// `binding` signed and `response` answered. A peer session (FIX 4748)
    /// replays the queue and runs its vector rounds without a clear, never
    /// re-bootstraps, reads nothing from the home's residence lane, and says
    /// `Connected`, not `Synced`.
    async fn sync_socket(
        &self,
        client: &mut SyncClient,
        event_tx: &mpsc::UnboundedSender<SyncEvent>,
        ws_stream: crate::sync::carrier::SyncSocket,
        response: &tokio_tungstenite::tungstenite::http::HeaderMap,
        binding: Option<&crate::sync::home_proof::UpgradeBinding>,
    ) -> Result<crate::sync::carrier::SyncSocket, SessionFault> {
        // Every send on this socket is judged for the machine the home
        // proved over this upgrade's own proof (OF-534 G6), before the first.
        client.home_peer =
            crate::sync::home_proof::home_peer(self.manager.vault(), response, binding);
        // FIX 4748: a peer session's far end proves the very peer it dialed,
        // so each send is judged for that machine as its destination; any
        // other answer ends the session before a frame goes.
        let peer = client.peer_session;
        if let Some(peer) = peer
            && !matches!(
                client.home_peer,
                crate::authority::PeerMachine::Proven { machine, .. } if machine == peer
            )
        {
            return Err(SessionFault::Remote(format!(
                "peer {} proved no machine of its own on the upgrade; no peer session",
                peer.to_hex()
            )));
        }
        // This end's receipt of the session, by the upgrade proof's nonce,
        // which the serving end reads too.
        if let Some(peer) = peer {
            client.peer_receipt = Some(crate::sync::peer_route::PeerSyncReceipt::leave(
                self.manager.vault(),
                crate::sync::peer_route::PeerSyncPart::Asked,
                peer,
                binding.map_or("unbound", |binding| binding.nonce.as_str()),
                None,
            ));
        }

        let (mut write, mut read) = ws_stream.split();

        // Phase 1-2: this socket needs fresh window subscriptions even if
        // the same client instance survived a prior disconnect.
        client.begin_connection_sync();
        let initial_messages = client
            .try_generate_initial_sync()
            .map_err(|e| SessionFault::Local(format!("Generate initial sync failed: {e}")))?;
        for msg in initial_messages {
            write
                .send(Message::Binary(msg.into()))
                .await
                .map_err(|e| SessionFault::Remote(format!("Send initial sync failed: {e}")))?;
        }

        // Read server responses until we get all window states
        // The server sends: root snapshot + window VV responses/updates
        // We process a limited number of messages for initial sync
        let mut init_messages_received = 0;
        let max_init_messages = 100;

        'initial_sync: while init_messages_received < max_init_messages
            || client.root_update_pending()
        {
            let msg = tokio::time::timeout(Duration::from_secs(30), read.next())
                .await
                .map_err(|_| SessionFault::remote("Initial sync timeout"))?;

            match msg {
                Some(Ok(Message::Binary(data))) => {
                    // A fault of this machine's own store applying the
                    // home's frame says nothing of the home (FIX 22153).
                    let responses = client.handle_server_message(&data).map_err(|e| {
                        SessionFault::of_frame(&e, format!("Handle server message failed: {e}"))
                    })?;
                    // Judged per frame: a device-only flag may turn while an
                    // earlier frame waits on the socket.
                    for resp in responses
                        .into_iter()
                        .filter(|frame| !client.frame_withheld(frame))
                    {
                        self.send_document_response(&mut write, &client, resp)
                            .await
                            .map_err(|exit| {
                                SessionFault::remote(super::document_response::response_error(exit))
                            })?;
                    }
                    init_messages_received += client.logical_openings(&data);

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
                        if init_messages_received >= max_init_messages
                            && !client.root_update_pending()
                        {
                            break 'initial_sync;
                        }
                        let quiet_check =
                            tokio::time::timeout(Duration::from_millis(200), read.next()).await;
                        match quiet_check {
                            Ok(Some(Ok(Message::Binary(data)))) => {
                                let responses =
                                    client.handle_server_message(&data).map_err(|e| {
                                        SessionFault::of_frame(
                                            &e,
                                            format!("Handle server message failed: {e}"),
                                        )
                                    })?;
                                // Judged per frame: a device-only flag may turn while an
                                // earlier frame waits on the socket.
                                for resp in responses
                                    .into_iter()
                                    .filter(|frame| !client.frame_withheld(frame))
                                {
                                    self.send_document_response(&mut write, &client, resp)
                                        .await
                                        .map_err(|exit| {
                                            SessionFault::remote(
                                                super::document_response::response_error(exit),
                                            )
                                        })?;
                                }
                                init_messages_received += client.logical_openings(&data);
                            }
                            Ok(Some(Ok(Message::Close(frame)))) => {
                                // Read the close code — a 4xxx code here is how a
                                // protocol-version mismatch shows up, a 1011 is the
                                // server's own fault (FIX 5927).
                                return Err(SessionFault::Remote(format!(
                                    "Initial sync ended: {}",
                                    ServerClose::read(frame.as_ref())
                                )));
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
                                return Err(SessionFault::Remote(format!(
                                    "WS error during initial sync: {e}"
                                )));
                            }
                            Ok(None) => {
                                return Err(SessionFault::remote(
                                    "WS stream ended during initial sync",
                                ));
                            }
                            // A root image must finish before the write-only queue replay.
                            // A quiet gap returns to the original initial read timeout.
                            Err(_) if client.root_update_pending() => continue 'initial_sync,
                            Err(_) => break 'initial_sync,
                        };
                    }
                }
                Some(Ok(Message::Close(frame))) => {
                    // Read the close code — a 4xxx code here is how a protocol-version
                    // mismatch shows up (ONE-1127), a 1011 is the server's own fault
                    // (FIX 5927).
                    return Err(SessionFault::Remote(format!(
                        "Initial sync ended: {}",
                        ServerClose::read(frame.as_ref())
                    )));
                }
                None => {
                    return Err(SessionFault::remote("Server closed during initial sync"));
                }
                Some(Err(e)) => {
                    return Err(SessionFault::Remote(format!(
                        "WS error during initial sync: {e}"
                    )));
                }
                _ => continue, // Skip ping/pong/text
            }
        }

        // Opened-item enrol finishes only after the grant-filtered thin index
        // is durable. A missing actor grant/session is a failure, never an
        // excuse to fall back to full-window sync. The index is the home's: a
        // peer session reads none (FIX 4748).
        if peer.is_none() && client.config.residence_mode == crate::sync::SyncResidenceMode::Opened
        {
            let now_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |duration| duration.as_secs());
            client
                .fetch_current_index_by_side(now_secs)
                .await
                .map_err(|fault| {
                    SessionFault::of_index_fetch(
                        &fault,
                        format!("Fetch residence index failed: {fault}"),
                    )
                })?;
        }

        // Phase 3: Drain offline queue
        let queued = self.queue.drain_updates().map_err(SessionFault::local)?;
        if peer.is_some() {
            // FIX 4748: the peer takes the queue's writes and answers with its
            // own, and nothing here clears, retires or re-bootstraps; the
            // queue and every `fr:w:` marker stay for the home session.
            if !queued.is_empty() {
                let sent = self
                    .replay_queued_updates(&mut write, client, event_tx, queued)
                    .await?;
                if client.config.residence_mode == crate::sync::SyncResidenceMode::All {
                    self.exchange_with_peer(&mut write, &mut read, client, event_tx, &sent)
                        .await?;
                }
            }
            let ws_stream = read.reunite(write).map_err(SessionFault::local)?;
            // A peer session is not the home's sync: no `m:last_sync`.
            let _ = event_tx.send(SyncEvent::StatusChanged(SyncStatus::Connected));
            return Ok(ws_stream);
        }
        let full_resync_markers = self.full_resync_markers()?;
        // FIX 20202: an opened-item session re-bootstraps from the server
        // each marked window this device promoted and the home may read, over
        // its promoted exchange, once the queue is replayed. Any other marked
        // window still needs sync-all.
        let (full_resync_markers, promoted_markers) =
            if client.config.residence_mode == crate::sync::SyncResidenceMode::Opened {
                for marker in &full_resync_markers {
                    let recoverable = match WindowKey::try_new(marker.window_key.as_str()) {
                        Some(key) => {
                            client
                                .opened_window_promoted(&key)
                                .map_err(SessionFault::local)?
                                && client.home_may_promote(&key)
                                && client.home_may_request(&key)
                        }
                        None => false,
                    };
                    if !recoverable {
                        return Err(SessionFault::local(
                            "opened-item full-resync requires explicit sync-all recovery",
                        ));
                    }
                }
                (Vec::new(), full_resync_markers)
            } else {
                (full_resync_markers, Vec::new())
            };
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
        if !promoted_markers.is_empty() {
            tracing::info!(
                marker_count = promoted_markers.len(),
                "re-bootstrapping marked promoted windows from the server"
            );
            self.re_bootstrap_promoted(&mut write, &mut read, client, event_tx, &promoted_markers)
                .await?;
        }

        // Reunite the stream
        let ws_stream = read.reunite(write).map_err(SessionFault::local)?;

        // The first round is complete: root and windows applied, the queue
        // replayed and taken. The home served this machine's sync (FIX 4748).
        let _ = event_tx.send(SyncEvent::StatusChanged(SyncStatus::Synced));

        // m:last_sync (ARCH-0023b key table) — last successful sync stamp.
        if let Err(e) = client.mark_synced() {
            let _ = event_tx.send(SyncEvent::Error(format!(
                "Failed to record last sync timestamp: {e}"
            )));
        }

        Ok(ws_stream)
    }
}
