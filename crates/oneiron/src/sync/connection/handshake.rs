//! Handshake: run loop, overflow check. The session opening (connect,
//! initial sync, queue replay) is in `initial_sync`.

use std::sync::Arc;

use tokio::sync::mpsc;
use tokio::time::Duration;

use crate::sync::client::{SyncClient, SyncEvent, SyncStatus, next_backoff};

use super::peer_session::HomeReach;
use super::{LocalUpdate, LoopExit, SyncConnection};

mod acks;
mod forbidden_park;
mod initial_sync;
mod replay;
mod resync_markers;
mod upgrade;

pub(super) use self::upgrade::{upgrade_carries_credential, upgrade_request};

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
    /// the mode that follows the committed home (FIX 8869), and the predicted
    /// level's upkeep on this machine (ARCH-0023b #predicted-residence).
    async fn drive(
        &self,
        client: SyncClient,
        shutdown_rx: tokio::sync::oneshot::Receiver<()>,
    ) -> crate::error::Result<()> {
        // Under the host's admission, set by now (FIX 12036).
        self.collect_left_env_bodies();
        let directives = self.run_residence_directives(client.event_tx.clone());
        let predicted = self.run_predicted_residence(client.event_tx.clone());
        let home_handoff = self.run_home_handoff(client.event_tx.clone());
        let residence_mode = self.run_residence_mode(client.event_tx.clone());
        tokio::select! {
            result = self.drive_loop(client, shutdown_rx) => result,
            never = directives => match never {},
            never = predicted => match never {},
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
        // sessions go to this vault's other machines (FIX 4748). A member
        // lane never counts the home down: its home is the shared vault's,
        // and a peer's full-lane bytes are never its lane's (MEMBER-SYNC D7).
        // `open_lane` sets no peer dialer, so this is unreachable there; the
        // flag holds the invariant even if a caller supplied one.
        let mut reach = HomeReach::new(
            self.config.client_config.peer_dialer.is_some()
                && !self.config.client_config.member_lane,
        );
        self.running.send_replace(true);
        // Every connection's upkeep, owned here across reconnects (FIX 12785).
        let mut upkeep = super::steady::UpkeepTasks::default();
        // Whether the home refused this credential the socket, on a dial or a
        // peer session's probe (MEMBER-SELECTOR-SOCKET): the run never
        // redials on it, and parks below once its loop has ended.
        let mut forbidden = false;

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
            // A member lane passes no dialer: no peer session, even if one
            // were configured (MEMBER-SYNC D7; the `HomeReach` above is
            // already disabled there, so this is belt and braces).
            let peer_dialer = self
                .config
                .client_config
                .peer_dialer
                .as_deref()
                .filter(|_| !self.config.client_config.member_lane);
            let peer = reach.next_peer(peer_dialer);
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
                    // The predicted upkeep asks again after a (re)connect, once the
                    // authority history it needs is in (Engine ruling L7-46-MERGE A).
                    self.predicted_connected
                        .store(true, std::sync::atomic::Ordering::Relaxed);
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
                        // The home refused this credential a peer session's
                        // probe (MEMBER-SELECTOR-SOCKET): the peer session
                        // ends, and the run stops as on a home dial's 403.
                        LoopExit::Forbidden => {
                            let _ =
                                event_tx.send(SyncEvent::StatusChanged(SyncStatus::Disconnected));
                            forbidden = true;
                            break;
                        }
                    }
                }
                // The home refused this credential the socket
                // (MEMBER-SELECTOR-SOCKET): the run never redials on it, and
                // the home counts neither served nor down, so no peer
                // session follows.
                Err(e) if e.is_forbidden() => {
                    let _ = event_tx.send(SyncEvent::Error(format!("Connection failed: {e}")));
                    let _ = event_tx.send(SyncEvent::StatusChanged(SyncStatus::Disconnected));
                    forbidden = true;
                    break;
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
        // A refused credential (MEMBER-SELECTOR-SOCKET) parks the run until
        // its shutdown or a confirmed leave, its sink attached and each
        // commit queued as it arrives (forbidden_park.rs); the run then ends
        // as below. A host that renews the credential opens a new connection
        // on it (device sync, FIX 3377).
        if forbidden && self.config.auto_reconnect {
            self.park_forbidden(
                &mut local_rx,
                &mut debounce_buffer,
                &mut shutdown_rx,
                &mut left_rx,
            )
            .await;
        }
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
}
