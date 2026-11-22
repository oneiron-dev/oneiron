//! Session opening: the connect, initial sync and queue replay a session
//! runs before its steady loop.

use std::collections::BTreeSet;
use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tokio::time::Duration;
use tokio_tungstenite::tungstenite::Message;

use crate::sync::client::{SyncClient, SyncEvent, SyncStatus};
use crate::sync::types::WindowKey;

use super::super::SyncConnection;
use super::super::server_close::ServerClose;
use super::super::session::SessionFault;

impl SyncConnection {
    /// Connects to the server and performs initial sync + queue replay. A
    /// peer session (FIX 4748, `client.peer_session`) dials its peer over
    /// the mesh and runs the same exchange, confirming nothing. A home
    /// session returns its socket only once its first round completed, so
    /// the home served this machine's sync; a fault of the far end before
    /// that, the home's refusal, fault or close included, leaves it unserved
    /// ([`HomeReach`]). A fault of this machine's own ([`SessionFault`], FIX
    /// 22107) says nothing of the home.
    ///
    /// [`HomeReach`]: super::super::peer_session::HomeReach
    pub(in crate::sync::connection) async fn open_sync_session(
        &self,
        client: &mut SyncClient,
        event_tx: &mpsc::UnboundedSender<SyncEvent>,
    ) -> Result<crate::sync::carrier::SyncSocket, SessionFault> {
        client.note_session_bound = false;
        client.note_bind_receipt = None;
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
    pub(in crate::sync::connection) async fn connect_and_sync(
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
                                SessionFault::remote(
                                    super::super::document_response::response_error(exit),
                                )
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
                                                super::super::document_response::response_error(
                                                    exit,
                                                ),
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
        // peer session reads none (FIX 4748). A member lane's residence
        // upgrade refusal is told once here, as the main upgrade's is in
        // `open_socket`, and its 403 parks through `SessionFault::Forbidden`
        // (MEMBER-SYNC threat F5); only a member lane's dial names either.
        if peer.is_none() && client.config.residence_mode == crate::sync::SyncResidenceMode::Opened
        {
            let now_secs = crate::unix_seconds_now();
            client
                .fetch_current_index_by_side(now_secs)
                .await
                .map_err(|fault| {
                    if let Some(refusal) = fault.upgrade_refusal() {
                        let _ = event_tx.send(refusal.event());
                    }
                    SessionFault::of_index_fetch(
                        &fault,
                        format!("Fetch residence index failed: {fault}"),
                    )
                })?;
        }

        // Each followed world's tombstone id set (FOLLOWED-WORLD-TIER1-
        // TOMBSTONE-IDS; ARCH-0023b :500): every delete the home lets this
        // device read writes its marker here, even of a window the home
        // refuses to it or that it never held. A fault never fails the
        // session: the residence upkeep asks again.
        if peer.is_none()
            && let Err(error) = client.fetch_followed_tombstones().await
        {
            let _ = event_tx.send(SyncEvent::Error(format!(
                "Followed tombstone fetch failed: {error}"
            )));
        }

        // A followed world's window asked as a follow waits for the home's
        // answer before the queue replays: a granted window's queued writes
        // go now, a refused one's stay owed, and the socket stays open. A home
        // that answers no follow leaves those windows' writes queued.
        let asked = client.unanswered_follow_requests();
        if peer.is_none() && !asked.is_empty() {
            let answered = |client: &SyncClient, key: &WindowKey| client.follow_answered(key);
            self.pump_until_each(&mut write, &mut read, client, event_tx, &asked, answered)
                .await?;
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
        // the marked windows it may recover over this connection
        // (`opened_resync_markers`), once the queue is replayed.
        let (full_resync_markers, promoted_markers) =
            if client.config.residence_mode == crate::sync::SyncResidenceMode::Opened {
                (
                    Vec::new(),
                    Self::opened_resync_markers(client, full_resync_markers)?,
                )
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

        // L7-47: the first full round under sync all writes this machine's
        // full-copy mark. A home session only, never a peer's (a peer serves
        // state-only copies, never a full copy), and never on a federation
        // lane. A mark that does not land never fails the session.
        if client.peer_session.is_none()
            && client.config.federation_peer.is_none()
            && client.config.residence_mode == crate::sync::SyncResidenceMode::All
        {
            let vault = Arc::clone(self.manager.vault());
            let configured = self.config.client_config.residence_mode;
            match tokio::task::spawn_blocking(move || vault.mark_first_round_full_copy(configured))
                .await
            {
                Ok(Ok(_)) => {}
                Ok(Err(error)) => tracing::warn!(
                    kind = ?error.kind(),
                    "the full-copy mark was not written"
                ),
                Err(error) => {
                    tracing::warn!("the full-copy mark write did not finish: {error}");
                }
            }
        }

        Ok(ws_stream)
    }
}
