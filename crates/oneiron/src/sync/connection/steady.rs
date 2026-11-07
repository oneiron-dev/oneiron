//! Steady state: debounced multiplex loop over WS, local updates, shutdown.

use std::sync::atomic::{AtomicBool, Ordering};

use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tokio::time::{Duration, Instant};
use tokio_tungstenite::tungstenite::Message;

use crate::sync::client::{SyncClient, SyncEvent};
use crate::sync::transport;
use crate::sync::types::parse_window_key_str;

use crate::side_table::HexId;
use crate::sync::documents::DS_E;

use super::server_close::ServerClose;
use super::session::{
    EPHEMERAL_HOUSEKEEPING_INTERVAL_SECS, MACHINE_HISTORY_FETCH_TASKS,
    MACHINE_HISTORY_RETRY_INTERVAL_SECS, SEALED_RELAY_INTERVAL_SECS,
};
use super::{LocalUpdate, LoopExit, SyncConnection, flush_to_queue};

impl SyncConnection {
    /// Steady-state event loop: multiplexes WS reads, local updates, and debounce.
    pub(super) async fn steady_state(
        &self,
        ws_stream: crate::sync::carrier::SyncSocket,
        client: &mut SyncClient,
        event_tx: &mpsc::UnboundedSender<SyncEvent>,
        local_rx: &mut mpsc::UnboundedReceiver<LocalUpdate>,
        debounce_buffer: &mut Vec<LocalUpdate>,
        promotion_rx: &mut tokio::sync::broadcast::Receiver<crate::sync::WindowKey>,
        shutdown_rx: &mut tokio::sync::oneshot::Receiver<()>,
    ) -> LoopExit {
        let (mut write, mut read) = ws_stream.split();
        // A staged import body pass a returned run left settles first
        // (FIX 12408); its socket closed with that run.
        client.end_staged_body_pull();
        // Live, bounded and lossy. Partials never enter the durable offline queue.
        let mut presence_rx = self
            .manager
            .vault()
            .message_streams
            .presence
            .subscribe_frames();

        // One node tick after its first edit; a busy writer cannot postpone it.
        let debounce_ms = u64::from(self.config.client_config.sync_debounce_ms).max(1);
        let mut document_buffer: Vec<Vec<u8>> = Vec::new();
        // Window updates and documents lead the tick's batch in turn (FIX 8870).
        let mut batch_turn = super::node_batch::NodeBatchTurn::default();
        // One owed artifact publication part at a time, outside the document
        // buffer, and where this connection stands in them (FIX 9575).
        let mut publication_cursor = crate::artifact_hosting::ArtifactPublicationCursor::default();
        let mut publication_slot = None;
        let mut debounce_deadline = (!debounce_buffer.is_empty())
            .then(|| Instant::now() + Duration::from_millis(debounce_ms));
        let mut ephemeral_housekeeping =
            tokio::time::interval(Duration::from_secs(EPHEMERAL_HOUSEKEEPING_INTERVAL_SECS));
        ephemeral_housekeeping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // One residence upkeep at a time (authority catch-up, then the sealed
        // bundle relay), on its own sockets, off this loop.
        let mut sealed_relay =
            tokio::time::interval(Duration::from_secs(SEALED_RELAY_INTERVAL_SECS));
        sealed_relay.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut sealed_task: Option<tokio::task::JoinHandle<()>> = None;
        // The committed pad tombstones no postcommit published (FIX 3849): one
        // retry at a time on the same tick, every lane, federation's included.
        let mut tombstone_task: Option<tokio::task::JoinHandle<()>> = None;
        // One staged import body pass at a time (FIX 12408): its producer's
        // socket runs off this loop, and its frames are handled here.
        let mut staged_pump: Option<crate::sync::client::StagedBodyPump> = None;
        // The machine-claim history this machine is owed (FIX 3820): rounds on
        // their own sockets, off this loop, at connect, every retry interval,
        // and once an import or a round lands rows it waits on.
        let mut machine_history =
            tokio::time::interval(Duration::from_secs(MACHINE_HISTORY_RETRY_INTERVAL_SECS));
        machine_history.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let machine_history_due = std::sync::Arc::new(AtomicBool::new(false));
        let mut machine_history_tasks = Vec::new();
        // A residence-mode switch closes this socket; the next connect sends
        // the new mode's hello. A live lane never changes mode.
        let mut mode_rx = self.mode.subscribe();
        if *mode_rx.borrow_and_update() != client.config.residence_mode {
            return LoopExit::Renegotiate;
        }
        let mut left_rx = self.left.subscribe();
        // The host's admission for each batch, and its pause (FIX 12036).
        let mut gate = self.batch_gate();
        // FIX 4748: a peer session takes none of the home's upkeep (residence
        // directives, home handoff rounds, machine history, authority
        // catch-up, leaf-key requests, publications), and it probes the home
        // on its cadence, ending once the home answers.
        let peer_session = client.peer_session;
        let mut home_probe =
            super::peer_session::HomeProbe::new(peer_session.is_some(), &self.config.client_config);

        // Every `break` is the run's shutdown; any other exit returns, and
        // its upkeep rounds run on beside the next connection.
        let exit = loop {
            // What the home sent, then the promotions asked, go first, in
            // order, each under its own admission; a pause keeps the rest.
            if let Err(exit) = self
                .apply_held(
                    &mut gate,
                    client,
                    &mut write,
                    event_tx,
                    &machine_history_due,
                    debounce_buffer,
                )
                .await
            {
                if matches!(exit, LoopExit::Shutdown) {
                    self.publish_leave_unqueued(debounce_buffer);
                    break exit;
                }
                return exit;
            }
            if peer_session.is_none() {
                self.run_machine_history(
                    &mut machine_history_tasks,
                    &machine_history_due,
                    event_tx,
                    &mut gate,
                )
                .await;
            }
            // Compute sleep future for debounce timer
            let debounce_sleep = match debounce_deadline {
                Some(deadline) => tokio::time::sleep_until(deadline),
                None => tokio::time::sleep(Duration::from_secs(86400)), // effectively never
            };

            tokio::select! {
                // WS message from server; while paused, read until the
                // frames held fill their room (FIX 12036).
                msg = read.next(), if gate.reading() => {
                    match msg {
                        // Applied at the loop's head, in order, under the
                        // host's admission (FIX 12036).
                        Some(Ok(Message::Binary(data))) => gate.hold_frame(data),
                        Some(Ok(Message::Ping(data))) => {
                            let mut send_left = self.left.subscribe();
                            let pong_result = tokio::select! {
                                biased;
                                () = async { let _ = send_left.wait_for(|left| *left).await; } => {
                                    self.publish_leave_unqueued(debounce_buffer);
                                    break LoopExit::Shutdown;
                                }
                                result = write.send(Message::Pong(data)) => result,
                            };
                            if let Err(e) = pong_result {
                                return LoopExit::Disconnected(format!("Pong failed: {e}"));
                            }
                        }
                        Some(Ok(Message::Close(frame))) => {
                            // Flush debounce buffer before disconnecting; the
                            // close code tells a server fault from a refusal
                            // (FIX 5927).
                            self.queue_on_exit(&mut gate, debounce_buffer).await;
                            return LoopExit::Closed(ServerClose::read(frame.as_ref()));
                        }
                        None => {
                            self.queue_on_exit(&mut gate, debounce_buffer).await;
                            return LoopExit::Disconnected("Server closed connection".to_string());
                        }
                        Some(Err(e)) => {
                            self.queue_on_exit(&mut gate, debounce_buffer).await;
                            return LoopExit::Disconnected(format!("WS error: {e}"));
                        }
                        _ => {} // Text, Pong — ignore
                    }
                }

                promotion = promotion_rx.recv(), if !gate.paused() => {
                    let key = match promotion {
                        Ok(key) => key,
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                            return LoopExit::Disconnected("promotion notice lagged; reconnect required".into());
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                            return LoopExit::Disconnected("promotion channel closed".into());
                        }
                    };
                    // Sent at the loop's head under the host's admission.
                    gate.hold_promotion(key);
                }

                // A frame from the staged import body pass's producer (FIX
                // 12408), handled under the host's admission. Its socket
                // gone, the pass ends.
                frame = async {
                    match staged_pump.as_mut() {
                        Some(pump) => pump.recv().await,
                        None => std::future::pending().await,
                    }
                }, if staged_pump.is_some() && !gate.paused() => {
                    let admitted = match frame {
                        Some(frame) => gate.admit().await.map(|batch| (frame, batch)),
                        None => None,
                    };
                    if let Some((frame, _batch)) = admitted {
                        let out = client.handle_staged_body_frame(&frame);
                        if let Some(pump) = &staged_pump {
                            pump.send(out);
                        }
                    } else {
                        if let Some(pump) = staged_pump.take() {
                            pump.stop().await;
                        }
                        client.end_staged_body_pull();
                    }
                }

                // Live and lossy: no admission, and none sent while paused.
                partial = presence_rx.recv(), if !gate.paused() => {
                    match partial {
                        Ok(frame) => {
                            let mut send_left = self.left.subscribe();
                            let send_result = tokio::select! {
                                biased;
                                () = async { let _ = send_left.wait_for(|left| *left).await; } => {
                                    self.publish_leave_unqueued(debounce_buffer);
                                    break LoopExit::Shutdown;
                                }
                                result = write.send(Message::Binary(frame.into())) => result,
                            };
                            if let Err(error) = send_result {
                                self.queue_on_exit(&mut gate, debounce_buffer).await;
                                return LoopExit::Disconnected(format!("Presence send failed: {error}"));
                            }
                        }
                        // A slow socket skips obsolete partials; the durable final
                        // and the next full-text partial repair the user view.
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break LoopExit::Shutdown,
                    }
                }

                frame = client.document_updates.recv() => {
                    match frame {
                        Ok(frame) => {
                            let id = match transport::decode_document(&frame[1..]) {
                                Ok(doc) => {
                                    if client.vault.get_entity_type(&doc.entity).ok().flatten() == Some(crate::registry::ENTITY_TYPE_NOTE) {
                                        // A NOTE's own commands, requests and fork uploads
                                        // (FIX 12789) go to its authority; its invalidations stay here.
                                        if !matches!(doc.kind, transport::document_sub_tags::NOTE_OPS | transport::document_sub_tags::REQUEST | transport::document_sub_tags::NOTE_FORK_UPLOAD) { continue; }
                                        if !client.note_session_bound { continue; }
                                    }
                                    doc.entity
                                },
                                Err(error) => return LoopExit::Disconnected(error.to_string()),
                            };
                            let withheld = client.frame_withheld(&frame);
                            // FIX 10872: a marked source's own edit, withheld, leaves
                            // as its copy lineage's operations under its copy id.
                            let released = if withheld { client.copy_release_frames(id) } else { Vec::new() };
                            let subscribed = (|| -> crate::error::Result<bool> {
                                let rtxn = client.vault.store.env.read_txn()?;
                                Ok(DS_E.contains(&client.vault.store, &rtxn, &HexId(id))? && !withheld)
                            })();
                            match subscribed {
                                Ok(true) => {
                                    document_buffer.push(frame);
                                    debounce_deadline.get_or_insert_with(||
                                        Instant::now() + Duration::from_millis(debounce_ms));
                                }
                                Ok(false) if !released.is_empty() => {
                                    document_buffer.extend(released);
                                    debounce_deadline.get_or_insert_with(||
                                        Instant::now() + Duration::from_millis(debounce_ms));
                                }
                                // Offline editing before admission, or on text a
                                // device-only world keeps here, stays journaled.
                                Ok(false) => {}
                                Err(error) => return LoopExit::Disconnected(error.to_string()),
                            }
                        }
                        Err(_) => return LoopExit::Disconnected("document journal resync required".into()),
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
                            debounce_deadline.get_or_insert_with(||
                                Instant::now() + Duration::from_millis(debounce_ms));
                        }
                        None => {
                            // Channel closed — application is shutting down
                            break LoopExit::Shutdown;
                        }
                    }
                }

                // Debounce timer fired — flush buffered updates
                _ = debounce_sleep, if debounce_deadline.is_some() && !gate.paused() => {
                    // Held until the batch is sent; a pause keeps the
                    // buffers for the tick after the thaw (FIX 12036).
                    let Some(_batch) = gate.admit().await else {
                        continue;
                    };
                    debounce_deadline = None;

                    match self.flush_node_batch(
                        &mut write, client, debounce_buffer, &mut document_buffer,
                        &mut publication_slot, &mut batch_turn,
                    ).await {
                        Err(LoopExit::Shutdown) => {
                            self.publish_leave_unqueued(debounce_buffer);
                            break LoopExit::Shutdown;
                        }
                        Err(exit) => {
                            flush_to_queue(&self.queue, debounce_buffer);
                            return exit;
                        }
                        Ok(Some((part, sent))) => {
                            client.artifact_publication_released(&mut publication_cursor, &part, sent);
                        }
                        Ok(None) => {}
                    }
                    // The next owed part goes on the next tick; the home's
                    // receipt retires it, so none goes to a peer.
                    if peer_session.is_none()
                        && let Err(error) = client.pull_artifact_publication(&mut publication_cursor, &mut publication_slot)
                    {
                        let _ = event_tx.send(SyncEvent::Error(format!("Artifact publication sync failed: {error}")));
                    }
                    if !debounce_buffer.is_empty() || !document_buffer.is_empty() || publication_slot.is_some() {
                        debounce_deadline = Some(Instant::now() + Duration::from_millis(debounce_ms));
                    }
                }

                _ = sealed_relay.tick(), if !gate.paused() => {
                    // Each upkeep task holds the host's admission until its
                    // last write; a pause leaves the tick due at the thaw
                    // (FIX 12036).
                    let (Some(tombstone_batch), Some(sealed_batch)) =
                        (gate.admit().await, gate.admit().await)
                    else {
                        sealed_relay.reset_immediately();
                        continue;
                    };
                    // The home handoff's delivery round (FIX 5661 C2a).
                    if peer_session.is_none() {
                        self.home_handoff_wake.notify_one();
                    }
                    if tombstone_task.as_ref().is_none_or(tokio::task::JoinHandle::is_finished) {
                        let vault = std::sync::Arc::clone(self.manager.vault());
                        let events = event_tx.clone();
                        tombstone_task = Some(tokio::task::spawn_blocking(move || {
                            let _batch = tombstone_batch;
                            if let Err(error) = crate::sync::residence::retry_pending_tombstones(&vault) {
                                let _ = events.send(SyncEvent::Error(format!(
                                    "Pending tombstone retry failed: {error}"
                                )));
                            }
                            // A world the owner keeps on one other machine
                            // leaves this one (FIX 14534).
                            match crate::sync::residence::evict_worlds_placed_elsewhere(&vault) {
                                Ok(eviction) if eviction.worlds > 0 => tracing::info!(
                                    worlds = eviction.worlds,
                                    windows_evicted = eviction.windows_evicted,
                                    windows_busy = eviction.windows_busy,
                                    windows_unconfirmed = eviction.windows_unconfirmed,
                                    windows_with_local_members =
                                        eviction.windows_with_local_members,
                                    removed = eviction.removed,
                                    kept = eviction.kept,
                                    cached_items_removed = eviction.cached_items_removed,
                                    cached_items_held = eviction.cached_items_held,
                                    "world copies placed elsewhere evicted"
                                ),
                                Ok(_) => {}
                                Err(error) => {
                                    let _ = events.send(SyncEvent::Error(format!(
                                        "World eviction failed: {error}"
                                    )));
                                }
                            }
                        }));
                    }
                    if self.config.client_config.federation_peer.is_none()
                        && peer_session.is_none()
                        && sealed_task.as_ref().is_none_or(tokio::task::JoinHandle::is_finished)
                    {
                        let manager = std::sync::Arc::clone(&self.manager);
                        let config = self.client_config();
                        let events = event_tx.clone();
                        let directives = std::sync::Arc::clone(&self.directive_wake);
                        let machine_history_due = std::sync::Arc::clone(&machine_history_due);
                        sealed_task = Some(tokio::spawn(async move {
                            let _batch = sealed_batch;
                            // An opened machine's windows carry only the
                            // authority rows they hold: take the rest first
                            // (OF-469). Any machine whose rows name history it
                            // lacks takes it too, and so does one whose pairing
                            // pinned a checkpoint it has yet to adopt.
                            if (config.residence_mode == crate::sync::SyncResidenceMode::Opened
                                || !manager
                                    .vault()
                                    .authority_missing_history()
                                    .is_ok_and(|missing| missing.is_complete())
                                || crate::sync::client::pinned_checkpoint_pending(
                                    manager.vault(),
                                    &config,
                                ))
                                && let Err(error) =
                                    crate::sync::client::catch_up_authority(manager.vault(), &config)
                                        .await
                                        // Authority an owed machine history waits on
                                        // may have landed: its exchange runs again
                                        // (FIX 4293).
                                        .inspect(|&taken| {
                                            if taken > 0 {
                                                machine_history_due.store(true, Ordering::Relaxed);
                                                // The host re-reads what those rows
                                                // decide, its home candidacy among
                                                // them (FIX 5572).
                                                let _ = events.send(SyncEvent::AuthorityCaughtUp);
                                            }
                                        })
                                && !matches!(error, crate::sync::TransportError::InvalidPayload(_))
                            {
                                let _ = events.send(SyncEvent::Error(format!(
                                    "Authority catch-up failed: {error}"
                                )));
                            }
                            // The owner's residence directives naming this
                            // machine run once its history is in (OF-534).
                            directives.notify_one();
                            // The owner work those rows name this machine to
                            // do (a world's key work) runs once they are in.
                            let vault = std::sync::Arc::clone(manager.vault());
                            match tokio::task::spawn_blocking(move || vault.run_pending_owner_work(|| true)).await {
                                Ok(Ok(_)) => {}
                                Ok(Err(error)) => {
                                    let _ = events.send(SyncEvent::Error(format!(
                                        "Owner work pickup failed: {error}"
                                    )));
                                }
                                Err(error) => {
                                    let _ = events.send(SyncEvent::Error(format!(
                                        "Owner work pickup stopped: {error}"
                                    )));
                                }
                            }
                            // A machine those rows made mine gets each portable
                            // credential's value sealed to it again (OF-422).
                            let vault = std::sync::Arc::clone(manager.vault());
                            match tokio::task::spawn_blocking(move || vault.reseal_custody_for_roster()).await {
                                Ok(Ok(_)) => {}
                                Ok(Err(error)) => {
                                    let _ = events.send(SyncEvent::Error(format!(
                                        "Custody re-seal failed: {error}"
                                    )));
                                }
                                Err(error) => {
                                    let _ = events.send(SyncEvent::Error(format!(
                                        "Custody re-seal stopped: {error}"
                                    )));
                                }
                            }
                            // The vault's sealed bundle: erase's rewrite of every
                            // kept pad, then the slot's take and upload (FIX 922).
                            // Its result is noted for the owner as it passes (FIX 4953).
                            match crate::sync::client::observe_sealed_bundle_relay(manager.vault(), crate::sync::client::relay_sealed_bundle(&manager, &config).await) {
                                Ok(_) | Err(crate::sync::TransportError::InvalidPayload(_)) => {}
                                Err(error) => {
                                    let _ = events.send(SyncEvent::Error(format!(
                                        "Sealed bundle relay failed: {error}"
                                    )));
                                }
                            }
                            // A window the home refused to retain is asked for
                            // again: a grant may have changed since (OF-534).
                            match crate::sync::client::retry_refused_retains(&manager, &config).await {
                                Ok(_) | Err(crate::sync::TransportError::InvalidPayload(_)) => {}
                                Err(error) => {
                                    let _ = events.send(SyncEvent::Error(format!(
                                        "Window retain retry failed: {error}"
                                    )));
                                }
                            }
                            // The checkpoint roots of the owner's policy, once the
                            // history is in (FIX 4882): a root held here attests the
                            // home's image, and the home's root this machine's.
                            if crate::authority::ROOT_CHECKPOINT_PICKUP
                                == crate::authority::RootCheckpointPickup::ExistingTickAndCatchup
                            {
                                match crate::sync::client::exchange_checkpoint_roots(manager.vault(), &config).await {
                                    Ok(_) | Err(crate::sync::TransportError::InvalidPayload(_)) => {}
                                    Err(error) => {
                                        let _ = events.send(SyncEvent::Error(format!(
                                            "Checkpoint root exchange failed: {error}"
                                        )));
                                    }
                                }
                            }
                            // This machine's key custody to its residence home
                            // (KS-4A2): a home out of reach stays pending by name.
                            if let Err(error) = crate::sync::client::relay_custody(manager.vault(), &config).await {
                                let _ = events.send(SyncEvent::Error(format!(
                                    "Custody relay failed: {error}"
                                )));
                            }
                        }));
                    }
                }

                _ = machine_history.tick() => {
                    machine_history_due.store(true, Ordering::Relaxed);
                }

                // Loro's Rust EphemeralStore has no internal timer. Its
                // sends and writes are one batch (FIX 12036).
                _ = ephemeral_housekeeping.tick(), if !gate.paused() => {
                    let Some(_batch) = gate.admit().await else {
                        continue;
                    };
                    client.remove_outdated_ephemeral();
                    let retries = client.retry_document_requests();
                    if !retries.is_empty() {
                        document_buffer.extend(retries);
                        debounce_deadline.get_or_insert_with(||
                            Instant::now() + Duration::from_millis(debounce_ms));
                    }
                    let mut housekeeping_left_rx = self.left.subscribe();
                    let send_result = tokio::select! {
                        biased;
                        () = async { let _ = housekeeping_left_rx.wait_for(|left| *left).await; } => {
                            self.publish_leave_unqueued(debounce_buffer);
                            break LoopExit::Shutdown;
                        }
                        result = async {
                            crate::sync::asset_body::client::send_asset_bodies(client, &mut write).await?;
                            if peer_session.is_none() {
                                crate::sync::client::send_leaf_key_requests(client, &mut write).await?;
                            }
                            crate::sync::client::send_sealed_updates(client, &mut write).await
                        } => result,
                    };
                    if let Err(e) = send_result {
                        return LoopExit::Disconnected(e);
                    }
                    if let Err(error) = client.replay_deferred_federation_update() {
                        return LoopExit::Disconnected(format!("federation replay: {error}"));
                    }
                    // The staged import body pass (FIX 12408): its next Want
                    // goes out, or it ends, or the next one due begins.
                    let now = std::time::Instant::now();
                    if staged_pump.is_none() {
                        match client.begin_staged_body_pull(now) {
                            Ok(Some(start)) => {
                                staged_pump = Some(crate::sync::client::StagedBodyPump::spawn(
                                    std::sync::Arc::clone(self.manager.vault()),
                                    start,
                                ));
                            }
                            Ok(None) => {}
                            Err(error) => {
                                let _ = event_tx.send(SyncEvent::Error(format!(
                                    "Staged import body pull failed: {error}"
                                )));
                            }
                        }
                    } else if client.staged_body_pull_done(now) {
                        if let Some(pump) = staged_pump.take() {
                            pump.stop().await;
                        }
                        client.end_staged_body_pull();
                    } else if let Some(pump) = &staged_pump {
                        pump.send(client.poll_staged_body_pull(now));
                    }
                    // Pinned artifact pointers this device still owes the server,
                    // one part at a time; the home's, never a peer's.
                    let pulled = if peer_session.is_none() {
                        client.pull_artifact_publication(&mut publication_cursor, &mut publication_slot)
                    } else {
                        Ok(false)
                    };
                    match pulled {
                        Ok(true) => {
                            debounce_deadline.get_or_insert_with(||
                                Instant::now() + Duration::from_millis(debounce_ms));
                        },
                        Ok(false) => {}
                        Err(error) => { let _ = event_tx.send(SyncEvent::Error(format!("Artifact publication sync failed: {error}"))); }
                    }
                    match self.manager.vault().pump_message_streams() {
                        Ok(report) => for (_, error) in report.refused {
                            let _ = event_tx.send(SyncEvent::Error(format!("Stream idle finalize refused: {error}")));
                        },
                        Err(error) => { let _ = event_tx.send(SyncEvent::Error(format!("Stream idle pump failed: {error}"))); }
                    }
                }

                // The host thawed: what the pause held goes first (FIX 12036).
                () = gate.thawed(), if gate.paused() => {}

                // FIX 4748: the home answers a peer session's probe: this
                // session ends, what it buffered queued, and the next
                // connect is the home's.
                () = home_probe.answered() => {
                    self.queue_on_exit(&mut gate, debounce_buffer).await;
                    let mut send_left = self.left.subscribe();
                    tokio::select! {
                        biased;
                        () = async { let _ = send_left.wait_for(|left| *left).await; } => {
                            self.publish_leave_unqueued(debounce_buffer);
                            break LoopExit::Shutdown;
                        }
                        _ = write.send(Message::Close(None)) => {}
                    }
                    return LoopExit::HomeReturned;
                }

                changed = mode_rx.changed() => {
                    if changed.is_ok() {
                        self.queue_on_exit(&mut gate, debounce_buffer).await;
                        let mut send_left = self.left.subscribe();
                        tokio::select! {
                            biased;
                            () = async { let _ = send_left.wait_for(|left| *left).await; } => {
                                self.publish_leave_unqueued(debounce_buffer);
                                break LoopExit::Shutdown;
                            }
                            _ = write.send(Message::Close(None)) => {}
                        }
                        return LoopExit::Renegotiate;
                    }
                }

                // A confirmed leave ends the lane for good (OF-158): what it
                // buffered gets one queue try, then the remaining valid buffer
                // is published and cleared as the explicit owner discard BEFORE
                // the close frame's await, so a blocked `Close` cannot delay
                // the count past the 10s quiesce. The borrow `wait_for` returns
                // goes before the close frame's await, so the loop stays `Send`
                // for a host that spawns it.
                () = async { let _ = left_rx.wait_for(|left| *left).await; } => {
                    self.queue_on_exit(&mut gate, debounce_buffer).await;
                    self.publish_leave_unqueued(debounce_buffer);
                    let mut send_left = self.left.subscribe();
                    tokio::select! {
                        biased;
                        _ = write.send(Message::Close(None)) => {}
                        () = async { let _ = send_left.wait_for(|left| *left).await; } => {}
                    }
                    break LoopExit::Shutdown;
                }

                // Shutdown signal
                _ = &mut *shutdown_rx => {
                    // Flush any remaining buffered updates to queue
                    let mut shutdown_left = self.left.subscribe();
                    tokio::select! {
                        biased;
                        () = async { let _ = shutdown_left.wait_for(|left| *left).await; } => {
                            self.queue_on_exit(&mut gate, debounce_buffer).await;
                            self.publish_leave_unqueued(debounce_buffer);
                        }
                        _ = self.queue_on_shutdown(&mut gate, debounce_buffer) => {}
                    }
                    // Send close frame
                    let mut send_left = self.left.subscribe();
                    tokio::select! {
                        biased;
                        () = async { let _ = send_left.wait_for(|left| *left).await; } => {
                            self.publish_leave_unqueued(debounce_buffer);
                        }
                        _ = write.send(Message::Close(None)) => {}
                    }
                    break LoopExit::Shutdown;
                }
            }
        };
        // The staged import body pass ends with the run (FIX 12408).
        if let Some(pump) = staged_pump.take() {
            pump.stop().await;
        }
        client.end_staged_body_pull();
        // FIX 12037: the run ends with its residence upkeep ended, so none of
        // its writes lands after it (a reap's export waits on this): the
        // async rounds are aborted, and each task, the blocking tombstone
        // retry included, is waited for.
        if let Some(task) = &sealed_task {
            task.abort();
        }
        for task in &machine_history_tasks {
            task.abort();
        }
        for task in sealed_task
            .into_iter()
            .chain(tombstone_task)
            .chain(machine_history_tasks)
        {
            let _ = task.await;
        }
        exit
    }

    /// Starts an owed machine-history round off this loop once one is due and
    /// a task is free (FIX 3820). Own residence only: the home answers it, a
    /// federation peer does not. A round that lands rows asks for another,
    /// since a row it released may owe more. Each round holds the host's
    /// admission until it ends; a paused host leaves it due (FIX 12036).
    async fn run_machine_history(
        &self,
        tasks: &mut Vec<tokio::task::JoinHandle<()>>,
        due: &std::sync::Arc<AtomicBool>,
        event_tx: &mpsc::UnboundedSender<SyncEvent>,
        gate: &mut super::batch_admission::BatchGate<'_>,
    ) {
        tasks.retain(|task| !task.is_finished());
        if self.config.client_config.federation_peer.is_some()
            || tasks.len() >= MACHINE_HISTORY_FETCH_TASKS
            || !due.swap(false, Ordering::Relaxed)
        {
            return;
        }
        let Some(batch) = gate.admit().await else {
            due.store(true, Ordering::Relaxed);
            return;
        };
        let manager = std::sync::Arc::clone(&self.manager);
        let config = self.client_config();
        let events = event_tx.clone();
        let due = std::sync::Arc::clone(due);
        tasks.push(tokio::spawn(async move {
            let _batch = batch;
            match crate::sync::client::fetch_owed_machine_history(&manager, &config).await {
                Ok(0) | Err(crate::sync::TransportError::InvalidPayload(_)) => {}
                Ok(_) => due.store(true, Ordering::Relaxed),
                Err(error) => {
                    let _ = events.send(SyncEvent::Error(format!(
                        "Machine history fetch failed: {error}"
                    )));
                }
            }
        }));
    }
}
