//! Steady state: debounced multiplex loop over WS, local updates, shutdown.

use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tokio::time::{Duration, Instant};
use tokio_tungstenite::tungstenite::Message;

use crate::sync::client::{SyncClient, SyncEvent};
use crate::sync::transport::{self, window_sub_tags};
use crate::sync::types::parse_window_key_str;

use crate::side_table::HexId;
use crate::sync::documents::DS_E;

use super::session::{EPHEMERAL_HOUSEKEEPING_INTERVAL_SECS, SEALED_RELAY_INTERVAL_SECS};
use super::{LocalUpdate, LoopExit, SyncConnection, flush_to_queue};

impl SyncConnection {
    /// Steady-state event loop: multiplexes WS reads, local updates, and debounce.
    pub(super) async fn steady_state(
        &self,
        ws_stream: crate::sync::carrier::SyncSocket,
        client: &mut SyncClient,
        event_tx: &mpsc::UnboundedSender<SyncEvent>,
        local_rx: &mut mpsc::UnboundedReceiver<LocalUpdate>,
        promotion_rx: &mut tokio::sync::broadcast::Receiver<crate::sync::WindowKey>,
        shutdown_rx: &mut tokio::sync::oneshot::Receiver<()>,
    ) -> LoopExit {
        let (mut write, mut read) = ws_stream.split();
        // Live, bounded and lossy. Partials never enter the durable offline queue.
        let mut presence_rx = self
            .manager
            .vault()
            .message_streams
            .presence
            .subscribe_frames();

        // One node tick after its first edit; a busy writer cannot postpone it.
        let debounce_ms = u64::from(self.config.client_config.sync_debounce_ms).max(1);
        let mut debounce_buffer: Vec<LocalUpdate> = Vec::new();
        let mut document_buffer: Vec<Vec<u8>> = Vec::new();
        let mut debounce_deadline: Option<Instant> = None;
        let mut ephemeral_housekeeping =
            tokio::time::interval(Duration::from_secs(EPHEMERAL_HOUSEKEEPING_INTERVAL_SECS));
        ephemeral_housekeeping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // One residence upkeep at a time (authority catch-up, then the sealed
        // relay), on its own sockets, off this loop.
        let mut sealed_relay =
            tokio::time::interval(Duration::from_secs(SEALED_RELAY_INTERVAL_SECS));
        sealed_relay.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut sealed_task: Option<tokio::task::JoinHandle<()>> = None;
        // A residence-mode switch closes this socket; the next connect sends
        // the new mode's hello. A live lane never changes mode.
        let mut mode_rx = self.mode.subscribe();
        if *mode_rx.borrow_and_update() != client.config.residence_mode {
            return LoopExit::Disconnected("residence mode changed".into());
        }
        let mut left_rx = self.left.subscribe();

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
                                    // Judged per frame: a device-only flag may turn while an
                                    // earlier frame waits on the socket.
                                    for resp in responses
                                        .into_iter()
                                        .filter(|frame| !client.frame_withheld(frame))
                                    {
                                        let send_result =
                                            write.send(Message::Binary(resp.into())).await;
                                        if let Err(e) = send_result {
                                            return LoopExit::Disconnected(format!("Send failed: {e}"));
                                        }
                                    }
                                    if client.config.residence_mode == crate::sync::SyncResidenceMode::Opened
                                        && !client.residence_acks.is_empty()
                                        && let Err(e) = self.clear_residence_acks(client)
                                    {
                                        return LoopExit::Disconnected(e);
                                    }
                                }
                                Err(e) => {
                                    let _ = event_tx.send(SyncEvent::Error(format!("Protocol error: {e}")));
                                    if matches!(data.first(),
                                        Some(&transport::TAG_WINDOW_SYNC)
                                            | Some(&transport::TAG_BULK_TRANSFER)
                                            | Some(&transport::TAG_BULK_TRANSFER_DONE)) {
                                        // A missing causal prefix cannot be repaired by
                                        // silently dropping one live delta. Reconnect repeats
                                        // the VV handshake for every followed window.
                                        flush_to_queue(&self.queue, &mut debounce_buffer);
                                        return LoopExit::Disconnected(format!("Window sync error: {e}"));
                                    }
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

                promotion = promotion_rx.recv() => {
                    let key = match promotion {
                        Ok(key) => key,
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                            return LoopExit::Disconnected("promotion notice lagged; reconnect required".into());
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                            return LoopExit::Disconnected("promotion channel closed".into());
                        }
                    };
                    if client.config.residence_mode != crate::sync::SyncResidenceMode::Opened {
                        continue;
                    }
                    let Some(selector) = client.config.residence_selector.as_ref() else {
                        return LoopExit::Disconnected("promoted window missing grant selector".into());
                    };
                    let bytes = match crate::sync::encode_sync_selector(selector) {
                        Ok(bytes) => bytes,
                        Err(e) => return LoopExit::Disconnected(format!("promotion selector: {e}")),
                    };
                    let proof = match transport::encode_window_sync(
                        key.as_str(), window_sub_tags::PROMOTION_REQUEST, &bytes,
                    ).into_result() {
                        Ok(frame) => frame,
                        Err(e) => return LoopExit::Disconnected(e.to_string()),
                    };
                    let window = match client.ensure_window(key.as_str()) {
                        Ok(window) => window,
                        Err(e) => return LoopExit::Disconnected(e.to_string()),
                    };
                    let vv = match transport::encode_window_sync(
                        key.as_str(), window_sub_tags::VV_REQUEST,
                        &crate::sync::loro_support::doc_version_vector(&window.doc),
                    ).into_result() {
                        Ok(frame) => frame,
                        Err(e) => return LoopExit::Disconnected(e.to_string()),
                    };
                    for frame in [proof, vv] {
                        if let Err(e) = write.send(Message::Binary(frame.into())).await {
                            return LoopExit::Disconnected(e.to_string());
                        }
                    }
                }

                partial = presence_rx.recv() => {
                    match partial {
                        Ok(frame) => {
                            if let Err(error) = write.send(Message::Binary(frame.into())).await {
                                flush_to_queue(&self.queue, &mut debounce_buffer);
                                return LoopExit::Disconnected(format!("Presence send failed: {error}"));
                            }
                        }
                        // A slow socket skips obsolete partials; the durable final
                        // and the next full-text partial repair the user view.
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => return LoopExit::Shutdown,
                    }
                }

                frame = client.document_updates.recv() => {
                    match frame {
                        Ok(frame) => {
                            let id = match transport::decode_document(&frame[1..]) {
                                Ok(doc) => {
                                    if client.vault.get_entity_type(&doc.entity).ok().flatten() == Some(crate::registry::ENTITY_TYPE_NOTE) {
                                        if !matches!(doc.kind, transport::document_sub_tags::NOTE_OPS | transport::document_sub_tags::REQUEST) { continue; }
                                        if !client.note_session_bound { continue; }
                                    }
                                    doc.entity
                                },
                                Err(error) => return LoopExit::Disconnected(error.to_string()),
                            };
                            let withheld = client.frame_withheld(&frame);
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
                            return LoopExit::Shutdown;
                        }
                    }
                }

                // Debounce timer fired — flush buffered updates
                _ = debounce_sleep, if debounce_deadline.is_some() => {
                    debounce_deadline = None;

                    if let Err(error) = self.flush_node_batch(
                        &mut write, client, &mut debounce_buffer, &mut document_buffer,
                    ).await {
                        flush_to_queue(&self.queue, &mut debounce_buffer);
                        return LoopExit::Disconnected(error);
                    }
                    if !debounce_buffer.is_empty() || !document_buffer.is_empty() {
                        debounce_deadline = Some(Instant::now() + Duration::from_millis(debounce_ms));
                    }
                }

                _ = sealed_relay.tick() => {
                    if self.config.client_config.federation_peer.is_none()
                        && sealed_task.as_ref().is_none_or(tokio::task::JoinHandle::is_finished)
                    {
                        let manager = std::sync::Arc::clone(&self.manager);
                        let config = self.client_config();
                        let events = event_tx.clone();
                        sealed_task = Some(tokio::spawn(async move {
                            // An opened machine's windows carry only the
                            // authority rows they hold: take the rest first
                            // (OF-469). Any machine whose rows name history it
                            // lacks takes it too.
                            if (config.residence_mode == crate::sync::SyncResidenceMode::Opened
                                || !manager
                                    .vault()
                                    .authority_missing_history()
                                    .is_ok_and(|missing| missing.is_complete()))
                                && let Err(error) =
                                    crate::sync::client::catch_up_authority(manager.vault(), &config)
                                        .await
                                && !matches!(error, crate::sync::TransportError::InvalidPayload(_))
                            {
                                let _ = events.send(SyncEvent::Error(format!(
                                    "Authority catch-up failed: {error}"
                                )));
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
                            match crate::sync::client::relay_sealed_windows(&manager, &config).await {
                                Ok(_) | Err(crate::sync::TransportError::InvalidPayload(_)) => {}
                                Err(error) => {
                                    let _ = events.send(SyncEvent::Error(format!(
                                        "Sealed window relay failed: {error}"
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
                        }));
                    }
                }

                // Loro's Rust EphemeralStore has no internal timer.
                _ = ephemeral_housekeeping.tick() => {
                    client.remove_outdated_ephemeral();
                    if let Err(error) = client.replay_deferred_federation_update() {
                        return LoopExit::Disconnected(format!("federation replay: {error}"));
                    }
                    // Pinned artifact pointers this device still owes the server.
                    match client.due_artifact_publication_frames() {
                        Ok(frames) => {
                            document_buffer.extend(frames);
                            if !document_buffer.is_empty() {
                                debounce_deadline.get_or_insert_with(||
                                    Instant::now() + Duration::from_millis(debounce_ms));
                            }
                        },
                        Err(error) => { let _ = event_tx.send(SyncEvent::Error(format!("Artifact publication sync failed: {error}"))); }
                    }
                    match self.manager.vault().pump_message_streams() {
                        Ok(report) => for (_, error) in report.refused {
                            let _ = event_tx.send(SyncEvent::Error(format!("Stream idle finalize refused: {error}")));
                        },
                        Err(error) => { let _ = event_tx.send(SyncEvent::Error(format!("Stream idle pump failed: {error}"))); }
                    }
                }

                changed = mode_rx.changed() => {
                    if changed.is_ok() {
                        flush_to_queue(&self.queue, &mut debounce_buffer);
                        let _ = write.send(Message::Close(None)).await;
                        return LoopExit::Disconnected("residence mode changed".into());
                    }
                }

                // A confirmed leave ends the lane for good (OF-158): what it
                // buffered is queued, to be counted and discarded.
                _ = left_rx.wait_for(|left| *left) => {
                    flush_to_queue(&self.queue, &mut debounce_buffer);
                    let _ = write.send(Message::Close(None)).await;
                    return LoopExit::Shutdown;
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
