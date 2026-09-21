//! Steady state: debounced multiplex loop over WS, local updates, shutdown.

use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tokio::time::{Duration, Instant};
use tokio_tungstenite::tungstenite::Message;

use crate::sync::client::{SyncClient, SyncEvent};
use crate::sync::transport::{self, window_sub_tags};
use crate::sync::types::parse_window_key_str;

use super::session::EPHEMERAL_HOUSEKEEPING_INTERVAL_SECS;
use super::{LocalUpdate, LoopExit, SyncConnection, flush_to_queue};

impl SyncConnection {
    /// Steady-state event loop: multiplexes WS reads, local updates, and debounce.
    pub(super) async fn steady_state(
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
        // Live, bounded and lossy. Partials never enter the durable offline queue.
        let mut presence_rx = self
            .manager
            .vault()
            .message_streams
            .presence
            .subscribe_frames();

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
                            match client.vault.sync_state_get(&format!("ds:e:{}", id.to_hex())) {
                                Ok(Some(_)) => {
                                    if let Err(error) = write.send(Message::Binary(frame.into())).await {
                                        return LoopExit::Disconnected(error.to_string());
                                    }
                                }
                                Ok(None) => {} // Offline editing before admission stays journaled.
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
                    if let Err(error) = client.replay_deferred_federation_update() {
                        return LoopExit::Disconnected(format!("federation replay: {error}"));
                    }
                    match self.manager.vault().pump_message_streams() {
                        Ok(report) => for (_, error) in report.refused {
                            let _ = event_tx.send(SyncEvent::Error(format!("Stream idle finalize refused: {error}")));
                        },
                        Err(error) => { let _ = event_tx.send(SyncEvent::Error(format!("Stream idle pump failed: {error}"))); }
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
