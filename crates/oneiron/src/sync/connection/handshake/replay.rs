//! Queued window replay keeps native copy evidence through socket release.

use tokio::sync::mpsc;
use tokio::time::Duration;

use crate::sync::client::{SyncClient, SyncEvent};
use crate::sync::queue::QueuedUpdate;
use crate::sync::transport::window_sub_tags;
use crate::sync::window::UpdateVerdict;

use super::super::node_batch::PreparedNodeBatch;
use super::super::session::WsSink;
use super::super::{SyncConnection, node_batch, session};

impl SyncConnection {
    /// Sends queued rows the way Phase 3 replays them, importing each into the
    /// local window doc first. Returns the rows sent; a row the device-only
    /// verdict withholds is skipped, and nothing past an unjudged row is sent.
    pub(in crate::sync::connection) async fn replay_queued_updates(
        &self,
        write: &mut WsSink,
        client: &mut SyncClient,
        event_tx: &mpsc::UnboundedSender<SyncEvent>,
        queued: Vec<QueuedUpdate>,
    ) -> Result<Vec<QueuedUpdate>, String> {
        let mut sent = Vec::with_capacity(queued.len());
        let mut frames = Vec::new();
        let mut copy_releases = Vec::new();
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
                UpdateVerdict::Withheld => {
                    // A home that may not read the world takes it sealed,
                    // when the world syncs sealed (DEC-0005 fix 8).
                    client.relay_withheld_update(&update.window_key, &update.encoded);
                    continue;
                }
                UpdateVerdict::Uninspectable => break,
            }
            // A window the home refused to grant again keeps its rows queued,
            // unsent; they hold back no other window's clear.
            if !client.residence_granted(&update.window_key) {
                continue;
            }
            // Each row goes in its window pad envelope for the home, its pads
            // projected and sealed at this send (FIX 7107).
            let opened = client.config.residence_mode == crate::sync::SyncResidenceMode::Opened;
            let context = client.window(&update.window_key);
            let ready = client
                .prepare_window_send(
                    &update.window_key,
                    &update.encoded,
                    context.as_ref().map(|window| &window.doc),
                )
                .map_err(|e| format!("Queue replay encode failed: {e}"))?;
            let ready = client.prepare_window_claim_send(
                ready,
                &update.window_key,
                if opened {
                    window_sub_tags::RESIDENCE_UPDATE
                } else {
                    window_sub_tags::UPDATE
                },
                context.as_ref().map(|window| &window.doc),
            );
            let msgs = ready
                .reply_frames(client, opened.then_some(update.seq), &update.encoded)
                .map_err(|e| format!("Queue replay encode failed: {e}"))?;
            for msg in msgs {
                let required = msg.as_bytes();
                // Optional-only parts never choose a batch or add a tick.
                if !required.is_empty() {
                    // A first frame past a member's room by its envelope header
                    // goes alone; its parts follow it in order.
                    let alone = !session::fits_alone(required);
                    if (alone
                        || !node_batch::fits(&frames, size, required).map_err(|e| e.to_string())?)
                        && !frames.is_empty()
                    {
                        tick.tick().await;
                        let batch = PreparedNodeBatch::encode(
                            std::mem::take(&mut frames),
                            std::mem::take(&mut copy_releases),
                        )
                        .map_err(|e| e.to_string())?;
                        write
                            .send_node_batch(batch)
                            .await
                            .map_err(|e| format!("Queue replay failed: {e}"))?;
                        size = 1;
                    }
                    if alone {
                        tick.tick().await;
                        write
                            .send_prepared(msg)
                            .await
                            .map_err(|e| format!("Queue replay failed: {e}"))?;
                        continue;
                    }
                }
                let (msg, release) = msg.into_batch_parts();
                if let Some(release) = release {
                    if msg.is_empty() && frames.is_empty() {
                        release.abandon();
                    } else {
                        copy_releases.push((frames.len(), release));
                    }
                }
                if !msg.is_empty() {
                    size += 4 + msg.len();
                    frames.push(msg);
                }
            }
            sent.push(update);
        }
        if !frames.is_empty() {
            tick.tick().await;
            let batch =
                PreparedNodeBatch::encode(frames, copy_releases).map_err(|e| e.to_string())?;
            write
                .send_node_batch(batch)
                .await
                .map_err(|e| format!("Queue replay failed: {e}"))?;
        }
        Ok(sent)
    }
}
