//! Phase 3 queue replay: the queued rows a session sends, each in its window
//! pad envelope, batched on the node tick.

use futures_util::SinkExt;
use tokio::sync::mpsc;
use tokio::time::Duration;
use tokio_tungstenite::tungstenite::Message;

use crate::sync::client::{SyncClient, SyncEvent};
use crate::sync::queue::QueuedUpdate;
use crate::sync::transport::{self, window_sub_tags};
use crate::sync::window::UpdateVerdict;

use super::super::SyncConnection;
use super::super::session::{SessionFault, WsSink};

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
    ) -> Result<Vec<QueuedUpdate>, SessionFault> {
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
            let msgs = client
                .window_pad_frames(
                    &update.window_key,
                    if opened {
                        window_sub_tags::RESIDENCE_UPDATE
                    } else {
                        window_sub_tags::UPDATE
                    },
                    opened.then_some(update.seq),
                    &update.encoded,
                    context.as_ref().map(|window| &window.doc),
                )
                .map_err(|e| SessionFault::Local(format!("Queue replay encode failed: {e}")))?;
            for msg in msgs {
                // A first frame past a member's room by its envelope header
                // goes alone; its parts follow it in order.
                let alone = !super::super::session::fits_alone(&msg);
                if (alone
                    || !super::super::node_batch::fits(&frames, size, &msg)
                        .map_err(SessionFault::local)?)
                    && !frames.is_empty()
                {
                    tick.tick().await;
                    let batch = transport::encode_node_batch(&frames)
                        .into_result()
                        .map_err(SessionFault::local)?;
                    write
                        .send(Message::Binary(batch.into()))
                        .await
                        .map_err(|e| SessionFault::Remote(format!("Queue replay failed: {e}")))?;
                    frames.clear();
                    size = 1;
                }
                if alone {
                    tick.tick().await;
                    write
                        .send(Message::Binary(msg.into()))
                        .await
                        .map_err(|e| SessionFault::Remote(format!("Queue replay failed: {e}")))?;
                    continue;
                }
                size += 4 + msg.len();
                frames.push(msg);
            }
            sent.push(update);
        }
        if !frames.is_empty() {
            tick.tick().await;
            let batch = transport::encode_node_batch(&frames)
                .into_result()
                .map_err(SessionFault::local)?;
            write
                .send(Message::Binary(batch.into()))
                .await
                .map_err(|e| SessionFault::Remote(format!("Queue replay failed: {e}")))?;
        }
        Ok(sent)
    }
}
