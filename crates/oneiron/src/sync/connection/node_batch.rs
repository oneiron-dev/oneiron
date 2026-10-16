//! One bounded node proposal batch per sync tick.

use futures_util::SinkExt;
use tokio_tungstenite::tungstenite::Message;

use super::session::{WsSink, residence_update_frame};
use super::{LocalUpdate, SyncConnection};
use crate::side_table::HexId;
use crate::sync::client::{SyncClient, SyncResidenceMode};
use crate::sync::documents::DS_E;
use crate::sync::transport::{self, TransportError, window_sub_tags};
use crate::sync::window::UpdateVerdict;

pub(super) fn fits(frames: &[Vec<u8>], size: usize, next: &[u8]) -> Result<bool, TransportError> {
    let total = size.saturating_add(4).saturating_add(next.len());
    if frames.is_empty() && total > transport::MAX_DECODED_PAYLOAD_BYTES {
        return Err(TransportError::FrameTooLarge {
            size: total,
            max: transport::MAX_DECODED_PAYLOAD_BYTES,
        });
    }
    Ok(frames.len() < transport::MAX_NODE_BATCH_MEMBERS
        && total <= transport::MAX_DECODED_PAYLOAD_BYTES)
}

impl SyncConnection {
    pub(super) async fn flush_node_batch(
        &self,
        write: &mut WsSink,
        client: &SyncClient,
        updates: &mut Vec<LocalUpdate>,
        documents: &mut Vec<Vec<u8>>,
    ) -> Result<(), String> {
        let opened = client.config.residence_mode == SyncResidenceMode::Opened;
        let mut frames = Vec::new();
        let mut size = 1;
        let mut full_updates = Vec::new();
        let prepared = (|| -> Result<(), String> {
            while let Some(update) = updates.first() {
                match client.update_verdict(&update.window_key, &update.update_bytes) {
                    UpdateVerdict::Withheld => {
                        updates.remove(0);
                        continue;
                    }
                    UpdateVerdict::Uninspectable => {
                        self.queue
                            .push(&update.window_key, &update.update_bytes)
                            .map_err(|error| error.to_string())?;
                        updates.remove(0);
                        continue;
                    }
                    UpdateVerdict::Portable => {}
                }
                // Check room before reserving a durable sequence. Excess work
                // stays in the buffer for the next tick, never a per-op send.
                let candidate = if opened {
                    residence_update_frame(1, &update.window_key, &update.update_bytes)
                } else {
                    transport::encode_window_sync(
                        &update.window_key,
                        window_sub_tags::UPDATE,
                        &update.update_bytes,
                    )
                    .into_result()
                }
                .map_err(|error| error.to_string())?;
                if !fits(&frames, size, &candidate).map_err(|error| error.to_string())? {
                    break;
                }
                let frame = if opened {
                    let seq = self
                        .queue
                        .push(&update.window_key, &update.update_bytes)
                        .map_err(|error| error.to_string())?;
                    residence_update_frame(seq, &update.window_key, &update.update_bytes)
                        .map_err(|error| error.to_string())?
                } else {
                    candidate
                };
                size += 4 + frame.len();
                frames.push(frame);
                let update = updates.remove(0);
                if !opened {
                    full_updates.push(update);
                }
            }
            while let Some(frame) = documents.first() {
                let doc =
                    transport::decode_document(&frame[1..]).map_err(|error| error.to_string())?;
                let subscribed = {
                    let txn = client
                        .vault
                        .store
                        .env
                        .read_txn()
                        .map_err(|error| error.to_string())?;
                    doc.kind == transport::document_sub_tags::ARTIFACT_PUBLICATION
                        || DS_E
                            .contains(&client.vault.store, &txn, &HexId(doc.entity))
                            .map_err(|error| error.to_string())?
                };
                if !subscribed || client.frame_withheld(frame) {
                    documents.remove(0);
                    continue;
                }
                if !fits(&frames, size, frame).map_err(|error| error.to_string())? {
                    break;
                }
                size += 4 + frame.len();
                frames.push(documents.remove(0));
            }
            Ok(())
        })();
        let sent = match prepared {
            Err(error) => Err(error),
            Ok(()) if frames.is_empty() => Ok(()),
            Ok(()) => match transport::encode_node_batch(&frames).into_result() {
                Err(error) => Err(error.to_string()),
                Ok(batch) => write
                    .send(Message::Binary(batch.into()))
                    .await
                    .map_err(|error| error.to_string()),
            },
        };
        if sent.is_err() {
            // Opened writes already have durable sequences. Full-window writes
            // keep the original reconnect/VV-confirmation recovery contract.
            for update in full_updates {
                if let Err(error) = self.queue.push(&update.window_key, &update.update_bytes) {
                    tracing::error!(%error, "failed to queue unsent node write");
                }
            }
            // Documents remain in their own durable journal until the home ACK.
        }
        sent
    }
}
